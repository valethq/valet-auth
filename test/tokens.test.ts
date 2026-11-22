import { Database } from "bun:sqlite";
import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { createAuthStore, MIGRATIONS } from "../src/db";
import plugin from "../src/index";
import { createIdentityProvider } from "../src/provider";
import { sha256Hex } from "../src/secrets";
import { call, cookieOf, type Fake, fakeContext, ownerCtx } from "./fake";

async function boot(): Promise<{ f: Fake; principalId: string; cookie: string }> {
  const f = fakeContext();
  await plugin.activate(f.ctx);
  f.declare("core:session.read");
  f.declare("core:session.write");
  const setup = await call(
    f,
    "POST /setup",
    new Request("http://x/setup", {
      method: "POST",
      body: JSON.stringify({
        token: readFileSync(join(f.dataDir, "setup-token"), "utf8"),
        password: "pw123456",
      }),
    }),
  );
  const { principalId } = (await setup.json()) as { principalId: string };
  return { f, principalId, cookie: cookieOf(setup) };
}

const mint = (f: Fake, body: unknown, rc = ownerCtx("pri_1")) =>
  call(f, "POST /tokens", new Request("http://x/tokens", { method: "POST", body: JSON.stringify(body) }), rc);

const bearer = (token: string) => new Request("http://x/", { headers: { authorization: `Bearer ${token}` } });

describe("token creation", () => {
  test("requires cap or tag, valid patterns and a non-empty cap", async () => {
    const { f } = await boot();
    expect((await mint(f, { name: "x" })).status).toBe(400);
    expect((await mint(f, { cap: [] })).status).toBe(400);
    expect((await mint(f, { cap: "core:session.read" })).status).toBe(400);
    for (const bad of ["", "Core:x", "core:", "a:b:c", "core:*:x", "core"]) {
      expect((await mint(f, { cap: [bad] })).status).toBe(400);
    }
    expect((await mint(f, { tag: "tag:ci" })).status).toBe(400);
    expect((await mint(f, { tag: "" })).status).toBe(400);
  });

  test("a capped token authenticates as its creator with the cap, never verified", async () => {
    const { f, principalId, cookie } = await boot();
    const res = await mint(f, { name: "ci", cap: ["core:session.read"] }, ownerCtx(principalId));
    expect(res.status).toBe(201);
    const { id, token } = (await res.json()) as { id: string; token: string };
    expect(await f.authenticate(bearer(token))).toEqual({
      principalId,
      credentialId: id,
      cap: ["core:session.read"],
    });
    expect(
      await f.authenticate(new Request("http://x/", { headers: { cookie: `valet_session=${cookie}` } })),
    ).toMatchObject({
      verifiedLogin: true,
    });
    const listed = (await (await call(f, "GET /tokens", new Request("http://x/t"))).json()) as {
      tokens: { id: string; cap: string[] | null; tag: string | null }[];
    };
    expect(listed.tokens.find((t) => t.id === id)).toMatchObject({ cap: ["core:session.read"], tag: null });
  });

  test("an uncapped owner may mint wildcard caps", async () => {
    const { f, principalId } = await boot();
    expect((await mint(f, { cap: ["core:*"] }, ownerCtx(principalId))).status).toBe(201);
    expect((await mint(f, { cap: ["*"] }, ownerCtx(principalId))).status).toBe(201);
  });

  test("a capped issuer cannot exceed itself or mint wildcards", async () => {
    const { f, principalId } = await boot();
    const capped = ownerCtx(principalId, { cap: ["core:session.read", "core:session.write"] });
    expect((await mint(f, { cap: ["core:session.read"] }, capped)).status).toBe(201);
    expect((await mint(f, { cap: ["core:session.write"] }, capped)).status).toBe(201);
    expect((await mint(f, { cap: ["core:project.read"] }, capped)).status).toBe(403);
    expect((await mint(f, { cap: ["core:*"] }, capped)).status).toBe(403);
    expect((await mint(f, { cap: ["*"] }, capped)).status).toBe(403);
    const narrow = ownerCtx(principalId, { cap: ["core:session.read"] });
    expect((await mint(f, { cap: ["core:session.write"] }, narrow)).status).toBe(403);
  });

  test("every concrete permission must pass can() for the caller", async () => {
    const { f } = await boot();
    const trusted = ownerCtx("pri_other", { role: "trusted" });
    expect((await mint(f, { cap: ["core:session.read"] }, trusted)).status).toBe(403);
    expect((await mint(f, { cap: ["nobody:declared"] })).status).toBe(403);
  });
});

describe("tagged tokens", () => {
  test("minting without policy@1 needs a verified owner login", async () => {
    const { f, principalId } = await boot();
    expect((await mint(f, { tag: "ci" }, ownerCtx(principalId, { verifiedLogin: false }))).status).toBe(403);
    expect((await mint(f, { tag: "ci" }, ownerCtx("pri_t", { role: "trusted" }))).status).toBe(403);
    expect((await mint(f, { tag: "ci" }, ownerCtx(principalId))).status).toBe(201);
  });

  test("minting with policy:tag.assign declared goes through can() on the tag", async () => {
    const { f, principalId } = await boot();
    f.declare("policy:tag.assign", { summary: "assign tags", resource: "tag" });
    expect((await mint(f, { tag: "ci" }, ownerCtx(principalId, { verifiedLogin: false }))).status).toBe(201);
    expect((await mint(f, { tag: "ci" }, ownerCtx("pri_t", { role: "trusted" }))).status).toBe(403);
  });

  test("authenticates as its own guest service principal with the tag", async () => {
    const { f, principalId } = await boot();
    const res = await mint(f, { name: "bot", tag: "ci" }, ownerCtx(principalId));
    const { id, token } = (await res.json()) as { id: string; token: string };
    const auth = await f.authenticate(bearer(token));
    expect(auth).toEqual({ principalId: expect.any(String), credentialId: id, tags: ["tag:ci"] });
    expect(auth?.principalId).not.toBe(principalId);
    expect(f.principals.get(auth?.principalId ?? "")).toMatchObject({ displayName: "tag:ci", role: "guest" });
    expect(f.credential(id)).toEqual({ active: true, tags: ["tag:ci"] });
  });

  test("a token may carry both cap and tag", async () => {
    const { f, principalId } = await boot();
    const res = await mint(f, { tag: "ci", cap: ["core:session.read"] }, ownerCtx(principalId));
    const { token } = (await res.json()) as { token: string };
    expect(await f.authenticate(bearer(token))).toMatchObject({
      tags: ["tag:ci"],
      cap: ["core:session.read"],
    });
    expect((await mint(f, { tag: "ci", cap: ["bad"] }, ownerCtx(principalId))).status).toBe(400);
  });
});

describe("credential()", () => {
  test("reports active, revoked, and unknown credentials", async () => {
    const { f, principalId } = await boot();
    const { id, token } = (await (
      await mint(f, { cap: ["core:session.read"] }, ownerCtx(principalId))
    ).json()) as {
      id: string;
      token: string;
    };
    expect(f.credential(id)).toEqual({ active: true, cap: ["core:session.read"] });
    const device = (
      (await (await call(f, "GET /devices", new Request("http://x/d"))).json()) as {
        devices: { id: string }[];
      }
    ).devices[0];
    expect(f.credential(device?.id ?? "")).toEqual({ active: true });

    await call(f, "DELETE /tokens/:id", new Request("http://x/"), {
      ...ownerCtx(principalId),
      params: { id },
    });
    expect(f.credential(id)).toEqual({ active: false });
    expect(await f.authenticate(bearer(token))).toBeUndefined();
    await call(f, "DELETE /devices/:id", new Request("http://x/"), {
      ...ownerCtx(principalId),
      params: { id: device?.id ?? "" },
    });
    expect(f.credential(device?.id ?? "")).toEqual({ active: false });

    expect(f.credential("tok_gone")).toEqual({ active: false });
    expect(f.credential("dev_gone")).toEqual({ active: false });
    expect(f.credential("run_123")).toBeUndefined();
  });
});

describe("legacy tokens and migration", () => {
  test("rows without cap or tag authenticate as the owner, uncapped, unverified", () => {
    const db = new Database(":memory:");
    for (const m of MIGRATIONS) db.exec(m.up);
    const store = createAuthStore(db);
    const row = store.createToken({
      id: store.newTokenId(),
      principalId: "pri_1",
      secretSha256: sha256Hex("s"),
    });
    const provider = createIdentityProvider(store, () => "valet_session");
    expect(provider.authenticate(bearer("s"))).toEqual({ principalId: "pri_1", credentialId: row.id });
    expect(provider.credential?.(row.id)).toEqual({ active: true });
  });

  test("migration 0002 adds nullable cap and tag to existing rows", () => {
    const db = new Database(":memory:");
    db.exec(MIGRATIONS[0]?.up ?? "");
    db.query(
      "INSERT INTO p_auth_tokens (id, principal_id, secret_sha256, created_at) VALUES ('tok_old', 'pri_1', 'h', 1)",
    ).run();
    db.exec(MIGRATIONS[1]?.up ?? "");
    const store = createAuthStore(db);
    expect(store.tokenById("tok_old")).toMatchObject({ cap: null, tag: null });
  });
});
