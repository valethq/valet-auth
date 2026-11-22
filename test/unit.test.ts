import { Database } from "bun:sqlite";
import { describe, expect, test } from "bun:test";
import { readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { createAuthStore, MIGRATIONS } from "../src/db";
import plugin from "../src/index";
import { clearCookie, parseCookies, randomSecret, sessionCookie, sha256Hex } from "../src/secrets";
import { call, cookieOf, fakeContext, ownerCtx } from "./fake";

// ---- pure helpers -----------------------------------------------------------

describe("secrets", () => {
  test("randomSecret is 32 bytes base64url and unique", () => {
    const a = randomSecret();
    const b = randomSecret();
    expect(a).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(a).not.toBe(b);
  });

  test("sha256Hex is a stable hex digest", () => {
    expect(sha256Hex("abc")).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  });

  test("parseCookies handles standard headers", () => {
    expect(parseCookies("a=1; b=2;valet_session=x.y-z")).toEqual({
      a: "1",
      b: "2",
      valet_session: "x.y-z",
    });
    expect(parseCookies(null)).toEqual({});
    expect(parseCookies("k=v=with=equals")).toEqual({ k: "v=with=equals" });
    expect(parseCookies(";; =dropped; ok=1")).toEqual({ ok: "1" });
  });

  test("sessionCookie shape and Secure flag", () => {
    const plain = sessionCookie("valet_session", "s3cr3t", false);
    expect(plain).toBe("valet_session=s3cr3t; HttpOnly; SameSite=Strict; Path=/; Max-Age=31536000");
    expect(sessionCookie("valet_session", "s3cr3t", true)).toContain("; Secure");
    expect(clearCookie("valet_session", false)).toContain("Max-Age=0");
  });

  test("argon2id hash round-trips and rejects a wrong password", async () => {
    const hash = await Bun.password.hash("hunter2", "argon2id");
    expect(hash).toContain("$argon2id$");
    expect(await Bun.password.verify("hunter2", hash)).toBe(true);
    expect(await Bun.password.verify("nope", hash)).toBe(false);
  });
});

// ---- db layer ---------------------------------------------------------------

describe("auth store", () => {
  const newStore = () => {
    const db = new Database(":memory:");
    for (const m of MIGRATIONS) db.exec(m.up);
    return createAuthStore(db);
  };

  test("owner create/read and single setup token", () => {
    const s = newStore();
    expect(s.owner()).toBeUndefined();
    s.setSetupToken("hash-a");
    expect(s.checkSetupToken("hash-a")).toBe(true);
    s.setSetupToken("hash-b"); // rotates: only one setup token at a time
    expect(s.checkSetupToken("hash-a")).toBe(false);
    s.createOwner("pri_1", "$argon2id$x");
    expect(s.owner()?.principalId).toBe("pri_1");
    s.clearSetupTokens();
    expect(s.checkSetupToken("hash-b")).toBe(false);
  });

  test("devices and tokens: lookup by secret, touch, revoke, list", () => {
    const s = newStore();
    const dev = s.createDevice("pri_1", "dhash", "laptop");
    expect(s.deviceBySecret("dhash")?.id).toBe(dev.id);
    s.touchDevice(dev.id);
    expect(s.deviceBySecret("dhash")?.lastSeenAt).not.toBeNull();
    expect(s.revokeDevice(dev.id)).toBe(true);
    expect(s.revokeDevice(dev.id)).toBe(false); // already revoked
    expect(s.deviceBySecret("dhash")?.revokedAt).not.toBeNull();

    const tok = s.createToken({
      id: s.newTokenId(),
      principalId: "pri_1",
      secretSha256: "thash",
      name: "cli",
    });
    expect(s.tokenBySecret("thash")?.id).toBe(tok.id);
    expect(s.listTokens()).toHaveLength(1);
    expect(s.listDevices()).toHaveLength(1);
    expect(s.revokeToken(tok.id)).toBe(true);
  });
});

describe("plugin", () => {
  test("mints a setup token on first boot and logs the setup URL", async () => {
    const f = fakeContext();
    await plugin.activate(f.ctx);
    const tokenFile = join(f.dataDir, "setup-token");
    const token = readFileSync(tokenFile, "utf8");
    expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(statSync(tokenFile).mode & 0o777).toBe(0o600);
    const log = f.logs.find((l) => l.msg === "valet-auth setup");
    expect(log?.data?.url).toBe(`http://127.0.0.1:7417/plugins/valet-auth/setup?token=${token}`);
    const status = await call(f, "GET /status", new Request("http://x/status"));
    expect(await status.json()).toEqual({ setupRequired: true });
  });

  test("routes declare their permissions and no control.request hook remains", async () => {
    const f = fakeContext();
    await plugin.activate(f.ctx);
    const declared = Object.fromEntries(
      [...f.routes].filter(([, r]) => !r.public).map(([k, r]) => [k, r.permission]),
    );
    expect(declared).toEqual({
      "GET /me": "identity:me",
      "GET /devices": "identity:device.read",
      "DELETE /devices/:id": "identity:device.revoke",
      "POST /tokens": "identity:token.create",
      "GET /tokens": "identity:token.read",
      "DELETE /tokens/:id": "identity:token.revoke",
    });
    expect(f.hooks).toEqual([]);
    const me = await call(f, "GET /me", new Request("http://x/me"), {
      ...ownerCtx("pri_1"),
      principal: undefined,
    });
    expect(me.status).toBe(401);
  });

  test("setup, login cookie auth, logout revoke, bearer tokens", async () => {
    const f = fakeContext();
    await plugin.activate(f.ctx);
    const setupToken = readFileSync(join(f.dataDir, "setup-token"), "utf8");

    const bad = await call(
      f,
      "POST /setup",
      new Request("http://x/setup", {
        method: "POST",
        body: JSON.stringify({ token: "wrong", password: "pw123456" }),
      }),
    );
    expect(bad.status).toBe(401);

    const res = await call(
      f,
      "POST /setup",
      new Request("http://x/setup", {
        method: "POST",
        body: JSON.stringify({ token: setupToken, password: "pw123456", displayName: "A" }),
      }),
    );
    expect(res.status).toBe(200);
    const { principalId } = (await res.json()) as { principalId: string };
    const cookie = cookieOf(res);
    expect(cookie).not.toBe("");
    expect(res.headers.get("set-cookie")).toContain("SameSite=Strict");
    expect(f.principals.get(principalId)?.role).toBe("owner");

    const authReq = (headers: Record<string, string>) => new Request("http://x/", { headers });
    expect(await f.authenticate(authReq({ cookie: `valet_session=${cookie}` }))).toEqual({
      principalId,
      credentialId: expect.stringMatching(/^dev_/),
      verifiedLogin: true,
    });
    expect(await f.authenticate(authReq({ cookie: "valet_session=bogus" }))).toBeUndefined();

    // owner routes
    const me = await call(f, "GET /me", authReq({}), ownerCtx(principalId));
    expect(((await me.json()) as { principal: { role: string } }).principal.role).toBe("owner");

    // bearer token lifecycle
    const tokRes = await call(
      f,
      "POST /tokens",
      new Request("http://x/tokens", {
        method: "POST",
        body: JSON.stringify({ name: "cli", cap: ["identity:me"] }),
      }),
      ownerCtx(principalId),
    );
    expect(tokRes.status).toBe(201);
    const { id: tokenId, token } = (await tokRes.json()) as { id: string; token: string };
    expect(await f.authenticate(authReq({ authorization: `Bearer ${token}` }))).toEqual({
      principalId,
      credentialId: tokenId,
      cap: ["identity:me"],
    });
    const delTok = await call(f, "DELETE /tokens/:id", authReq({}), {
      ...ownerCtx(principalId),
      params: { id: tokenId },
    });
    expect(delTok.status).toBe(200);
    expect(await f.authenticate(authReq({ authorization: `Bearer ${token}` }))).toBeUndefined();

    // logout revokes the device
    const out = await call(f, "POST /logout", authReq({ cookie: `valet_session=${cookie}` }));
    expect(out.headers.get("set-cookie")).toContain("Max-Age=0");
    expect(await f.authenticate(authReq({ cookie: `valet_session=${cookie}` }))).toBeUndefined();
  });

  test("logout emits identity.changed once with the principal id", async () => {
    const f = fakeContext();
    await plugin.activate(f.ctx);
    const setupToken = readFileSync(join(f.dataDir, "setup-token"), "utf8");
    const res = await call(
      f,
      "POST /setup",
      new Request("http://x/setup", {
        method: "POST",
        body: JSON.stringify({ token: setupToken, password: "pw123456" }),
      }),
    );
    const { principalId } = (await res.json()) as { principalId: string };
    const cookie = cookieOf(res);
    f.emits.length = 0; // setup itself emits once

    const out = await call(
      f,
      "POST /logout",
      new Request("http://x/logout", { headers: { cookie: `valet_session=${cookie}` } }),
    );
    expect(out.status).toBe(200);
    expect(f.emits).toEqual([{ name: "identity.changed", payload: { principalId } }]);

    // no device cookie -> no revoke -> no emit
    const bare = await call(f, "POST /logout", new Request("http://x/logout"));
    expect(bare.status).toBe(200);
    expect(f.emits).toHaveLength(1);
  });

  test("login rejects a wrong password and authenticates a right one", async () => {
    const f = fakeContext();
    await plugin.activate(f.ctx);
    const setupToken = readFileSync(join(f.dataDir, "setup-token"), "utf8");
    await call(
      f,
      "POST /setup",
      new Request("http://x/setup", {
        method: "POST",
        body: JSON.stringify({ token: setupToken, password: "pw123456" }),
      }),
    );

    const t0 = Date.now();
    const wrong = await call(
      f,
      "POST /login",
      new Request("http://x/login", { method: "POST", body: JSON.stringify({ password: "no" }) }),
    );
    expect(wrong.status).toBe(401);
    expect(Date.now() - t0).toBeGreaterThanOrEqual(290);

    const right = await call(
      f,
      "POST /login",
      new Request("http://x/login", {
        method: "POST",
        body: JSON.stringify({ password: "pw123456", deviceName: "phone" }),
      }),
    );
    expect(right.status).toBe(200);
    const devices = (await (
      await call(f, "GET /devices", new Request("http://x/d"), ownerCtx("pri_1"))
    ).json()) as { devices: { name: string | null }[] };
    expect(devices.devices.map((d) => d.name)).toContain("phone");
  });

  test("a reloaded cookieName applies to the next login", async () => {
    const f = fakeContext();
    await plugin.activate(f.ctx);
    const setupToken = readFileSync(join(f.dataDir, "setup-token"), "utf8");
    const setup = (): Request =>
      new Request("http://x/setup", {
        method: "POST",
        body: JSON.stringify({ token: setupToken, password: "pw123456" }),
      });
    await call(f, "POST /setup", setup());
    await f.reconfigure({ cookieName: "renamed" });
    const login = await call(
      f,
      "POST /login",
      new Request("http://x/login", { method: "POST", body: JSON.stringify({ password: "pw123456" }) }),
    );
    expect(cookieOf(login, "renamed")).not.toBe("");
    expect(cookieOf(login)).toBe("");
  });
});
