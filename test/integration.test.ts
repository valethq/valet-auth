import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import type { Subprocess } from "bun";
import { parseCookies } from "../src/secrets";

const CORE = process.env.VALET_CORE_DIR ?? join(import.meta.dir, "..", "..", "valet-core");
const CORE_CLI = join(CORE, "packages/core/src/cli.ts");
const SDK_DIR = join(CORE, "packages/sdk");
const REPO = join(import.meta.dir, "..");
const BUN = Bun.which("bun") ?? join(homedir(), ".npm-global/bin/bun");

let home: string;
let base: string;
let proc: Subprocess;
let output = "";

function freePort(): number {
  const srv = Bun.serve({ port: 0, fetch: () => new Response("ok") });
  const port = srv.port ?? 0;
  srv.stop(true);
  return port;
}

/** pluginPaths can't point at this repo's parent (it would load every sibling), so copy just this plugin. */
function stagePlugin(pluginsDir: string): void {
  const dest = join(pluginsDir, "valet-auth");
  mkdirSync(join(dest, "node_modules", "@valethq"), { recursive: true });
  cpSync(join(REPO, "src"), join(dest, "src"), { recursive: true });
  cpSync(join(REPO, "manifest.json"), join(dest, "manifest.json"));
  symlinkSync(SDK_DIR, join(dest, "node_modules", "@valethq", "sdk"));
  const policy = join(pluginsDir, "valet-fixture-policy");
  mkdirSync(join(policy, "node_modules", "@valethq"), { recursive: true });
  cpSync(join(REPO, "test", "fixtures", "valet-fixture-policy"), policy, { recursive: true });
  symlinkSync(SDK_DIR, join(policy, "node_modules", "@valethq", "sdk"));
}

async function api(path: string, init: RequestInit = {}, cookie?: string): Promise<Response> {
  const headers = new Headers(init.headers);
  if (cookie) headers.set("cookie", `valet_session=${cookie}`);
  return fetch(`${base}${path}`, { ...init, headers });
}

const post = (path: string, body: unknown, cookie?: string) =>
  api(
    path,
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    },
    cookie,
  );

beforeAll(async () => {
  home = mkdtempSync(join(tmpdir(), "valet-auth-it-"));
  const pluginsDir = join(home, "plugins");
  mkdirSync(pluginsDir, { recursive: true });
  stagePlugin(pluginsDir);
  const port = freePort();
  base = `http://127.0.0.1:${port}`;
  writeFileSync(
    join(home, "config.json"),
    JSON.stringify({
      server: { host: "127.0.0.1", port, allowedOrigins: [] },
      pluginPaths: [pluginsDir],
      plugins: { "valet-auth": { enabled: true, config: {} } },
    }),
  );
  proc = Bun.spawn([BUN, CORE_CLI, "start", "--home", home], {
    stdout: "pipe",
    stderr: "pipe",
  });
  const drain = async (stream: ReadableStream<Uint8Array> | null) => {
    if (!stream) return;
    for await (const chunk of stream) output += Buffer.from(chunk).toString("utf8");
  };
  void drain(proc.stdout as ReadableStream<Uint8Array>);
  void drain(proc.stderr as ReadableStream<Uint8Array>);

  const deadline = Date.now() + 20_000;
  for (;;) {
    if (proc.exitCode !== null) {
      throw new Error(`valet exited ${proc.exitCode}\n${output}`);
    }
    try {
      if ((await fetch(`${base}/`)).ok) return;
    } catch {
      // not up yet
    }
    if (Date.now() > deadline) throw new Error(`valet did not start\n${output}`);
    await Bun.sleep(100);
  }
});

afterAll(async () => {
  proc.kill();
  await proc.exited;
});

const cookieOf = (res: Response): string => parseCookies(res.headers.get("set-cookie")).valet_session ?? "";

describe("kernel integration", () => {
  let cookie = "";
  let cookie2 = "";
  let bearer = "";
  let bearerId = "";

  test("status reports setupRequired and writes a 0600 setup token", async () => {
    const res = await api("/plugins/valet-auth/status");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ setupRequired: true });
    const tokenFile = join(home, "data", "valet-auth", "setup-token");
    expect(existsSync(tokenFile)).toBe(true);
    expect(readFileSync(tokenFile, "utf8")).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  test("core REST refuses anonymous before setup", async () => {
    expect((await api("/api/core/projects")).status).toBe(401);
  });

  test("setup with the one-time token creates the owner and a session", async () => {
    const token = readFileSync(join(home, "data", "valet-auth", "setup-token"), "utf8");
    expect((await post("/plugins/valet-auth/setup", { token: "bad", password: "pw" })).status).toBe(401);
    const res = await post("/plugins/valet-auth/setup", {
      token,
      password: "correct horse battery staple",
      displayName: "Test Owner",
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { principalId: string };
    expect(body.principalId).toMatch(/^pri_/);
    cookie = cookieOf(res);
    expect(cookie).not.toBe("");
    const setCookie = res.headers.get("set-cookie") ?? "";
    expect(setCookie).toContain("HttpOnly");
    expect(setCookie).toContain("SameSite=Strict");
    expect(setCookie).not.toContain("Secure"); // http URL
    expect(await (await api("/plugins/valet-auth/status")).json()).toEqual({ setupRequired: false });
    expect(existsSync(join(home, "data", "valet-auth", "setup-token"))).toBe(false);
  });

  test("cookie authenticates core REST and plugin owner routes", async () => {
    expect((await api("/api/core/projects", {}, cookie)).status).toBe(200);
    const me = await api("/plugins/valet-auth/me", {}, cookie);
    expect(me.status).toBe(200);
    const { principal } = (await me.json()) as { principal: { role: string } };
    expect(principal.role).toBe("owner");
  });

  test("bearer token from /tokens authenticates, revokes cleanly", async () => {
    const res = await post("/plugins/valet-auth/tokens", { name: "cli", cap: ["core:project.read"] }, cookie);
    expect(res.status).toBe(201);
    const body = (await res.json()) as { id: string; token: string };
    bearer = body.token;
    bearerId = body.id;
    expect(bearer).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(
      (
        await api("/api/core/projects", {
          headers: { authorization: `Bearer ${bearer}` },
        })
      ).status,
    ).toBe(200);
    const listed = (await (await api("/plugins/valet-auth/tokens", {}, cookie)).json()) as {
      tokens: { id: string; cap: string[] | null }[];
    };
    expect(listed.tokens.find((t) => t.id === bearerId)?.cap).toEqual(["core:project.read"]);
  });

  test("a token without cap or tag is refused", async () => {
    expect((await post("/plugins/valet-auth/tokens", { name: "bare" }, cookie)).status).toBe(400);
  });

  test("a revoked device stops working", async () => {
    const login = await post("/plugins/valet-auth/login", {
      password: "correct horse battery staple",
      deviceName: "second",
    });
    expect(login.status).toBe(200);
    cookie2 = cookieOf(login);
    expect((await api("/api/core/projects", {}, cookie2)).status).toBe(200);

    const devices = (await (await api("/plugins/valet-auth/devices", {}, cookie)).json()) as {
      devices: { id: string; name: string | null }[];
    };
    const second = devices.devices.find((d) => d.name === "second");
    expect(second).toBeDefined();
    expect(
      (await api(`/plugins/valet-auth/devices/${second?.id}`, { method: "DELETE" }, cookie)).status,
    ).toBe(200);
    expect((await api("/api/core/projects", {}, cookie2)).status).toBe(401);
    expect((await api("/api/core/projects", {}, cookie)).status).toBe(200); // other device fine
  });

  test("wrong password is a delayed 401; revoked token refuses", async () => {
    const t0 = Date.now();
    const bad = await post("/plugins/valet-auth/login", { password: "wrong" });
    expect(bad.status).toBe(401);
    expect(Date.now() - t0).toBeGreaterThanOrEqual(290);
    expect((await api(`/plugins/valet-auth/tokens/${bearerId}`, { method: "DELETE" }, cookie)).status).toBe(
      200,
    );
    expect((await api("/api/core/projects", { headers: { authorization: `Bearer ${bearer}` } })).status).toBe(
      401,
    );
  });

  test("logout revokes the device and clears the cookie", async () => {
    const res = await post("/plugins/valet-auth/logout", {}, cookie);
    expect(res.status).toBe(200);
    expect(res.headers.get("set-cookie")).toContain("Max-Age=0");
    expect((await api("/api/core/projects", {}, cookie)).status).toBe(401);
    expect((await post("/plugins/valet-auth/setup", { token: "x", password: "y" })).status).toBe(409);
  });

  test("the route gate and the scoped issuer check both reach the policy", async () => {
    const login = await post("/plugins/valet-auth/login", {
      password: "correct horse battery staple",
    });
    const c3 = cookieOf(login);
    const mint = (body: unknown) => post("/plugins/valet-auth/tokens", body, c3);
    const deny = (permission: string, resource: string) =>
      post("/plugins/valet-fixture-policy/deny", { permission, resource });

    // The handler's scoped can() reaches the policy with the claimed resource.
    expect((await deny("core:project.read", "project:prj_denied")).status).toBe(200);
    expect(
      (
        await mint({
          name: "denied",
          cap: ["core:project.read"],
          resource: "project:prj_denied",
        })
      ).status,
    ).toBe(403);
    expect((await mint({ name: "ok", cap: ["core:project.read"], resource: "project:prj_ok" })).status).toBe(
      201,
    );

    // Denying the unscoped route permission stops the request before the handler runs.
    expect((await deny("identity:token.create", "*")).status).toBe(200);
    expect((await mint({ name: "late", cap: ["core:project.read"] })).status).toBe(403);
  });
});
