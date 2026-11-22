import { Database } from "bun:sqlite";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type {
  AuthResult,
  CredentialState,
  IdentityProvider,
  PermissionDef,
  PluginContext,
  PluginEventBus,
  PluginStorage,
  Principal,
  RequestContext,
  Role,
  RouteAcl,
  RouteHandler,
  ScopeRegistry,
  Store,
} from "@valethq/sdk";
import manifest from "../manifest.json";
import type { AuthConfig } from "../src/index";
import { parseCookies } from "../src/secrets";

export interface Fake {
  ctx: PluginContext<AuthConfig>;
  routes: Map<string, { handler: RouteHandler; public: boolean; permission: string | undefined }>;
  hooks: string[];
  authenticate: (req: Request) => AuthResult | undefined | Promise<AuthResult | undefined>;
  credential: (id: string) => CredentialState | undefined;
  declare: (name: string, def?: PermissionDef) => void;
  logs: { msg: string; data?: Record<string, unknown> }[];
  emits: { name: string; payload: unknown }[];
  principals: Map<string, Principal>;
  dataDir: string;
  reconfigure: (next: AuthConfig) => Promise<void>;
}

export function fakeContext(config: Record<string, unknown> = {}): Fake {
  const dataDir = mkdtempSync(join(tmpdir(), "valet-auth-test-"));
  const db = new Database(":memory:");
  const routes: Fake["routes"] = new Map();
  const logs: Fake["logs"] = [];
  const principals = new Map<string, Principal>();
  const hooks: string[] = [];
  const emits: Fake["emits"] = [];
  const permissions = new Map<string, PermissionDef>();
  for (const [name, def] of Object.entries(manifest.acl.permissions))
    permissions.set(`identity:${name}`, def as PermissionDef);
  let provider: IdentityProvider = { authenticate: () => undefined };
  const listeners: ((next: AuthConfig, prev: AuthConfig) => void | Promise<void>)[] = [];

  const principalByExternal = new Map<string, Principal>();
  const store = {
    principals: {
      get: (id: string) => principals.get(id),
      resolveIdentity: (platform: string, externalId: string, fallback?: { displayName: string }) => {
        const key = `${platform}:${externalId}`;
        const existing = principalByExternal.get(key);
        if (existing) return existing;
        const p: Principal = {
          id: `pri_${principalByExternal.size + 1}`,
          displayName: fallback?.displayName ?? externalId,
          role: "guest",
        };
        principalByExternal.set(key, p);
        principals.set(p.id, p);
        return p;
      },
      setRole: async (id: string, role: Role) => {
        const p = principals.get(id);
        if (!p) throw new Error(`unknown principal "${id}"`);
        principals.set(id, { ...p, role });
      },
      link: async () => {},
    },
    sessions: { get: () => undefined },
  } as unknown as Store;

  const ctx = {
    plugin: { id: "valet-auth", version: "0.1.0", dir: dataDir, manifest: {} },
    config,
    log: {
      debug: (msg: string, data?: Record<string, unknown>) => logs.push({ msg, data }),
      info: (msg: string, data?: Record<string, unknown>) => logs.push({ msg, data }),
      warn: (msg: string, data?: Record<string, unknown>) => logs.push({ msg, data }),
      error: (msg: string, data?: Record<string, unknown>) => logs.push({ msg, data }),
    },
    acl: {
      permission: (name: string) => permissions.get(name),
      credential: (id: string) => provider.credential?.(id),
    },
    events: {
      before: (name: string) => {
        hooks.push(name);
        return { active: true, disconnect: () => {} };
      },
      emit: async (name: string, payload: unknown) => {
        emits.push({ name, payload });
        return { payload, cancelled: false };
      },
    } as unknown as PluginEventBus,
    scopes: {
      define: () => {},
      maybe: () => undefined,
      provide: (scope: string, impl: IdentityProvider) => {
        if (scope === "identity") provider = impl;
        return { dispose: () => {} };
      },
    } as unknown as ScopeRegistry,
    store,
    storage: {
      kv: {
        get: () => undefined,
        set: () => {},
        delete: () => {},
        list: () => [],
      },
      sql: {
        migrate: (ms: { id: string; up: string }[]) => {
          for (const m of ms) db.exec(m.up);
        },
        db,
      },
    } satisfies PluginStorage,
    http: {
      route: (method: string, path: string, handler: RouteHandler, opts?: RouteAcl) => {
        routes.set(`${method} ${path}`, {
          handler,
          public: opts?.public ?? false,
          permission: opts?.permission,
        });
        return { dispose: () => {} };
      },
      url: (path: string) => `http://127.0.0.1:7417/plugins/valet-auth${path}`,
    },
    ws: { handle: () => ({ dispose: () => {} }), publish: () => {} },
    secrets: { get: async () => undefined, require: async () => "x" },
    paths: { data: dataDir, cache: dataDir, valetHome: dataDir },
    signal: new AbortController().signal,
    onConfigChange: (fn: (typeof listeners)[number]) => listeners.push(fn),
    onDispose: () => {},
  } as unknown as PluginContext<AuthConfig>;

  return {
    ctx,
    routes,
    hooks,
    authenticate: (req) => provider.authenticate(req),
    credential: (id) => provider.credential?.(id),
    declare: (name, def = { summary: name }) => {
      permissions.set(name, def);
    },
    logs,
    emits,
    principals,
    dataDir,
    reconfigure: async (next) => {
      const prev = ctx.config;
      (ctx as { config: AuthConfig }).config = next;
      for (const fn of listeners) await fn(next, prev);
    },
  };
}

export const ownerCtx = (
  principalId: string,
  extra: { cap?: string[]; verifiedLogin?: boolean; credentialId?: string; role?: Role } = {},
): RequestContext => ({
  caller: {
    plugin: "core",
    actor: { principalId, role: extra.role ?? "owner", ...(extra.cap ? { cap: extra.cap } : {}) },
    verifiedLogin: extra.verifiedLogin ?? true,
    ...(extra.credentialId ? { credentialId: extra.credentialId } : {}),
  },
  principal: { id: principalId, displayName: "o", role: extra.role ?? "owner" },
  params: {},
  url: new URL("http://127.0.0.1:7417/"),
});

export const call = (f: Fake, key: string, req: Request, rc?: RequestContext) => {
  const route = f.routes.get(key);
  if (!route) throw new Error(`route ${key} not registered`);
  return route.handler(req, rc ?? ownerCtx("pri_1"));
};

// A Set-Cookie value happens to parse like a Cookie header; attributes just look like extra pairs.
export const cookieOf = (res: Response, name = "valet_session"): string =>
  parseCookies(res.headers.get("set-cookie"))[name] ?? "";
