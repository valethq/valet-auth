import { existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { definePlugin, type PluginContext } from "@valethq/sdk";
import { createAuthStore, MIGRATIONS } from "./db";
import { createIdentityProvider } from "./provider";
import { error, json, jsonBody } from "./respond";
import { clearCookie, parseCookies, randomSecret, sessionCookie, sha256Hex } from "./secrets";
import { registerSettings } from "./settings";
import { createToken } from "./tokens";

export interface AuthConfig {
  cookieName?: string;
}

export default definePlugin<AuthConfig>({
  async activate(ctx: PluginContext<AuthConfig>) {
    let cookieName = ctx.config.cookieName ?? "valet_session";
    ctx.onConfigChange((next) => {
      cookieName = next.cookieName ?? "valet_session";
    });
    const tokenFile = join(ctx.paths.data, "setup-token");
    ctx.storage.sql.migrate(MIGRATIONS);
    const store = createAuthStore(ctx.storage.sql.db);

    // First boot without an owner: mint a one-time setup token (11.7).
    if (store.owner() === undefined) {
      let token = existsSync(tokenFile) ? readFileSync(tokenFile, "utf8").trim() : "";
      if (token === "" || !store.checkSetupToken(sha256Hex(token))) {
        token = randomSecret();
        store.setSetupToken(sha256Hex(token));
        writeFileSync(tokenFile, token, { mode: 0o600 });
      }
      ctx.log.info("valet-auth setup", { url: `${ctx.http.url("/setup")}?token=${token}` });
    }

    const issueSession = (principalId: string, url: URL, deviceName?: string): Response => {
      const secret = randomSecret();
      store.createDevice(principalId, sha256Hex(secret), deviceName);
      return json({ principalId }, 200, {
        "set-cookie": sessionCookie(cookieName, secret, url.protocol === "https:"),
      });
    };

    // ---- public routes ------------------------------------------------------

    ctx.http.route("GET", "/status", () => json({ setupRequired: store.owner() === undefined }), {
      public: true,
    });

    ctx.http.route(
      "POST",
      "/setup",
      async (req) => {
        if (store.owner() !== undefined) return error(409, "setup already complete");
        const b = await jsonBody(req);
        const token = typeof b.token === "string" ? b.token : "";
        if (token === "" || !store.checkSetupToken(sha256Hex(token))) {
          return error(401, "invalid setup token");
        }
        const password = b.password;
        if (typeof password !== "string" || password === "") {
          return error(400, "password is required");
        }
        const displayName =
          typeof b.displayName === "string" && b.displayName !== "" ? b.displayName : "owner";
        const principal = ctx.store.principals.resolveIdentity("web", "owner", { displayName });
        if (principal.role !== "owner") await ctx.store.principals.setRole(principal.id, "owner");
        store.createOwner(principal.id, await Bun.password.hash(password, "argon2id"));
        store.clearSetupTokens();
        rmSync(tokenFile, { force: true });
        await ctx.events.emit("identity.changed", { principalId: principal.id });
        return issueSession(principal.id, new URL(req.url));
      },
      { public: true },
    );

    ctx.http.route(
      "POST",
      "/login",
      async (req) => {
        const b = await jsonBody(req);
        const owner = store.owner();
        const password = typeof b.password === "string" ? b.password : "";
        const ok =
          owner !== undefined && (await Bun.password.verify(password, owner.passwordHash).catch(() => false));
        if (!ok || owner === undefined) {
          await Bun.sleep(300); // ~300ms delay against credential probing
          return error(401, "invalid credentials");
        }
        const deviceName = typeof b.deviceName === "string" ? b.deviceName : undefined;
        return issueSession(owner.principalId, new URL(req.url), deviceName);
      },
      { public: true },
    );

    ctx.http.route(
      "POST",
      "/logout",
      async (req) => {
        const secret = parseCookies(req.headers.get("cookie"))[cookieName];
        if (secret !== undefined && secret !== "") {
          const device = store.deviceBySecret(sha256Hex(secret));
          if (device !== undefined && store.revokeDevice(device.id)) {
            await ctx.events.emit("identity.changed", { principalId: device.principalId });
          }
        }
        const secure = new URL(req.url).protocol === "https:";
        return json({ ok: true }, 200, { "set-cookie": clearCookie(cookieName, secure) });
      },
      { public: true },
    );

    // ---- permissioned routes (core enforces `permission` before the handler) ---

    ctx.http.route(
      "GET",
      "/me",
      (_req, rc) =>
        rc.principal === undefined
          ? error(401, "authentication required")
          : json({ principal: rc.principal }),
      { permission: "identity:me" },
    );

    ctx.http.route("GET", "/devices", () => json({ devices: store.listDevices() }), {
      permission: "identity:device.read",
    });

    ctx.http.route(
      "DELETE",
      "/devices/:id",
      async (_req, rc) => {
        const device = store.deviceById(rc.params.id ?? "");
        if (device === undefined || !store.revokeDevice(device.id)) return error(404, "unknown device");
        await ctx.events.emit("identity.changed", { principalId: device.principalId });
        return json({ ok: true });
      },
      { permission: "identity:device.revoke" },
    );

    ctx.http.route("POST", "/tokens", createToken(ctx, store), { permission: "identity:token.create" });

    ctx.http.route("GET", "/tokens", () => json({ tokens: store.listTokens() }), {
      permission: "identity:token.read",
    });

    ctx.http.route(
      "DELETE",
      "/tokens/:id",
      async (_req, rc) => {
        const token = store.tokenById(rc.params.id ?? "");
        if (token === undefined || !store.revokeToken(token.id)) return error(404, "unknown token");
        await ctx.events.emit("identity.changed", { principalId: token.principalId });
        return json({ ok: true });
      },
      { permission: "identity:token.revoke" },
    );

    ctx.scopes.provide(
      "identity",
      createIdentityProvider(store, () => cookieName),
    );

    registerSettings(ctx, store);
  },
});
