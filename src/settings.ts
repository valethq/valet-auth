import type { PluginContext } from "@valethq/sdk";
import type { createAuthStore } from "./db";

type AuthStore = ReturnType<typeof createAuthStore>;

export function registerSettings(ctx: PluginContext, store: AuthStore): void {
  ctx.scopes.define({ name: "settings", version: 1, cardinality: "many" });
  ctx.scopes.provide(
    "settings",
    {
      title: "Account",
      description: "Owner account. Leave both fields blank to keep the current password.",
      schema: {
        type: "object",
        properties: {
          currentPassword: { type: "string", format: "password", title: "Current password" },
          newPassword: { type: "string", format: "password", title: "New password" },
        },
      },
      get: () => ({}),
      set: async (v) => {
        const current = typeof v.currentPassword === "string" ? v.currentPassword : "";
        const next = typeof v.newPassword === "string" ? v.newPassword : "";
        if (current === "" && next === "") return;
        if (current === "") throw new Error("current password is required");
        if (next.length < 8) throw new Error("new password must be at least 8 characters");
        const owner = store.owner();
        if (owner === undefined) throw new Error("no owner account yet");
        const ok = await Bun.password.verify(current, owner.passwordHash).catch(() => false);
        if (!ok) throw new Error("current password is incorrect");
        store.setPassword(owner.principalId, await Bun.password.hash(next, "argon2id"));
      },
    },
    { key: "valet-auth" },
  );
}
