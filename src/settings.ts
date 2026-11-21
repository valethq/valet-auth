import type { PluginContext } from "@valethq/sdk";
import type { createAuthStore } from "./db";

type AuthStore = ReturnType<typeof createAuthStore>;

/** The owner's password: a settings@2 runtime subsection whose values live here, never in config. */
export function registerSettings(ctx: PluginContext, store: AuthStore): void {
  ctx.scopes.define({ name: "settings", version: 2, cardinality: "many" });
  ctx.scopes.provide("settings", {
    subsections: () => [
      {
        id: "account",
        label: "Account",
        summary: "Owner account. Leave both fields blank to keep the current password.",
        order: -1,
        items: [
          {
            id: "currentPassword",
            label: "Current password",
            input: { type: "string", masked: true },
          },
          {
            id: "newPassword",
            label: "New password",
            summary: "At least 8 characters.",
            input: { type: "string", masked: true, minLength: 8 },
          },
        ],
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
    ],
  });
}
