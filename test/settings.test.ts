import { Database } from "bun:sqlite";
import { expect, test } from "bun:test";
import type { PluginContext } from "@valethq/sdk";
import { MIGRATIONS, createAuthStore } from "../src/db";
import { registerSettings, type SettingsPanel } from "../src/settings";

function setup() {
  const db = new Database(":memory:");
  for (const m of MIGRATIONS) db.exec(m.up);
  const store = createAuthStore(db);
  const panels: { key?: string; impl: SettingsPanel }[] = [];
  const ctx = {
    scopes: {
      define: () => {},
      provide: (_s: string, impl: SettingsPanel, opts?: { key?: string }) => {
        panels.push({ key: opts?.key, impl });
        return { dispose() {} };
      },
    },
  } as unknown as PluginContext;
  registerSettings(ctx, store);
  return { store, panel: panels[0]?.impl as SettingsPanel };
}

test("password change verifies the current password and rehashes", async () => {
  const { store, panel } = setup();
  store.createOwner("pri_1", await Bun.password.hash("old-password", "argon2id"));

  await expect(panel.set({ currentPassword: "wrong", newPassword: "new-password-1" })).rejects.toThrow(
    "incorrect",
  );
  await panel.set({ currentPassword: "old-password", newPassword: "new-password-1" });
  const hash = store.owner()?.passwordHash ?? "";
  expect(await Bun.password.verify("new-password-1", hash)).toBe(true);
  expect(await Bun.password.verify("old-password", hash)).toBe(false);
});

test("password change validates inputs", async () => {
  const { store, panel } = setup();
  store.createOwner("pri_1", "hash");
  // blank form is a no-op
  await panel.set({});
  await panel.set({ currentPassword: "", newPassword: "" });
  await expect(panel.set({ newPassword: "new-password-1" })).rejects.toThrow("current password");
  await expect(panel.set({ currentPassword: "x", newPassword: "short" })).rejects.toThrow("8 characters");
  // no owner yet
  const { panel: empty } = setup();
  await expect(empty.set({ currentPassword: "x", newPassword: "new-password-1" })).rejects.toThrow(
    "no owner",
  );
});
