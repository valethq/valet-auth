import { expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createAuthStore, MIGRATIONS } from "../src/db";
import { resetOwner } from "../src/reset";
import { sha256Hex } from "../src/secrets";

test("reset clears the owner, revokes devices and tokens, and mints a usable setup token", () => {
  const db = new Database(":memory:");
  for (const m of MIGRATIONS) db.exec(m.up);
  const store = createAuthStore(db);
  store.createOwner("pri_1", "hash");
  const device = store.createDevice("pri_1", "d1", "phone");
  const token = store.createToken("pri_1", "t1");

  const tokenFile = join(mkdtempSync(join(tmpdir(), "valet-reset-")), "data", "setup-token");
  const setup = resetOwner(db, tokenFile);

  expect(store.owner()).toBeUndefined();
  expect(store.deviceById(device.id)?.revokedAt).not.toBeNull();
  expect(store.tokenById(token.id)?.revokedAt).not.toBeNull();
  expect(store.checkSetupToken(sha256Hex(setup))).toBe(true);
  expect(readFileSync(tokenFile, "utf8")).toBe(setup);
});
