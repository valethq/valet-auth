import { Database } from "bun:sqlite";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { createAuthStore } from "./db";
import { randomSecret, sha256Hex } from "./secrets";

/** Drops the owner password, revokes every device and token, and mints a fresh one-time setup token. */
export function resetOwner(db: Database, tokenFile: string): string {
  const token = randomSecret();
  const now = Date.now();
  db.transaction(() => {
    db.query("DELETE FROM p_auth_owner").run();
    db.query("UPDATE p_auth_devices SET revoked_at = ? WHERE revoked_at IS NULL").run(now);
    db.query("UPDATE p_auth_tokens SET revoked_at = ? WHERE revoked_at IS NULL").run(now);
    createAuthStore(db).setSetupToken(sha256Hex(token));
  })();
  mkdirSync(dirname(tokenFile), { recursive: true });
  writeFileSync(tokenFile, token, { mode: 0o600 });
  return token;
}

if (import.meta.main) {
  const at = process.argv.indexOf("--home");
  const home =
    (at >= 0 ? process.argv[at + 1] : undefined) ?? process.env.VALET_HOME ?? join(homedir(), ".valet");
  const dbPath = join(home, "valet.sqlite");
  if (!existsSync(dbPath)) {
    console.error(`no valet database at ${dbPath} (use --home <dir>)`);
    process.exit(1);
  }
  const db = new Database(dbPath);
  db.exec("PRAGMA busy_timeout = 5000");
  try {
    const token = resetOwner(db, join(home, "data", "valet-auth", "setup-token"));
    console.log("Owner password cleared; all devices and tokens revoked.");
    console.log("Open the valet UI and set a new password with this one-time setup token:");
    console.log(token);
  } catch (error) {
    console.error(`reset failed: ${error instanceof Error ? error.message : String(error)}`);
    process.exit(1);
  }
}
