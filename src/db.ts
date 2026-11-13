import type { Database } from "bun:sqlite";

export const MIGRATIONS: { id: string; up: string }[] = [
  {
    id: "0001-init",
    up: `
      CREATE TABLE IF NOT EXISTS p_auth_owner (
        principal_id TEXT PRIMARY KEY,
        password_hash TEXT NOT NULL,
        created_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS p_auth_devices (
        id TEXT PRIMARY KEY,
        principal_id TEXT NOT NULL,
        secret_sha256 TEXT NOT NULL UNIQUE,
        name TEXT,
        created_at INTEGER NOT NULL,
        last_seen_at INTEGER,
        revoked_at INTEGER
      );
      CREATE TABLE IF NOT EXISTS p_auth_tokens (
        id TEXT PRIMARY KEY,
        principal_id TEXT NOT NULL,
        secret_sha256 TEXT NOT NULL UNIQUE,
        name TEXT,
        created_at INTEGER NOT NULL,
        last_seen_at INTEGER,
        revoked_at INTEGER
      );
      CREATE TABLE IF NOT EXISTS p_auth_setup (
        token_sha256 TEXT PRIMARY KEY,
        created_at INTEGER NOT NULL
      );
    `,
  },
];

export interface OwnerRow {
  principalId: string;
  passwordHash: string;
  createdAt: number;
}

export interface CredentialRow {
  id: string;
  principalId: string;
  name: string | null;
  createdAt: number;
  lastSeenAt: number | null;
  revokedAt: number | null;
}

interface RawCredential {
  id: string;
  principal_id: string;
  name: string | null;
  created_at: number;
  last_seen_at: number | null;
  revoked_at: number | null;
}

const toCredential = (r: RawCredential): CredentialRow => ({
  id: r.id,
  principalId: r.principal_id,
  name: r.name,
  createdAt: r.created_at,
  lastSeenAt: r.last_seen_at,
  revokedAt: r.revoked_at,
});

const newId = (prefix: string): string => `${prefix}_${Bun.randomUUIDv7()}`;

/** Typed access to the plugin's p_auth_* tables (ctx.storage.sql.db). */
export function createAuthStore(db: Database) {
  const credential = (table: "devices" | "tokens", column: "id" | "secret_sha256", value: string) =>
    db
      .query<RawCredential, string>(
        `SELECT id, principal_id, name, created_at, last_seen_at, revoked_at
         FROM p_auth_${table} WHERE ${column} = ?`,
      )
      .get(value);
  const createCredential = (
    table: "devices" | "tokens",
    principalId: string,
    secretSha256: string,
    name?: string,
  ) => {
    const row: CredentialRow = {
      id: newId(table === "devices" ? "dev" : "tok"),
      principalId,
      name: name ?? null,
      createdAt: Date.now(),
      lastSeenAt: null,
      revokedAt: null,
    };
    db.query(
      `INSERT INTO p_auth_${table} (id, principal_id, secret_sha256, name, created_at)
       VALUES (?, ?, ?, ?, ?)`,
    ).run(row.id, principalId, secretSha256, row.name, row.createdAt);
    return row;
  };
  const listCredentials = (table: "devices" | "tokens") =>
    db
      .query<RawCredential, []>(
        `SELECT id, principal_id, name, created_at, last_seen_at, revoked_at
         FROM p_auth_${table} ORDER BY created_at`,
      )
      .all()
      .map(toCredential);
  const revokeCredential = (table: "devices" | "tokens", id: string) =>
    db
      .query(`UPDATE p_auth_${table} SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`)
      .run(Date.now(), id).changes > 0;
  const touch = (table: "devices" | "tokens", id: string) =>
    db.query(`UPDATE p_auth_${table} SET last_seen_at = ? WHERE id = ?`).run(Date.now(), id);

  return {
    owner(): OwnerRow | undefined {
      const row = db
        .query<{ principal_id: string; password_hash: string; created_at: number }, []>(
          "SELECT principal_id, password_hash, created_at FROM p_auth_owner LIMIT 1",
        )
        .get();
      return row === null
        ? undefined
        : { principalId: row.principal_id, passwordHash: row.password_hash, createdAt: row.created_at };
    },
    createOwner(principalId: string, passwordHash: string): void {
      db.query("INSERT INTO p_auth_owner (principal_id, password_hash, created_at) VALUES (?, ?, ?)").run(
        principalId,
        passwordHash,
        Date.now(),
      );
    },
    setPassword(principalId: string, passwordHash: string): void {
      db.query("UPDATE p_auth_owner SET password_hash = ? WHERE principal_id = ?").run(
        passwordHash,
        principalId,
      );
    },

    checkSetupToken(tokenSha256: string): boolean {
      return (
        db.query("SELECT token_sha256 FROM p_auth_setup WHERE token_sha256 = ?").get(tokenSha256) !== null
      );
    },
    setSetupToken(tokenSha256: string): void {
      db.query("DELETE FROM p_auth_setup").run();
      db.query("INSERT INTO p_auth_setup (token_sha256, created_at) VALUES (?, ?)").run(
        tokenSha256,
        Date.now(),
      );
    },
    clearSetupTokens(): void {
      db.query("DELETE FROM p_auth_setup").run();
    },

    deviceById: (id: string) => optional(credential("devices", "id", id)),
    deviceBySecret: (h: string) => optional(credential("devices", "secret_sha256", h)),
    createDevice: (principalId: string, secretSha256: string, name?: string) =>
      createCredential("devices", principalId, secretSha256, name),
    listDevices: () => listCredentials("devices"),
    revokeDevice: (id: string) => revokeCredential("devices", id),
    touchDevice: (id: string) => touch("devices", id),

    tokenById: (id: string) => optional(credential("tokens", "id", id)),
    tokenBySecret: (h: string) => optional(credential("tokens", "secret_sha256", h)),
    createToken: (principalId: string, secretSha256: string, name?: string) =>
      createCredential("tokens", principalId, secretSha256, name),
    listTokens: () => listCredentials("tokens"),
    revokeToken: (id: string) => revokeCredential("tokens", id),
    touchToken: (id: string) => touch("tokens", id),
  };
}

const optional = (r: RawCredential | null): CredentialRow | undefined =>
  r === null ? undefined : toCredential(r);

export type AuthStore = ReturnType<typeof createAuthStore>;
