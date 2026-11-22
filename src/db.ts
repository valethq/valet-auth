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
  {
    id: "0002-token-cap-tag",
    up: `
      ALTER TABLE p_auth_tokens ADD COLUMN cap TEXT;
      ALTER TABLE p_auth_tokens ADD COLUMN tag TEXT;
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

export interface TokenRow extends CredentialRow {
  cap: string[] | null;
  tag: string | null;
}

interface RawCredential {
  id: string;
  principal_id: string;
  name: string | null;
  created_at: number;
  last_seen_at: number | null;
  revoked_at: number | null;
}

interface RawToken extends RawCredential {
  cap: string | null;
  tag: string | null;
}

const COLUMNS = "id, principal_id, name, created_at, last_seen_at, revoked_at";

const toCredential = (r: RawCredential): CredentialRow => ({
  id: r.id,
  principalId: r.principal_id,
  name: r.name,
  createdAt: r.created_at,
  lastSeenAt: r.last_seen_at,
  revokedAt: r.revoked_at,
});

const toToken = (r: RawToken): TokenRow => ({
  ...toCredential(r),
  cap: r.cap === null ? null : (JSON.parse(r.cap) as string[]),
  tag: r.tag,
});

const newId = (prefix: string): string => `${prefix}_${Bun.randomUUIDv7()}`;

export interface NewToken {
  id: string;
  principalId: string;
  secretSha256: string;
  name?: string;
  cap?: string[];
  tag?: string;
}

/** Typed access to the plugin's p_auth_* tables (ctx.storage.sql.db). */
export function createAuthStore(db: Database) {
  const revoke = (table: "devices" | "tokens", id: string) =>
    db
      .query(`UPDATE p_auth_${table} SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`)
      .run(Date.now(), id).changes > 0;
  const touch = (table: "devices" | "tokens", id: string) =>
    db.query(`UPDATE p_auth_${table} SET last_seen_at = ? WHERE id = ?`).run(Date.now(), id);
  const device = (column: "id" | "secret_sha256", value: string) => {
    const row = db
      .query<RawCredential, string>(`SELECT ${COLUMNS} FROM p_auth_devices WHERE ${column} = ?`)
      .get(value);
    return row === null ? undefined : toCredential(row);
  };
  const token = (column: "id" | "secret_sha256", value: string) => {
    const row = db
      .query<RawToken, string>(`SELECT ${COLUMNS}, cap, tag FROM p_auth_tokens WHERE ${column} = ?`)
      .get(value);
    return row === null ? undefined : toToken(row);
  };

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

    deviceById: (id: string) => device("id", id),
    deviceBySecret: (h: string) => device("secret_sha256", h),
    createDevice(principalId: string, secretSha256: string, name?: string): CredentialRow {
      const row: CredentialRow = {
        id: newId("dev"),
        principalId,
        name: name ?? null,
        createdAt: Date.now(),
        lastSeenAt: null,
        revokedAt: null,
      };
      db.query(
        `INSERT INTO p_auth_devices (id, principal_id, secret_sha256, name, created_at)
         VALUES (?, ?, ?, ?, ?)`,
      ).run(row.id, principalId, secretSha256, row.name, row.createdAt);
      return row;
    },
    listDevices: () =>
      db
        .query<RawCredential, []>(`SELECT ${COLUMNS} FROM p_auth_devices ORDER BY created_at`)
        .all()
        .map(toCredential),
    revokeDevice: (id: string) => revoke("devices", id),
    touchDevice: (id: string) => touch("devices", id),

    newTokenId: () => newId("tok"),
    tokenById: (id: string) => token("id", id),
    tokenBySecret: (h: string) => token("secret_sha256", h),
    createToken(t: NewToken): TokenRow {
      const row: TokenRow = {
        id: t.id,
        principalId: t.principalId,
        name: t.name ?? null,
        createdAt: Date.now(),
        lastSeenAt: null,
        revokedAt: null,
        cap: t.cap ?? null,
        tag: t.tag ?? null,
      };
      db.query(
        `INSERT INTO p_auth_tokens (id, principal_id, secret_sha256, name, created_at, cap, tag)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      ).run(
        row.id,
        row.principalId,
        t.secretSha256,
        row.name,
        row.createdAt,
        row.cap === null ? null : JSON.stringify(row.cap),
        row.tag,
      );
      return row;
    },
    listTokens: () =>
      db
        .query<RawToken, []>(`SELECT ${COLUMNS}, cap, tag FROM p_auth_tokens ORDER BY created_at`)
        .all()
        .map(toToken),
    revokeToken: (id: string) => revoke("tokens", id),
    touchToken: (id: string) => touch("tokens", id),
  };
}

export type AuthStore = ReturnType<typeof createAuthStore>;
