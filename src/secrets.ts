const COOKIE_MAX_AGE = 31_536_000; // 1 year

/** 32 random bytes, base64url — safe to embed in a cookie or bearer header verbatim. */
export function randomSecret(): string {
  return Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("base64url");
}

export function sha256Hex(secret: string): string {
  return new Bun.CryptoHasher("sha256").update(secret).digest("hex");
}

/** Minimal Cookie-header parse; last occurrence of a name wins. */
export function parseCookies(header: string | null): Record<string, string> {
  const out: Record<string, string> = {};
  if (header === null) return out;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq <= 0) continue;
    const name = part.slice(0, eq).trim();
    if (name === "") continue;
    out[name] = part.slice(eq + 1).trim();
  }
  return out;
}

function attrs(secure: boolean): string {
  return `HttpOnly; SameSite=Strict; Path=/${secure ? "; Secure" : ""}`;
}

/** Session cookie, `Secure` only on https request URLs. */
export function sessionCookie(name: string, secret: string, secure: boolean): string {
  return `${name}=${secret}; ${attrs(secure)}; Max-Age=${COOKIE_MAX_AGE}`;
}

export function clearCookie(name: string, secure: boolean): string {
  return `${name}=; ${attrs(secure)}; Max-Age=0`;
}
