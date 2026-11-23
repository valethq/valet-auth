import type { AuthResult, CredentialState, IdentityProvider } from "@valethq/sdk";
import type { AuthStore, TokenRow } from "./db";
import { parseCookies, sha256Hex } from "./secrets";

const grants = (t: TokenRow) => ({
  ...(t.cap === null ? {} : { cap: t.cap }),
  ...(t.tag === null ? {} : { tags: [`tag:${t.tag}`] }),
});

export function createIdentityProvider(store: AuthStore, cookieName: () => string): IdentityProvider {
  return {
    authenticate(req): AuthResult | undefined {
      const authz = req.headers.get("authorization");
      if (authz?.toLowerCase().startsWith("bearer ")) {
        const secret = authz.slice(7).trim();
        if (secret !== "") {
          const token = store.tokenBySecret(sha256Hex(secret));
          if (token !== undefined && token.revokedAt === null) {
            store.touchToken(token.id);
            return { principalId: token.principalId, credentialId: token.id, ...grants(token) };
          }
        }
      }
      const secret = parseCookies(req.headers.get("cookie"))[cookieName()];
      if (secret !== undefined && secret !== "") {
        const device = store.deviceBySecret(sha256Hex(secret));
        if (device !== undefined && device.revokedAt === null) {
          store.touchDevice(device.id);
          return { principalId: device.principalId, credentialId: device.id, verifiedLogin: true };
        }
      }
      return undefined;
    },
    credential(rawId): CredentialState | undefined {
      if (rawId.startsWith("dev_")) {
        const device = store.deviceById(rawId);
        return device === undefined || device.revokedAt !== null ? { active: false } : { active: true };
      }
      if (rawId.startsWith("tok_")) {
        const token = store.tokenById(rawId);
        return token === undefined || token.revokedAt !== null
          ? { active: false }
          : { active: true, ...grants(token) };
      }
      return undefined;
    },
  };
}
