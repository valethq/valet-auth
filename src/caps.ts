import { type AclContext, type Caller, can, matchPermission } from "@valethq/sdk";

const PATTERN = /^(\*|[a-z][a-z0-9-]*:(\*|[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)*))$/;
const isWildcard = (pattern: string): boolean => pattern.endsWith("*");

export const validTag = (tag: string): boolean => /^[A-Za-z0-9][\w.-]*$/.test(tag);

export interface CapProblem {
  status: 400 | 403;
  message: string;
}

export function checkPatterns(cap: string[]): CapProblem | undefined {
  if (cap.length === 0) return { status: 400, message: "cap must not be empty" };
  const bad = cap.find((p) => !PATTERN.test(p));
  return bad === undefined ? undefined : { status: 400, message: `invalid permission pattern "${bad}"` };
}

/** A capped token acts as its creator, so it may not exceed what the issuing caller holds. */
export function checkIssuer(ctx: AclContext, caller: Caller, cap: string[]): CapProblem | undefined {
  const issuer = caller.actor;
  const uncappedOwner = issuer?.role === "owner" && issuer.cap === undefined;
  for (const pattern of cap) {
    if (isWildcard(pattern)) {
      if (!uncappedOwner) return { status: 403, message: `wildcard "${pattern}" needs an uncapped owner` };
      continue;
    }
    if (issuer?.cap !== undefined && !issuer.cap.some((held) => matchPermission(held, pattern)))
      return { status: 403, message: `"${pattern}" exceeds the issuing credential` };
    const decision = can(ctx, caller, pattern);
    if (!decision.allow) return { status: 403, message: decision.reason };
  }
  return undefined;
}
