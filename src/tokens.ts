import { type PluginContext, type RouteHandler, can, sessionResource } from "@valethq/sdk";
import { checkIssuer, checkPatterns, validTag } from "./caps";
import type { AuthStore } from "./db";
import { error, json, jsonBody } from "./respond";
import { randomSecret, sha256Hex } from "./secrets";

const TAG_ASSIGN = "policy:tag.assign";

export function createToken(ctx: PluginContext, store: AuthStore): RouteHandler {
  return async (req, rc) => {
    const actor = rc.caller.actor;
    if (actor === undefined) return error(401, "authentication required");
    const b = await jsonBody(req);
    const name = typeof b.name === "string" && b.name !== "" ? b.name : undefined;
    const cap = b.cap;
    const tag = b.tag;
    const resource = b.resource;
    if (cap !== undefined && (!Array.isArray(cap) || !cap.every((p) => typeof p === "string")))
      return error(400, "cap must be an array of permission patterns");
    if (tag !== undefined && (typeof tag !== "string" || !validTag(tag)))
      return error(400, "tag must be a tag name without the tag: prefix");
    if (resource !== undefined && (typeof resource !== "string" || !/^[a-z][a-z0-9-]*:.+$/.test(resource)))
      return error(400, "resource must be a <kind>:<id> string");
    if (cap === undefined && tag === undefined) return error(400, "cap or tag is required");

    const bad = cap === undefined ? undefined : checkPatterns(cap as string[]);
    if (bad !== undefined) return error(bad.status, bad.message);

    // `can` checks credential liveness on the paths that call it; the wildcard and no-policy tag paths do not.
    const credentialId = rc.caller.credentialId;
    if (credentialId !== undefined && ctx.acl.credential(credentialId)?.active !== true)
      return error(403, "credential is not active");

    if (tag === undefined) {
      // A claimed resource is only a scope for the check; session ancestors resolve from core's records.
      const scope =
        typeof resource === "string" && resource.startsWith("session:")
          ? sessionResource(ctx, resource.slice("session:".length))
          : (resource as string | undefined);
      const problem = checkIssuer(ctx, rc.caller, cap as string[], scope);
      if (problem !== undefined) return error(problem.status, problem.message);
    } else {
      // spec-gap: without policy@1 nothing declares policy:tag.assign; fall back to an owner with a verified login.
      const allowed =
        ctx.acl.permission(TAG_ASSIGN) === undefined
          ? actor.role === "owner" && rc.caller.verifiedLogin === true
          : can(ctx, rc.caller, TAG_ASSIGN, `tag:${tag}`).allow;
      if (!allowed) return error(403, `not allowed to assign tag:${tag}`);
    }

    const secret = randomSecret();
    const id = store.newTokenId();
    const principalId =
      tag === undefined
        ? actor.principalId
        : ctx.store.principals.resolveIdentity("token", id, { displayName: `tag:${tag}` }).id;
    const row = store.createToken({
      id,
      principalId,
      secretSha256: sha256Hex(secret),
      ...(name === undefined ? {} : { name }),
      ...(cap === undefined ? {} : { cap: cap as string[] }),
      ...(tag === undefined ? {} : { tag }),
    });
    return json({ id: row.id, token: secret, cap: row.cap, tag: row.tag }, 201);
  };
}
