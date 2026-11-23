import { definePlugin } from "@valethq/sdk";

/** Test policy: allows everything until POST /deny { permission, resource } blacklists a permission+resource pair. */
export default definePlugin({
  activate(ctx) {
    const denied = new Set<string>();
    ctx.http.route(
      "POST",
      "/deny",
      async (req) => {
        const body = (await req.json().catch(() => ({}))) as {
          permission?: unknown;
          resource?: unknown;
        };
        if (typeof body.permission === "string" && typeof body.resource === "string")
          denied.add(`${body.permission}|${body.resource}`);
        return Response.json({ ok: true });
      },
      { public: true },
    );
    ctx.scopes.provide("policy", {
      check: (_subject, permission, resource) =>
        denied.has(`${permission}|*`) ||
        (resource !== undefined && denied.has(`${permission}|${resource.id}`))
          ? { allow: false as const, by: "valet-fixture-policy", reason: `fixture denies ${permission}` }
          : { allow: true as const },
    });
  },
});
