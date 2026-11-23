# valet-auth

Identity (owner password, device cookies, scoped bearer tokens).

A [valet](https://github.com/valethq/valet-core) plugin. Imports `@valethq/sdk` only.

## Tokens

`POST /plugins/valet-auth/tokens` needs a JSON body with `cap` (an array of permission patterns, e.g.
`["core:session.read", "project:*"]`) or `tag` (a tag name for a service-principal token), plus optional `name`.
An optional `resource` (`"<kind>:<id>"`, e.g. `"project:prj_…"`) scopes the issuer check to where the token will
be used, so a caller whose grant only covers one resource can still mint. Tokens minted before caps existed keep
authenticating as their owner until rotated; rotate them to scoped tokens when convenient.

## Config

| Field        | Meaning                                                           |
| ------------ | ----------------------------------------------------------------- |
| `cookieName` | HTTP cookie that holds a device session. Default `valet_session`. |

`cookieName` is ordinary plugin config (edit via PATCH /settings or `config.json`). Changing the owner password is not config: the Account settings panel asks for the current and new password.
