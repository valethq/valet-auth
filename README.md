# valet-auth

Identity (owner password, device cookies, bearer tokens) and the default control-plane policy.

A [valet](https://github.com/valethq/valet-core) plugin. Imports `@valethq/sdk` only.

## Config

| Field        | Meaning                                                           |
| ------------ | ----------------------------------------------------------------- |
| `cookieName` | HTTP cookie that holds a device session. Default `valet_session`. |

`cookieName` is ordinary plugin config (edit via PATCH /settings or `config.json`). Changing the owner password is not config: the Account settings panel asks for the current and new password.
