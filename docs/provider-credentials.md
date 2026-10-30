# Provider credentials

What each provider module needs from its credential. Mint keys with exactly these permissions. A key missing one fails in ways that are hard to read: Daytona's list returns nothing instead of an error.

## Daytona (`daytona`, Rust host)

Credential: an API key, as a plain token file. Configuration also needs `organization_id` and `ssh_host_key`.

Create it on the Daytona website (Dashboard → API Keys); the CLI can't create keys.

| Resource | Needs | Used for |
|---|---|---|
| Sandboxes | read, write, delete | `GET /sandbox` (inventory, adoption, orphan sweeps), `GET /sandbox/{id}`, create, start, stop, exec, delete |
| Snapshots | read, write, delete | `GET /snapshots/{name}`, create, activate (prepare) |
| Organization usage | read | `GET /organizations/{id}/usage` (quota) and the analytics usage aggregate |

Without sandbox read, `GET /sandbox` returns an empty list rather than an error, so drydock can't see the sandboxes it made, including leaked ones (found 2026-10-30). Fetching one sandbox by ID or name still works.

## Namespace (`namespace`, TypeScript host)

Credential: a revocable token as JSON, `{"bearer_token": …}`. The same token is the `nscr.io` push password (user `token`).

Create it with `nsc token create` and explicit grants. Revocable tokens refuse wildcards on `instance`, so list its actions.

```
devbox *            devbox/image *
instance create, dial_host, ssh, exec, get, list, refresh, wait
ingress access
containerregistry *  containerregistry/repository *  containerregistry/image *
```

- Without `ingress access`, every SDK gateway call returns 403.
- Quota (`UsageService/GetConcurrency`) needs a grant beyond these, not yet identified. Without it quota is refused and the provider stays ready.
- Image optimize is refused for every grant a revocable token can carry; the module doesn't call it.
