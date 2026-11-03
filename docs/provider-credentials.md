# Provider credentials

What each provider module needs from its credential. Mint keys with exactly these permissions. A key missing one fails in ways that are hard to read: Daytona's list returns nothing instead of an error.

## Daytona (`daytona`, Rust host)

Credential: an API key, as a plain token file. Configuration also needs `organization_id` and `ssh_host_key`.

Create it on the Daytona website (Dashboard → API Keys → Restricted); the CLI can't create keys. Read on sandboxes, snapshots, registries and regions is always granted.

| Permission | Used for |
|---|---|
| Sandboxes: Write, Delete | create, start, stop, exec, delete |
| Snapshots: Write, Delete | create and activate (prepare) |
| Limits: Read | `GET /organizations/{id}/usage` (quota) |
| Billing: Read | the analytics usage aggregate (usage) |

Leave the rest off.

Known problem (2026-10-30): `GET /sandbox` returned an empty list for our key while sandboxes were live, so drydock couldn't see the sandboxes it made, including leaked ones. Read on sandboxes is always granted, so the key's permissions aren't the cause; it is not yet understood. Fetching one sandbox by ID or name works.

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

## Runtime (`runtime`, Rust host)

Credential: an API key (`rtcloud_…`), as a plain token file.

Create it on the Runtime website (Account → Keys) or with `POST /v1/keys`. Runtime keys are full or read-only, and see only what they made (`reach: agent`, the default) or the whole account.

| Setting | Why |
|---|---|
| Access: full | images (prepare), sandboxes, exec, network rules, and the tunnel (which needs exec) |
| Reach: agent | drydock sees only the sandboxes and images this key made, which is what `list` should return |
| Daily limit: set one | caps what a runaway launch loop can spend; `GET /v1/limits` reports it as quota |

- `reach: agent` scopes listing to the key. A sandbox made by another key, or before a key rotation, is invisible: list shows nothing and inspect returns 404, as if it were gone. Destroy drydock's sandboxes before revoking a key, or use `reach: account`.
- A read-only key fails at prepare with a permission error, but list and quota still work, so the provider looks ready.
- Private-registry pulls use logins stored once in the account (`POST /v1/images/registries`), not this key; prepare refuses a private base whose registry has none. Runtime's builders refuse private addresses, so drydock refuses a base on one up front.
- At its image limit (20 by default), prepare deletes the oldest `dd-` image no sandbox started from, and refuses when every one is in use.
- The base image must carry `python3`: Runtime's tunnel runs a python3 helper inside the sandbox, which its docs don't say. Provision checks first and refuses an image without it, rather than leaving the tunnel to time out.
- Without credit, sandboxes reach ports 80 and 443 only and host:port rules (`connect`) are refused; drydock refuses them at provision, naming trial funding. Persistent sandboxes need credit too, so without it drydock creates ordinary ones, which keep no disk once stopped.
- Every guest process gets `RUNTIME_ID_TOKEN_REQUEST_TOKEN`, a credential for minting Runtime identity tokens; drydock removes it from the agent's environment, so neither the agent nor what it starts can use it.
- The key goes as a Bearer header to `api_url` (default `https://api.withruntime.com/v1`) and its tunnel. Change that setting only to a host you trust with the key.
