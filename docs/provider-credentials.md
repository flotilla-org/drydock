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

## Tensorlake (`tensorlake`, Rust host)

Credential: a project API key (`tl_apiKey_…`), as a plain token file. Usage also needs `organization_id` in the settings; without it the provider declares no usage.

Create the key in the Tensorlake dashboard (project → API Keys). Use a project that holds only drydock's sandboxes. The key sees and controls every sandbox, snapshot and image in its project, and sandboxes carry no labels, so drydock finds its own by name (`dd-<instance>-…`).

API keys have no scopes; every key has project-member rights:

| Operation | Used for |
|---|---|
| Sandboxes: create, suspend, resume, delete; snapshots: list, delete | provision, suspend, resume, destroy and its snapshot cleanup |
| Images: CAS build (`/images/v4/builds`) and lookup by name | prepare |
| Sandbox proxy: processes, TCP tunnel | bootstrap, exec, reach |
| Sandbox usage (`/platform/v1/organizations/{org}/sandbox-usage`) | usage |

- Deleting images needs the project admin role, which an API key never has (403 "requires the 'admin' role"). Drydock cannot retire prepared images. A project admin removes stale `dd-` images with `tl sbx image rm` from a logged-in session.
- There is no quota API. Plan limits arrive as 400 errors at create ("Per-sandbox vCPU limit exceeded", "project has reached its quota"); drydock reports a per-sandbox limit as refused and the project's quota as exhausted. Set `max_cpus` and `max_memory` to the plan's per-sandbox limits (default 4 vCPU and 16 GiB, Usage Credits) so oversized requests are refused before they reach Tensorlake.
- Tensorlake's builders pull base images themselves, so a base must be in a registry they can reach; drydock refuses a private-address base up front. The pull credential goes to the build for the base's registry only.
- SSH needs a key registered to a user and is unavailable to API keys; drydock doesn't use it.
- The key goes as a Bearer header to `api_url` and to every `<sandbox>.<sandbox_domain>` host (default `api.tensorlake.ai` and `sandbox.tensorlake.ai`). Change those settings only to hosts you trust with the key. The presigned build-context upload never gets it.

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
