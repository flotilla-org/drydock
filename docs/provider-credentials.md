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

## Modal (`modal`, TypeScript host)

Credential: a Modal token pair as JSON, `{"token_id": …, "token_secret": …}`. The module passes it to the SDK client directly, never through `~/.modal.toml` or `MODAL_TOKEN_*` in the host's environment. Configuration names the app the module owns (`app`, default `drydock`) and optionally an `environment`.

Use a service user scoped to one environment that holds only drydock's app (Workspace → Service Users). Service users need a paid plan; until then a personal token works, with every right its owner has in every environment, so give drydock an environment of its own (for example `drydock`) holding only its app, where a fault in list or terminate cannot reach other apps. Modal tokens have no per-operation scopes: the unit of least privilege is the environment and its role.

| Role in drydock's environment | Used for |
|---|---|
| Contributor | look up or create the app, build images with ephemeral registry secrets, create, exec, connect-token and terminate sandboxes, list by app and tags |

- Registry pulls use an ephemeral secret per prepare from the route's credential; nothing persists in the workspace. Modal pulls only from registries on the public internet.
- The module never deletes built images; Modal keeps them in its cache.
- A token that can't see the app lists nothing rather than failing.
- DNS resolution is never filtered, whatever the egress policy, so it remains a covert channel.
- Quota has no API; it is the count of live sandboxes in the app.
- The agent is reached through Modal's connect-token edge, where TLS ends: Modal sees the connect token and the agent's TCP token (`Authorization`) in transit, and every byte to and from the agent. The agent listens on all addresses in the sandbox, since the edge cannot reach loopback, so its token is the only gate on that port. drydockd masks both credentials in its errors and log.

## Tensorlake (`tensorlake`, Rust host)

Credential: a project API key (`tl_apiKey_…`), as a plain token file. Usage also needs `organization_id` in the settings; without it the provider declares no usage.

Create the key in the Tensorlake dashboard (project → API Keys). Use a project that holds only drydock's sandboxes. The key sees and controls every sandbox, snapshot and image in its project, and sandboxes carry no labels, so drydock finds its own by name (`dd-<instance>-…`).

API keys have no scopes; every key has project-member rights:

| Operation | Used for |
|---|---|
| Sandboxes: create, suspend, resume, delete; snapshots: list, delete | provision, suspend, resume, destroy and its snapshot cleanup |
| Images: CAS build (`/images/v4/builds`) and lookup by name | prepare |
| Sandbox proxy: files, processes, TCP tunnel | agent upload, exec, reach |
| Sandbox usage (`/platform/v1/organizations/{org}/sandbox-usage`) | usage |

- Deleting images needs the project admin role, which an API key never has (403 "requires the 'admin' role"). Drydock cannot retire prepared images. A project admin removes stale `dd-` images with `tl sbx image rm` from a logged-in session.
- There is no quota API. Plan limits arrive as 400 errors at create ("Per-sandbox vCPU limit exceeded", "project has reached its quota"); drydock reports a per-sandbox limit as refused and the project's quota as exhausted. Set `max_cpus` and `max_memory` to the plan's per-sandbox limits (default 4 vCPU and 16 GiB, Usage Credits) so oversized requests are refused before they reach Tensorlake.
- Tensorlake's builders pull base images themselves, so a base must be in a registry they can reach; drydock refuses a private-address base up front. The pull credential goes to the build for the base's registry only.
- SSH needs a key registered to a user and is unavailable to API keys; drydock doesn't use it.
- The key goes as a Bearer header to `api_url` and to every `<sandbox>.<sandbox_domain>` host (default `api.tensorlake.ai` and `sandbox.tensorlake.ai`). Change those settings only to hosts you trust with the key. The presigned build-context upload never gets it.
