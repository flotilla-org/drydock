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

## E2B (`e2b`, Rust host)

Credential: a team API key (`e2b_…`), as a plain token file, sent as `X-API-Key`. Configuration also needs `team_id`.

Create it in the E2B dashboard (Team → API Keys). Keys have no scopes: a key can build and delete every template and kill every sandbox in the team. Use a team that holds only drydock's sandboxes; drydock finds its own by their `drydock.provider` and `flotilla.label` metadata, and refuses to adopt or destroy a sandbox without both.

| Call | Used for |
|---|---|
| `/templates/aliases/{name}`, `/v3/templates`, `/templates/{id}/files/{hash}`, `/v2/templates/{id}/builds/{build}`, `/templates/{id}/builds/{build}/status` | prepare |
| `/v2/sandboxes`, `/sandboxes/{id}`, `/sandboxes/{id}/pause`, `/v2/sandboxes/{id}/connect` | provision, list, inspect, suspend, resume, destroy |
| envd's `process.Process/Start` and `/files` at `49983-<sandbox>.e2b.app` | exec, the agent's upload |
| the proxy at `7811-<sandbox>.e2b.app`, dialled by drydockd | reach |
| `/events/sandboxes`, `/templates/{id}` (builds) | usage |
| `/teams/{teamID}/metrics` | quota (in use) |

- drydockd uploads the agent to each sandbox (upload bootstrap) through envd's `/files`; templates are the base image alone.
- The module declares `agent_tcp_port` 7811, so drydockd starts the agent listening on loopback there. envd forwards loopback ports to the proxy ([`envd/internal/port`](https://github.com/e2b-dev/infra/blob/main/packages/envd/internal/port/forward.go)), so the agent's token is what gates that port at E2B's edge. The module reads the token back with `drydock-agent --print-token`.
- Reach is a dial reach: drydockd opens the WebSocket upgrade to the agent's port itself, with the agent's token as its Bearer and the sandbox's traffic token in E2B's `e2b-traffic-access-token` header. Set `sandbox_url` (default `https://{port}-{id}.e2b.app`) for a self-hosted E2B.
- Each sandbox returns `envdAccessToken` and `trafficAccessToken` at create and connect. The host holds them in memory; they are never written to a record or a log, and the traffic token leaves the host only in a reach. After a host restart it reads the envd token back from `GET /sandboxes/{id}` and the traffic token from a running sandbox's connect, which extends its timeout to `lifetime_seconds`.
- The key can't read the team's limits, credit or spend; set `concurrency_limit` in settings. Usage reports no cost.
- Usage counts each execution, clipped to the period, at the size E2B granted: an ended one from E2B's pause and kill events, which carry its start, vCPUs and memory, with its disk from its template's build (`GET /templates/{id}`), or the template's own disk for a build the template doesn't list, such as the one a resumed sandbox runs from, and a running one from its listed start, size and disk until now. A period with a sandbox whose template has since been deleted is refused, since that disk is no longer known. A period holding more than 10,000 of E2B's sandbox events is refused rather than undercounted; ask for a shorter one.
- drydockd observes the team's sandboxes by listing them every `poll_interval_ms` (default 30000).
- Private registries are given per prepare, not stored at E2B. E2B pulls over the public internet, so drydock refuses a base whose registry is or resolves to a private address, or is a bare host name without a dot, `localhost`, or a name under `.local`, `.localhost`, `.internal`, `.lan`, `.home.arpa`, `.test` or `.invalid`; a staging registry (`pull_from`) is the way to such images. The check is best effort: E2B resolves the name again at build, and a name drydock's host cannot resolve is left to E2B.
- Hobby caps a sandbox at one hour of running: a longer timeout is refused at create and silently clamped on extend. Sandboxes are created with `autoPause`, so the cap pauses rather than kills; drydock reads that pause as `paused_by_provider` and resumes on demand. A paused sandbox keeps its snapshot, which E2B may bill as storage, until drydock destroys it. Set `lifetime_seconds` (default 3600) to 86400 on Pro, and `disk_mb` (default 10240) to the plan's sandbox disk.
- Egress is the vendor's claim, not a measurement: the module declares E2B's documented model (a firewall outside the guest; listing a domain also opens 8.8.8.8 for DNS, and domains filter only HTTP on 80 and TLS on 443) and runs no guest probe, so every row is advisory and unmeasured until drydockd's conformance verdict says otherwise (drydock#214).
- Templates stay at teardown, one per base image and size, so each new image or size adds one until a retention decision retires them (drydock#61). A new tools pin adds none.
- E2B's terms ask for written consent before a third-party app interacts with the Services. This module is our own use of our own account; confirm with E2B before offering it to anyone else.
