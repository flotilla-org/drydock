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
- The module translates: provision is one create (then the agent service), and inspect, suspend, resume and destroy are one SDK call each; rows carry Namespace's state word and the devbox's labels in `vendor`. On a `shared_account` (the default) it tags what it makes with the `drydock.provider` label and lists only devboxes carrying it, and drydockd acts by id only on what does. On an `owned_account` nothing is tagged or filtered, so use a workspace that holds only drydock's devboxes. Devboxes made before this tag existed carry none, so a shared-account instance no longer lists or acts on them.

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
- The module declares no quota: Modal has none to report.
- On a `shared_account` (the default) the module tags each sandbox `drydock.provider` with the instance, and drydockd lists and acts by id only on sandboxes that carry it. On an `owned_account` nothing is tagged or filtered, so the environment must hold only drydock's app. The label is the `flotilla.label` tag; provisioning a label twice makes two sandboxes.
- The agent is reached through Modal's connect-token edge, where TLS ends: Modal sees the connect token and the agent's TCP token (`Authorization`) in transit, and every byte to and from the agent. The agent listens on all addresses in the sandbox, since the edge cannot reach loopback, so its token is the only gate on that port. drydockd masks both credentials in its errors and log.

## Runtime (`runtime`, Rust host)

Credential: an API key (`rtcloud_…`), as a plain token file.

Create it on the Runtime website (Account → Keys) or with `POST /v1/keys`. Runtime keys are full or read-only, and see only what they made (`reach: agent`, the default) or the whole account. The module translates: provision, list, destroy and suspend are Runtime's own operations, and rows carry Runtime's state name, its `stopReason` and the sandbox's labels in `vendor`. On a `shared_account` (the default) it labels what it makes with `drydock.provider`, lists with Runtime's `label=` filter, and drydockd acts by id only on sandboxes that carry the label. On an `owned_account` nothing is tagged or filtered. The client's label is the `flotilla.label` label; the sandbox's Runtime name comes from the instance and the label, so a second provision of a live label is Runtime's refusal of the name.

| Setting | Why |
|---|---|
| Access: full | images (prepare), sandboxes, exec, files (the agent upload), network rules, and previews (a preview's token is signed only for a key that can run commands) |
| Reach: agent | drydock sees only the sandboxes and images this key made, which is what `list` should return |
| Daily limit: set one | caps what a runaway launch loop can spend; `GET /v1/limits` reports it as quota |

| Call | Used for |
|---|---|
| `GET /v1/images?name=`, `POST /v1/images`, `GET /v1/images/{id}` | prepare |
| `POST /v1/sandboxes` | provision |
| `GET /v1/sandboxes` (every page, stopped ones included) | list |
| `GET /v1/sandboxes/{id}`, `GET /v1/sandboxes/{id}/network` | inspect |
| `DELETE /v1/sandboxes/{id}/previews/7811`, `DELETE /v1/sandboxes/{id}` | destroy (Runtime keeps a preview after its sandbox goes) |
| `POST /v1/sandboxes/{id}:pause` | suspend (the resume token is the sandbox id) |
| `GET /v1/sandboxes/{id}`, then `:wake` (paused) or `:restart` (stopped) | resume |
| `POST /v1/sandboxes/{id}:exec`, `/files/archive/uploads` | exec, the agent's upload |
| `GET` or `POST /v1/sandboxes/{id}/previews` | reach |
| `GET /v1/limits` | quota |

- `reach: agent` scopes listing to the key. A sandbox made by another key, or before a key rotation, is invisible: list shows nothing and inspect returns 404, as if it were gone. Destroy drydock's sandboxes before revoking a key, or use `reach: account`.
- A read-only key fails at prepare with a permission error, but list and quota still work, so the provider looks ready.
- Create, pause, wake and restart send `Prefer: wait=25`, so Runtime answers once the sandbox settled or after 25 seconds; the module waits no longer. drydockd's `settle` option waits the rest.
- drydock reaches the agent through a private preview of its port (7811): each reach signs a preview token good for `preview_ttl_seconds` (default 86400), and drydockd sends it in `x-runtime-preview-token` beside the agent's own token. Reach reads no state: Runtime's exec wakes a paused sandbox that has `autoWake`.
- Inspect reports egress `enforced` when Runtime's network read says its host holds the current version of the rules (`enforced`, with `enforcedVersion` equal to `version`); the policy identity is a digest of the rules Runtime states. A list row carries no network, so it is advisory with no policy identity.
- The module declares no usage. Runtime's usage export and its sandbox event log are the sources to collect as Runtime gives them (drydock#257).
- Without credit, sandboxes reach ports 80 and 443 only and Runtime refuses host:port rules (`connect`). Runtime refuses persistent sandboxes without credit too: set `persistent` (default true) to false on such an account; ordinary sandboxes keep no disk once stopped.
- Prepare waits for an image build by reading it every `build_poll_seconds` (default 3), up to `build_polls` times (default 150), then answers unavailable. Runtime ends a command after `exec_seconds` (default 25). drydockd lists sandboxes every `poll_seconds` (default 30).
- The key goes as a Bearer header to `api_url` (default `https://api.withruntime.com/v1`) only. Change that setting only to a host you trust with the key.

## Tensorlake (`tensorlake`, Rust host)

Credential: a project API key (`tl_apiKey_…`), as a plain token file. Reading Tensorlake's webhooks also needs `project_id`, the project's public id, which every delivery names.

Create the key in the Tensorlake dashboard (project → API Keys). The key sees and controls every sandbox, snapshot and image in its project. The module translates: provision, list, inspect, suspend and resume are one Tensorlake call each, and destroy is the delete and the sweep of the sandbox's snapshots. Rows carry Tensorlake's `status` in `vendor`, and its `outcome`/`outcome_reason` or `termination_reason` as the reason. An environment's id is Tensorlake's sandbox id.

Sandboxes carry no labels or metadata, so the sandbox's name holds them: `dd-<digest of the instance>-r-<label>` (or `-b-` with the label in base32, or `-h-` with a digest when it does not fit). The module reports `drydock.provider` and `flotilla.label`, decoded from a name with this instance's prefix, as `vendor.tags`. On a `shared_account` (the default) drydockd lists and acts by id only on sandboxes carrying that tag. On an `owned_account` nothing is filtered, so use a project that holds only drydock's sandboxes. Names are unique in a project: provisioning a label that already names a sandbox is refused with Tensorlake's 409.

| Call | Used for |
|---|---|
| `POST /sandboxes` (`wait: false`) | provision |
| `GET /sandboxes` (every page) | list |
| `GET /sandboxes/{id}`, then `GET /archived-sandboxes/{id}` when it is not found | inspect |
| `DELETE /sandboxes/{id}`; snapshots: list, delete | destroy and its snapshot sweep |
| `POST /sandboxes/{id}/suspend`, `POST /sandboxes/{id}/resume` | suspend, resume (the resume token is the sandbox id) |
| Images: CAS build (`/images/v4/builds`) and lookup by name | prepare |
| Sandbox proxy: files, processes, TCP tunnel | agent upload, exec, reach |

- Sandboxes are created with `auto_resume` off: a relay or a command to a suspended sandbox fails with Tensorlake's answer instead of waking it. Sandboxes made before drydock#287 have it on, and a relay or command still wakes them.
- Tensorlake states no platform for a sandbox, and its rows give no time for their state, so rows carry neither. drydockd chooses the agent build from the module's only declared platform (`linux/amd64`).
- The module declares no usage, and no longer accepts `organization_id`, which only usage read: remove it from the settings. Tensorlake's per-sandbox usage export is its source when usage is collected as each vendor gives it (drydock#257).
- Prepare waits for an image build by reading its status every `build_poll_seconds` (default 3), up to `build_polls` times (default 150), then answers unavailable; Tensorlake offers no other way to learn a build finished. The agent upload may take `upload_seconds` (default 300).
- drydockd observes the project's sandboxes by listing them every `poll_interval_ms` (default 30000).
- Webhooks: with `project_id` set, the module declares Tensorlake's webhook way in (`tensorlake.sandbox.created`, `.running`, `.suspended`, `.resumed`, `.terminated`, `.failed`, at least once, in no promised order). Registering it is an installation step: in Tensorlake Cloud, select the project, then **Webhooks** → **Create webhook**, with the relay's receiver URL for source `tensorlake` as the endpoint and those six events selected. Open the new destination and copy its signing secret (`whsec_…`): the relay holds it, as the source's Standard Webhooks (Svix) secret, and drydock never sees it. drydockd reads the deliveries from the relay when `[providers.<name>.events]` names it. A delivery for another project says nothing drydock follows.
- Deleting images needs the project admin role, which an API key never has (403 "requires the 'admin' role"). Drydock cannot retire prepared images. A project admin removes stale `dd-` images with `tl sbx image rm` from a logged-in session.
- There is no quota API. Plan limits arrive as 400 errors at create ("Per-sandbox vCPU limit exceeded", "project has reached its quota"); drydock reports a per-sandbox limit as refused and the project's quota as exhausted. Set `max_cpus` and `max_memory` to the plan's per-sandbox limits (default 4 vCPU and 16 GiB, Usage Credits) so oversized requests are refused before they reach Tensorlake.
- Tensorlake's builders pull base images themselves, so a base must be in a registry they can reach; drydock refuses a private-address base up front. The pull credential goes to the build for the base's registry only.
- SSH needs a key registered to a user and is unavailable to API keys; drydock doesn't use it.
- The key goes as a Bearer header to `api_url` and to every `<sandbox>.<sandbox_domain>` host (default `api.tensorlake.ai` and `sandbox.tensorlake.ai`). Change those settings only to hosts you trust with the key. The presigned build-context upload never gets it.

## E2B (`e2b`, Rust host)

Credential: a team API key (`e2b_…`), as a plain token file, sent as `X-API-Key`. Configuration also needs `team_id`.

Create it in the E2B dashboard (Team → API Keys). Keys have no scopes: a key can build and delete every template and kill every sandbox in the team. The module translates: provision, list, inspect, destroy, suspend and resume are one E2B call each, and rows carry E2B's state name and the sandbox's metadata in `vendor`. On a `shared_account` (the default) it tags what it makes with `drydock.provider` metadata, and drydockd lists and acts by id only on sandboxes that carry the tag. On an `owned_account` nothing is tagged or filtered, so use a team that holds only drydock's sandboxes. The label is `flotilla.label` metadata; provisioning a label twice makes two sandboxes.

| Call | Used for |
|---|---|
| `/templates/aliases/{name}`, `/v3/templates`, `/templates/{id}/files/{hash}`, `/v2/templates/{id}/builds/{build}`, `/templates/{id}/builds/{build}/status` | prepare |
| `POST /v2/sandboxes` | provision |
| `GET /v2/sandboxes` (every page) | list |
| `GET /sandboxes/{id}` | inspect, reach (whether the sandbox runs and needs the traffic token) |
| `DELETE /sandboxes/{id}` | destroy |
| `POST /sandboxes/{id}/pause`, `POST /v2/sandboxes/{id}/connect` | suspend, resume (the resume token is the sandbox id) |
| envd's `process.Process/Start` and `/files` at `49983-<sandbox>.e2b.app` | exec, the agent's upload |
| the proxy at `7811-<sandbox>.e2b.app`, dialled by drydockd | reach |
| `/teams/{teamID}/metrics` | quota (in use) |

- drydockd uploads the agent to each sandbox (upload bootstrap) through envd's `/files`; templates are the base image alone.
- The module declares `agent_tcp_port` 7811, so drydockd starts the agent listening on loopback there. envd forwards loopback ports to the proxy ([`envd/internal/port`](https://github.com/e2b-dev/infra/blob/main/packages/envd/internal/port/forward.go)), so the agent's token is what gates that port at E2B's edge. The module reads the token back with `drydock-agent --print-token`.
- Reach is a dial reach: drydockd opens the WebSocket upgrade to the agent's port itself, with the agent's token as its Bearer and the sandbox's traffic token in E2B's `e2b-traffic-access-token` header. Set `sandbox_url` (default `https://{port}-{id}.e2b.app`) for a self-hosted E2B.
- Each sandbox returns `envdAccessToken` and `trafficAccessToken` at create and connect. The host holds them in memory; they are never written to a record or a log, and the traffic token leaves the host only in a reach. After a host restart it reads the envd token back from `GET /sandboxes/{id}` and the traffic token from a running sandbox's connect, which extends its timeout to `lifetime_seconds`.
- The key can't read the team's limits, credit or spend; set `concurrency_limit` in settings.
- The module declares no usage. E2B reports execution records in its lifecycle events and concurrency samples in its team metrics, and drydock's usage shape cannot carry either as given (drydock#257).
- Prepare waits for a template build by reading its status every `build_poll_seconds` (default 3), up to `build_polls` times (default 150), then answers unavailable; E2B offers no other way to learn a build finished. envd ends a command after `exec_timeout_ms` (default 25000).
- drydockd observes the team's sandboxes by listing them every `poll_interval_ms` (default 30000), and, when the installation gives the instance a relay (`[providers.<name>.events]`, source `e2b`), from E2B's lifecycle webhooks (drydock#286).
- The webhook is an installation step; drydockd registers none. Register it in the E2B dashboard (Team → Webhooks) or through E2B's API (`POST /events/webhooks` with the team key), pointing at the relay's receiver for source `e2b`, with the six `sandbox.lifecycle.*` events the module declares: `created`, `updated`, `paused`, `resumed`, `checkpointed`, `killed`. The registration takes a signature secret of your choosing; the relay holds the same secret for source `e2b` and checks each delivery's `e2b-signature` header (`e2b_sha256`: base64 SHA-256 of the secret followed by the body). drydockd holds only its relay consumer token, never E2B's secret.
- A delivery is read as E2B states it: its `type` is the vendor state, verbatim (`sandbox.lifecycle.paused`); created and resumed are running, paused is stopped and killed is gone, each with no cause; updated and checkpointed state no drydock state. `kill_reason` is the vendor reason, and `sandbox_metadata` the tags; a body without metadata states no tags, and the held row keeps its own. Deliveries for another `sandbox_team_id` are ignored. `event_data.execution` is usage and is not read (drydock#257).
- Private registries are given per prepare, not stored at E2B. E2B pulls over the public internet, so drydock refuses a base whose registry is or resolves to a private address, or is a bare host name without a dot, `localhost`, or a name under `.local`, `.localhost`, `.internal`, `.lan`, `.home.arpa`, `.test` or `.invalid`; a staging registry (`pull_from`) is the way to such images. The check is best effort: E2B resolves the name again at build, and a name drydock's host cannot resolve is left to E2B.
- Hobby caps a sandbox at one hour of running: a longer timeout is refused at create and silently clamped on extend. Sandboxes are created with `autoPause`, so the cap pauses rather than kills; E2B does not say whether a pause was its own or a client's, so drydock reports a paused sandbox as stopped with no cause (drydock#283), and resumes it on demand. A paused sandbox keeps its snapshot, which E2B may bill as storage, until drydock destroys it. Set `lifetime_seconds` (default 3600) to 86400 on Pro, and `disk_mb` (default 10240) to the plan's sandbox disk.
- Egress is the vendor's claim, not a measurement: the module declares E2B's documented model (a firewall outside the guest; listing a domain also opens 8.8.8.8 for DNS, and domains filter only HTTP on 80 and TLS on 443) and runs no guest probe, so every row is advisory and unmeasured until drydockd's conformance verdict says otherwise (drydock#214).
- Templates stay at teardown, one per base image and size, so each new image or size adds one until a retention decision retires them (drydock#61). A new tools pin adds none.
- E2B's terms ask for written consent before a third-party app interacts with the Services. This module is our own use of our own account; confirm with E2B before offering it to anyone else.
