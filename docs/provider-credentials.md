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

## Docker Sandboxes (`docker_sandboxes`, Rust host)

Credential: a Docker personal access token and its owner, as JSON, `{"username": …, "personal_access_token": …}`. It is exchanged at Docker Hub (`token_exchange_url`, default `https://hub.docker.com/v2/auth/token`) for a short-lived access token, as Docker's SDK does; the module keeps that token in memory until a minute before it expires, and exchanges again after. An access token that states no expiry is not kept, so each verb then costs an extra Docker Hub call. Docker's API rejects a bare personal access token as the Bearer, so the module rejects a plain token file before any call.

Create the token on Docker Hub (Account settings → Personal access tokens), for an account with Cloud Sandboxes access. The API is experimental: Docker says features and behaviour may change. The module translates: provision, list, inspect, destroy, suspend and resume are Docker's own operations, and rows carry Docker's `status`, its `failure` message and the sandbox's labels in `vendor`. On a `shared_account` (the default) it labels what it makes with `drydock.provider`, and drydockd lists, destroys, suspends and resumes only sandboxes that carry it; Docker's list filters by no label, so the module lists the whole account. On an `owned_account` nothing is labelled or filtered, so use an account that holds only drydock's sandboxes. The client's label is the `flotilla.label` label; provisioning a label twice makes two sandboxes.

| Call | Used for |
|---|---|
| `POST /v1/sandboxes` | provision |
| `GET /v1/sandboxes` (every page) | list |
| `GET /v1/sandboxes/{id}`, and `GET /v1/sandboxes/{id}/network-policies` while it is running | inspect |
| `GET /v1/sandboxes/{id}`, then `DELETE /v1/sandboxes/{id}` | destroy |
| `GET /v1/sandboxes/{id}`, then `POST /v1/sandboxes/{id}/stop` or `/start` | suspend, resume (the resume token is the id) |
| `POST /v1/sandboxes/{id}/endpoint-credentials` | a five-minute credential for the sandbox's endpoint, for each exec, upload and relay |
| endpoint `POST /v1/processes/exec` | exec |
| endpoint `PUT /v1/files/directories`, `PUT /v1/files/content` | the agent's upload |
| endpoint `POST /v1/processes`, then the `interact` WebSocket | relay (reach) |

Docker's spec names the permission each call needs: `sandboxesRead`, `sandboxesCreate`, `sandboxesDelete`, `sandboxesLifecycle`, `sandboxesCredential` and `networkPoliciesRead`, and `sandboxesExec` and `sandboxesFilesWrite` on the endpoint credential. It does not say how a personal access token's scopes map to them; the live run uses a token that can do all of these.

- Every change of a sandbox (delete, stop, start) needs the etag of its last read, so each is a read and the change. A sandbox that changed in between is Docker's 412, reported as unavailable.
- Images: Docker runs a public image by digest (`imageRef`). Its API takes no credential for a private registry, so prepare refuses one, and a private image needs a staging registry (`pull_from`) that Docker can pull from anonymously. Prepare makes nothing at Docker.
- Sizes are Docker's fixed shapes: Micro (1 CPU / 2048 MiB), Small (2 / 4096), Medium (4 / 8192), Large (8 / 16384) and XL (16 / 32768). Any other size is refused before the call. Docker takes no disk size, so ask for a disk of 0; rows report no granted size, since Docker states no disk.
- drydockd uploads the agent (upload bootstrap) through the sandbox's file API and starts it through exec. Docker's PID 1 is its own init, not the image's entrypoint, and a process started through exec keeps running between execs and across stop and start.
- Reach is a relay: a process running `drydock-agent --bridge`, its stdin and stdout carried over the interact WebSocket with the endpoint credential. The endpoint credential lasts at most five minutes; whether Docker closes an interact stream when it expires is for the live run to show.
- Egress: open only. Docker's create takes a sandbox's own policy (`networkPolicies`), but installs it beside the account's default layer, which allows every network: a live deny-all create left the sandbox open (effective `allowNetworks` `**` from layer `default`, no `attached` document installed). The spec states no way for a sandbox's own policy to narrow egress below that default, so the module refuses deny-all in those terms and sends no policy. Restricting egress is the account's governance (org or owner layers), outside this API. Inspect still reports what Docker states: `enforced` only when, for that sandbox, a deny-all policy holds its own (`attached`) document and every effective allowed network comes from that document. The policy identity is Docker's `revision`. Docker states a sandbox's policy only while it runs (otherwise 409 `failedPrecondition`), so inspect of a stopped or starting sandbox states no egress.
- Platform: `linux/amd64` only. Docker's spec lists no platforms, so the module declares the one it asks for at create, and prepare refuses any other (for example `linux/arm64`).
- Docker's stop keeps memory and disk, and start resumes in about two seconds. Docker does not say who stopped a sandbox, so a stopped row has no cause. Docker caps a sandbox at 24 hours.
- The module declares no usage (Docker has no usage API) and no quota. Docker's quota refusals carry a `QuotaFailure` detail and are reported as exhausted quota.
- drydockd observes sandboxes by listing them every `poll_seconds` (default 30). An exec may run `exec_seconds` (default 60), and the agent's upload `upload_seconds` (default 300).
- The personal access token goes to `token_exchange_url` only, and the access token it is exchanged for as a Bearer header to `api_url` (default `https://connect.docker.com/sandboxes`). Endpoint calls carry only the sandbox's short-lived credential. Change those settings only to hosts you trust with the token.

## Docker Engine (`docker_engine`, Rust host)

Credential: none. The engine has no authentication of its own: whoever can open its socket, or holds a client certificate its TLS endpoint trusts, controls it, and with it the engine's machine (a container can be made with any host path mounted, as root). Leave the instance's `credential` unset. The module reads its access from settings, and a request never carries it.

`endpoint` is required unless the instance has a `parent`: an instance with neither is refused when it is configured. It is a Unix socket on drydock's machine:

```toml
[providers.engine]
module = "docker_engine"
image = "ubuntu@sha256:…"
size = { cpus = 2, memory = "4GiB", disk = 0 }   # the engine sets no per-container disk
egress = "open"
semantics = { settle = true, idempotent = true }

[providers.engine.settings]
endpoint = "unix:///var/run/docker.sock"
```

or TCP with TLS and a client certificate, the three files as `dockerd --tlsverify` and `docker --tlsverify` use them:

```toml
[providers.engine.settings]
endpoint = "tcp://engine.example.net:2376"
tls = { ca = "/etc/drydock/engine/ca.pem", cert = "/etc/drydock/engine/cert.pem", key = "/etc/drydock/engine/key.pem" }
```

or, for an engine on another machine, a Unix socket on a parent instance's machine, which the parent carries each connection to. The engine's socket is not exposed beyond its machine, and the instance takes no `endpoint` in its settings:

```toml
[providers.b1-engine]
module = "docker_engine"
image = "ubuntu@sha256:…"
size = { cpus = 2, memory = "4GiB", disk = 0 }
egress = "open"
semantics = { settle = true, idempotent = true }
parent = { instance = "b1", endpoint = { unix = "/run/user/1002/docker.sock" } }
```

- `parent` names another instance by its name, here [b1's `ssh_host` instance](#ssh-host-ssh_host-rust-host), and an endpoint on its machine, here the rootless engine's socket of the user b1's instance signs in as. `ssh_host` and `local` instances can be parents. drydockd makes a socket for the instance, `parents/<digest>.sock` under its runtime directory, named by a digest of the instance's name so that it stays put when the configuration is reordered. It gives that to the module as its endpoint, and for each connection the module opens there asks the parent for a stream to the engine's socket. drydockd asks for no other stream, and the parent's stream call is not on drydockd's API. The module speaks to it as to any local socket. The child's declaration (`GET /v1/providers/b1-engine`) shows that socket as `endpoint`; `docker -H unix://<it>` reaches the same engine. Whoever can open that socket controls the engine, and with it b1, so it is made as the exposures' sockets are: in a directory of mode 0700, the socket 0600, both owned by the user drydockd runs as. drydockd removes it when it stops and makes it again when it starts; a configured instance cannot change without a restart.
- Refused when drydockd reads its configuration, so that it does not start: a parent that is not configured, parents that form a cycle, an endpoint path that is not absolute, an `endpoint` key written beside `parent`, a `parent` on an instance of a module that cannot be given its endpoint (`docker_engine` is the only one that can), and a parent whose module carries no streams to that form of endpoint (the parent's `capabilities.carries`). A `parent` beside an `endpoint` setting is refused when the module configures the instance.
- While the parent is not ready, the child's readiness is `parent_not_ready`, naming the parent and saying why, and its calls are refused as unavailable with that reason. A stream the parent cannot open, the engine's socket missing on b1 for instance, ends the module's connection, which the module reports as the engine not answering; the child's readiness stays its own, and drydockd logs the parent's reason against both instances. While drydockd is starting, the parent's host opens each stream once it has configured the parent, so the child's first look at its engine, made while it is configured, reaches it: that look is where `docker_engine` learns the engine's platform.
- `endpoint` is `unix://` and an absolute path, or `tcp://` and a host and port. TCP without `tls` is refused, and so is `tls` with a socket. The engine's TLS certificate is checked against `ca` alone, for the endpoint's host: a name against the certificate's DNS names, an IP address against its IP addresses. Its common name is not read, so a server certificate made without `subjectAltName` fails each call with a TLS error that the certificate is not valid for that name.
- drydock-host reads the three files when the instance is configured, and keeps the certificate and key in memory for as long as the configuration stands. Give them to the user drydock-host runs as, readable by it alone. A changed file takes effect when the instance is configured again. A file that cannot be read or parsed fails the configuration; a certificate the engine no longer accepts, an expired one for instance, fails each call with the TLS error, and readiness reports it.
- Making the client certificate: Docker's [Protect the Docker daemon socket](https://docs.docker.com/engine/security/protect-access/) shows the CA, the server certificate and the client certificate (`extendedKeyUsage = clientAuth`). Any client the CA signs has full control of the engine, so use a CA of the engine's own, signing nothing else.
- The socket: the user drydock-host runs as needs read and write on it, usually by membership of the `docker` group, which is root on that machine.

The module speaks Engine API v1.44 (Engine 25 and later): every request path starts `/v1.44/`, so a newer engine answers as v1.44 does. An older engine refuses each call with its own message, and the module reports that.

| Call | Used for |
|---|---|
| `GET /version` | readiness, and the platform the module declares (the engine's `Os` and `Arch`) |
| `POST /images/create` (`fromImage` by digest, `platform`, the registry credential in `X-Registry-Auth`), read to the end of its progress stream; then `GET /images/{reference}/json` | prepare |
| `GET /info`; `POST /containers/create`; `POST /containers/{id}/start`; `GET /containers/{id}/json` | provision (`DELETE /containers/{id}` when create warns, or start or the inspect after it fails) |
| `GET /containers/json?all=1`, filtered by the `drydock.provider` label on a `shared_account` | list |
| `GET /containers/{id}/json` | inspect |
| `DELETE /containers/{id}?force=1&v=1` | destroy |
| `POST /containers/{id}/exec`, `POST /exec/{id}/start` (the connection is taken over), `GET /exec/{id}/json` | exec, and relay (reach) |
| `PUT /containers/{id}/archive` | the agent's upload, after `mkdir -p` of its directory through exec |
| `GET /info` | quota: the engine's count of running containers |

- Control is the Engine API alone: the module runs no command on the engine's machine, assumes no shared user id and mounts nothing. The checkout is a clone inside the vessel.
- Images: the engine pulls by digest, for the platform the engine states, with the prepare request's registry credential sent in that pull alone. Nothing is stored on the engine's machine, and pulled images stay there (drydock does not remove them).
- Sizes: CPUs as `NanoCpus`, memory as `Memory` (and `MemorySwap` the same, when the engine states it can limit swap). A provision is refused, with the engine's own words, when `/info` does not state that it enforces memory limits and CPU quotas (rootless Docker without cgroups is one such engine), and a container whose create answers with warnings is removed and refused with them: the engine discards a limit it cannot apply and warns. The engine sets no per-container disk, so ask for a disk of 0; rows report no granted size.
- Each container runs `sleep infinity` under the engine's init (`Init`), with the image's entrypoint replaced, so the image needs `sleep` and `sh`. Every exec, the agent's included, runs as root (`User` 0), whatever the image's `USER`. drydockd uploads the agent after start and runs it through exec. When the engine refuses the start, or the inspect after it fails, the container is removed and the provision answers with that failure; if the removal fails too, the reason names the container and says it may be left on the engine. An image without `sleep` still starts: the provision succeeds, the container exits with 127, the launch fails at the agent upload (409, the container is not running), and the stopped container stays listed until destroy removes it.
- Reach is a relay: a process running `drydock-agent --bridge` through exec, its stdin and stdout carried over the connection the engine takes over. The engine has no port or socket forwarding.
- Egress: open, or deny-all with no destinations, which is `NetworkMode: none`: the container has no network at all, and exec and the file calls still work. Inspect and list report egress enforced when the container's `NetworkMode` is `none`. Deny-all with destinations is refused: the engine has no allow-list.
- On a `shared_account` (the default) the module labels what it makes with `drydock.provider` and lists with the engine's label filter; drydockd acts by id only on containers that carry it. On an `owned_account` nothing is labelled or filtered, so use an engine that runs only drydock's containers. The client's label is the `flotilla.label` label; provisioning a label twice makes two containers.
- Rows carry the engine's state name in `vendor`; inspect adds its `ExitCode`, `OOMKilled` and `Error` as the reason. A stopped row has no cause: the engine does not say who stopped a container.
- An exec runs up to `exec_seconds` (default 60); the engine has no exec timeout, so a command still running then keeps running after drydock stops reading it, until it ends or the container is destroyed: the API has no call that ends an exec'd process. A pull may take `pull_seconds` (default 600), and an upload `upload_seconds` (default 300). drydockd lists containers every `poll_seconds` (default 30).
- The module declares no usage. Quota is the engine's count of running containers, all of them, not only drydock's; the engine admits nothing, so admission stays with the caller.

## SSH host (`ssh_host`, Rust host)

Credential: none. The private key drydock signs in with is a file named in the settings. One instance is one machine:

```toml
[providers.b1]
module = "ssh_host"
image = "ubuntu@sha256:…"   # recorded, not pulled: vessels run on the machine itself
size = { cpus = 2, memory = "4GiB", disk = 0 }   # no per-vessel disk
egress = "open"

[providers.b1.settings]
address = "b1.lab.example.net"
port = 22
user = "drydock"
host_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA…"
identity_file = "/home/me/.config/drydock/b1_ed25519"
# directory = "/run/user/1001/drydock"
```

- `address`, `port`, `user`, `host_key` and `identity_file` are required; nothing is guessed. `host_key` is the machine's raw host public key, as `ssh-keyscan` prints it without the host name, and the connection is refused unless the machine presents exactly that key. drydock reads no ssh_config, known_hosts or ssh-agent of the user it runs as, and needs OpenSSH 8.7 or later as `ssh` on its PATH. A machine behind a jump host cannot be reached yet.
- `directory` is where vessel directories live, an absolute path without whitespace, colons, quotes, backslashes, backticks, `$` or `%` (a shell or systemd would read them). It defaults to `drydock` under the user's `XDG_RUNTIME_DIR` on the machine (`/run/user/<uid>/drydock`), which systemd empties when the machine restarts.
- `identity_file` is an absolute path, on drydock's machine, to the OpenSSH private key, unencrypted (drydock never prompts for a passphrase), readable by drydock-host and by no one else: `ssh` refuses a key file its owner has left readable by group or others, so give it mode `0600`. `ssh` reads it in place each time it connects; drydock never copies it. Readiness reports a missing or unreadable file as a missing credential.

What the machine needs:

- An OpenSSH server that accepts the key for `user`, and a POSIX login shell for it: every command runs as `sh -c` through it.
- Linux, with a systemd user manager for `user` that keeps running without a login: `loginctl enable-linger <user>`. Without lingering the manager, the runtime directory and every vessel end when drydock's connection does, so readiness reports it missing.
- A writable vessels' directory. Nothing goes in `/opt` or `/run` outside it, and nothing needs root.
- For limits, cgroup v2 with the `memory` and `cpu` controllers delegated to the user's manager (`Delegate=` on `user@.service`, as systemd's [delegation](https://systemd.io/CGROUP_DELEGATION/) describes). The module reads the manager's `cgroup.controllers` to see whether they are.
- drydock-host needs a `drydock-agent` build for the machine's platform: `drydock-agent-linux-<arch>` beside it, `DRYDOCK_AGENT_BIN_LINUX_<ARCH>`, or, when the machine's platform is drydock's own, `drydock-agent` beside it or `DRYDOCK_AGENT_BIN`.

Every call is a command or a stream over one SSH session:

| On the machine | Used for |
|---|---|
| `uname`, `nproc`, `/proc/meminfo`, `systemctl --user show`, the manager's `cgroup.controllers`, `loginctl show-user` | readiness, the platform, and provision and quota's statement of the machine |
| `mkdir` and `cat` with the agent build on stdin, its length checked with `wc -c`, then the record the same way | provision: the vessel's directory |
| `systemd-run --user --unit=drydock-<id>.service`, with the vessel's limits as properties | provision and resume: the agent, as a transient service |
| `systemctl --user show` of each vessel's unit, its cgroup's `cpu.max` and `memory.max`, and the vessels' records | list, inspect, quota |
| `systemctl --user stop drydock-<id>.service` | suspend, destroy |
| `chmod -R u+w`, `rm -rf` | destroy: the vessel's directory |
| a stream to `<directory>/<id>/run/drydock/agent.sock` | relay (reach) |
| a stream to a Unix socket path a child instance names | a child's endpoint, such as a [Docker engine's](#docker-engine-docker_engine-rust-host) |

- Vessels are host-direct, and the module declares them so (`host_filesystem`, `host_processes`): a vessel is the directory `<directory>/<id>/` and the processes its agent starts, as the machine's user, with the machine's processes and filesystem visible. The checkout is a clone in the vessel's directory. Egress is open and advisory: deny-all is refused. Nothing is pulled; the image is only recorded.
- The agent runs unprivileged from the vessel's own copy, `<id>/opt/drydock/drydock-agent`, with its socket at `<id>/run/drydock/agent.sock`, as the service `drydock-<id>.service` of the user's manager. Stopping the unit ends the agent and everything it started. A vessel whose unit is not active is stopped: suspended when it was asked to be, otherwise halted. Resume starts the unit again; the directory stays. Rows carry the unit's `ActiveState` in `vendor`.
- Sizes, where the manager has the controllers: each vessel's unit has `MemoryMax` (with `MemorySwapMax=0`) and `CPUQuota` from the size asked for, and that size is the vessel's granted size. Provisions on one instance are serialised.
- The whole-machine case, where it does not: the machine takes one vessel at a time, granted the whole machine, and its unit carries no limits. The granted size is the machine's CPUs (`nproc`) and memory (`MemTotal`), shared with whatever else runs on the machine outside drydock, and the row's `vendor.reason` says so. A provision while one of this instance's vessels exists, running or suspended, is refused as exhausted quota naming it; destroying that vessel frees the machine.
- Disk: no per-vessel disk is set, so ask for a disk of 0; granted sizes have a disk of 0.
- Quota is what the machine states: its CPUs and memory as the limits, the CPU and memory limits its running vessels' cgroups hold summed as in use (a vessel with the whole machine holds all of it), the count of running vessels, and a concurrency limit of 1 in the whole-machine case. The module refuses nothing on free room; that is the caller's to decide.
- Each command may take 60 seconds, and the agent's upload 300. drydockd lists the vessels every 5 seconds.
- An instance carries streams (`capabilities.carries` is `["unix"]`), so it can be the `parent` of another instance whose endpoint is on the machine: each stream is a stream to a Unix socket, by absolute path, over the session, as the agents' are, opened as `user` with that user's access. A path that is not absolute is refused; a socket that is missing or that `user` cannot open fails the stream with the session's words. Only Unix sockets are carried. drydockd asks for a stream only to the endpoint a child's `parent` names.

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
