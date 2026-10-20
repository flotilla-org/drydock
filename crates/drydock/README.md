# Host supervision and CLI

`drydock` embeds `drydock-client` and owns host lifetime and credential resolution.
It has no desired-state database. Dropping a `HostHandle` cancels supervision and
terminates its managed process through rigging's command runner. External hosts
remain running. Managed commands receive `--unix SOCKET`; commands that use a
different flag convention can provide a wrapper.

`Supervisor` injects a `CommandRunner`, `ToolDetector` and `CredentialSource`.
`runtime: "node"` or `"uv"` requests detection; Rust hosts need no runtime.
A missing tool or incompatible hello remains visible for every configured instance
through `HostHandle::instances()`. `status` is a watch receiver with the handshake,
declarations and generation. `ready()` waits for host initialization; inspect
individual instance readiness before placement. `ready()` waits through missing
runtimes and retains the last readiness cause in a distinct timeout error;
terminal credential errors also retain their readiness cause. Restart delay defaults to 100 ms.
The runtime directory must be private and owned by the current user. A per-name
OS lock prevents two supervisors from taking the same socket.

## Credentials

Each Direct wire configuration's opaque `credential_reference` indexes
`HostSpec.credentials`. References are File (`path`, optional top-level
`json_field`), Env (`name`), or Embedder (`reference`). Built-ins implement File
and Env; an embedder supplies `CredentialSource` for its own store. Resolution
returns a redacting `Secret` and optional `SystemTime` expiry. Errors deliberately
omit input values and parser diagnostics. Do not log serialized configuration,
credential documents or request bodies.

The source exposes a watch receiver of change revisions. A notification triggers
re-resolution; periodic resolution (one second by default) also notices file
replacement and expiry. Unchanged values are not resent. Missing, empty, rejected
or expired credentials make that instance not ready without affecting its peers.
Recovery refreshes the credential without replacing the live provider. Restarted
hosts always receive configuration and fresh credentials again.

Proxied instances do not resolve Direct credentials. The embedder supplies the
per-host `proxy_environment` (for example `HTTP_PROXY`, `HTTPS_PROXY` and
`DRYDOCK_PROXY_CA`) and the wire configuration's proxy URL and placeholder token.
The proxy must already exist; the CLI does not create one. Proxy environment
values must not contain secrets: they are passed through `env` as command
arguments. Direct secrets are sent only over the authenticated connection.

## CLI

Build the binaries with `cargo build -p drydock -p drydock-host`. Configuration is
a JSON array of `HostSpec`s. For the reference module:

```json
[
  {
    "name": "rust",
    "connection": {
      "kind": "managed",
      "command": ["/absolute/path/to/drydock-host"],
      "runtime": null
    },
    "configuration": {
      "modules": [{"name": "memory", "entrypoint": "reference"}],
      "providers": [{
        "name": "demo",
        "module": "memory",
        "settings": {},
        "credential": {"mode": "direct", "credential_reference": "demo-token"}
      }]
    },
    "credentials": {
      "demo-token": {"kind": "env", "name": "DEMO_TOKEN"}
    }
  }
]
```

```sh
export DEMO_TOKEN=reference-only
# Choose a private directory with an existing parent.
drydock --config hosts.json --runtime-directory /tmp/my-drydock hosts
drydock --config hosts.json --runtime-directory /tmp/my-drydock instances
drydock --config hosts.json --runtime-directory /tmp/my-drydock list rust demo
drydock --config hosts.json --runtime-directory /tmp/my-drydock launch rust demo request.json
drydock --config hosts.json --runtime-directory /tmp/my-drydock destroy rust demo PROVIDER_ID
```

`launch` reads a protocol `ProvisionRequest`, including a prepared image from the
client's separate `prepare` call. Output is JSON, one host/instance per line for
inventory commands. Each invocation owns any managed hosts it starts; use an
external host for process state that must survive CLI invocations. Real vendor
modules use the provider's tags as their record, so they need no local store.

An external Unix host uses `{"kind":"external_unix","path":"/path/host.sock"}`.
External TCP uses `{"kind":"external","url":"http://127.0.0.1:PORT/",
"token_file":"/path/token"}`. Tokens must be nonempty regular files with mode
0400 or 0600 and owned by the current user. Symlinks, special files, tokens over
64 KiB, and whitespace inside the token are refused; a final CR/LF is removed.
The open descriptor is checked before reading it. TCP URLs must use a literal loopback IP; redirects, ambient proxies and
HTTP retries are disabled. External hosts receive the same configuration and
credential refresh calls, but drydock never starts or terminates them.
