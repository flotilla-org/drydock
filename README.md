# drydock

The substrate for just launching vessels: isolated environments for AI coding agents, on any provider.

Drydock hosts out-of-process provider adaptors behind one HTTP protocol, reaches an agent inside each vessel over a stream transport, and carries the vessel's egress. [Flotilla](https://github.com/flotilla-org/flotilla) embeds it; it is also usable on its own.

Status: design decided ([flotilla-org/flotilla#3503](https://github.com/flotilla-org/flotilla/issues/3503)); protocol workspace implemented; language hosts and providers are next.

Project contents and roadmap:

- the protocol crate: Rust types, the generated OpenAPI document and a drift test;
- language hosts for TypeScript and Python, each with its own version of the provider interface;
- provider modules, Namespace first;
- a conformance suite runnable against any language host or built-in provider.

Licensed under either of Apache License 2.0 or MIT, at your option.

## Protocol workspace

`drydock-protocol` contains the JSON types and OpenAPI route descriptions for
ADR 0070, including its API-review amendment. It has no flotilla dependency and
no HTTP server or client implementation. Language hosts should generate their
models from [`openapi.json`](openapi.json).

```sh
cargo run -p drydock-protocol --bin generate-openapi > openapi.json
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
uvx --from openapi-spec-validator==0.7.2 openapi-spec-validator openapi.json
```

The drift test compares deterministic generation with the checked-in document.
Regenerate it whenever wire types or route descriptions change. CI separately
validates the document against OpenAPI 3.1.

Wire conventions chosen for this first protocol version:

- Names follow the ADR amendment: configured `providers` load `modules`;
  sandbox `id` is opaque and `label` is the client's environment ID. Provision
  repeats by label return 200; new creations return 201. Inspect and destroy
  use IDs even when a sandbox has no label. Destroying an absent ID succeeds.
- Configuration contains non-secret settings and credential references or proxy
  placeholders. Direct credential values are sent separately through the
  authenticated credential refresh route, including initial delivery.
- Prepare is look-up-or-build by image/tools digest pair; a prepared form belongs
  to its named provider. Hosts must refuse cross-provider use. Baking and upload
  start the agent with fixed flags, without per-vessel configuration.
- Missing egress means deny-all with no direct destinations. `open` is explicit;
  unsupported destinations are refused, never widened. The result records
  enforced versus advisory protection.
- `/v1/observe` is one host-wide NDJSON stream. Each line is an `ObserveRecord`.
  `since` is an opaque exclusive cursor. A host unable to replay emits a complete
  list snapshot with a new cursor, marking a metering gap. Event times are RFC
  3339 with explicit provider/adaptor provenance; running events carry granted size.
- Retry hints are whole seconds. Modules do not retry. Capability flags govern
  optional suspend/resume, export, exec, usage and quota operations. A resume
  token is valid only at the same provider. Usage periods are RFC 3339 start/end;
  quota credit units are provider-defined.
- Relay and exec responses upgrade to raw streams. Dial uses TCP or WebSocket
  URLs and an expiring token; SSH carries endpoint, user and host key. Transport
  setup, authentication enforcement, semantic input validation and idempotency
  behaviour belong to hosts and their future conformance suite.
