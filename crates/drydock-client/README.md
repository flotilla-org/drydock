# The provider API and its client

`api::ProviderApi` is the provider API served by both the drydock server and
language hosts, and `api::router` is its one HTTP adapter (`api::server_router`
adds the server-only credential and event routes). `Client` implements every `/v1`
protocol route with protocol types, including relay and exec byte streams.
`Client::credentialed` sends a provider credential as `Drydock-Credential`,
marked sensitive, on every request. It uses rigging's `HttpClient` execution port for
buffered calls; `with_http` injects recording or stand-in clients. The Unix socket
adapter and streaming routes retain a restricted reqwest client because rigging's
buffered port cannot carry a long-lived stream or an HTTP upgrade.

`Client::unix` connects over an authenticated local socket. `Client::external`
accepts a loopback HTTP URL and redacting bearer token. Calls make one attempt,
with no redirects, retries or ambient proxies. Buffered calls and upgrade setup
share one 30-second deadline, set by `with_request_timeout`; event streams
intentionally remain open. Errors keep their causes: transport failures carry
their source chain (connection refused, missing socket), an expired deadline is
`Timeout`, an invalid response carries the decoder's reason, and protocol
refusals are typed `ProtocolError`s. `Client` implements `api::ProviderApi`.
Error displays never include vendor raw text, secrets or response documents.
Provider names and IDs are escaped as individual URL path segments.

`hello` refuses an incompatible protocol version. `Observer` retains the last
cursor across calls, reconnecting with `since` after disconnect. Consumers call
`next()` again after an error. Reconnection attempts use cancellation-safe
exponential backoff from 100 ms up to five seconds, reset after a delivered record;
connection refusal and stream disconnect both schedule the next attempt.
Ordinary route calls never retry. Snapshots remain
`ObserveRecord::Snapshot`, explicitly marking a gap. Protocol v2's
`unavailable_providers` map is preserved: keep previous inventory for those
providers rather than interpreting their absence as deletion or a billing event. NDJSON framing supports
fragmented/multiple records and rejects incomplete final records; a single record
is limited to 8 MiB, and buffered framing input to 8 MiB plus its newline;
chunks that exceed the remaining framing budget are rejected before copying. Dropping the observer drops its stream.

`StatusCache::new(client, declarations)` caches list/inspect results according to
the providers' declared rate limits. Entries expire at the most conservative declared
period/requests interval. Rolling budgets are per provider and operation; `*`
shares one budget across both operations. Distinct inspect IDs share the same
budget, and concurrent identical reads coalesce. Different providers have independent
locks, so a slow request to one does not block another. Zero request limits return a
typed local refusal. Failures consume an attempt but are not cached. An exhausted
budget returns `Error::RateLimited`, with no hidden sleep or retry. No declaration
means no caching. Each declared provider holds at most 1024 cached entries. Recreate the cache when
host generation or declarations change; provider-side polling and other clients
may consume additional budget and return typed remote rate errors.

The real handlers register the shared host/server routes and their OpenAPI
annotations together via utoipa-axum. Root `openapi.json` remains the single
canonical document; `host` tags select the common surface, while the two
server-only extensions retain `x-drydock-server-only`. Regenerate with
`cargo run --locked -p drydock-client --bin generate-openapi > openapi.json`.
The client crate owns the one drift check and serialization-against-document
check; existing protocol schema-validation assertions run there unchanged.
