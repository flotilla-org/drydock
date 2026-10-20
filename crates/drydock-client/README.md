# Typed host client

`Client` implements every `/v1` protocol route with protocol types, including
relay and exec byte streams. It uses rigging's `HttpClient` execution port for
buffered calls; `with_http` injects recording or stand-in clients. The Unix socket
adapter and streaming routes retain a restricted reqwest client because rigging's
buffered port cannot carry a long-lived stream or an HTTP upgrade.

`Client::unix` connects over an authenticated local socket. `Client::external`
accepts a loopback HTTP URL and redacting bearer token. Calls make one attempt,
with no redirects, retries or ambient proxies. Buffered calls have a 30-second
deadline; event streams intentionally remain open. Errors distinguish transport,
invalid response, version mismatch, readiness/timeout causes, local rate budget
and typed `ProtocolError`.
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
the provider's hello rate limits. Entries expire at the most conservative declared
period/requests interval. Rolling budgets are per provider and operation; `*`
shares one budget across both operations. Distinct inspect IDs share the same
budget, and concurrent identical reads coalesce. Different providers have independent
locks, so a slow request to one does not block another. Zero request limits return a
typed local refusal. Failures consume an attempt but are not cached. An exhausted
budget returns `Error::RateLimited`, with no hidden sleep or retry. No declaration
means no caching. Each declared provider holds at most 1024 cached entries. Recreate the cache when
host generation or declarations change; provider-side polling and other clients
may consume additional budget and return typed remote rate errors.
