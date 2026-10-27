# Server provider policy

This runtime is owned by the main server, shared by embedded `Daemon` and
standalone `drydockd`. Public operations reach it before the private provider seam.
The following detailed behaviours moved with the implementation from the Rust host.

`operations.rs` implements `ProviderApi`: the typed entry points the public
router and the Daemon call. `instance.rs` holds one configured provider's
readiness, admission, credential rejection, budgets and call deadlines;
`events.rs` the history, cursors, replay and snapshots; `evidence.rs` the
lifecycle-inspection and egress-evidence cache; `observer.rs` polling and push
reconciliation; `diagnostics.rs` credential masking; `remote.rs` the private
trait adapter. `mod.rs` owns configuration, credential delivery and shutdown.

## Server-owned observation

A provider declares `ObservationMode::Poll { interval }` or Push. For Poll the
server owns one list loop, last-seen state and diffing. It stretches the interval
within declared list/global limits and skips missed ticks. Observation gets at
most half the long-run list/global rate and max(1, requests/2) slots per window;
route calls share the total budget and can use the remaining slots. An indivisible
one-request window is polled at most every two windows: a route immediately after
that single poll can still receive 429 until the shared window expires. If route
traffic consumes a single-slot window before a due poll, the server reserves the next
free slot for that pending observation. Routes may receive 429 until the next poll
attempt takes the slot; this prevents steady route traffic from starving observation.
The first
poll is eligible immediately; Direct credential delivery wakes observation, so a
large steady-state interval does not delay the first snapshot. Failed or unready lists preserve prior state and never report
resources gone. Successful complete lists emit Created/Running, Stopped/Paused,
Resumed/Running, size changes, and Gone transitions. Confirmed requested deletions
use DestroyedByRequest; unexplained absence uses MissingOnList. If a list observes
absence while destroy is pending, the server defers the billing cause until the call
confirms or fails. Failure/cancellation is never promoted to confirmed deletion.

The default `inspect_after_lifecycle` reads the complete inventory to avoid guest
probes on a completed lifecycle. This costs O(inventory); providers with a cheap
per-environment read can override it, as Daytona does, retaining that observation
if optional enrichment fails. Explicit inspect remains strict.

Modules return `ObservedEnvironment` from list/inspect: the environment plus an optional
typed provider timestamp. Polling uses that time, including matching inspect
metadata when list has none; otherwise the server stamps first observation with
TimestampSource::Adaptor. Push modules publish raw ObservedEnvironment updates and explicit removals through EventSink, retaining optional typed timestamps. Some means Provider provenance; None asks the server to stamp
Adaptor time. Modules never format event times. The reference declares Poll and
publishes no events itself, so its lifecycle tests exercise the server poller.

The server retains `EVENT_HISTORY_CAPACITY` server-wide events in memory (1024).
`GET /v1/events` starts with a snapshot; `?since=` resumes exclusively at
retained cursors. Unknown, expired and previous-process cursors produce a
gap snapshot. Poll snapshots use the last successful server-owned inventory, never
another vendor list request. A poll commits its inventory and transition events
under the same log lock, so a poll-only snapshot cursor identifies that exact cut.
Before a provider's first successful poll, a snapshot waits for observation or
marks that provider's typed failure. With neither cache nor a failure, it waits for
an observation, an error, or server shutdown. Later transient poll failures retain the inventory.
Push snapshot cursors precede provider listing to replay overlapping events.
Independent push lists run concurrently under one shared five-second deadline
(`PUSH_SNAPSHOT_TIMEOUT`), once per snapshot. This is a fixed server policy rather than
provider configuration. A timed-out list is cancelled and its provider is marked
Unavailable; healthy providers still publish inventory. Lists return complete vectors:
no captured or unfinished response is published as authoritative. Server shutdown
cancels the whole batch immediately. Waiting for an initial poll inventory does not
restart the push lists or their deadline. If enough events arrive during that wait
to evict the pre-list cursor from the 1024-event history, the next stream iteration
emits a fresh gap snapshot instead of replaying the lost events. Clients apply that
replacement snapshot normally, preserving inventory for unavailable providers;
individual evicted billing transitions cannot be recovered from this in-memory log.
Snapshot rows mark a metering gap and do not create extra billing transitions.

Snapshots omit inventory for unready providers and failed push lists, reporting
those providers in an optional `unavailable_providers` map of name to typed error.
Cached poll rows are also withheld when that provider is unready; a ready provider's
cached inventory remains available through transient polling failures.
The map is absent for a complete snapshot. Consumers must preserve previous inventory
for marked providers: missing rows are not evidence of deletion or a billing transition.
Healthy providers continue streaming. Events from a marked provider can still follow
the snapshot cursor. Each such event is authoritative only for its own environment
row; it does not make that provider's omitted inventory complete or remove its marker.
Push lists use the normal call gate, so a
successful list repairs a proxied rejection without requiring a separate route call.
Direct credentials still require refresh. Poll providers repair through normal polling.
Retained-cursor replay does not list. Server stopping still returns an initial typed
HTTP error or ends an existing stream. The protocol defines no terminal NDJSON error record.
Polling cannot report transitions hidden entirely between samples; modules with
event streams declare Push.

Push observers receive `Provider::run(PushContext)` only after configuration commits.
The context carries a provider-scoped raw observation sink, an immutable credential snapshot, and a stop watch. The server cancels/reopens subscriptions on rotation.
On shutdown the server signals and cancels pending configuration and subscription futures, then awaits observer
cleanup against one shared five-second deadline. It aborts remaining observers without
awaiting cooperative cancellation and releases instances. Once the shared deadline
expires, remaining observers receive no additional grace; already-completed tasks
are still collected. Module factories must be
cancellation safe; configuration remains transactional until commit. Poll factories
receive no sink and do not start background work. Upgraded streams close on shutdown; they
are not drained to completion.

## Diagnostics and readiness

The library emits structured tracing events with route/provider/environment identity,
static error classes and readiness statuses; it never installs a subscriber or logs
request bodies, credentials or unmasked vendor error text. The binary installs a plain-text
stderr subscriber using `RUST_LOG`, defaulting to `info`. Embedders choose a subscriber.

One policy derives readiness and call admission from module readiness plus server
credential state. Direct rejection is sticky until a new refresh. A rejection also
invalidates older calls, so a stale success cannot repair it. Proxied rejection
reports Unknown while allowing subsequent probes; a successful post-rejection
probe restores readiness after the supervisor repairs the proxy. Direct credential
refresh is still refused for Proxied providers.
