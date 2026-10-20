# Protocol proposals for PR #34

**Pending owner ruling.** This is the review boundary requested in
[owner review 5586902182](https://github.com/flotilla-org/drydock/pull/34#pullrequestreview-5586902182),
items 6 and 10. The candidate Rust types live in
[proposal.rs](../crates/drydock-protocol/src/proposal.rs), with executable wire
examples in [proposal.rs tests](../crates/drydock-protocol/tests/proposal.rs).
They are isolated from active routes, the checked-in OpenAPI, host reconciliation,
and Daytona mappings. Those consumers will change only after the ruling. This
intermediate PR head is not ready to merge: the other required findings remain.

## Item 6: represent progress separately from failure

Add this variant to the existing observation union:

```json
{"state":"transitioning","phase":"starting"}
```

The generic phases are `preparing`, `starting`, `stopping`, `reconfiguring`, and
`destroying`. They report normal progress. `unknown` continues to mean that the
module cannot establish a state, with an explicit typed reason; normal lifecycle
progress must not claim `provider_api_error`.

Proposed host rules:

- Keep latest inventory and last stable billing observation separately. A stable
  observation is Running, Stopped or Gone. Transitioning updates inventory but
  does not replace that stable billing baseline or emit a billing transition.
- Stopped → Transitioning → Running emits Resumed and Running, using the final
  stable observation's timestamp and granted size. Multiple transitional samples
  do not lose the stopped baseline or create duplicate events.
- Running → Transitioning → Stopped emits one Stopped transition. The previous
  running allocation continues to be the billing baseline during progress.
- Running → Transitioning → Running with unchanged size emits no new billing
  transition. A changed final size emits Running with the new granted size.
- With no stable baseline, a transition does not invent one. A restart/gap
  snapshot still marks the metering gap; the first stable observation establishes
  the new baseline. No Resumed event is inferred from a transition alone.
- Provider-confirmed Gone or authoritative absence still follows existing
  deletion attribution. Transitioning is not evidence of disappearance.
- This proposal does not silently change Unknown handling. Genuine uncertain
  observations and cache recovery are a separate question from known progress.
  An intervening Unknown must not be treated as a known transitional sample or
  gain a new Resumed inference merely because this variant was added.

This keeps polling/diff state in the host; the module remains a stateless vendor
translator. For illustration only, Daytona's `creating`/`pulling_snapshot` could
map to Preparing, `starting`/`restoring` to Starting, and `stopping`/`archiving` to
Stopping. These are not implemented mappings pending the ruling.

**Ruling requested:** approve the Transitioning variant and phases, and retaining
last stable billing state across these samples (rather than encoding a guessed
stable billing state in each module's transition response).

## Item 10: generic resources, units, cost and structured quota scope

Replace the vendor-shaped UsageTotals with optional generic measurements. Keep
`period` and the original `environment_hours` by size:

```json
{
  "period":{"start":"2026-10-20T00:00:00Z","end":"2026-10-21T00:00:00Z"},
  "environment_hours":[],
  "measurements":{
    "scope":{"kind":"organization","id":"account-a"},
    "resources":{
      "cpu":{"amount":7200,"unit":"vcpu_second"},
      "memory":{"amount":15461882265600,"unit":"byte_second"},
      "environments":{"amount":1,"unit":"count"}
    },
    "cost":{"amount":0.0123,"currency":"USD"}
  }
}
```

Resource keys are the neutral vocabulary `cpu`, `memory`, `disk`, `gpu`,
`snapshot_storage`, `volume_storage`, and `environments`. Units are `count`,
`vcpu`, `byte`, `vcpu_second`, `byte_second`, `device_second`, and `count_second`.
Providers normalize storage to bytes and report an explicit unit; consumers do
not know a vendor's CPU/RAM/GB response field names. Unknown cost is omitted;
known zero cost carries amount 0. Currency is a code supplied with the amount,
not a hard-coded field suffix. The numeric representation here is f64, matching
existing usage amounts; validators and conversion bounds will be added during
adoption, after the shape is ruled on.

Measurements explicitly identify provider, organisation, or environment scope.
Organisation aggregates cannot assert that one stopped sandbox used no CPU while
other sandboxes continued running. Adoption must update conformance to respect
that scope instead of inferring an environment's billing state from account totals.

Replace ResourceQuota's opaque resource string with a structured key:

```json
{
  "key":{"region":"eu","class":"container","resource":"cpu"},
  "unit":"vcpu",
  "in_use":2,
  "limit":10
}
```

The existing Quota.resources collection remains a vector of these rows: JSON
object keys cannot be structured objects. Region and class are optional data,
not pieces to split out of a resource string. A provider-wide snapshot-storage
quota can therefore have `{"resource":"snapshot_storage"}` as its key. Limit
null means unknown; zero remains a known zero. Other existing account/concurrency
quota fields need not change for this proposal.

The existing `Destination::Host { host }` is proposed as a generic all-ports host
destination, alongside HostPort and Cidr. It is not Daytona-specific. A provider
can refuse unsupported combinations rather than widening them. Following the
owner's separate direction, Daytona will use its native `domainAllowList` for
host-only requests, `networkAllowList` for CIDR-only requests, and refuse mixed
requests; adopting these generic types does not mandate DNS pinning or resolution.

**Ruling requested:** approve the resource and unit vocabulary, scoped usage map,
explicit-currency cost, structured quota key, and generic Host destination.
Approved adoption would replace the current vendor-shaped public fields and
update all producers/consumers together, with an exact protocol-version bump.

## Work after the ruling

Required findings 1–5, 7–9 and 11 remain open. In particular, production-pathed
Daytona tests must use a multi-origin extension of Rigging's existing StandIn in
a separate Rigging PR; a new local HTTP harness is not the plan. Polling must not
run guest probes on every row, and rate-limit, toolbox URL, mutually exclusive
network settings, deny-all conformance and diagnostic handling must be corrected.
Optional findings will be taken where cheap, as directed. No ADR file is changed;
the decision ledger records the requested carry and unapproved choices.
