# CLAUDE.md — Affinidi Messaging Mediator

The DIDComm v2 / TSP mediator that every service in the VTI ecosystem (VTA,
VTC, trust registry, cierge, message bridge) delivers through, plus its admin
client, console and the in-process test mediator. The client SDK it speaks to
lives in `../affinidi-tdk-rs` and is a crates.io dependency here.

## Cross-service networking & integration discipline

Read the ecosystem doc set in `../design-docs/` before changing delivery,
auth, storage or reconnect behaviour:

- **`vti-stack-development-guide.md`** — binding rules (R-numbers); paste its
  pre-merge checklist into PRs.
- **`vti-networking-remediation-plan.md`** and
  **`vti-architectural-direction.md`** (Decision 1, the Delivery Layer).

Rules that bite hardest here:

- **R1.1 — never report a frame as delivered that wasn't.** Acks, `delivered`
  monitor events and queue deletions must follow the actual write.
- **R1.7 — deletion happens exactly once.** `auto_delete` on live streams and
  explicit deletes must not race each other or another consumer's replies.
- **R6.2 — connection state must be observable.** Emit on every drop and
  reconnect; never make clients infer connectivity.

## Releases

Lockstep versioning: every crate carries `[workspace.package] version`, and
internal dependencies require it exactly. Never bump one crate on its own —
use `scripts/release_lib.py` / `scripts/prepare-release.py`. Flow is main →
nightly → `release/X.Y`; see `RELEASES.md`. Publishing is crates.io Trusted
Publishing from `publish.yml` only; a brand-new crate needs a manual first
publish.

Semver caution: services pin these crates loosely; behavioural changes to
delivery/ack/auth semantics are breaking even when signatures don't change —
call them out in CHANGELOG and coordinate with the consuming repos (R3.6).

## TDK dependencies

TDK crates come from crates.io as `major.minor` requirements: no git or path
dependencies and no `[patch.crates-io]`. When a change needs a TDK fix, land
and release it in affinidi-tdk-rs first, then bump the requirement here.
`scripts/check-workspace-duplicates.sh` fails CI if a second copy of an
`affinidi-*` crate enters the lockfile.
