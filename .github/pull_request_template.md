## What and why

<!-- What changes, and the problem it solves. Link issues with "Closes #N". -->

## Consumer impact

<!--
Behavioural changes to delivery, ack, auth or reconnect semantics are breaking
for consumers even when no signature changes (R3.6): say so here and in the
changelog.d/ fragment, and name the consuming repositories to coordinate with.
Write "none" if there is none.
-->

## Checklist

- [ ] Commits are signed off (`git commit -s`) with conventional subjects
- [ ] A `changelog.d/<short-kebab-name>.md` fragment for user-visible changes (never `CHANGELOG.md`)
- [ ] Tests cover new code paths, including feature-gated ones
- [ ] Any new `unsafe` has `#[allow(unsafe_code)]`, a `// SAFETY:` comment, and a sign-off request below
- [ ] No version bumps by hand, no git/path dependencies on TDK crates

### Pre-merge checklist (VTI stack development guide, section 9)

- [ ] No new reqwest::Client::new() / bare fetch(); all clients have finite timeouts (R1.2)
- [ ] No lock held across a network await (R1.3)
- [ ] No local state committed before its remote effect, or the flow is resumable with an idempotency key (R2.1)
- [ ] Every retry is bounded + backed off; non-idempotent ops are not blind-retried (R1.4)
- [ ] Accept/poll/listen loops survive transient errors (R1.5)
- [ ] Acks/deletes happen only after durable handoff (R1.6)
- [ ] New/changed wire types: camelCase, deny_unknown_fields where security-relevant, schema registered, all consumers (incl. JS) updated (R3.*)
- [ ] Config absence = most restrictive; fail-closed if enforcement can't start (R5.*)
- [ ] Logs/status claim only what was verified; background-job failures are surfaced (R6.*)
- [ ] "Process dies on the next line" answered for every mutation touched (R2.1)
- [ ] Deviations from this guide flagged explicitly with rule numbers
