# Delivery and contract rules (the R-numbers)

Code comments, PR checklists and changelog entries in this repository cite
rules by number: "(R1.1)", "(R3.6)" and so on. They come from the development
guide shared by the services built on this mediator (the Verifiable Trust
Agent and Community, the trust registry, the message bridge and their
clients). That guide is not public, so this page states each rule this
repository cites and what it means here.

The numbers are stable: a rule that is cited never changes number. Gaps in
the numbering are rules this repository does not cite.

## 1. Networking and delivery

| Rule | Statement | What it means in the mediator |
|---|---|---|
| **R1.1** | Never trust a bare `Ok` from a send, and never return one. | A frame is reported as delivered (an ack, a `delivered` monitor event, a queue deletion) only after it was actually written. "Accepted" and "delivered" are different results. |
| **R1.2** | Every outbound network call has a finite timeout. | HTTP clients, WebSocket relays, Redis calls and admin-console requests all carry deadlines; none can wait forever on a stalled peer. |
| **R1.3** | Never hold a lock across a network or store await. | Copy what is needed, release the lock, do the I/O, then re-acquire to write back. |
| **R1.4** | Retry loops are bounded, backed off and only around idempotent work. | Every retry has a cap and backoff with jitter; a non-idempotent operation is not blindly retried. |
| **R1.5** | Accept, listen and poll loops survive transient errors. | A failed accept or poll cycle is logged and continued; only an unrecoverable error ends the loop, and then loudly. |
| **R1.6** | Ack or delete a message only after it is durably handed off. | A message is removed from a queue after the recipient has it, never before. |
| **R1.7** | A shared receive stream has one owner, and deletion happens exactly once. | One task owns a connection's stream and routes what arrives. `auto_delete` on live streams, explicit deletes and another consumer's replies never race to delete the same message: exactly one delete succeeds and is counted. |

## 2. State and consistency

| Rule | Statement | What it means in the mediator |
|---|---|---|
| **R2.1** | Remote first. | A local state change is committed only after the remote effect it depends on is durable, or the flow can be resumed from every intermediate state. Ask of every mutation: "what happens if the process dies on the next line?" |

## 3. Wire contracts

| Rule | Statement | What it means in the mediator |
|---|---|---|
| **R3.2** | Reject unknown fields on anything security-relevant. | Inbound bodies that carry scope, authorization or identity (Trust Task proofs, mux grant statements) are refused when they hold a field the mediator does not understand, never silently trimmed. |
| **R3.6** | Changing a contract? Find every consumer first. | Messages, response shapes, error codes and delivery, ack or auth *behaviour* are contracts. A change to any of them is breaking for consumers even when no Rust signature changes: the changelog entry says so, and the consuming services are checked before release. |
| **R3.7** | Error responses are part of the contract. | Clients detect conditions from stable, machine-readable codes ([ERRORS.md](../crates/affinidi-messaging-mediator/ERRORS.md)), never by parsing message text. |

## 5. Configuration and defaults

| Rule | Statement | What it means in the mediator |
|---|---|---|
| **R5.1** | Absence means the most restrictive interpretation. | An absent setting or empty list means "off" or "nothing", never "everything": DID multiplexing is off unless enabled, an empty scope grants no scope. |
| **R5.2** | Every documented security tier must be expressible in config. | A setting never silently means less than its name; a combination that cannot be honoured refuses to start. |
| **R5.3** | Fail closed when enforcement infrastructure fails. | If a check cannot run (a key that cannot be resolved, a policy store that is down), the gated action does not proceed. |

## 6. Health, observability and honesty

| Rule | Statement | What it means in the mediator |
|---|---|---|
| **R6.2** | No latched status. | Connection state is observable: every drop and reconnect is emitted, and a "connected" or "healthy" flag can go false again. Clients never have to infer connectivity. |
| **R6.3** | Log what happened, not what you hoped. | "Sent" only after the transport accepted it, "delivered" only on the write or ack. |
| **R6.5** | Background jobs surface their failures. | A failing background task shows up in a metric or a degraded health state, not only in a log line. |

## 7. Security

| Rule | Statement | What it means in the mediator |
|---|---|---|
| **R7.2** | Revocation and consent are delivery-critical. | A revoke (for example of a mux grant) takes effect on every affected connection before the mediator answers that it is done. |
| **R7.5** | Verify before you consume, sign before you claim. | Verify the proof, check policy, consume resources, commit state, respond: in that order. |

## Before you open a PR

The [pull request template](../.github/pull_request_template.md) carries the
checklist form of these rules. A change to delivery, ack or auth behaviour
also needs a `changelog.d/` entry that calls it out (see
[changelog.d/README.md](../changelog.d/README.md)).
