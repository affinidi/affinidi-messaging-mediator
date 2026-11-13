### Changed — `affinidi-messaging-sdk` 0.46 and `trust-tasks-rs` 0.38 (R3.6)

- The workspace moves to `affinidi-messaging-sdk` 0.46.1 and to
  `trust-tasks-rs` / `trust-tasks-proof` 0.38.0, from 0.45.17 and 0.37. The
  TDK crates that move in lockstep with them move too: `affinidi-tdk` 0.43.0
  (mediator-setup, test-mediator) and `affinidi-messaging-didcomm-service`
  0.31.0 (test-mediator dev-dependency).
- **Library users:** `trust-tasks-rs` and SDK types cross these crates'
  public APIs. Examples are the generated
  `affinidi_messaging_mediator::task_specs`, the SDK's `ATM` /
  `ATMProfile` / `ATMError` taken and returned by
  `affinidi-messaging-mediator-admin` and `affinidi-messaging-test-mediator`.
  A crate that passes such values to or from these crates must itself move
  to `trust-tasks-rs` 0.38 and `affinidi-messaging-sdk` 0.46, or it gets
  mismatched types from two copies.
- 0.38 is stricter than 0.37:
  - It refuses out-of-range `issuedAt` / `expiresAt` / proof `created`
    values instead of rolling them over.
  - It refuses a document whose `type` is not the spec it is consumed under.
  - It follows the JCS cryptosuites' `@context` rule in proofs.
  - It bounds DID resolution in the `affinidi` proof backend (10 s, no
    private hosts).
  - Its in-memory replay guard refuses when full.
  A request the mediator accepted before can therefore be refused if it
  breaks one of these rules.
- `vta-sdk` (the `vta` feature) still brings its own `affinidi-messaging-sdk`
  0.44 and `trust-tasks-rs` 0.36, as before. Nothing passes their types
  across.

### Breaking — the console reads typed refusals; `ConsoleError::Refused` gains `current_epoch` (sdk 0.46.2)

- The workspace requires `affinidi-messaging-sdk` 0.46.2. Every Trust Task
  it sends now asks to be refused with a `trust-task-error` document. A
  mediator that serves that answers with one; others keep answering with
  problem reports.
- `ConsoleError::Refused` is built from either form, and gains a
  `current_epoch: Option<u64>` field. This is a breaking change for code that
  constructs it or matches it without `..`.
  - `code` is the mediator's own code (`ATMError::mediator_code`), so code
    that matched it keeps working. A problem report's code keeps its `e.p.`
    prefix, as before.
  - `ConsoleError::current_epoch()` reads the field, which comes from the
    document's `details.currentEpoch`, or from an older mediator's comment.
    It no longer parses the comment itself.
- The console's other refusal checks (monitor unsupported-type fallback, a
  failed `admin-revoke` round) read either form.
