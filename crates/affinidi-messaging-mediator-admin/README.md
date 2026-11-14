# affinidi-messaging-mediator-admin

The engine behind the mediator console. It connects to an Affinidi messaging
mediator as a DID and lets you operate it: headless, or embedded in any
application.

There are two modes, and the mediator decides which one applies from its own
record of the account:

| Mode | Who | What you can do |
|---|---|---|
| **Admin** | an `admin` or `rootAdmin` account | Mediator statistics, every account's queues ranked by depth, age or saturation, any account's messages and settings, the audit log, the configuration, and live traffic for everyone. A `rootAdmin` can also read another account's message bodies and act on privileged accounts' queues. |
| **Self-service** | any other account | Your own queues and messages (including decrypting your own mail locally), the settings you're allowed to manage yourself, and your own live traffic. |

Every operation is a signed [Trust Task](https://trusttasks.org), so the
mediator authorises each one on its own. The console also checks
`Capabilities` before sending, which saves a round trip and an error for
things the mediator would refuse anyway. Your mediator needs to serve the
`messaging/*` operations tasks (`affinidi-messaging-mediator` 0.28.20 or later).

At connect, the console reads the mediator's version from its public `readyz`
endpoint (`mediator_version()`). On an older mediator, `serves_operations()`
is false, and the operations calls (statistics, queues, messages, purges and
the monitor) return `ConsoleError::Refused` with code
`protocol.trust_task.unsupported` straight away. The message names the version
found and the version needed. An older mediator doesn't answer these tasks at
all, so without this check each call would wait out the reply timeout. Account,
access-list, audit and configuration calls work on older mediators too.

## Connecting

```rust
use affinidi_messaging_mediator_admin::{Identity, MediatorConsole, Mode};

let console = MediatorConsole::connect(Identity {
    alias: "operator".into(),
    did: "did:peer:2...".into(),
    secrets,                 // the DID's Ed25519 and key-agreement secrets
    mediator_did: None,      // None = use the mediator from the DID's DIDCommMessaging service
})
.await?;

match console.mode() {
    Mode::Admin { root } => println!("administering (rootAdmin: {root})"),
    Mode::SelfService => println!("managing {}", console.did_hash()),
}
```

To connect through an existing SDK instance, read
[How the console reads its connection](#how-the-console-reads-its-connection)
first, then choose: `MediatorConsole::connect_with_unclaimed(atm, identity, tx)`
when your application also reads live messages for the same DID on that
instance, or `MediatorConsole::connect_exclusive(atm, identity)` when the
instance is dedicated to the console. (`connect_with` is deprecated: it is
`connect_exclusive` under a name that hides that it takes those messages.)

`console.connection_state()` is the connection's state as the SDK publishes
it: `ConnState::Disconnected` on every drop, `Connected` on every reconnect.
Show it rather than inferring connectivity from failed calls:

```rust
if let Some(mut state) = console.connection_state() {
    while state.changed().await.is_ok() {
        println!("mediator connection: {:?}", *state.borrow_and_update());
    }
}
```

## Where identities come from

An `IdentitySource` lists the identities you can pick from and loads the one
you choose, including its secrets:

- **`ProfileFileSource`** reads TDK profile JSON files. That's the
  `{ alias, did, mediator, secrets }` file `mediator-setup` writes for its
  administrator.
- **`StaticIdentities`** holds identities already in memory, for embedding
  applications and tests.
- **Anything else:** implement the trait yourself. `pnm` implements it against
  a Verifiable Trust Agent, so a console can act as any DID the VTA manages
  without a secrets file. This crate deliberately doesn't depend on the VTA
  SDK; the dependency points the other way.

## Names for accounts

The mediator knows an account only by `sha256(did)`, as lowercase hex.
`AddressBook` maps that hash back to a DID and a nickname:

```rust
use affinidi_messaging_mediator_admin::{AddressBook, account_hash};

let mut book = AddressBook::load(&path)?;       // a JSON list of { name, did }
book.insert("did:peer:2.Vz6Mk…", "alice's phone"); // saved
book.know(&vta_did, "billing context");          // supplied by the app, not saved
assert_eq!(book.name_of(&account_hash("did:peer:2.Vz6Mk…")), Some("alice's phone"));
book.save(&path)?;
```

A name you save wins over one the application supplies, so an embedding
application can pre-fill names (every DID it manages, say) without writing
over yours.

## Destructive operations are two-step

```rust
use affinidi_messaging_mediator_admin::PurgeRequest;
use affinidi_messaging_mediator_admin::specs::queue::purge::v0_1::Queue;

let plan = console
    .purge_preview(PurgeRequest {
        target: Some(stuck_account),
        queue: Queue::Send,
        peer: Some(stalled_recipient),
        older_than_seconds: None,
    })
    .await?;
// Show plan.matched to the user and ask them to confirm it.
let done = console.purge(plan).await?;
// done.purged says how many actually went.
```

`purge` is pinned to the moment of the preview: it never removes a message
that arrived after the preview, or one that was not yet old enough then. It
can remove **fewer** than `plan.matched`, when messages were delivered or
deleted in between (and, because the pin is in whole seconds, it can leave out
what arrived in the second before the preview). Report `purged`, not
`matched`, as what was removed.

The mediator's `queue/purge` has no "as of" member yet, so the pin is an age
(`olderThanSeconds`) the console computes from the preview time.

## Live traffic

```rust
use affinidi_messaging_mediator_admin::{MonitorFilter, MonitorUpdate};

let filter: MonitorFilter = serde_json::from_value(serde_json::json!({
    "dids": [account_hash],
    "failuresOnly": true,
}))?;
let mut feed = console.monitor(filter).await?;
while let Some(update) = feed.next().await {
    match update {
        MonitorUpdate::Events { events, dropped } => { /* render */ }
        MonitorUpdate::Membership { events, dropped } => { /* only with monitor_with */ }
        MonitorUpdate::Gap { missing } => { /* batches lost in transit */ }
        MonitorUpdate::Heartbeat => { /* the tap is alive */ }
        MonitorUpdate::Disconnected => { /* the connection dropped, just now */ }
        MonitorUpdate::Reconnected => { /* …and is back */ }
        MonitorUpdate::Ended(reason) => break,
        _ => {}
    }
}
```

- **What the feed does for you:** it renews its lease, reports lost batches as
  `Gap`, a quiet-but-alive tap as `Heartbeat`, and each drop and recovery of
  the connection as `Disconnected` / `Reconnected` the moment it happens, and
  unsubscribes when dropped.
- **What an event contains:** metadata only. Stage, direction, channel,
  protocol (DIDComm or TSP), sender, recipient, size and refusal code.
  Never a message body.
- **Accountability:** every administrator subscription is recorded in the
  mediator's audit log.
- **Mux membership:** `console.monitor_with(filter, Some(membership))` also
  reports each member DID that attaches to or detaches from a principal's mux
  connection, as `MonitorUpdate::Membership`. That needs mediator 0.52.0
  (`messaging/monitor/subscribe` 0.2). A traffic-only feed on an older
  mediator falls back to subscribe 0.1 by itself.

## Stored mux grants

An administrator can list, revoke and void the stored grants of DID
multiplexing (mediator 0.52.0 and later):

```rust
use affinidi_messaging_mediator_admin::{GrantKey, GrantSelection, revoke_summary};

// A member's grants, a page at a time; `epoch` is the member's current one.
let page = console.mux_grants(None, Some(&member_did), None, Some(100)).await?;

// Revoke chosen grants, or all of a principal's or member's. It keeps going
// while grants still match, a bounded number of rounds.
let outcome = console
    .mux_revoke(&GrantSelection::grants(&member_did, vec![grant_id]))
    .await?;
println!("{}", revoke_summary(&outcome)); // "revoked 1 grant(s); none remain"

// Revoke several chosen grants, one request each, and hear about each:
// a refusal (a rootAdmin party's grant is protected) doesn't stop the rest,
// and a grant counts as revoked only when the mediator's answer lists it.
let bulk = console
    .mux_revoke_each(&[GrantKey::new(&member_did, grant_a), GrantKey::new(&other_did, grant_b)])
    .await?;
println!("{}", bulk.summary()); // "revoked 1 of 2 grant(s); 1 refused"
for line in bulk.failures() { println!("{line}"); }

// Void every grant a member gave: read its epoch, confirm, then name it.
let epoch = console.mux_epoch(&member_did).await?;
match console.mux_bump_epoch(&member_did, epoch).await {
    Ok(r) if r.epoch_advanced => { /* r.revoked_grants voided */ }
    Ok(_) => { /* someone voided that epoch already: nothing changed */ }
    Err(e) => eprintln!("{}", e.explain()), // epochMismatch, protectedAccount, …
}
```

`ConsoleError::explain` puts the stored-grant refusals in plain words, and
`ConsoleError::current_epoch` reads the epoch in force from an
`epochMismatch`.

## How the console reads its connection

The console runs a single reader over its live stream. That reader hands each
monitor batch to the feed it belongs to. Request/response calls on the same
connection are safe alongside it, because the SDK (0.26.19 and later) hands
each reply to the call waiting for it before any reader sees it.

**Every other message pushed live to the console's DID is taken too.** The SDK
has no receive filtered by message type, so the reader pops each live message
for its profile off the SDK's cache. The console never deletes one, so the
mediator keeps its stored copy, but on that SDK instance the message is gone
until a later pickup or reconnect redelivers it:

- With `connect` (a private SDK instance) this doesn't matter.
- With `connect_exclusive` (and the deprecated `connect_with`), nothing else
  on that instance may read live messages for the same DID.
- With `connect_with_unclaimed(atm, identity, tx)`, every message that is not
  a monitor batch goes to `tx`, with its unpack metadata, for your
  application to handle and delete as usual. If `tx` is full, the message is
  not passed on (a warning is logged); it stays stored at the mediator.

The reader logs each drop of the connection at `warn`, and each reconnect at
`info`.
