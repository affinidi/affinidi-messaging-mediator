# mediator-console

`mediator-console` is a terminal console for an Affinidi messaging mediator.
Connect as any DID with an account on the mediator:

- **as an administrator**, you run the whole mediator: its health, every
  account's queues, anyone's messages and settings, the audit log, and live
  traffic;
- **as any other account**, you manage your own queues, your own messages
  (including reading your own mail), and your own live traffic.

The same screens are also available as ratatui components, which you can embed
in another application ([Embedding](#embedding)).

```
 mediator-console  ADMIN  ● connected  b48a53fa…1f29 → did:peer:2.Vz6Mkkn…  updated 1s ago
 1 Dashboard │ 2 Queues │ 3 Account │ 4 Audit │ 5 Accounts │ 6 Config │ 7 Mux │ 8 Grants
┌ Account 1f22bbf6…b9a1 ─────────────────────┐┌ Traffic — all traffic ● live ───────┐
│receive: 0 / 200    oldest –                ││22:46:24 ▶ received  didcomm   rest …│
│   send: 3 / 2000   oldest 4s               ││22:46:24 · stored    didcomm   …     │
│▏███████▊                                   ││22:46:25 ◀ delivered didcomm   websoc│
└────────────────────────────────────────────┘│22:46:26 ▶ refused   tsp       rest …│
┌ Send queue by recipient — who hasn't coll… ┐│          authorization.send         │
│recipient       waiting bytes     oldest    ││                                     │
│36c23eba…4584   3       20.5K     4s        ││                                     │
```

## Before you start

- **A mediator that serves the operations Trust Tasks.** You need
  `affinidi-messaging-mediator` **0.28.20 or later**, which serves the
  `messaging/stats`, `queue`, `message` and `monitor` tasks. On an older
  mediator the console still connects, and the header shows its version:
  - the Audit screen (and account settings) work;
  - the Dashboard, Queues and Account screens and the monitor explain what
    they need instead of loading;
  - an administrator starts on Audit.
- **An identity:** a DID and its secrets, in a TDK profile JSON file:
  ```json
  { "alias": "operator", "did": "did:…", "mediator": "did:…", "secrets": [ … ] }
  ```
  - `mediator-setup` writes one for the mediator's administrator, as
    `admin-monitor.json` next to `mediator.toml`.
  - Any other account's profile works too.
  - If you leave out `mediator`, the console uses the mediator named in the
    DID's `DIDCommMessaging` service.
- **Admin rights, for admin mode.** The console asks the mediator what the
  account is, and the mediator's answer decides the mode. To administer, the
  account must have the `admin` or `rootAdmin` role (`mediator-setup`
  configures the admin DID; grant the role to others with the
  `messaging/account/update` Trust Task, or affinidi-tdk-rs's
  `mediator_administration` tool).
- **Signing, recommended.** The mediator verifies every Trust Task, including
  its proof, according to `security.trust_task_verification`. The SDK the
  console uses signs every request with the profile's Ed25519 key, so no extra
  setup is needed.

## Running it

```bash
cargo run --release -p affinidi-messaging-mediator-tui -- \
  --profile path/to/conf/admin-monitor.json
```

| Option | Meaning |
|---|---|
| `-p, --profile <file>` | A profile to connect with. Repeat it to offer several. |
| `--as <alias or DID>` | Which of several profiles to use. The default is the first. |
| `--mediator <DID>` | Override the mediator from the profile and the DID document. |
| `--address-book <file>` | Where to keep account nicknames ([Names for accounts](#names-for-accounts)). |
| `--timeout <seconds>` | How long to wait for each answer from the mediator (default 30). |
| `--connect-timeout <seconds>` | How long to wait for the connection: resolving, authenticating and reading the account (default 30). |

Connection errors are printed before the console takes over the screen, so a
wrong profile, an unreachable mediator, or an account the mediator doesn't know
is reported plainly.

## Scripting

Give a command and `mediator-console` runs that one operation, prints the
answer and exits, without opening the console. `--json` prints the mediator's
answer as the Trust Task's own JSON, one document per line, for runbooks and
monitoring; errors go to stderr.

```bash
mediator-console -p admin-monitor.json stats --json
mediator-console -p admin-monitor.json queues --sort saturation --limit 20
mediator-console -p admin-monitor.json purge <account> --send --dry-run
```

| Command | Answers |
|---|---|
| `stats` | Mediator statistics *(admin)*. |
| `queues [--send] [--sort count\|bytes\|oldest\|saturation]` | The queue ranking *(admin)*. |
| `accounts` | Every account *(admin)*. |
| `account [<account>]` | One account's settings and queue depths; your own by default. |
| `messages [<account>] [--send]` | A queue's messages, metadata only. |
| `audit` | The audit log, newest first *(admin)*. |
| `config` | The mediator's configuration *(admin)*. |
| `access-list [<account>]` | An account's access list. |
| `grants --principal <DID> \| --member <DID>` | Stored mux grants *(admin)*. |
| `purge [<account>] [--send] [--peer <account>] [--older-than <s>] --dry-run \| --yes` | `--dry-run` counts what would go; `--yes` counts and then removes it, pinned to the count. One of the two is required. |

`<account>` is a DID or its account hash. Lists take `--limit` and
`--cursor`; a page with more after it ends with a `next_cursor` line (in
JSON, the answer's `nextCursor`).

The exit code says what happened, so a script can tell a retry from a fault:

| Code | Meaning |
|---|---|
| `0` | Done. |
| `1` | Failed for a reason trying again won't fix: a bad profile, a malformed request, an unexpected answer. |
| `2` | Invalid arguments; nothing was sent. |
| `3` | Refused: the mediator (or the console, knowing its rules) said no. |
| `4` | Unreachable: the connection failed, dropped or timed out. Trying again may work; a change that timed out may have been made, so read before you retry. |

## Screens

| Key | Screen | Shows |
|---|---|---|
| `1` | **Dashboard** *(admin)* | Version and uptime, websocket connections, message and session totals, forwarding queue and circuit breaker, and **queue pressure**: the fullest receive and send queue, as gradient bars. Below that, the busiest queues. |
| `2` | **Queues** *(admin)* | Every account with a non-empty queue, ranked by depth, bytes, oldest message or saturation (`s` cycles the ranking, `x` switches between receive and send). Each queue has a **quota bar**. The ranking comes from the mediator's once-a-minute survey, and the title shows when that survey ran; the console asks again only once a newer survey is due. 200 rows a page, `]` for more. |
| `3` | **Account** | One account's two queues with quota bars, its **send queue by recipient** (who hasn't collected yet), and its messages, 200 at a time (the title says "200 of 5000"; `]` or the last row loads more). For a standard account, this is the whole console. |
| `4` | **Audit** *(admin)* | The mediator's audit log of privileged changes, newest first: when, actor, action, target, **outcome** (success, denied, …) and the detail as `key=value` pairs. Monitor subscriptions and cross-account reads are recorded here too. Scroll with `↑↓` / `PgUp` `PgDn`; reaching the last row (or `]`) loads the next page. |
| `5` | **Accounts** *(admin)* | Every account on the mediator: name, hash, role (coloured), receive and send depth, bytes queued, access-list size. The mediator and administrators come first, then accounts you've named, then the rest. `⏎` opens one. Loaded a page (500) at a time as you scroll, and reloaded every five minutes or on `r`, not on every refresh. Works on older mediators too. |
| `6` | **Config** *(admin)* | The mediator's configuration: key, value, source (`override` when a patch set it) and whether a change applies live or at restart. A **rootAdmin** can change a `limits.*` value (`⏎`) or reset an override (`x`); a patch can tighten a limit, not loosen it past the configuration. |
| `7` | **Mux** *(admin)* | Live mux connections and the member DIDs each carries. `g` lists the selected connection's stored grants. |
| `8` | **Grants** *(admin)* | Stored mux grants of a principal or member DID (`/` to look one up): member, principal, state, scope, expiry, the epoch each was signed under, and the member's current epoch. `d` revokes the selected grant — or, with grants marked (`space`, `a`), every marked grant, each on its own — `D` every grant listed, `E` advances the member's epoch (voiding every grant it gave). Each asks for confirmation first; a bulk revocation then lists every grant it did not revoke, and why. Needs mediator 0.52.0. |

**Quota bars** shade smoothly from green through amber to red along the bar,
so how full a queue is shows as colour at its leading edge. They use 24-bit
colour when `COLORTERM` says the terminal supports it. Otherwise they fall back
to 256 colours, then to three plain colours. `NO_COLOR` switches colour off
everywhere: badges and highlights are shown reversed instead.

### Keys

`?` shows every key that works on the screen you're on; the footer shows the
common ones, and ends in `… ? for more` when they don't all fit.

| Key | Where | Does |
|---|---|---|
| `↑` `↓` / `j` `k` | tables | select a row |
| `PgUp` `PgDn` | tables (monitor closed) | a page of rows |
| `]` | Dashboard, Queues, Account, Audit, Accounts, Grants | load the next page (reaching the last row does too) |
| `⏎` | Dashboard, Queues, Accounts | open the selected account |
| `⏎` / `x` | Config (rootAdmin) | change the selected limit / reset its override. Both show the change (`from → to`) and wait for `y` |
| `x` | Queues, Account | receive ↔ send queue |
| `s` | Dashboard, Queues | change the ranking |
| `e` | Account | **edit** the account's role, ACL flags, access-list mode and queue limits. `s` shows what changes (`role: admin → rootAdmin`) and `y` applies it; editing your own account to a lower role or `blocked` warns that it can lock you out |
| `i` | Account | **inspect** the selected message: its metadata and whole raw envelope, decrypted locally when you hold the recipient's key (your own mail). Scroll with `↑↓` `PgUp` `PgDn`; `y` copies it, `w` writes it to a file in the current directory |
| `d` | Account | **delete** the selected message. The confirmation names the account, the queue, the message id, and who it is from and to |
| `p` / `P` | Account | **purge** the queue, or only messages exchanged with the selected message's counterparty (see below) |
| `o` | Account | back to your own account |
| `g` | Mux | the selected connection's **stored grants** |
| `/` | Grants | **find** grants by principal DID, member DID, or both |
| `p` / `g` | Grants | list the selected grant's principal's / member's grants |
| `space` | Grants | **mark** the selected grant (or unmark it) and move down |
| `a` / `c` | Grants | mark every grant listed / clear the marks |
| `d` / `D` | Grants | **revoke** the marked grants (or the selected one, with none marked) / every grant listed (asks for confirmation). Marked grants are revoked one at a time: a refusal — a rootAdmin party's grant is protected — leaves the rest to go ahead, and every grant not revoked is listed with why and stays marked |
| `E` | Grants | **advance the member's epoch**: shows its current epoch, and names only that one, so nothing changes if it moved on meanwhile |
| `m` | anywhere | show or hide the **traffic monitor**; an administrator watching everything also sees mux members attach and detach |
| `f` | anywhere | monitor failures only |
| `t` | monitor open | switch the monitor between live lines and **per-account totals** |
| `PgUp` `PgDn` / `⇧↑` `⇧↓` | monitor open | **scroll back** through traffic that has left the pane; `Home` goes to the oldest kept, `End` follows new traffic again |
| `l` | anywhere | the **log**: errors and warnings the console captured (see below) |
| `Ctrl-L` | anywhere | repaint the whole screen |
| `n` | anywhere | **name** an account: the selected one, or any account by pasting its DID |
| `y` | anywhere | **copy** the selected row's full account hash, DID or message id to the clipboard (OSC 52: the terminal must allow it) |
| `?` | anywhere | every key |
| `b` | anywhere | the **address book**: rename (`n`), add (`a`), remove (`x`) |
| `r` | anywhere | reload now, from the first page (screens also refresh every 5 s; a list you've paged through waits for `r`) |
| `Tab` | anywhere | next screen |
| `q` / `Ctrl-C` | anywhere | quit |
| `Esc` | popups | close it. On its own `Esc` does nothing: it never quits |

## Names for accounts

The mediator knows an account only by a hash: SHA-256 of the DID, as
lowercase hex. That is what `36c23eba…4584` in every table is. The **address
book** puts a name on it: give it a DID and a nickname, and the console shows
the nickname wherever that account appears, in tables, the audit log and the
traffic monitor.

- **`n`** names the account in view: the selected queue row, the selected
  message's counterparty, or the account on screen. Paste its DID, and the
  console checks the DID really hashes to that account. With no account
  selected, paste any DID (or a bare 64-hex hash) to name it.
- **`b`** lists the book, where you can rename or remove entries.
- **Filled in for you:** your own account shows as `you`, and the mediator as
  `mediator`. Applications that embed the console can supply more names; for
  example, `pnm` names every DID the VTA manages after its label.
- **Where it's kept:** a JSON list of `{ "name", "did" }` at
  `~/.config/mediator-console/address-book.json` (or under
  `$XDG_CONFIG_HOME`), shared by every console front end. You can edit it by
  hand. `--address-book <file>` points the console at another one.

## Deleting and purging

A purge is always counted first. The console shows whose queue, which queue,
and how many messages (and bytes) would go, and waits for `y`. The purge is
then pinned to the moment of that count: a message that arrives after it is
never removed. Fewer may go than were counted, when some are delivered in the
meantime, and the console says how many did. (The pin keeps a safety
margin for the request's transit, the request timeout and at least 30 s, and is in whole seconds, so it also leaves
out what arrived in that window before the count.) Purged messages are gone;
they aren't returned to their senders. `mediator-console purge --yes` works
the same way.

A delete names the account, queue, message id, sender and recipient before it
asks. Background answers are tied to what they were asked for: a slow answer
for one account never lands on another's screen, and a purge count for an
account you have left is dropped rather than shown.

What the mediator allows:

- **Your own queues:** always, provided your account is served locally.
- **Another account's queues:** admins only.
- **An admin's, rootAdmin's or the mediator's own queue:** rootAdmin only.
- **Another account's message body** (inspecting it): rootAdmin only. An admin
  sees the metadata.
- **Audit:** every cross-account delete, purge and read is written to the audit
  log.

## The traffic monitor

`m` splits the screen, with live traffic in a pane beside whatever you're
looking at. Each line is one step in a message's life:

- received, stored, delivered, forwarded, refused, deleted or purged
- over REST, websocket or a peer mediator
- as DIDComm or TSP
- with sender, recipient and size
- for a refusal, the problem code, in red

Opened from an account, the monitor watches that account; otherwise it watches
everything (admin) or your own traffic (everyone else).

- **Metadata only.** Message bodies never appear.
- **Honest about its own state.** The pane's title shows whether the feed is
  live, silent or stopped, or the connection down (the moment it drops, not
  after a silence), how many events the mediator dropped (because of the
  rate limit, or because the console was briefly offline), and how many batches
  were lost in transit.
- **Totals.** The title shows how many messages the monitor has seen and
  the rate, over the whole run and the last ten seconds. `t` switches to a
  table of the busiest accounts: messages sent, addressed to them, delivered
  to them, refused, and bytes, all since the monitor started.
- **Your own polling is hidden,** so the pane shows traffic rather than the
  console talking to the mediator.
- **Comes back on its own.** If the feed is interrupted (a lease renewal
  failed with the connection down, or nothing, not even the 30 s heartbeat,
  for 90 s), the pane resubscribes, backing off up to 30 s between attempts.
  The title shows `↻ resubscribing`. It stops only when the mediator refuses
  the subscription, and then says why.
- **Scroll back.** The pane keeps the last 2,000 lines. `PgUp` stops following
  and pages back; new traffic keeps arriving below without moving what you're
  reading, and the bottom edge says how much is newer. `End` follows again.

## Connection state

The header always says what the SDK reports of the console's connection to
the mediator: `● connected`, `◌ connecting`, or `✗ disconnected 12s —
reconnecting` while it is down (`? connection unknown` when there is no
websocket to report on). Each drop and each recovery is also written into the
monitor pane as a line, and the drop is logged at `warn`, so it shows in the
log (`l`) too. When the connection comes back the screen reloads.

## Log output

The console keeps log output off the screen. A full-screen terminal program
redraws only the cells it changed, so anything else printed to the terminal
stays on top of it. While the mediator is unreachable the SDK logs an error
every few seconds, which is enough to bury the screen.

Instead, the console keeps those lines. The header shows how many errors and
warnings you haven't read; `l` opens the log, newest last, wrapped to the
width, with a line printed several times in a row shown once with its count.
`mediator-console` logs at `warn` unless `RUST_LOG` says otherwise. When you
quit, logging goes back to stderr.

## Embedding

The console is a library as well as a binary:

```rust
use affinidi_messaging_mediator_admin::{Identity, MediatorConsole};
use affinidi_messaging_mediator_tui::{App, Control};

let console = MediatorConsole::connect(identity).await?;
let mut app = App::new(console);

// Hand over a terminal and let the console run its own loop…
app.run(&mut terminal).await?;

// …or keep your own loop and feed the console:
//   app.handle_key(key)                  on a key press (Control::Quit when done)
//   app.apply(app.next_update().await?)  when background work finishes
//   app.render(frame, area)              to draw into any area of your layout
```

- `App::with_logs(capture)` keeps your log output off the console's screen.
  Give the same `LogCapture` to your `tracing` subscriber as its writer. It
  prints to stderr as usual, except while a console holds it:

  ```rust
  let logs = LogCapture::new();
  tracing_subscriber::fmt().with_writer(logs.make_writer()).init();
  // …
  App::new(console).with_logs(logs.clone()).run(&mut terminal).await?;
  ```

  A host with its own loop redraws when `app.log_changed()` resolves.
- `App::open_account(did_hash)` jumps straight to one account; `App::reload()`
  reloads the screen from its first page, as `r` does.
- `App::run` redraws at once for keys and answers, and batches monitor
  traffic (`Update::Monitor`) into at most ten frames a second. A host with
  its own loop should do the same under heavy traffic.
- `Update::Connection` carries the connection state into the header and the
  monitor; `App::new` subscribes to it for you.
- Every `Update` carries the mediator's answer as the typed Trust Task
  struct the admin crate returned (`specs::…::Response`), and the screens
  draw from those types: a field the mediator renames or retypes fails to
  compile here rather than showing as `–`.
- The gradient `QuotaBar` widget (and `quota_line` for table cells) works on
  its own.
- The engine underneath, including identities, purge plans and monitor feeds,
  is [`affinidi-messaging-mediator-admin`](../affinidi-messaging-mediator-admin/).

## From `pnm`

`pnm messaging console` will open this console as any DID a Verifiable Trust
Agent manages, fetching its keys from the VTA for the session, with no profile
file to keep. It's being built in the `verifiable-trust-infrastructure`
repository and implements `IdentitySource` from the engine crate.

## Replaces `mediator-monitor`

`mediator-monitor` polled the mediator's REST `/admin/status` route (since
removed) for a read-only dashboard. The
console's Dashboard shows the same figures and much more, over signed Trust
Tasks, and `mediator-monitor` has been removed.
