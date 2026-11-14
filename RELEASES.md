# Releases

What operators deploy is a **release**, named by its `major.minor` version
(`0.42`, `0.43`, …). It is cut from `nightly`, stabilised and patched on its own
branch for as long as it is supported, and published from there as crates on
crates.io, a container image on GHCR and a tag. Patches (`0.42.1`, `0.42.2`, …)
only ever happen on the release branch.

This follows the branching model of the DID hosting service
(`affinidi-webvh-service`) and verifiable-trust-infrastructure. Every crate in
the workspace carries the release's version (lockstep). Tagging, publishing,
`nightly` and the `branch rules` check run the `release-*` actions of
[affinidi/pipeline-rust](https://github.com/affinidi/pipeline-rust) (README,
"Release branches"). The cut, prep, backport and `release guards` stay local
while only they handle `changelog.d/`.

## Branches

```
feature/*  ──PR──▶  main  ──(nightly.yml: last fully green commit)──▶  nightly
                                                                          │
                          release/0.42 ◀── cut ───────────────────────────┤
                          release/0.43 ◀── cut ───────────────────────────┘
```

| Branch | What it is | Written by |
|---|---|---|
| `main` | Active development. Every PR lands here first. Carries the *next* release's version (`0.43.0` once `release/0.42` is cut) and publishes nothing. | PRs |
| `nightly` | The newest `main` commit on which **every** CI job passed. Fast-forward only. Releases are cut from here, never from `main`'s tip. | `nightly.yml`, daily at 02:00 UTC |
| `release/<major.minor>` | One release, from its cut to its end of life. Takes backported fixes only. | Backport and prep PRs |
| `feature/*`, `fix/*` | Short-lived work. A large effort lands on `main` behind a feature flag, not on a long-lived branch. | Anyone |

## Versions and tags

The workspace is versioned in lockstep: `[workspace.package] version` in the
root `Cargo.toml` is the version of every crate (`version.workspace = true`),
and every internal dependency requires exactly that version
(`{ version = "0.42.0", path = "…" }`). Nobody edits either by hand;
`scripts/release_lib.py` moves them together, and the `release guards` CI job
fails a tree where they disagree.

On a release branch the current version is its `RELEASE` file; the tag is `v`
+ that. `RELEASE` exists on release branches only.

| Step | `RELEASE` | Tag | Crates (crates.io) | Image (GHCR) |
|---|---|---|---|---|
| **Cut** `release/0.42` from `nightly` | `0.42.0-rc.0` | `v0.42.0-rc.0` (prerelease) | set to `0.42.0`, not published | `:v0.42.0-rc.0` |
| **Stabilise** — backport fixes; each prep is another candidate | `0.42.0-rc.1`, … | `v0.42.0-rc.1`, … (prerelease) | — | `:v0.42.0-rc.N` |
| **GA** | `0.42.0` | `v0.42.0` | publish `0.42.0` | `:v0.42.0`, `:latest` |
| **Patch** as fixes are backported | `0.42.1`, `0.42.2`, … | `v0.42.1`, … | publish `0.42.N` | `:v0.42.N`, `:latest`* |
| **EOL** — 90 days after GA, once a newer GA exists (see [Support](#support)); the branch stays, read-only | — | — | — | — |

\* `:latest` moves only to the highest released GA/patch version: a patch to
an older supported release publishes `:v<version>` but leaves `:latest` on
the newest. A release candidate **never** moves `:latest`.

`main` never publishes and never edits the version: the cut moves it to the
next minor. A patch never changes a public API in a breaking way — the
`semver (patch-compatible)` CI job runs `cargo semver-checks --release-type
patch` on every PR into a release branch — and a fix that needs a break stays
on `main` for the next release.

Up to `0.41.x` the crates were released from the
[affinidi-tdk-rs](https://github.com/affinidi/affinidi-tdk-rs) monorepo with
per-crate versions (`affinidi-messaging-mediator-v…` tags there). `0.42.0` is the
first lockstep release from this repository.

## Schedule

| Release | Branch | First RC | GA | Latest | Supported until | Status |
|---|---|---|---|---|---|---|
| ≤ 0.41 | — | — | — | `0.41.x` | — | released from affinidi-tdk-rs, per-crate versions; not patched here |
| 0.42 | `release/0.42` | 2026-10-14 | 2026-10-14 | `0.42.0` | 2027-01-12 | supported |
| 0.43 | `release/0.43` | 2026-10-18 | 2026-10-18 | `0.43.0` | 2027-01-16 | supported |
| 0.44 | `release/0.44` | — | 2026-10-21 | `0.44.0` | 2027-01-19 | supported |
| 0.45 | `release/0.45` | — | 2026-10-24 | `0.45.0` | 2027-01-22 | supported |
| 0.46 | `release/0.46` | 2026-10-26 | 2026-10-26 | `0.46.0` | 2027-01-24 | supported |
| 0.47 | `release/0.47` | 2026-10-27 | 2026-10-27 | `0.47.0` | 2027-01-25 | supported |
| 0.48 | `release/0.48` | — | 2026-10-28 | `0.48.0` | 2027-01-26 | supported |
| 0.49 | `release/0.49` | 2026-11-02 | 2026-11-02 | `0.49.0` | 2027-01-31 | supported |
| 0.50 | `release/0.50` | 2026-11-04 | 2026-11-04 | `0.50.0` | 2027-02-02 | supported |
| 0.51 | `release/0.51` | 2026-11-09 | 2026-11-09 | `0.51.0` | 2027-02-07 | supported |
| 0.52 | — | TBD | TBD | — | — | in development on `main` |

## Support

Support is by time, not by count: **a release is supported for 90 days
after its GA** (the "Supported until" column above), and the newest GA
release is always supported, however old it is. Releases are cut often, so
several lines are usually supported at once.

"Supported" means fixes for security problems and for defects that break a
deployment are backported to the release branch and released as a patch.
Features never are. A fix that would need a breaking change cannot be
backported (see [What goes on a release branch](#what-goes-on-a-release-branch));
it ships in the next release, and the advisory or changelog says so.

When a release passes its "Supported until" date and a newer GA exists, it
reaches end of life: set its Status to `end of life` in the table. Nothing
is deleted (see [End of life](#end-of-life)).

**Which line to track.** Under Cargo's rules for `0.x` versions every minor
release is a breaking release, so a dependency on `"0.51"` never picks up
`0.52`. Track the newest release, and move to each new minor within the 90
days its predecessor stays supported. Delivery, ack and auth behaviour can
change between minors even where no signature does: read the release's
`CHANGELOG.md` section (its **Breaking** entries first) before you move.

## What goes on a release branch

**Fix on `main` first, then backport.** Label the merged PR
`backport release/<major.minor>` (one label per target branch); `backport.yml`
opens the cherry-pick as a PR on that branch, as a draft carrying the conflict
if it does not apply cleanly. A backport carries no changelog notes: a patch's
changelog is generated from the commit subjects it ships, so `backport.yml`
removes the `changelog.d/` fragments the cherry-pick adds (and reverts any
`CHANGELOG.md` change or conflict) in a follow-up commit on the backport PR.

Only fix on the release branch directly when the code there no longer exists on
`main`: a maintainer adds the `release-direct` label to that PR, and its
description says why.

The `branch rules` check holds all of this: a PR into `release/**` is a
backport or prep PR, or labelled `release-direct`; only the release tooling
changes the version, `RELEASE` or `CHANGELOG.md`, on any branch. A cut, prep or
backport PR counts as one only when the release-bot app
(`affinidi-semantic-release[bot]`) opened it from a branch of this repository:
a branch name alone proves nothing. A cut or prep PR also counts when a person
with the admin or maintain role opened it, since cuts are still run by hand.
The check runs pipeline-rust's rules, then `scripts/check-branch-rules.py` for
the `CHANGELOG.md` rule.

## Changelog

A PR records a user-facing change as a new file,
`changelog.d/<short-kebab-name>.md`, holding one or more entries in the
changelog's own format (`### <Kind> — <title>`, then bullets or paragraphs);
[changelog.d/README.md](changelog.d/README.md) has the details. It never edits
`CHANGELOG.md`: on `main` that file's `## Unreleased` holds only a line
pointing at `changelog.d/`, which the `release guards` check enforces, and the
`branch rules` check fails a PR that changes `CHANGELOG.md` unless it comes from
a release-tooling branch in this repository. Every PR adds its own file, so
open PRs never conflict over the changelog.

`scripts/changelog_fragments.py` turns the fragments into a release's section
and deletes them. Entries are ordered by kind (Breaking, Changed, Fixed, Added,
Removed, Deprecated, Security, then any other), and within a kind by when the
fragment was added on the branch, oldest first. The section is laid out as
`## Unreleased` always was, so `release-tag.yml` reads it unchanged.

| Step | What happens to the fragments |
|---|---|
| **Cut** | main's `release-cut/<name>` PR assembles the fragments the cut's source commit has into `## <name>.0 (release/<name>)`; ones added after it stay for the next release. The release branch keeps its copies. |
| **rc** | Untouched. |
| **GA** | The prep assembles the release branch's fragments into `## <name>.0 (date)`. |
| **Patch** | Notes are the commit subjects since the last tag. A fragment that reached the branch (a `release-direct` PR) is assembled above them. |
| **Backport** | `backport.yml` drops the fragments the cherry-pick adds. |

```sh
python3 scripts/changelog_fragments.py --dry-run   # the next section, as it would be written
python3 scripts/changelog_fragments.py --check     # validate the fragments
```

## Procedures

### Cut

```sh
python3 scripts/cut-release.py 0.42 --dry-run   # builds both commits, pushes nothing
python3 scripts/cut-release.py 0.42
```

From a clean checkout with push access, Python ≥ 3.11, cargo, and `gh`
authenticated. It pushes `release/0.42` (workspace at `0.42.0`, `RELEASE` =
`0.42.0-rc.0`, which `release-tag.yml` tags and builds an image for), creates
the `backport release/0.42` label, and opens the `release-cut/0.42` PR that
moves `main` to `0.43.0` and assembles the `changelog.d/` fragments that shipped
into `## 0.42.0 (release/0.42)` (the release branch's copy is assembled, with
its date, at GA). Merge it, then update the schedule table above.

`--from <rev>` cuts from something other than `origin/nightly` — the first cut,
before `nightly` exists, is `--from origin/main`.

### Release candidate, GA, patch

Actions → **Prepare a release** → choose the release branch as the ref and
`rc`, `ga` or `patch`. It moves `RELEASE`, writes the changelog (GA: the
`changelog.d/` fragments become `## 0.42.0 (date)`, replacing `## Unreleased`;
patch: a new section listing the commits since the last tag), moves the whole
workspace for a patch, and
opens a `chore(release): v…` PR from `release-prep/<major.minor>/<version>`.
After a GA, fill in its GA date and its "Supported until" date (GA + 90
days) in the schedule table.

**Merging it is the release.** On that push to the release branch:

- `release-tag.yml` tags `v<RELEASE>`, opens the GitHub Release (notes = that
  version's changelog section; an rc is a prerelease). The tag, created by
  the release-bot app, triggers `publish-images.yaml` (`ghcr.io/affinidi/messaging-mediator`,
  multi-arch, signed build provenance; mirrored to ECR Public when
  `AWS_ROLE_ARN` is set).
- `publish.yml` publishes the crates for a GA or patch (below).

### Publish (crates.io)

Automatic, by `publish.yml`, on every push to `release/**`. It publishes only
when `RELEASE` is a GA/patch version equal to the workspace version, and only
the crates whose version is not on crates.io yet — so it is a no-op on every
other push, and re-running it after a failure resumes from the first missing
crate. Order is dependency order from `cargo metadata`; the run's log prints
the plan.

It authenticates with **crates.io Trusted Publishing only** — no registry token
is stored anywhere. Each crate is verify-built first (`cargo package`), then a
fresh 30-minute token is minted for its upload alone and revoked after it, so
a long release never outlives its token; a failed upload is retried with a new
token.

**A new crate** cannot be published this way: Trusted Publishing can only
publish to a crate that already exists and names this workflow as a trusted
publisher. `publish.yml` stops with an explanation. To add a crate:

1. An owner (`affinidibot`) publishes its first version by hand:
   `git switch --detach v<version> && cargo publish -p <crate>`.
2. On crates.io → the crate → Settings → Trusted Publishing, add GitHub
   repository `affinidi/affinidi-messaging-mediator`, workflow `publish.yml`,
   environment `release`.
3. Re-run `publish.yml` on the release branch for anything that waited on it.

### End of life

A release reaches end of life 90 days after its GA, provided a newer GA
exists (see [Support](#support)). Set its status in the table. Nothing is
deleted: the branch, its tags, its crates and its images stay.

## Repository settings this relies on

Settings, not files:

- **Ruleset `release branches`** (`release/**`): require a PR; require
  `branch rules`, `DCO sign-off`, `cargo test (workspace)`, `cargo clippy`,
  `cargo fmt` and `release guards`; block force pushes and deletion; only
  admins and the `affinidi-semantic-release` app create a release branch
  (`cut-release.py` is run by an admin) or push to one directly.
- **Ruleset `main required checks`** (default branch): require `branch
  rules`, `DCO sign-off`, `cargo test (workspace)`, `cargo clippy` and `cargo
  fmt`. `Default_branch_managed` adds the PR, review and signature rules.
- **Ruleset `nightly`:** block force pushes and deletion. `nightly.yml` only
  fast-forwards it, as the release-bot app, so a ruleset can also limit who
  creates or moves it to that app, maintainers and admins.
- **`branch rules`** honours the release-tooling branch names (`backport-…`,
  `release-prep/…`, `release-cut/…`) only on branches in this repository, not
  on a fork's. That covers who may edit `CHANGELOG.md` too.
- **Ruleset `tags_managed`** (all tags): blocks creation, update and
  deletion; admins and the `affinidi-semantic-release` app bypass it. That
  app is the identity `release-tag.yml` tags with — `GITHUB_TOKEN` (the
  GitHub Actions app) is not on the bypass list.
- **Environment `release`** — `publish.yml` (crates.io), the ECR mirror in
  `publish-images.yaml`, and the release-bot steps of `release-tag.yml`,
  `release-prep.yml`, `backport.yml` and `nightly.yml` run in it. Restrict it to `main`
  (backports run there), `release/*` branches and `v*` tags. Each crate's
  Trusted Publisher on crates.io names this repository, `publish.yml` and
  this environment.
- **`RELEASE_BOT_APP_ID`, `RELEASE_BOT_PRIVATE_KEY`** (environment `release`
  secrets) — the `affinidi-semantic-release` app, installed org-wide with
  contents write, as in affinidi-trust-registry-rs. Its token creates the
  tags and GitHub Releases, moves `nightly`, and opens the prep and backport
  PRs: the enterprise does not allow `GITHUB_TOKEN` to open pull requests, and
  a PR it opened would trigger no CI anyway. `publish.yml` needs no secret.
- **`CI_RUNNER_LARGE`** (variable, optional) — a larger runner label for the
  heavy CI jobs and `publish.yml`; `ubuntu-24.04` otherwise.
- **`AWS_ROLE_ARN`** (variable, optional) — enables the ECR Public mirror in
  `publish-images.yaml` (environment `release`).
