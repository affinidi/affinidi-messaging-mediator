# Releases

What operators deploy is a **release**, named by its `major.minor` version
(`0.42`, `0.43`, …). It is cut from `nightly`, stabilised and patched on its own
branch for as long as it is supported, and published from there as crates on
crates.io, a container image on GHCR and a tag. Patches (`0.42.1`, `0.42.2`, …)
only ever happen on the release branch.

This follows the branching model of the DID hosting service
(`affinidi-webvh-service`) and verifiable-trust-infrastructure. Every crate in
the workspace carries the release's version (lockstep).

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
| **EOL** — marked in the table below; the branch stays, read-only | — | — | — | — |

\* `:latest` moves only to the highest released GA/patch version: a patch to
N-1 after N is out publishes `:v<version>` but leaves `:latest` on N. A release
candidate **never** moves `:latest`.

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

| Release | Branch | First RC | GA | Latest | Status |
|---|---|---|---|---|---|
| ≤ 0.41 | — | — | — | `0.41.x` | released from affinidi-tdk-rs, per-crate versions |
| 0.42 | `release/0.42` | 2026-10-14 | TBD | `0.42.0-rc.0` | release candidate |
| 0.43 | — | TBD | TBD | — | in development on `main` |

## Support

The newest two GA releases (N and N-1) are supported. When a release goes GA,
the release before N-1 reaches end of life. "Supported" means fixes for
security problems and for defects that break a deployment are backported and
released. Features never are.

## What goes on a release branch

**Fix on `main` first, then backport.** Label the merged PR
`backport release/<major.minor>` (one label per target branch); `backport.yml`
opens the cherry-pick as a PR on that branch, as a draft carrying the conflict
if it does not apply cleanly. A conflict in `CHANGELOG.md` is expected — main's
`## Unreleased` is not on a GA'd branch — drop that hunk: a patch's changelog is
generated from the commit subjects it ships.

Only fix on the release branch directly when the code there no longer exists on
`main`: a maintainer adds the `release-direct` label to that PR, and its
description says why.

The `branch rules` check (`scripts/check-branch-rules.py`) holds all of this: a
PR into `release/**` is a bot backport, a prep PR or labelled `release-direct`;
only the release tooling changes the version or `RELEASE`, on any branch.

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
moves `main` to `0.43.0` and closes `main`'s `## Unreleased` changelog section
under `## 0.42.0`. Merge it, then update the schedule table above.

`--from <rev>` cuts from something other than `origin/nightly` — the first cut,
before `nightly` exists, is `--from origin/main`.

### Release candidate, GA, patch

Actions → **Prepare a release** → choose the release branch as the ref and
`rc`, `ga` or `patch`. It moves `RELEASE`, writes the changelog (GA: the
`## Unreleased` section becomes `## 0.42.0 (date)`; patch: a new section listing
the commits since the last tag), moves the whole workspace for a patch, and
opens a `chore(release): v…` PR from `release-prep/<major.minor>/<version>`.

**Merging it is the release.** On that push to the release branch:

- `release-tag.yml` tags `v<RELEASE>`, opens the GitHub Release (notes = that
  version's changelog section; an rc is a prerelease) and dispatches
  `publish-images.yaml` for the tag (`ghcr.io/affinidi/messaging-mediator`,
  multi-arch, signed build provenance; mirrored to ECR Public when
  `AWS_ROLE_ARN` is set).
- `publish.yml` publishes the crates for a GA or patch (below).

### Publish (crates.io)

Automatic, by `publish.yml`, on every push to `release/**`. It publishes only
when `RELEASE` is a GA/patch version equal to the workspace version, and only
the crates whose version is not on crates.io yet — so it is a no-op on every
other push, and re-running it after a failure resumes from the first missing
crate. Order is dependency order from `cargo metadata`:

```sh
python3 .github/scripts/publish-crates.py plan
```

It authenticates with **crates.io Trusted Publishing only** — no registry token
is stored anywhere. Each crate is verify-built first (`cargo package`), then a
fresh 30-minute token is minted for its upload alone, so a long release never
outlives its token; a failed upload is retried with a new token.

**A new crate** cannot be published this way: Trusted Publishing can only
publish to a crate that already exists and names this workflow as a trusted
publisher. `publish.yml` stops with an explanation. To add a crate:

1. An owner (`affinidibot`) publishes its first version by hand:
   `git switch --detach v<version> && cargo publish -p <crate>`.
2. On crates.io → the crate → Settings → Trusted Publishing, add GitHub
   repository `affinidi/affinidi-messaging-mediator`, workflow `publish.yml`,
   environment `crates-io`.
3. Re-run `publish.yml` on the release branch for anything that waited on it.

### End of life

Set the status in the table. Nothing is deleted: the branch, its tags, its
crates and its images stay.

## Repository settings this relies on

Settings, not files:

- **Ruleset on `release/**`:** require a PR, require the CI jobs, `branch
  rules` and `DCO sign-off`, block force pushes and deletion.
- **Ruleset on `main`:** require a PR, and require `branch rules` and `DCO
  sign-off`.
- **Ruleset on `nightly`:** block force pushes and deletion; only the
  workflow's identity may update it.
- **Environment `crates-io`** — `publish.yml` runs in it; restrict it to
  `release/**` branches. Each crate's Trusted Publisher on crates.io names this
  repository, `publish.yml` and this environment.
- **`RELEASE_TOKEN`** (required for backports and preps) — a fine-grained PAT
  or GitHub App token on this repository with contents and pull-requests
  write and actions read. The enterprise does not allow `GITHUB_TOKEN` to
  open pull requests, so without it `backport.yml` and `release-prep.yml`
  fail at the PR step. (A PR opened with `GITHUB_TOKEN` would trigger no CI
  anyway.) `nightly.yml`, `release-tag.yml` and `publish.yml` need no secret.
- **`CI_RUNNER_LARGE`** (variable, optional) — a larger runner label for the
  heavy CI jobs and `publish.yml`; `ubuntu-24.04` otherwise.
- **`AWS_ROLE_ARN`** (variable, optional) — enables the ECR Public mirror in
  `publish-images.yaml` (environment `release`).
