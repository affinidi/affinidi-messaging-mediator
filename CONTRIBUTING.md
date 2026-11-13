# Contributing

When contributing to this repository, please first discuss the change you wish to
make by opening a [GitHub issue](https://github.com/affinidi/affinidi-messaging-mediator/issues/new).

## Development requirements

- **Rust 1.95.0** — pinned in `rust-toolchain.toml` (rustup picks it up
  automatically) and equal to the workspace `rust-version`. The `release
  guards` CI job fails if a workflow's `toolchain:` pin drifts from it.
- **Edition 2024.**
- Native libraries on Linux: `libdbus-1-dev libssl-dev libchafa-dev pkg-config`
  (keyring, TLS, and the console's image rendering).
- **Redis** (optional) for the Redis-backed tests: `docker run -p 6379:6379 redis:7`
  and `REDIS_URL=redis://localhost:6379`.
- Python ≥ 3.11 for the scripts in `scripts/`.

Optional but useful: `cargo-deny` (config in `deny.toml`), `cargo-semver-checks`.

## Pre-push workflow

CI (`.github/workflows/ci.yml`) runs the equivalent of these; running them
locally before pushing avoids round-trips:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
python3 scripts/check-release-guards.py
bash scripts/check-test-clock-isolation.sh
```

CI builds with `RUSTFLAGS="-D warnings --cfg tracing_unstable"`. It also runs
the mediator across its storage backends (redis / fjall / memory), protocols
(`tsp`, `didcomm-v1`) and secrets backends, and a `cargo publish --workspace
--dry-run`. If you touch a feature-gated path, reproduce the matching job, e.g.:

```bash
cargo test -p affinidi-messaging-test-mediator --features tsp --tests
cargo check -p affinidi-messaging-mediator --no-default-features --features didcomm,fjall-backend
```

PRs that touch `docker/` should add the `ci:image` label: it builds the
production image and boot-probes it.

## Branches and releases

All work lands on `main` by PR. Releases are `major.minor` (`0.42`) branches
cut from `nightly` — the last fully green `main` — and patched only there.
Three rules follow (details in [RELEASES.md](RELEASES.md)):

- **Never edit a version.** The workspace is versioned in lockstep and only the
  release tooling moves it; the `branch rules` check fails a PR that changes it.
- **Record user-facing changes as a `changelog.d/` fragment**, never in
  `CHANGELOG.md`: add a new file `changelog.d/<short-kebab-name>.md` holding a
  `### <Kind> — <title>` entry (format in
  [changelog.d/README.md](changelog.d/README.md)). The release tooling assembles
  the fragments into `CHANGELOG.md`, and the `branch rules` check fails any
  other PR that edits it.
- **Need a fix in a supported release?** Merge it to `main`, then label the PR
  `backport release/<major.minor>`; a bot opens the cherry-pick on that branch.

## Commit hygiene

### Conventional-commit subjects

Commit subjects (and PR titles, which become the squash-merge subject) follow
[Conventional Commits](https://www.conventionalcommits.org):
`<type>(<optional scope>)<optional !>: <subject>`, with type one of `build`,
`ci`, `docs`, `feat`, `fix`, `perf`, `refactor`, `style`, `test`, `chore`,
`revert`. A patch release's changelog is generated from these subjects, so
write them for the operator who reads it.

### DCO sign-off

Every commit must carry a `Signed-off-by: <name> <email>` trailer
([Developer Certificate of Origin](https://developercertificate.org)). The
`DCO sign-off` check fails a PR with an unsigned commit. Add it with `-s`:

```bash
git commit -s -m "fix: short subject"
# or, for commits already made:
git rebase --signoff origin/main
```

## Code-quality expectations

1. **Pipeline checks must pass green.** Don't open a PR with red CI
   unless the failure is explicit context for the discussion.
2. **No mocks/stubs in integration tests.** Integration tests use the real
   mediator through `affinidi-messaging-test-mediator`, real stores (memory,
   fjall via `tempfile`, Redis via `REDIS_URL`). Unit tests may stub for
   isolation; integration tests prove the whole thing fits.
3. **Tests for new code paths**, including the feature-gated ones: a test
   behind `#[cfg(feature = "tsp")]` only runs in the job that enables it.
4. **Test-only code stays test-only.** The advanceable `TestClock` lives behind
   mediator-common's `test-clock` feature and must never reach the mediator
   binary (`scripts/check-test-clock-isolation.sh`).
5. **Comments explain WHY, not WHAT.** Reserve `///` and `//` for the
   non-obvious — a subtle invariant, a reason for an unusual ordering, a
   reference to an incident or upstream issue.
6. **No `unsafe`** in production code without a sign-off in the PR description.
   The workspace sets `unsafe_code = "deny"`: a new site needs
   `#[allow(unsafe_code)]` and a `// SAFETY:` comment saying why it is sound,
   which is what the reviewer signs off.
7. **No `unwrap`/`expect` on untrusted input** (network frames, config,
   stored data). `unwrap` on internal invariants is fine. Not lint-enforced
   (clippy's `unwrap_used` cannot tell the two apart); reviewers check it.
8. **Transport semantics are API.** Changes to send / ack / reconnect / delivery
   behaviour are breaking for consumers even when signatures do not change:
   call them out in a `changelog.d/` fragment.
9. **Clippy is clean under every feature combination CI builds**, with
   `-D warnings`: the default set, `--all-features`, TSP-only, and each
   storage and secrets backend.

## Code of Conduct

### Our Pledge

In the interest of fostering an open and welcoming environment, we as
contributors and maintainers pledge to make participation in our project
and our community a harassment-free experience for everyone, regardless of
age, body size, disability, ethnicity, gender identity and expression,
level of experience, nationality, personal appearance, race, religion, or
sexual identity and orientation.

### Our Standards

Examples of behavior that contributes to creating a positive environment
include:

- Using welcoming and inclusive language.
- Being respectful of differing viewpoints and experiences.
- Gracefully accepting constructive criticism.
- Focusing on what is best for the community.
- Showing empathy towards other community members.
- Avoiding obvious comments about things like code styling and indentation.
  If you see yourself wanting to do that more than once, open an issue to
  update the lint/formatter config to address the concern once and for all.
  **Code reviews should be about logic, not indenting or adding more
  newlines.**

Examples of unacceptable behavior by participants include:

- The use of sexualised language or imagery and unwelcome sexual attention or
  advances.
- Trolling, insulting/derogatory comments, and personal or political attacks.
- Public or private harassment.
- Publishing others' private information, such as a physical or electronic
  address, without explicit permission.
- Other conduct which could reasonably be considered inappropriate in a
  professional setting.

### Scope and enforcement

This Code of Conduct is adapted from the
[Contributor Covenant](https://www.contributor-covenant.org), version 1.4,
available at
<https://www.contributor-covenant.org/version/1/4/code-of-conduct.html>; that
text, including its responsibilities, scope and enforcement sections, applies
in full. The sections above summarise it.

It applies within all project spaces (issues, pull requests, discussions and
reviews) and when someone represents the project in public spaces.

Report abusive, harassing, or otherwise unacceptable behaviour to the project
team at <security@affinidi.com> (the contact in [SECURITY.md](SECURITY.md)).
Every complaint is reviewed and investigated, and results in a response
deemed necessary and appropriate to the circumstances. The project team keeps
the reporter's identity confidential. Maintainers who do not follow or enforce
the Code of Conduct in good faith may face temporary or permanent
repercussions as determined by other members of the project's leadership.
