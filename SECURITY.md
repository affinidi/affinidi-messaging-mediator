# Security Notice

To report a security issue, please email <security@affinidi.com> with a description
of the issue, the steps you took to create the issue, affected versions, and, if
known, mitigations for the issue. Our vulnerability management team will respond
within 5 working days of your email. If the issue is confirmed as a vulnerability,
we will open a Security Advisory. This project follows a 120 day disclosure timeline.

Please do not open a public GitHub issue for a suspected vulnerability.

## Supported versions

A release is supported for 90 days after its GA, and the newest GA release
is always supported. Security fixes are backported to every supported
release and released as patches from its `release/<major.minor>` branch —
crates on crates.io and images on `ghcr.io/affinidi/messaging-mediator`. A
fix that needs a breaking change ships only in the next release, and the
advisory says so. See [RELEASES.md](RELEASES.md#support) for the policy and
the schedule table for each release's "Supported until" date. Versions up to `0.41.x` were released from
[affinidi-tdk-rs](https://github.com/affinidi/affinidi-tdk-rs) and are not
patched from this repository.
