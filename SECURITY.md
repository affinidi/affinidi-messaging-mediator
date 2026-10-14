# Security Notice

To report a security issue, please email <security@affinidi.com> with a description
of the issue, the steps you took to create the issue, affected versions, and, if
known, mitigations for the issue. Our vulnerability management team will respond
within 5 working days of your email. If the issue is confirmed as a vulnerability,
we will open a Security Advisory. This project follows a 120 day disclosure timeline.

Please do not open a public GitHub issue for a suspected vulnerability.

## Supported versions

Security fixes are backported to the newest two GA releases (N and N-1) and
released as patches from their `release/<major.minor>` branches — crates on
crates.io and images on `ghcr.io/affinidi/messaging-mediator`. See
[RELEASES.md](RELEASES.md) for the schedule and the current status of each
release. Versions up to `0.41.x` were released from
[affinidi-tdk-rs](https://github.com/affinidi/affinidi-tdk-rs) and are not
patched from this repository.
