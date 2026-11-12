### Changed — manual image runs publish only what their ref allows

- A manual run of `publish-images.yaml` on a release tag publishes only that
  tag's version. On `main` or `release/*` it publishes only a dev version,
  `vX.Y.Z-dev.<hex sha>` (the default); any other branch is refused. A
  version already in GHCR is replaced only with the new `overwrite` input,
  checked before the build and again just before the tag moves; one run at a
  time publishes a given version. Rules in `docker/ci/check-dispatch.sh`,
  self-tested by `docker/ci/test-dispatch-guard.sh` on every image run.
- The jobs that push images (`build`, `publish-ghcr`) now run in the
  `release` environment, like the ECR mirror. Its deployment policy must
  admit `v*` tags (RELEASES.md) or tag runs will wait.
- The README says how to pin the image by digest and verify its provenance.
