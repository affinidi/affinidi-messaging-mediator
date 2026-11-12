### Changed — access and refresh tokens are each accepted only where they belong (R3.6)

Auth-semantics change: clients that send the access token as the bearer and
the refresh token to `/authenticate/refresh` (as the SDK does) are
unaffected.

- Session tokens now carry a `token_use` claim, `"access"` or `"refresh"`.
  `aud`, the header and the signing key are unchanged.
- REST routes and `/ws` (both the `Authorization` header and the
  `bearer.<jwt>` subprotocol) accept only access tokens; a refresh token is
  refused with `401`.
- `/authenticate/refresh` exchanges only refresh tokens. An access token is
  refused with `400` (error code 38) before the stored refresh-token hash is
  consulted, so it no longer ends the session.
- Transition for tokens issued by the previous release, which have no
  `token_use`:
  - as a bearer, an unmarked token is accepted only if it has no `jti` and
    expires within one access-token lifetime (`jwt_access_expiry`) plus the
    60 s expiry leeway. Anything longer-lived is a refresh token and is
    refused;
  - at `/authenticate/refresh`, an unmarked token is still accepted; the
    one-time stored-hash check applies as before.
  - All such tokens have expired one `jwt_refresh_expiry` after the upgrade;
    a later release will refuse unmarked tokens outright.
  - An operator who lowered `jwt_access_expiry` in the same upgrade will see
    previously issued access tokens refused early; clients refresh or
    re-authenticate as on expiry.
