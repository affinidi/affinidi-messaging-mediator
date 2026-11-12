### Changed — embedded mediators get a generated JWT key by default

- `Config::headless`, `SecurityConfig::headless` and `MediatorBuilder` now
  start with an Ed25519 JWT key pair generated for the process, instead of a
  fixed placeholder key. Sessions it signs end when the process restarts and
  are not shared between instances; set a persistent key with
  `SecurityConfig::set_jwt_keys_from_pkcs8`. The shipped binary and the test
  mediator already set their own key and are unaffected.
