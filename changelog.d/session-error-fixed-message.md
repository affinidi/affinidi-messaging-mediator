### Fixed — a session error over HTTP returns a fixed message

- **Behaviour change (R3.6):** an HTTP `SessionError` response (status 406)
  now carries the message "Session could not be established or found"
  instead of the error's own text, which could include a storage backend's
  error message. The status, `errorCode` and `errorCodeStr` are unchanged;
  the full text is logged at WARN.
