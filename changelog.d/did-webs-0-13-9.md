### Fixed — a `did:webs` with a designated service resolves

`affinidi-did-webs` 0.13.9 (lockfile only). Its check of a published
`did.json` against the services the key event stream authorises compared each
service's `type` as written, so `"TSPTransport"` and `["TSPTransport"]` were
different services. A did:webs host serves the document rendered through
`Document`, which writes every `type` as an array, so any did:webs with a
designated service — such as a VTA's own identity, whose `#tsp` and
`#didcomm` name this mediator — failed to resolve with `DocumentMismatch`, and
the mediator could not authenticate it. Types are now compared as a set. No
configuration or wire change.
