### Fixed — DIDComm direct delivery answers the same way for every recipient it refuses

- **Behaviour change (R3.6):** with `local_direct_delivery_allowed`, the
  checks about the sender (session binding, `SEND_MESSAGES`,
  `local_direct_delivery_allow_anon`) now run before the recipient is looked
  up. A sender-side refusal (`52`, `44`, `50`) is therefore the same whether
  or not the recipient has an account here. Previously an unknown recipient
  was answered `73 delivery.refused` first, while a known one got the
  sender-side code. Every recipient-side refusal (no account, no
  `RECEIVE_MESSAGES`, access list) is still the single `73
  delivery.refused`. The TSP path already ran its checks in this order.
