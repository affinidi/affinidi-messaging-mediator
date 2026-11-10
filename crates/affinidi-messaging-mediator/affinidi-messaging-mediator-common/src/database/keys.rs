//! Names of the Redis keys whose layout depends on `cluster_mode`.
//!
//! With cluster mode off every name is unchanged (`DID:abc`). With it on, keys
//! that must share a cluster slot carry a hash tag (`DID:{abc}`):
//!
//! - everything about one account, tagged with its DID hash;
//! - a message's body and metadata, tagged with the message hash;
//! - the streaming registry, tagged `streaming`;
//! - every mux record and principal index, tagged `mux`, since one grant
//!   change updates a record and the indexes of several principals at once.
//!
//! Every other key (`GLOBAL`, `KNOWN_DIDS`, `ADMINS`, `MSG_EXPIRY*`,
//! `FORWARD_Q`, `AUDIT_LOG`, `SESSION:*`, `OOB_INVITES:*`, `V1_KEY:*`, …) is
//! untagged in both modes and is named where it is used.

/// Builds key names for the configured cluster mode. Cheap to copy.
#[derive(Clone, Copy, Debug, Default)]
pub struct Keys {
    cluster: bool,
}

impl Keys {
    pub fn new(cluster_mode: bool) -> Self {
        Keys {
            cluster: cluster_mode,
        }
    }

    /// Whether cluster mode is on.
    pub fn cluster_mode(self) -> bool {
        self.cluster
    }

    fn tagged(self, prefix: &str, tag: &str) -> String {
        if self.cluster {
            format!("{prefix}{{{tag}}}")
        } else {
            [prefix, tag].concat()
        }
    }

    /// Account record hash.
    pub fn did(self, did_hash: &str) -> String {
        self.tagged("DID:", did_hash)
    }

    /// Account access-list set.
    pub fn access_list(self, did_hash: &str) -> String {
        self.tagged("ACCESS_LIST:", did_hash)
    }

    /// Account inbox stream.
    pub fn receive_q(self, did_hash: &str) -> String {
        self.tagged("RECEIVE_Q:", did_hash)
    }

    /// Account outbox stream.
    pub fn send_q(self, did_hash: &str) -> String {
        self.tagged("SEND_Q:", did_hash)
    }

    /// Inbox stream id of each message queued for an account, by message hash.
    /// Cluster mode only: it makes a repeated store and delete idempotent in
    /// the account's slot (the Lua library does this in one script).
    pub fn receive_ids(self, did_hash: &str) -> String {
        self.tagged("RECEIVE_IDS:", did_hash)
    }

    /// Outbox stream id of each message an account sent, by message hash.
    /// Cluster mode only, as [`receive_ids`](Self::receive_ids).
    pub fn send_ids(self, did_hash: &str) -> String {
        self.tagged("SEND_IDS:", did_hash)
    }

    /// Per-recipient queued-message counts of a sender.
    pub fn peer_q(self, did_hash: &str) -> String {
        self.tagged("PEER_Q:", did_hash)
    }

    /// Account lifetime counters: one field per counter, so each bump is an
    /// `HINCRBY` and nothing is read-modified.
    pub fn stats(self, did_hash: &str) -> String {
        self.tagged("STATS:", did_hash)
    }

    /// Account activity times: one field per activity kind, so recording one
    /// never rewrites the other.
    pub fn activity(self, did_hash: &str) -> String {
        self.tagged("ACTIVITY:", did_hash)
    }

    /// The DIDComm v1 verkeys an account owns.
    pub fn v1_keys(self, did_hash: &str) -> String {
        self.tagged("V1_KEYS:", did_hash)
    }

    /// A sender's receipt for one message that left its outbox. Keyed under
    /// the sender so no other account's lookup can reach it.
    pub fn outbox_receipt(self, from_hash: &str, message_hash: &str) -> String {
        [&self.tagged("RECEIPT:", from_hash), ":", message_hash].concat()
    }

    /// Message body.
    pub fn msg(self, message_hash: &str) -> String {
        self.tagged("MSG:", message_hash)
    }

    /// Message metadata hash.
    pub fn msg_meta(self, message_hash: &str) -> String {
        self.tagged("MSG:META:", message_hash)
    }

    /// One mediator instance's streaming sessions.
    pub fn streaming_sessions(self, mediator_uuid: &str) -> String {
        self.shared("STREAMING_SESSIONS:", "streaming", mediator_uuid)
    }

    /// DID hash → streaming instance of every live client.
    pub fn global_streaming(self) -> &'static str {
        if self.cluster {
            "GLOBAL_STREAMING:{streaming}"
        } else {
            "GLOBAL_STREAMING"
        }
    }

    /// One member DID's mux record: a hash `{ v: version, r: record JSON }`.
    pub fn mux_record(self, did_hash: &str) -> String {
        self.shared("MUX_DID:", "mux", did_hash)
    }

    /// The member DID hashes a principal holds mux grants on: a sorted set
    /// (all scores 0, ordered by member), paged with `ZRANGEBYLEX`.
    pub fn mux_principal(self, principal_hash: &str) -> String {
        self.shared("MUX_PRINCIPAL:", "mux", principal_hash)
    }

    fn shared(self, prefix: &str, group: &str, name: &str) -> String {
        if self.cluster {
            format!("{prefix}{{{group}}}:{name}")
        } else {
            [prefix, name].concat()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const H: &str = "abc123";

    fn all(keys: Keys) -> Vec<String> {
        vec![
            keys.did(H),
            keys.access_list(H),
            keys.receive_q(H),
            keys.send_q(H),
            keys.peer_q(H),
            keys.stats(H),
            keys.activity(H),
            keys.v1_keys(H),
            keys.outbox_receipt(H, "m1"),
            keys.msg("m1"),
            keys.msg_meta("m1"),
            keys.streaming_sessions("u1"),
            keys.global_streaming().to_string(),
            keys.mux_record(H),
            keys.mux_principal("p1"),
        ]
    }

    #[test]
    fn cluster_mode_off_keeps_todays_names() {
        assert_eq!(
            all(Keys::new(false)),
            [
                "DID:abc123",
                "ACCESS_LIST:abc123",
                "RECEIVE_Q:abc123",
                "SEND_Q:abc123",
                "PEER_Q:abc123",
                "STATS:abc123",
                "ACTIVITY:abc123",
                "V1_KEYS:abc123",
                "RECEIPT:abc123:m1",
                "MSG:m1",
                "MSG:META:m1",
                "STREAMING_SESSIONS:u1",
                "GLOBAL_STREAMING",
                "MUX_DID:abc123",
                "MUX_PRINCIPAL:p1",
            ]
        );
    }

    #[test]
    fn cluster_mode_on_tags_keys() {
        assert_eq!(
            all(Keys::new(true)),
            [
                "DID:{abc123}",
                "ACCESS_LIST:{abc123}",
                "RECEIVE_Q:{abc123}",
                "SEND_Q:{abc123}",
                "PEER_Q:{abc123}",
                "STATS:{abc123}",
                "ACTIVITY:{abc123}",
                "V1_KEYS:{abc123}",
                "RECEIPT:{abc123}:m1",
                "MSG:{m1}",
                "MSG:META:{m1}",
                "STREAMING_SESSIONS:{streaming}:u1",
                "GLOBAL_STREAMING:{streaming}",
                "MUX_DID:{mux}:abc123",
                "MUX_PRINCIPAL:{mux}:p1",
            ]
        );
    }

    #[test]
    fn cluster_mode_on_puts_each_group_in_one_slot() {
        let keys = Keys::new(true);
        let slot = |k: &str| redis::cluster_routing::Slot::for_key(k);

        let account = slot(&keys.did(H));
        for k in [
            keys.access_list(H),
            keys.receive_q(H),
            keys.send_q(H),
            keys.peer_q(H),
            keys.receive_ids(H),
            keys.send_ids(H),
            keys.stats(H),
            keys.activity(H),
            keys.v1_keys(H),
            keys.outbox_receipt(H, "m1"),
        ] {
            assert_eq!(slot(&k), account, "{k} is not in the account's slot");
        }
        assert_eq!(slot(&keys.msg("m1")), slot(&keys.msg_meta("m1")));
        assert_eq!(
            slot(&keys.streaming_sessions("u1")),
            slot(keys.global_streaming())
        );
        assert_eq!(slot(&keys.mux_record(H)), slot(&keys.mux_principal("p1")));
        assert_eq!(
            slot(&keys.mux_principal("p1")),
            slot(&keys.mux_principal("p2"))
        );
    }
}
