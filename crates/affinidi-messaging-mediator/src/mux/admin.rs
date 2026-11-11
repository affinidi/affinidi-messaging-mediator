//! `messaging/mux/connections`: an administrator's view of this instance's
//! live mux connections.
//!
//! The answer is built from [`MuxRegistry::all`](super::registry::MuxRegistry::all),
//! one connection's session locked at a time, and paged by position:
//! connections ordered by `openedAt` then `sessionId`, members by DID. The
//! page's member budget may end a page inside a connection; the next page
//! repeats that connection and carries on with its remaining members.
//!
//! A cursor is tied to the requester, the filters, this instance and the time
//! it was issued, and carries a MAC under a key that lives only in this
//! process, so a cursor this instance did not issue is refused.

use std::sync::{Arc, LazyLock};

use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::connection::MuxWire;
use super::registry::MuxConn;
use super::session::MuxSource;

/// Connections per page when the request does not say.
pub const DEFAULT_LIMIT: usize = 50;
/// The most connections per page.
pub const MAX_LIMIT: usize = 100;
/// Member entries per page when the request does not say, and the most.
pub const MAX_MEMBER_LIMIT: usize = 1000;
/// How long a cursor stays valid.
pub const CURSOR_TTL_SECS: u64 = 600;

/// The task's own error code.
pub const CURSOR_INVALID: &str = "messaging/mux/connections:cursorInvalid";

/// What the request asks for, read from its payload.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Query {
    pub principal: Option<String>,
    pub member: Option<String>,
    pub member_limit: usize,
    pub limit: usize,
    pub cursor: Option<String>,
}

impl Query {
    pub fn from_payload(payload: &Value) -> Self {
        let text = |k: &str| payload.get(k).and_then(Value::as_str).map(str::to_string);
        let count = |k: &str, default: usize, max: usize| {
            payload
                .get(k)
                .and_then(Value::as_u64)
                .map_or(default, |n| (n as usize).min(max))
        };
        Self {
            principal: text("principal"),
            member: text("member"),
            member_limit: count("memberLimit", MAX_MEMBER_LIMIT, MAX_MEMBER_LIMIT),
            limit: count("limit", DEFAULT_LIMIT, MAX_LIMIT).max(1),
            cursor: text("cursor"),
        }
    }

    /// What a cursor must have been issued for: the filters and the member
    /// budget (paging continues with the same request members).
    fn fingerprint(&self) -> String {
        sha256::digest(format!(
            "{}\n{}\n{}",
            self.principal.as_deref().unwrap_or(""),
            self.member.as_deref().unwrap_or(""),
            self.member_limit
        ))[..32]
            .to_string()
    }
}

/// One member, copied out of its connection's session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberView {
    pub did: String,
    pub grant_id: Option<String>,
    pub scope: Value,
    pub expires_at: u64,
    pub delivery_active: bool,
}

/// One live connection, copied out under its session lock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionView {
    pub session_id: String,
    pub principal: String,
    pub wire: MuxWire,
    pub opened_at: u64,
    /// Ordered by DID.
    pub members: Vec<MemberView>,
}

/// Copy one connection out, holding its locks only while copying.
pub async fn view(conn: &Arc<MuxConn>) -> ConnectionView {
    let inactive = conn.inactive.lock().await.clone();
    let s = conn.session.lock().await;
    let mut members: Vec<MemberView> = s
        .members()
        .map(|m| MemberView {
            did: m.did.clone(),
            grant_id: match &m.source {
                MuxSource::Grant { grant_id } => Some(grant_id.clone()),
                MuxSource::Attach => None,
            },
            scope: serde_json::to_value(&m.scope).unwrap_or(Value::Null),
            expires_at: m.expires_at,
            delivery_active: !inactive.contains(&m.did_hash),
        })
        .collect();
    members.sort_by(|a, b| a.did.cmp(&b.did));
    ConnectionView {
        session_id: s.session_id.clone(),
        principal: s.principal_did.clone(),
        wire: conn.wire,
        opened_at: conn.opened_at,
        members,
    }
}

/// Where a page stopped: the connection, and within it the last member
/// returned (`None` when the whole connection was returned).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Position {
    #[serde(rename = "o")]
    opened_at: u64,
    #[serde(rename = "s")]
    session_id: String,
    #[serde(rename = "m", default, skip_serializing_if = "Option::is_none")]
    after_member: Option<MemberMark>,
}

/// The last member a page returned, kept short: a DID may be 2048
/// characters and a cursor at most 1024. Its index among the connection's
/// members in DID order, and a short hash of the DID. Resuming continues
/// after that DID while the connection still carries it, and from the same
/// index once it has left.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct MemberMark {
    #[serde(rename = "n")]
    index: usize,
    #[serde(rename = "h")]
    did_hash: String,
}

/// A short, stable digest: 128 bits of SHA-256, hex.
fn short_digest(s: &str) -> String {
    sha256::digest(s)[..32].to_string()
}

impl MemberMark {
    fn of(members: &[MemberView], did: &str) -> Self {
        Self {
            index: members.iter().position(|m| m.did == did).unwrap_or(0),
            did_hash: short_digest(did),
        }
    }

    /// The index of the first member after this mark in `members` (DID order).
    fn resume_at(&self, members: &[MemberView]) -> usize {
        match members
            .iter()
            .position(|m| short_digest(&m.did) == self.did_hash)
        {
            Some(i) => i + 1,
            None => self.index.min(members.len()),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct CursorBody {
    #[serde(rename = "p")]
    at: Position,
    /// The request's filters ([`Query::fingerprint`]).
    #[serde(rename = "q")]
    query: String,
    /// The requester's DID hash.
    #[serde(rename = "r")]
    requester: String,
    /// The instance that issued it.
    #[serde(rename = "i")]
    instance: String,
    /// When it was issued (unix seconds).
    #[serde(rename = "t")]
    issued: u64,
}

/// A key that lives only in this process: a cursor carrying a MAC under it
/// was issued here.
static CURSOR_KEY: LazyLock<String> =
    LazyLock::new(|| format!("{}{}", uuid::Uuid::new_v4(), uuid::Uuid::new_v4()));

fn mac(body: &str) -> String {
    short_digest(&format!("{}\n{body}", *CURSOR_KEY))
}

/// Who and what a cursor must belong to.
pub struct Binding<'a> {
    pub requester: &'a str,
    pub instance: &'a str,
    pub now: u64,
}

fn issue(at: Position, query: &Query, b: &Binding<'_>) -> String {
    let body = serde_json::to_string(&CursorBody {
        at,
        query: query.fingerprint(),
        requester: short_digest(b.requester),
        instance: b.instance.to_string(),
        issued: b.now,
    })
    .expect("cursor serialises");
    let tag = mac(&body);
    BASE64_URL_SAFE_NO_PAD.encode(format!("{tag}.{body}"))
}

/// The position a cursor names, if this instance issued it for this
/// requester and these filters and it has not expired.
fn redeem(cursor: &str, query: &Query, b: &Binding<'_>) -> Option<Position> {
    let raw = String::from_utf8(BASE64_URL_SAFE_NO_PAD.decode(cursor).ok()?).ok()?;
    let (tag, body) = raw.split_once('.')?;
    if mac(body) != tag {
        return None;
    }
    let c: CursorBody = serde_json::from_str(body).ok()?;
    let fresh = b.now.saturating_sub(c.issued) <= CURSOR_TTL_SECS && c.issued <= b.now + 60;
    (c.query == query.fingerprint()
        && c.requester == short_digest(b.requester)
        && c.instance == b.instance
        && fresh)
        .then_some(c.at)
}

/// Why a page could not be built.
#[derive(Debug, PartialEq, Eq)]
pub enum PageError {
    CursorInvalid,
}

fn rfc3339(secs: u64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(secs as i64, 0)
        .unwrap_or_default()
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn member_json(m: &MemberView) -> Value {
    let mut v = json!({
        "did": m.did,
        "source": if m.grant_id.is_some() { "grant" } else { "attach" },
        "scope": m.scope,
        "expiresAt": rfc3339(m.expires_at),
        "deliveryActive": m.delivery_active,
    });
    if let Some(id) = &m.grant_id {
        v["grantId"] = json!(id);
    }
    v
}

/// One page of `connections`, as the response payload.
///
/// `all` is every live connection on this instance, in any order; `all_instances`
/// says whether the answer may claim to cover every instance.
pub fn page(
    mut all: Vec<ConnectionView>,
    query: &Query,
    binding: &Binding<'_>,
    all_instances: bool,
) -> Result<Value, PageError> {
    let from = match &query.cursor {
        None => None,
        Some(c) => Some(redeem(c, query, binding).ok_or(PageError::CursorInvalid)?),
    };

    all.retain(|c| {
        query.principal.as_ref().is_none_or(|p| &c.principal == p)
            && query
                .member
                .as_ref()
                .is_none_or(|m| c.members.iter().any(|x| &x.did == m))
    });
    all.sort_by(|a, b| (a.opened_at, &a.session_id).cmp(&(b.opened_at, &b.session_id)));

    // Resume by position: the connection the cursor names (if it is still
    // open) continues after its last returned member; otherwise the next one
    // in order. A connection that closed meanwhile is simply not there.
    let start = |c: &ConnectionView| match &from {
        None => true,
        Some(p) => match (c.opened_at, c.session_id.as_str()).cmp(&(p.opened_at, &p.session_id)) {
            std::cmp::Ordering::Greater => true,
            std::cmp::Ordering::Equal => p.after_member.is_some(),
            std::cmp::Ordering::Less => false,
        },
    };

    let mut out = Vec::new();
    let mut budget = query.member_limit;
    let mut next: Option<Position> = None;
    let mut pending = all.into_iter().filter(|c| start(c)).peekable();
    while let Some(c) = pending.next() {
        let member_count = c.members.len();
        // The members this connection still owes, in DID order.
        let skip = from
            .as_ref()
            .filter(|p| p.opened_at == c.opened_at && p.session_id == c.session_id)
            .and_then(|p| p.after_member.as_ref())
            .map_or(0, |mark| mark.resume_at(&c.members));
        let mut owed: Vec<&MemberView> = c
            .members
            .iter()
            .skip(skip)
            .filter(|m| query.member.as_ref().is_none_or(|want| &m.did == want))
            .collect();
        let mut split = false;
        if query.member_limit > 0 && owed.len() > budget {
            owed.truncate(budget);
            split = true;
        }
        if query.member_limit == 0 {
            owed.clear();
        }
        budget -= owed.len().min(budget);
        let last = owed.last().map(|m| m.did.clone());
        out.push(json!({
            "sessionId": c.session_id,
            "principal": c.principal,
            "wire": match c.wire { MuxWire::DidComm => "didcomm", MuxWire::Tsp => "tsp" },
            "openedAt": rfc3339(c.opened_at),
            "memberCount": member_count,
            "members": owed.into_iter().map(member_json).collect::<Vec<_>>(),
        }));
        if split {
            next = Some(Position {
                opened_at: c.opened_at,
                session_id: c.session_id.clone(),
                after_member: last.map(|did| MemberMark::of(&c.members, &did)),
            });
            break;
        }
        let full = out.len() >= query.limit || (query.member_limit > 0 && budget == 0);
        if full {
            if pending.peek().is_some() {
                next = Some(Position {
                    opened_at: c.opened_at,
                    session_id: c.session_id.clone(),
                    after_member: None,
                });
            }
            break;
        }
    }

    let mut response = json!({
        "connections": out,
        "coverage": if all_instances { "allInstances" } else { "thisInstance" },
    });
    if let Some(at) = next {
        response["nextCursor"] = json!(issue(at, query, binding));
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(did: &str, grant: bool, active: bool) -> MemberView {
        MemberView {
            did: did.to_string(),
            grant_id: grant.then(|| format!("g-{did}")),
            scope: json!(["receive"]),
            expires_at: 2_000_000_000,
            delivery_active: active,
        }
    }

    fn conn(id: &str, principal: &str, opened: u64, members: &[&str]) -> ConnectionView {
        let mut m: Vec<MemberView> = members.iter().map(|d| member(d, true, true)).collect();
        m.sort_by(|a, b| a.did.cmp(&b.did));
        ConnectionView {
            session_id: id.to_string(),
            principal: principal.to_string(),
            wire: MuxWire::DidComm,
            opened_at: opened,
            members: m,
        }
    }

    const B: Binding<'static> = Binding {
        requester: "admin",
        instance: "i1",
        now: 1_000,
    };

    fn fleet() -> Vec<ConnectionView> {
        vec![
            conn("s2", "did:p:tablet", 20, &["did:m:a", "did:m:b"]),
            conn("s1", "did:p:phone", 10, &["did:m:a", "did:m:c", "did:m:d"]),
            conn("s3", "did:p:phone", 30, &[]),
        ]
    }

    fn sessions(page: &Value) -> Vec<String> {
        page["connections"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["sessionId"].as_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn everything_in_order_on_one_page() {
        let q = Query::from_payload(&json!({}));
        let p = page(fleet(), &q, &B, false).unwrap();
        assert_eq!(sessions(&p), ["s1", "s2", "s3"]);
        assert_eq!(p["coverage"], "thisInstance");
        assert!(p.get("nextCursor").is_none());
        let s1 = &p["connections"][0];
        assert_eq!(s1["memberCount"], 3);
        assert_eq!(s1["members"][0]["did"], "did:m:a");
        assert_eq!(s1["members"][0]["source"], "grant");
        assert_eq!(s1["members"][0]["grantId"], "g-did:m:a");
        assert_eq!(
            p["connections"][2]["members"],
            json!([]),
            "an empty connection is listed"
        );
    }

    #[test]
    fn filters_narrow_connections_and_members() {
        let q = Query::from_payload(&json!({ "principal": "did:p:phone" }));
        assert_eq!(
            sessions(&page(fleet(), &q, &B, true).unwrap()),
            ["s1", "s3"]
        );

        let q = Query::from_payload(&json!({ "member": "did:m:a" }));
        let p = page(fleet(), &q, &B, true).unwrap();
        assert_eq!(
            sessions(&p),
            ["s1", "s2"],
            "an empty connection is not listed for a member filter"
        );
        for c in p["connections"].as_array().unwrap() {
            assert_eq!(c["members"].as_array().unwrap().len(), 1);
            assert_eq!(c["members"][0]["did"], "did:m:a");
        }
        assert_eq!(
            p["connections"][0]["memberCount"], 3,
            "the count stays exact"
        );
    }

    #[test]
    fn the_member_budget_splits_a_connection_across_pages() {
        let q = Query::from_payload(&json!({ "memberLimit": 2 }));
        let p1 = page(fleet(), &q, &B, false).unwrap();
        assert_eq!(sessions(&p1), ["s1"]);
        assert_eq!(p1["connections"][0]["members"].as_array().unwrap().len(), 2);
        let cursor = p1["nextCursor"].as_str().unwrap();

        let q2 = Query::from_payload(&json!({ "memberLimit": 2, "cursor": cursor }));
        let p2 = page(fleet(), &q2, &B, false).unwrap();
        assert_eq!(
            sessions(&p2),
            ["s1", "s2"],
            "s1 again, with its remaining member"
        );
        assert_eq!(p2["connections"][0]["members"][0]["did"], "did:m:d");
        assert_eq!(p2["connections"][1]["members"].as_array().unwrap().len(), 1);

        let q3 = Query::from_payload(&json!({ "memberLimit": 2, "cursor": p2["nextCursor"] }));
        let p3 = page(fleet(), &q3, &B, false).unwrap();
        assert_eq!(sessions(&p3), ["s2", "s3"]);
        assert_eq!(p3["connections"][0]["members"][0]["did"], "did:m:b");
        assert!(p3.get("nextCursor").is_none());
    }

    #[test]
    fn a_cursor_fits_the_spec_whatever_the_dids() {
        let long = |c: char| format!("did:peer:2.{}", c.to_string().repeat(1800));
        let mut fleet = fleet();
        fleet[0].session_id = "s".repeat(64);
        fleet[0].members = vec![
            member(&long('a'), true, true),
            member(&long('b'), true, true),
        ];
        let q = Query::from_payload(&json!({ "memberLimit": 1 }));
        let p = page(fleet, &q, &B, false).unwrap();
        let c = p["nextCursor"].as_str().unwrap();
        assert!(c.len() <= 1024, "nextCursor is {} characters", c.len());
    }

    #[test]
    fn a_member_leaving_between_pages_does_not_restart_the_connection() {
        let q = Query::from_payload(&json!({ "memberLimit": 2 }));
        let p1 = page(fleet(), &q, &B, false).unwrap();
        // s1 returned did:m:a and did:m:c; did:m:c leaves before page two.
        let mut fleet = fleet();
        fleet[1].members.retain(|m| m.did != "did:m:c");
        let q2 = Query::from_payload(&json!({ "memberLimit": 2, "cursor": p1["nextCursor"] }));
        let p2 = page(fleet, &q2, &B, false).unwrap();
        assert_eq!(p2["connections"][0]["sessionId"], "s1");
        assert_eq!(p2["connections"][0]["members"][0]["did"], "did:m:d");
    }

    #[test]
    fn a_summary_without_members_pages_by_connection() {
        let q = Query::from_payload(&json!({ "memberLimit": 0, "limit": 2 }));
        let p1 = page(fleet(), &q, &B, false).unwrap();
        assert_eq!(sessions(&p1), ["s1", "s2"]);
        assert_eq!(p1["connections"][0]["members"], json!([]));
        assert_eq!(p1["connections"][0]["memberCount"], 3);
        let q2 = Query::from_payload(
            &json!({ "memberLimit": 0, "limit": 2, "cursor": p1["nextCursor"] }),
        );
        assert_eq!(sessions(&page(fleet(), &q2, &B, false).unwrap()), ["s3"]);
    }

    #[test]
    fn a_closed_connection_is_skipped_not_restarted() {
        let q = Query::from_payload(&json!({ "limit": 1 }));
        let p1 = page(fleet(), &q, &B, false).unwrap();
        assert_eq!(sessions(&p1), ["s1"]);
        // s1 closes before the next page.
        let rest: Vec<_> = fleet()
            .into_iter()
            .filter(|c| c.session_id != "s1")
            .collect();
        let q2 = Query::from_payload(&json!({ "limit": 1, "cursor": p1["nextCursor"] }));
        assert_eq!(sessions(&page(rest, &q2, &B, false).unwrap()), ["s2"]);
    }

    #[test]
    fn a_cursor_is_refused_unless_issued_here_for_this_request() {
        let q = Query::from_payload(&json!({ "limit": 1 }));
        let p1 = page(fleet(), &q, &B, false).unwrap();
        let c = p1["nextCursor"].as_str().unwrap().to_string();
        let with = |payload: Value, b: &Binding<'_>| {
            page(fleet(), &Query::from_payload(&payload), b, false)
        };

        assert!(with(json!({ "limit": 1, "cursor": c }), &B).is_ok());
        // Different filters.
        assert_eq!(
            with(
                json!({ "limit": 1, "principal": "did:p:phone", "cursor": c }),
                &B
            ),
            Err(PageError::CursorInvalid)
        );
        // Another requester, another instance, expired.
        for b in [
            Binding {
                requester: "other",
                ..B
            },
            Binding {
                instance: "i2",
                ..B
            },
            Binding {
                now: B.now + CURSOR_TTL_SECS + 1,
                ..B
            },
        ] {
            assert_eq!(
                with(json!({ "limit": 1, "cursor": c }), &b),
                Err(PageError::CursorInvalid)
            );
        }
        // Forged: a valid body under a wrong tag, and garbage.
        let raw = String::from_utf8(BASE64_URL_SAFE_NO_PAD.decode(&c).unwrap()).unwrap();
        let (_, body) = raw.split_once('.').unwrap();
        let forged = BASE64_URL_SAFE_NO_PAD.encode(format!("{}.{body}", "0".repeat(64)));
        assert_eq!(
            with(json!({ "limit": 1, "cursor": forged }), &B),
            Err(PageError::CursorInvalid)
        );
        assert_eq!(
            with(json!({ "cursor": "not-a-cursor" }), &B),
            Err(PageError::CursorInvalid)
        );
    }
}
