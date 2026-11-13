//! What each key does: on every screen, on one screen, and in each popup.

use std::path::PathBuf;

use affinidi_messaging_mediator_admin::{
    GrantSelection, PurgeRequest, account_hash, revoke_summary, specs,
};
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use serde_json::Value;

use super::format::{config_value, did_label, human_bytes, label, short};
use super::popup::Popup;
use super::screens::config::is_override;
use super::state::{GrantQuery, MessageRow, SORTS, grant_key};
use super::{App, Control, List, Tab, Update};
use crate::account_edit::AccountEdit;
use crate::requests::Job;

impl App {
    /// Handle a key press.
    pub fn handle_key(&mut self, key: KeyEvent) -> Control {
        if key.kind != KeyEventKind::Press {
            return Control::Continue;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            return Control::Quit;
        }
        if let Some(popup) = self.s.popup.take() {
            self.popup_key(popup, key.code);
            return Control::Continue;
        }
        let monitor = self.s.monitor.visible;
        let shift = key.modifiers.contains(KeyModifiers::SHIFT);
        match key.code {
            // Only `q` (and Ctrl-C) quit: Esc closes popups, and one Esc too
            // many must not end the session.
            KeyCode::Char('q') => return Control::Quit,
            KeyCode::Esc => {}
            KeyCode::Char('?') => self.s.popup = Some(Popup::Help { scroll: 0 }),
            KeyCode::Char('y') => self.copy_selected(),
            KeyCode::Char(']') => self.load_more(),
            KeyCode::Char(c @ '1'..='8') => {
                if let Some(tab) = self.s.tabs().get((c as u8 - b'1') as usize) {
                    self.s.tab = *tab;
                    self.refresh();
                }
            }
            KeyCode::Tab => {
                let tabs = self.s.tabs();
                let i = tabs.iter().position(|t| *t == self.s.tab).unwrap_or(0);
                self.s.tab = tabs[(i + 1) % tabs.len()];
                self.refresh();
            }
            KeyCode::Char('r') => self.reload(),
            KeyCode::Char('n') => self.s.popup = Some(self.name_popup(self.account_in_view())),
            KeyCode::Char('b') => self.s.popup = Some(Popup::Book { selected: 0 }),
            KeyCode::Char('m') => self.toggle_monitor(),
            KeyCode::Char('l') => match &self.s.logs {
                Some(logs) => {
                    logs.mark_seen();
                    self.s.popup = Some(Popup::Logs { back: 0 });
                }
                None => self.s.set_notice("this console isn't keeping a log", true),
            },
            KeyCode::PageUp if monitor => {
                let page = self.s.monitor.page as i64;
                self.s.monitor.scroll(page)
            }
            KeyCode::PageDown if monitor => {
                let page = self.s.monitor.page as i64;
                self.s.monitor.scroll(-page)
            }
            KeyCode::Up if monitor && shift => self.s.monitor.scroll(1),
            KeyCode::Down if monitor && shift => self.s.monitor.scroll(-1),
            KeyCode::Home if monitor => self.s.monitor.scroll(i64::MAX),
            KeyCode::End if monitor => self.s.monitor.back = 0,
            KeyCode::Char('t') if monitor => {
                self.s.monitor.show_totals = !self.s.monitor.show_totals;
            }
            KeyCode::Char('f') => {
                self.s.monitor.failures_only = !self.s.monitor.failures_only;
                if monitor {
                    self.start_monitor();
                }
            }
            KeyCode::Down | KeyCode::Char('j') => self.move_selection(1),
            KeyCode::Up | KeyCode::Char('k') => self.move_selection(-1),
            KeyCode::PageDown => self.move_selection(self.s.page_rows.max(1) as i32),
            KeyCode::PageUp => self.move_selection(-(self.s.page_rows.max(1) as i32)),
            _ => self.tab_key(key.code),
        }
        Control::Continue
    }

    /// Text pasted into the console (bracketed paste): goes to the field being
    /// edited, if any. Control characters (line breaks) are dropped.
    pub fn handle_paste(&mut self, text: &str) {
        let clean: String = text.chars().filter(|c| !c.is_control()).collect();
        match &mut self.s.popup {
            Some(Popup::EditConfig { value, .. }) => value.push_str(clean.trim()),
            Some(Popup::FindGrants {
                principal,
                member,
                on_member,
            }) => {
                let field = if *on_member { member } else { principal };
                field.push_str(clean.trim());
            }
            Some(Popup::Name {
                did, name, on_name, ..
            }) => {
                if *on_name {
                    name.push_str(&clean);
                } else {
                    did.push_str(clean.trim());
                }
            }
            _ => {}
        }
    }

    fn tab_key(&mut self, code: KeyCode) {
        let can_patch = self.s.session.can_patch_config;
        match (self.s.tab, code) {
            (Tab::Queues | Tab::Dashboard, KeyCode::Char('s')) => {
                self.s.sort = (self.s.sort + 1) % SORTS.len();
                self.s.queues.clear();
                self.load_queues(true);
            }
            (Tab::Queues | Tab::Dashboard, KeyCode::Char('x')) => {
                self.s.queue_send = !self.s.queue_send;
                self.s.queues.clear();
                self.load_queues(true);
            }
            (Tab::Queues | Tab::Dashboard, KeyCode::Enter) => {
                if let Some(q) = self.s.queues.selected() {
                    let did = q.did.to_string();
                    self.open_account(Some(did));
                }
            }
            (Tab::Config, KeyCode::Enter) if can_patch => {
                if let Some(field) = self.s.config.selected() {
                    let key = field.key.to_string();
                    if key.starts_with("limits.") {
                        let value = field.value.to_string();
                        self.s.popup = Some(Popup::EditConfig { key, value });
                    } else {
                        self.s
                            .set_notice("only limits can be changed at runtime", true);
                    }
                }
            }
            // The same key toggles a queue on other screens, so this one asks
            // before it changes anything.
            (Tab::Config, KeyCode::Char('x')) if can_patch => match self.s.config.selected() {
                Some(field) if is_override(field) => {
                    self.s.popup = Some(Popup::ConfirmPatch {
                        key: field.key.to_string(),
                        from: config_value(&field.value),
                        to: Value::Null,
                        typed: None,
                    });
                }
                Some(_) => self
                    .s
                    .set_notice("that key has no override to reset", false),
                None => {}
            },
            (Tab::Accounts, KeyCode::Enter) => {
                if let Some(a) = self.s.accounts.selected() {
                    let did = a.did.to_string();
                    self.open_account(Some(did));
                }
            }
            (Tab::Mux, KeyCode::Char('g')) => {
                if let Some(principal) = self.s.selected_principal() {
                    self.open_grants(GrantQuery {
                        principal: Some(principal),
                        member: None,
                    });
                }
            }
            (Tab::Grants, _) => self.grants_key(code),
            (Tab::Account, _) => self.account_key(code),
            _ => {}
        }
    }

    /// A key on the Grants tab.
    fn grants_key(&mut self, code: KeyCode) {
        let g = &self.s.grants;
        let selected = g.selected();
        let member = selected.map(|r| r.did.to_string());
        match code {
            KeyCode::Char('/') => {
                self.s.popup = Some(Popup::FindGrants {
                    principal: g.query.principal.clone().unwrap_or_default(),
                    member: g.query.member.clone().unwrap_or_default(),
                    on_member: false,
                });
            }
            KeyCode::Char('p') => {
                if let Some(principal) = selected.map(|r| r.principal.to_string()) {
                    self.open_grants(GrantQuery {
                        principal: Some(principal),
                        member: None,
                    });
                }
            }
            KeyCode::Char('g') => {
                if let Some(member) = member {
                    self.open_grants(GrantQuery {
                        principal: None,
                        member: Some(member),
                    });
                }
            }
            KeyCode::Char(' ') => {
                if let Some(key) = selected.map(grant_key) {
                    self.s.grants.marks.toggle(key);
                    self.move_selection(1);
                }
            }
            KeyCode::Char('a') => {
                let g = &mut self.s.grants;
                g.marks.mark_all(&g.rows);
            }
            KeyCode::Char('c') => self.s.grants.marks.clear(),
            KeyCode::Char('d') if !g.marks.is_empty() => {
                self.s.popup = Some(Popup::ConfirmRevokeMarked(g.marks.in_listed_order(&g.rows)));
            }
            KeyCode::Char('E') if !g.marks.is_empty() => self.s.set_notice(
                "E advances one member's epoch, not the marked grants: c clears the marks",
                true,
            ),
            KeyCode::Char('d') => {
                if let Some(row) = selected {
                    self.s.popup = Some(Popup::ConfirmRevoke(GrantSelection::grants(
                        row.did.to_string(),
                        vec![row.grant_id.to_string()],
                    )));
                }
            }
            KeyCode::Char('D') if !g.query.is_empty() => {
                self.s.popup = Some(Popup::ConfirmRevoke(GrantSelection {
                    principal: g.query.principal.clone(),
                    member: g.query.member.clone(),
                    grant_ids: Vec::new(),
                }));
            }
            KeyCode::Char('E') => match g.query.member.clone().or(member) {
                Some(did) => self.ask_bump_epoch(did),
                None => self
                    .s
                    .set_notice("select a grant, or list a member's", true),
            },
            _ => {}
        }
    }

    /// A key on the Account tab.
    fn account_key(&mut self, code: KeyCode) {
        match code {
            KeyCode::Char('x') => {
                self.s.message_send = !self.s.message_send;
                self.set_target(self.s.target.clone());
            }
            KeyCode::Char('e') => match &self.s.account_info {
                // The account on screen: `account_info` is only ever the
                // answer for it (a late one for another is dropped). Only a
                // rootAdmin may change roles: every role an admin could set
                // other than `standard` is privileged, so the row is offered
                // to a rootAdmin alone.
                Some(info) => {
                    let edit = AccountEdit::new(
                        self.s.account_hash().to_string(),
                        info,
                        self.s.session.root(),
                    );
                    self.s.popup = Some(Popup::EditAccount(edit));
                }
                None => self
                    .s
                    .set_notice("the account's settings are still loading", true),
            },
            KeyCode::Char('o') => self.set_target(None),
            KeyCode::Char('i') => {
                if let Some(m) = self.s.messages.selected() {
                    let (id, target) = (m.msg_id.to_string(), self.s.target.clone());
                    self.request(Job::Inspect, true, move |c| async move {
                        Update::Inspected(Box::new(c.inspect(target, &id).await))
                    });
                }
            }
            KeyCode::Char('d') => {
                if let Some(m) = self.s.messages.selected() {
                    let about = delete_summary(&self.s, m);
                    self.s.popup = Some(Popup::ConfirmDelete {
                        target: self.s.target.clone(),
                        ids: vec![m.msg_id.to_string()],
                        about,
                    });
                }
            }
            KeyCode::Char('p') | KeyCode::Char('P') => {
                let peer = if code == KeyCode::Char('P') {
                    self.s.selected_peer()
                } else {
                    None
                };
                use specs::queue::purge::v0_1::Queue;
                let request = PurgeRequest {
                    target: self.s.target.clone(),
                    queue: if self.s.message_send {
                        Queue::Send
                    } else {
                        Queue::Receive
                    },
                    peer,
                    older_than_seconds: None,
                };
                self.request(Job::PurgePreview, true, move |c| async move {
                    Update::PurgePreview(c.purge_preview(request).await)
                });
            }
            _ => {}
        }
    }

    /// The account the user is looking at, to name with `n`.
    fn account_in_view(&self) -> Option<String> {
        let s = &self.s;
        match s.tab {
            Tab::Queues | Tab::Dashboard => s.queues.selected().map(|q| q.did.to_string()),
            Tab::Accounts => s.accounts.selected().map(|a| a.did.to_string()),
            Tab::Account => s
                .selected_peer()
                .or_else(|| Some(s.account_hash().to_string())),
            Tab::Grants => s.grants.selected().map(|g| account_hash(&g.did)),
            Tab::Audit | Tab::Config | Tab::Mux => None,
        }
    }

    fn name_popup(&self, hash: Option<String>) -> Popup {
        let entry = hash.as_deref().and_then(|h| self.s.book.lookup(h));
        Popup::Name {
            did: entry
                .filter(|e| !e.is_bare_hash())
                .map(|e| e.did.clone())
                .unwrap_or_default(),
            name: entry.map(|e| e.name.clone()).unwrap_or_default(),
            on_name: hash.is_some(),
            hash,
        }
    }

    /// Save a Name popup. Returns the popup to keep open when the input needs
    /// correcting.
    fn save_name(&mut self, hash: Option<String>, did: String, name: String) -> Option<Popup> {
        let (did, name) = (did.trim().to_string(), name.trim().to_string());
        let key = match (&hash, did.is_empty()) {
            (_, false) => {
                if let Some(h) = &hash
                    && account_hash(&did) != *h
                {
                    self.s.set_notice(
                        format!(
                            "that DID is account {}, not {}",
                            short(&account_hash(&did)),
                            short(h)
                        ),
                        true,
                    );
                    return Some(Popup::Name {
                        hash,
                        did,
                        name,
                        on_name: false,
                    });
                }
                did
            }
            (Some(h), true) => h.clone(),
            (None, true) => {
                self.s
                    .set_notice("paste a DID (or an account hash) to name", true);
                return Some(Popup::Name {
                    hash,
                    did,
                    name,
                    on_name: false,
                });
            }
        };
        let hash = account_hash(&key);
        if name.is_empty() {
            self.s.book.remove(&hash);
            self.s
                .set_notice(format!("{} unnamed", short(&hash)), false);
        } else {
            self.s.book.insert(&key, &name);
            self.s
                .set_notice(format!("{} is now {name}", short(&hash)), false);
        }
        self.save_book();
        None
    }

    /// Copy the full identifier behind the selected row — an account hash, a
    /// DID, a message id — to the terminal's clipboard (`y`).
    fn copy_selected(&mut self) {
        let s = &self.s;
        let picked: Option<(&str, String)> = match s.tab {
            Tab::Dashboard | Tab::Queues => s
                .queues
                .selected()
                .map(|q| ("account hash", q.did.to_string())),
            Tab::Accounts => s
                .accounts
                .selected()
                .map(|a| ("account hash", a.did.to_string())),
            Tab::Account => Some(match s.messages.selected() {
                Some(m) => ("message id", m.msg_id.to_string()),
                None => ("account hash", s.account_hash().to_string()),
            }),
            Tab::Audit => s
                .audit
                .selected()
                .and_then(|e| e.target.clone().or_else(|| e.actor.clone()))
                .map(|v| ("DID", v)),
            Tab::Config => s
                .config
                .selected()
                .map(|f| ("value", config_value(&f.value))),
            Tab::Mux => s.selected_principal().map(|v| ("principal DID", v)),
            Tab::Grants => s
                .grants
                .selected()
                .map(|g| ("member DID", g.did.to_string())),
        };
        match picked {
            Some((what, text)) => self.copy_out(what, &text),
            None => self.s.set_notice("nothing selected to copy", true),
        }
    }

    /// Send `text` to the terminal's clipboard and say so.
    fn copy_out(&mut self, what: &str, text: &str) {
        match crate::clipboard::copy(text) {
            Ok(()) => self.s.set_notice(
                format!(
                    "copied {what} {} (if the terminal allows OSC 52)",
                    short(text)
                ),
                false,
            ),
            Err(e) => self.s.set_notice(format!("copy failed: {e}"), true),
        }
    }

    fn popup_key(&mut self, popup: Popup, code: KeyCode) {
        let yes = matches!(code, KeyCode::Char('y') | KeyCode::Char('Y'));
        match popup {
            Popup::Logs { back } => {
                const PAGE: usize = 10;
                let back = match code {
                    KeyCode::Up | KeyCode::Char('k') => back.saturating_add(1),
                    KeyCode::Down | KeyCode::Char('j') => back.saturating_sub(1),
                    KeyCode::PageUp => back.saturating_add(PAGE),
                    KeyCode::PageDown => back.saturating_sub(PAGE),
                    KeyCode::Home => usize::MAX,
                    KeyCode::End => 0,
                    KeyCode::Char('c') => {
                        if let Some(logs) = &self.s.logs {
                            logs.clear();
                        }
                        0
                    }
                    // Esc, q, l or anything else closes it.
                    _ => {
                        if let Some(logs) = &self.s.logs {
                            logs.mark_seen();
                        }
                        return;
                    }
                };
                self.s.popup = Some(Popup::Logs { back });
            }
            Popup::Name {
                hash,
                mut did,
                mut name,
                on_name,
            } => match code {
                KeyCode::Esc => self.s.set_notice("cancelled", false),
                KeyCode::Enter => self.s.popup = self.save_name(hash, did, name),
                KeyCode::Tab | KeyCode::BackTab | KeyCode::Up | KeyCode::Down => {
                    self.s.popup = Some(Popup::Name {
                        hash,
                        did,
                        name,
                        on_name: !on_name,
                    })
                }
                other => {
                    let field = if on_name { &mut name } else { &mut did };
                    edit_text(field, other);
                    self.s.popup = Some(Popup::Name {
                        hash,
                        did,
                        name,
                        on_name,
                    });
                }
            },
            Popup::Book { selected } => {
                let len = self.s.book.entries().len();
                match code {
                    KeyCode::Down | KeyCode::Char('j') => {
                        self.s.popup = Some(Popup::Book {
                            selected: (selected + 1).min(len.saturating_sub(1)),
                        })
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        self.s.popup = Some(Popup::Book {
                            selected: selected.saturating_sub(1),
                        })
                    }
                    KeyCode::Char('x') | KeyCode::Delete => {
                        if let Some(entry) = self.s.book.entries().get(selected).cloned() {
                            self.s.book.remove(&entry.hash());
                            self.save_book();
                            self.s.set_notice(format!("{} removed", entry.name), false);
                        }
                        self.s.popup = Some(Popup::Book {
                            selected: selected.min(len.saturating_sub(2)),
                        });
                    }
                    KeyCode::Char('n') | KeyCode::Enter => {
                        let hash = self.s.book.entries().get(selected).map(|e| e.hash());
                        self.s.popup = Some(self.name_popup(hash));
                    }
                    KeyCode::Char('a') => self.s.popup = Some(self.name_popup(None)),
                    _ => {}
                }
            }
            Popup::Inspect {
                id,
                body,
                mut scroll,
            } => {
                let lines = body.lines().count() as u16;
                let page = self.s.page_rows.max(1) as u16;
                match code {
                    KeyCode::Up | KeyCode::Char('k') => scroll = scroll.saturating_sub(1),
                    KeyCode::Down | KeyCode::Char('j') => scroll = scroll.saturating_add(1),
                    KeyCode::PageUp => scroll = scroll.saturating_sub(page),
                    KeyCode::PageDown | KeyCode::Char(' ') => scroll = scroll.saturating_add(page),
                    KeyCode::Home => scroll = 0,
                    KeyCode::End => scroll = lines,
                    KeyCode::Char('y') => self.copy_out("message", &body),
                    KeyCode::Char('w') => {
                        let dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
                        match crate::clipboard::save(&dir, &format!("message-{id}"), &body) {
                            Ok(path) => self.s.set_notice(
                                format!("message written to {}", path.display()),
                                false,
                            ),
                            Err(e) => self.s.set_notice(format!("message not written: {e}"), true),
                        }
                    }
                    // Esc, q or anything else closes it.
                    _ => return,
                }
                self.s.popup = Some(Popup::Inspect {
                    id,
                    body,
                    scroll: scroll.min(lines.saturating_sub(1)),
                });
            }
            Popup::Help { scroll } => {
                let scroll = match code {
                    KeyCode::Up | KeyCode::Char('k') => scroll.saturating_sub(1),
                    KeyCode::Down | KeyCode::Char('j') => scroll.saturating_add(1).min(200),
                    KeyCode::PageUp => scroll.saturating_sub(10),
                    KeyCode::PageDown => scroll.saturating_add(10).min(200),
                    _ => return,
                };
                self.s.popup = Some(Popup::Help { scroll });
            }
            Popup::ConfirmAccount { edit, .. } if yes => self.save_account(edit),
            // Anything else goes back to the editor, the changes intact.
            Popup::ConfirmAccount { edit, .. } => {
                self.s.set_notice("not saved — still editing", false);
                self.s.popup = Some(Popup::EditAccount(edit));
            }
            Popup::ConfirmPatch { key, to, .. } if yes => self.patch(key, to),
            Popup::ConfirmPatch {
                key,
                typed: Some(value),
                ..
            } => {
                self.s.set_notice("not applied — still editing", false);
                self.s.popup = Some(Popup::EditConfig { key, value });
            }
            Popup::ConfirmPatch { .. } => self.s.set_notice("cancelled", false),
            Popup::EditAccount(mut edit) => match code {
                KeyCode::Esc => self.s.set_notice("cancelled", false),
                KeyCode::Char('s') => {
                    if edit.changed() {
                        self.s.popup = Some(self.confirm_account(edit));
                    } else {
                        self.s.set_notice("nothing changed", false);
                    }
                }
                other => {
                    match other {
                        KeyCode::Up | KeyCode::Char('k') => edit.up(),
                        KeyCode::Down | KeyCode::Char('j') => edit.down(),
                        KeyCode::Char(' ') | KeyCode::Enter => edit.toggle(),
                        KeyCode::Backspace => edit.backspace(),
                        KeyCode::Char(c) => edit.type_char(c),
                        _ => {}
                    }
                    self.s.popup = Some(Popup::EditAccount(edit));
                }
            },
            Popup::EditConfig { key, mut value } => match code {
                KeyCode::Esc => self.s.set_notice("cancelled", false),
                KeyCode::Enter => {
                    // A number when it reads as one; otherwise the text as given.
                    let parsed = serde_json::from_str::<Value>(value.trim())
                        .unwrap_or_else(|_| Value::String(value.trim().to_string()));
                    let from = self
                        .s
                        .config
                        .rows
                        .iter()
                        .find(|f| f.key.as_str() == key)
                        .map(|f| config_value(&f.value))
                        .unwrap_or_else(|| "?".into());
                    self.s.popup = Some(Popup::ConfirmPatch {
                        key,
                        from,
                        to: parsed,
                        typed: Some(value),
                    });
                }
                other => {
                    edit_text(&mut value, other);
                    self.s.popup = Some(Popup::EditConfig { key, value });
                }
            },
            Popup::FindGrants {
                mut principal,
                mut member,
                on_member,
            } => match code {
                KeyCode::Esc => self.s.set_notice("cancelled", false),
                KeyCode::Enter => {
                    let query = GrantQuery::from_fields(&principal, &member);
                    if query.is_empty() {
                        self.s
                            .set_notice("name a principal DID, a member DID, or both", true);
                        self.s.popup = Some(Popup::FindGrants {
                            principal,
                            member,
                            on_member,
                        });
                    } else {
                        self.open_grants(query);
                    }
                }
                KeyCode::Tab | KeyCode::BackTab | KeyCode::Up | KeyCode::Down => {
                    self.s.popup = Some(Popup::FindGrants {
                        principal,
                        member,
                        on_member: !on_member,
                    })
                }
                other => {
                    let field = if on_member {
                        &mut member
                    } else {
                        &mut principal
                    };
                    edit_text(field, other);
                    self.s.popup = Some(Popup::FindGrants {
                        principal,
                        member,
                        on_member,
                    });
                }
            },
            Popup::ConfirmRevoke(selection) if yes => {
                self.spawn(move |c| async move {
                    Update::Done(c.mux_revoke(&selection).await.map(|o| revoke_summary(&o)))
                });
            }
            Popup::ConfirmRevokeMarked(keys) if yes => {
                self.spawn(move |c| async move {
                    Update::RevokedMarked(c.mux_revoke_each(&keys).await)
                });
            }
            Popup::ConfirmBumpEpoch { did, epoch } if yes => {
                let name = did_label(&self.s.book, &did);
                self.spawn(move |c| async move {
                    Update::Done(c.mux_bump_epoch(&did, epoch).await.map(|r| {
                        bump_summary(&name, epoch, r.epoch, r.epoch_advanced, r.revoked_grants)
                    }))
                });
            }
            Popup::Text { .. } => {}
            Popup::ConfirmDelete { target, ids, .. } if yes => {
                self.spawn(move |c| async move {
                    Update::Done(c.delete(target, &ids).await.map(|r| {
                        let deleted = r.results.iter().filter(|x| x.deleted).count();
                        format!("deleted {deleted} message(s)")
                    }))
                });
            }
            Popup::ConfirmPurge(plan) if yes => {
                let matched = plan.matched;
                self.spawn(move |c| async move {
                    Update::Done(
                        c.purge(plan)
                            .await
                            .map(|r| purge_summary(matched, r.purged)),
                    )
                });
            }
            // Anything but "y" cancels a confirmation.
            Popup::ConfirmDelete { .. }
            | Popup::ConfirmPurge(_)
            | Popup::ConfirmRevoke(_)
            | Popup::ConfirmRevokeMarked(_)
            | Popup::ConfirmBumpEpoch { .. } => self.s.set_notice("cancelled", false),
        }
    }

    pub(crate) fn move_selection(&mut self, delta: i32) {
        let s = &mut self.s;
        let (state, len, more) = match s.tab {
            Tab::Queues | Tab::Dashboard => (
                &mut s.queues.table,
                s.queues.rows.len(),
                s.queues.next.is_some(),
            ),
            Tab::Account => (
                &mut s.messages.table,
                s.messages.rows.len(),
                s.messages.next.is_some(),
            ),
            Tab::Accounts => (
                &mut s.accounts.table,
                s.accounts.rows.len(),
                s.accounts.next.is_some(),
            ),
            Tab::Audit => (
                &mut s.audit.table,
                s.audit.rows.len(),
                s.audit.next.is_some(),
            ),
            Tab::Config => (&mut s.config.table, s.config.rows.len(), false),
            Tab::Mux => (
                &mut s.mux_table,
                s.mux.as_ref().map_or(0, |p| p.connections.len()),
                false,
            ),
            Tab::Grants => (&mut s.grants.table, s.grants.rows.len(), false),
        };
        if len == 0 {
            return;
        }
        let i = (state.selected().unwrap_or(0) as i32 + delta).clamp(0, len as i32 - 1) as usize;
        state.select(Some(i));
        // At the last row of a list with more behind it: fetch the next page.
        if delta > 0 && i + 1 == len && more {
            self.load_more();
        }
    }

    /// The confirmation an account edit needs before it is sent: what
    /// changes, and a warning when it can lock the console out.
    fn confirm_account(&self, mut edit: AccountEdit) -> Popup {
        let changes = edit
            .diff()
            .into_iter()
            .map(|(name, was, now)| format!("{name}: {was} → {now}"))
            .collect();
        let own = edit.target == self.s.session.did_hash;
        let warning = edit.risks_lockout().filter(|_| own).map(|what| {
            format!(
                "⚠ This is the account the console is signed in as. {what} can lock \
                 you out of this console, and only another administrator can undo it."
            )
        });
        let who = if own {
            format!("{} (you)", label(&self.s.book, &edit.target))
        } else {
            label(&self.s.book, &edit.target)
        };
        Popup::ConfirmAccount {
            edit,
            who,
            changes,
            warning,
        }
    }

    /// Send an account edit's changes with `account/update`.
    fn save_account(&mut self, mut edit: AccountEdit) {
        let changes = edit.changes();
        let target = (edit.target != self.s.session.did_hash).then(|| edit.target.clone());
        self.spawn(move |c| async move {
            Update::Done(
                c.update_account(target, changes.role, changes.acl, changes.limits)
                    .await
                    .map(|_| "account updated".to_string()),
            )
        });
    }

    /// Ask the mediator to set `key` to `value` (`null` removes its override).
    fn patch(&self, key: String, value: Value) {
        self.spawn(move |c| async move {
            let mut overrides = serde_json::Map::new();
            overrides.insert(key, value);
            Update::Patched(c.patch_config(overrides).await)
        });
    }

    /// A page of the list on screen after the one shown: `]`, or reaching
    /// its last row.
    pub(crate) fn load_more(&mut self) {
        let list = match self.s.tab {
            Tab::Dashboard | Tab::Queues => List::Queues,
            Tab::Account => List::Messages,
            Tab::Audit => List::Audit,
            Tab::Accounts => List::Accounts,
            Tab::Grants => {
                match self.s.grants.next.clone() {
                    Some(cursor) => self.load_grants(Some(cursor), super::GRANT_PAGE),
                    None => self.s.set_notice("no more grants", false),
                }
                return;
            }
            _ => return,
        };
        if self.inflight.is_pending(Job::More(list)) {
            return;
        }
        let s = &self.s;
        let next = match list {
            List::Queues => s.queues.next.clone(),
            List::Messages => s.messages.next.clone(),
            List::Audit => s.audit.next.clone(),
            List::Accounts => s.accounts.next.clone(),
        };
        match (list, next) {
            (_, None) => self.s.set_notice("that's all of them", false),
            (List::Queues, Some(c)) => self.queue_page(Some(c)),
            (List::Messages, Some(c)) => self.load_messages(Some(c)),
            (List::Audit, Some(c)) => self.load_audit(Some(c)),
            (List::Accounts, Some(c)) => self.load_accounts(Some(c)),
        }
    }
}

/// Typing into a text field: a character, or Backspace.
fn edit_text(field: &mut String, code: KeyCode) {
    match code {
        KeyCode::Backspace => {
            field.pop();
        }
        KeyCode::Char(c) => field.push(c),
        _ => {}
    }
}

/// The lines a delete confirmation shows: whose message, from which queue,
/// which one, from and to whom.
fn delete_summary(s: &super::state::State, m: &MessageRow) -> Vec<String> {
    let who = |v: &Option<specs::message::list::v0_1::Vid>| {
        v.as_deref()
            .map_or_else(|| "anonymous".to_string(), |h| label(&s.book, h))
    };
    vec![
        format!("Account  {}", s.account_label()),
        format!(
            "Queue    {}",
            if s.message_send { "send" } else { "receive" }
        ),
        format!("Message  {}", m.msg_id.as_str()),
        format!("From     {}", who(&m.from)),
        format!("To       {}", who(&m.to)),
        format!(
            "Received {}  ({})",
            m.received_at.to_rfc3339(),
            human_bytes(Some(m.size))
        ),
    ]
}

/// What a confirmed purge did, against what was counted.
fn purge_summary(matched: u64, purged: u64) -> String {
    if purged < matched {
        format!(
            "purged {purged} of the {matched} message(s) counted; the rest were delivered or \
             deleted meanwhile"
        )
    } else {
        format!("purged {purged} message(s)")
    }
}

/// What advancing member `name`'s epoch did, in a sentence.
fn bump_summary(name: &str, named: u64, epoch: u64, advanced: bool, revoked: u64) -> String {
    if advanced {
        format!("epoch of {name} advanced {named} → {epoch}: {revoked} grant(s) voided")
    } else {
        format!("epoch {named} of {name} was already voided (now {epoch}); nothing changed")
    }
}

#[cfg(test)]
mod tests {
    use super::super::Tab;
    use super::super::screens::testing::state;
    use super::*;

    #[test]
    fn an_epoch_bump_says_whether_it_advanced() {
        assert_eq!(
            bump_summary("work", 0, 1, true, 2),
            "epoch of work advanced 0 → 1: 2 grant(s) voided"
        );
        assert_eq!(
            bump_summary("work", 0, 3, false, 0),
            "epoch 0 of work was already voided (now 3); nothing changed"
        );
    }

    #[test]
    fn a_short_purge_says_what_happened_to_the_rest() {
        assert_eq!(purge_summary(3, 3), "purged 3 message(s)");
        assert!(purge_summary(3, 2).starts_with("purged 2 of the 3"));
    }

    #[test]
    fn a_delete_confirmation_names_its_account_queue_and_message() {
        let mut s = state(Tab::Account);
        s.book.insert("did:example:alice", "alice");
        s.target = Some("bobhash".into());
        s.book.insert("bobhash", "bob");
        let m: MessageRow = serde_json::from_value(serde_json::json!({
            "msgId": "m-1", "from": sha256::digest("did:example:alice"), "queue": "receive",
            "to": "bobhash", "receivedAt": "2026-09-21T10:00:00Z", "size": 10,
        }))
        .unwrap();
        let lines = delete_summary(&s, &m).join("\n");
        for want in [
            "Account  bob",
            "Queue    receive",
            "Message  m-1",
            "From     alice",
            "To       bob",
        ] {
            assert!(lines.contains(want), "{want}:\n{lines}");
        }
    }
}
