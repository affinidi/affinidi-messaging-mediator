//! The test mediator's end-to-end suite, as one test binary.
//!
//! Each file here was its own integration-test binary, each linking the whole
//! mediator, SDK and TDK. One binary links once. Run one area with a filter:
//!
//! ```sh
//! cargo test -p affinidi-messaging-test-mediator --test e2e -- mux_send::
//! ```
//!
//! Tests that need a process of their own (the Prometheus recorder and the
//! recorded configuration path are process-wide) stay separate binaries in
//! `tests/`.

#[path = "../common/mod.rs"]
mod common;
#[path = "../support/forge.rs"]
mod forge;

mod account_activity;
mod account_counters;
mod acknowledgement_scope;
mod authcrypt_forgery;
mod authentication_session;
mod clock_injection;
mod credo_mediation_interop;
mod cross_mediator_forwarding;
mod delivery_path_correctness;
mod did_rate_limit;
mod didcomm_v1_mediation;
mod direct_delivery_queue_limits;
mod direct_delivery_uniform_refusal;
mod explicit_allow_auth_gate;
mod fjall_backend;
mod forward_recipient_admission;
mod forwarding_abandonment_report;
mod forwarding_processor;
mod health_endpoints;
mod http_hardening;
mod lifecycle;
mod local_did_websocket;
mod mediator_ops;
mod monitor_membership;
mod monitor_membership_two_instances;
mod mux_admin;
mod mux_admin_two_instances;
mod mux_audit;
mod mux_connection;
mod mux_cross_instance;
mod mux_fair_queue;
mod mux_limits;
mod mux_member_standing;
mod mux_notice;
mod mux_notice_sdk;
mod mux_open_race;
mod mux_sdk;
mod mux_send;
mod mux_standing_two_instances;
mod mux_startup;
mod mux_two_instances;
mod mux_two_processes;
mod privileged_accounts;
mod receive_leg_probe;
mod receive_messages_acl;
mod request_identity_and_roles;
mod size_sweep;
mod soft_restart_websocket;
mod streaming_forwarding_acl;
mod topology;
mod trust_task_error;
mod trust_tasks;
mod trust_tasks_transport;
mod tsp_auth;
mod tsp_capability;
mod tsp_cross_mediator;
mod tsp_delivery;
mod tsp_discover_capability;
mod tsp_federation;
mod tsp_invite_then_payload;
mod tsp_live_stream;
mod tsp_mediated_recipient;
mod tsp_monitor;
mod tsp_mutual_cancel;
mod tsp_mux;
mod tsp_mux_sdk;
mod tsp_mux_two_instances;
mod tsp_pickup_socket;
mod tsp_relay_peer_trust;
mod tsp_send_to;
mod tsp_session_binding;
mod tsp_transport_adapter;
mod tsp_websocket;
mod unprocessable_live_frames;
mod wake;
mod websocket_expired_token;
mod websocket_limits;
mod websocket_liveness;
mod websocket_per_did_cap;
mod websocket_shutdown;
mod websocket_subprotocol_auth;
mod ws_message_rate;
mod ws_relay_admission;
mod ws_relay_limits;
