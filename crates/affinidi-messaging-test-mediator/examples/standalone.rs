//! **Test fixture only: plain HTTP (no TLS) and an allow-all ACL.** Never
//! bind it to an interface anyone else can reach; it says so loudly on
//! start-up when the bind address is not loopback.
//!
//! Run the in-process [`TestMediator`] as a **standalone process**, so
//! out-of-process test clients — a separately-spawned daemon, a client running
//! inside a Docker container, a CI job on another host — can share one mediator
//! for local DIDComm testing. Prints the mediator DID + endpoints, then blocks
//! until the process is killed.
//!
//! Run from the workspace root:
//!   cargo run -p affinidi-messaging-test-mediator --example standalone
//!
//! ## Environment
//!
//! - `TEST_MEDIATOR_LISTEN` — bind address (`host:port`). Default `127.0.0.1:0`
//!   (loopback, OS-assigned port). Use `0.0.0.0:0` to bind every interface.
//! - `TEST_MEDIATOR_ADVERTISE_HOST` — host to advertise in the mediator's DID
//!   service endpoint instead of the bound address. Set this when clients reach
//!   the mediator from a different network namespace than loopback — e.g.
//!   `host.docker.internal` for clients in Docker containers. See
//!   [`TestMediatorBuilder::advertise_host`].
//!
//! ## Example — reachable from inside Docker containers
//!
//! ```sh
//! TEST_MEDIATOR_LISTEN=0.0.0.0:0 \
//! TEST_MEDIATOR_ADVERTISE_HOST=host.docker.internal \
//!   cargo run -p affinidi-messaging-test-mediator --example standalone
//! ```
//!
//! Binds all interfaces but puts `host.docker.internal:<port>` in the mediator's
//! DID, so a containerized client (which reaches the host via the Docker gateway,
//! not `127.0.0.1`) can both *connect to* and *receive replies through* the
//! mediator.

use affinidi_messaging_test_mediator::{AccessListModeType, TestMediator, acl::allow_all};

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Permissive ACL: any DID may connect/register and send/receive.
    // Standalone harnesses typically connect with arbitrary, unregistered
    // DIDs, which take the global default ACL. The mediator's default one
    // has no `local` (so no WebSocket upgrade); `allow_all` grants
    // everything. `ExplicitDeny` is the builder's default mode too, set here
    // so the harness reads as what it is: an access list that admits anyone
    // not on it.
    let mut builder = TestMediator::builder()
        .acl_mode(AccessListModeType::ExplicitDeny)
        .global_acl_default(allow_all());

    if let Ok(addr) = std::env::var("TEST_MEDIATOR_LISTEN") {
        builder = builder.listen_addr(
            addr.parse::<std::net::SocketAddr>()
                .expect("TEST_MEDIATOR_LISTEN must be host:port"),
        );
    }
    if let Ok(host) = std::env::var("TEST_MEDIATOR_ADVERTISE_HOST")
        && !host.is_empty()
    {
        builder = builder.advertise_host(host);
    }

    let mediator = builder.spawn().await?;
    if !mediator.bound_addr().ip().is_loopback() {
        eprintln!(
            "\n\
             ************************************************************************\n\
             *  TEST FIXTURE — no TLS, allow-all ACL. Not a production mediator.     *\n\
             *  Bound to {:<59} *\n\
             *  Any client that can reach this address can register and relay mail. *\n\
             ************************************************************************\n",
            mediator.bound_addr().to_string()
        );
    }
    println!("MEDIATOR_DID={}", mediator.did());
    println!("MEDIATOR_HTTP={}", mediator.endpoint());
    println!("MEDIATOR_WS={}", mediator.ws_endpoint());
    eprintln!("[test-mediator] running; kill the process to stop");

    std::future::pending::<()>().await;
    drop(mediator);
    Ok(())
}
