//! Tests that the network a `Network` actor starts ends with the actor, however
//! the actor stops. Ractor kills the children of a stopping actor, and a killed
//! actor skips `post_stop`, where the actor shuts its network down.

use std::net::TcpListener;
use std::time::Duration;

use libp2p_identity::{Keypair, PeerId};

use arc_malachitebft_test::codec::proto::ProtobufCodec;
use arc_malachitebft_test::TestContext;

use malachitebft_app::spawn::{spawn_network_actor, spawn_node_actor};
use malachitebft_config::{ConsensusConfig, P2pConfig, ValueSyncConfig};
use malachitebft_engine::network::{Multiaddr, NetworkIdentity, NetworkMsg, NetworkRef};
use malachitebft_metrics::{Metrics, SharedRegistry};

/// How long a peer may still hold a connection to a network whose actor stopped.
const CLOSE_BOUND: Duration = Duration::from_secs(5);

/// How long two networks may take to connect.
const CONNECT_BOUND: Duration = Duration::from_secs(10);

/// Returns a TCP address on the loopback interface that nothing listens on.
fn free_address() -> Multiaddr {
    let port = TcpListener::bind("127.0.0.1:0")
        .and_then(|listener| listener.local_addr())
        .expect("bind an ephemeral port")
        .port();
    format!("/ip4/127.0.0.1/tcp/{port}").parse().unwrap()
}

async fn spawn_network(
    moniker: &str,
    keypair: Keypair,
    listen_addr: Multiaddr,
    persistent_peers: Vec<Multiaddr>,
) -> NetworkRef<TestContext> {
    let consensus = ConsensusConfig {
        p2p: P2pConfig {
            listen_addr,
            persistent_peers,
            ..P2pConfig::default()
        },
        ..ConsensusConfig::default()
    };

    spawn_network_actor(
        &consensus,
        &ValueSyncConfig::default(),
        NetworkIdentity::new(moniker.to_string(), keypair, None),
        &SharedRegistry::new(Default::default(), None),
        ProtobufCodec,
    )
    .await
    .expect("spawn the network actor")
}

/// Whether `network` holds a connection to `peer`, by the state it dumps.
async fn holds_connection_to(network: &NetworkRef<TestContext>, peer: &PeerId) -> bool {
    let dump = ractor::call!(network, NetworkMsg::DumpState)
        .expect("the network actor replies")
        .expect("the network is running");
    dump.peers.contains_key(peer)
}

/// Waits until `network` does or does not hold a connection to `peer`, up to
/// `bound`. Returns whether it got there.
async fn wait_connection(
    network: &NetworkRef<TestContext>,
    peer: &PeerId,
    connected: bool,
    bound: Duration,
) -> bool {
    let deadline = tokio::time::Instant::now() + bound;
    loop {
        if holds_connection_to(network, peer).await == connected {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// A node's network connected to a peer's, and the node's identity.
struct ConnectedPair {
    node: NetworkRef<TestContext>,
    node_id: PeerId,
    peer: NetworkRef<TestContext>,
}

async fn connected_pair() -> ConnectedPair {
    let peer_addr = free_address();
    let peer = spawn_network(
        "network-actor-peer",
        Keypair::generate_ed25519(),
        peer_addr.clone(),
        vec![],
    )
    .await;

    let node_keypair = Keypair::generate_ed25519();
    let node_id = node_keypair.public().to_peer_id();
    let node = spawn_network(
        "network-actor-node",
        node_keypair,
        free_address(),
        vec![peer_addr],
    )
    .await;

    assert!(
        wait_connection(&peer, &node_id, true, CONNECT_BOUND).await,
        "the node did not connect to the peer"
    );

    ConnectedPair {
        node,
        node_id,
        peer,
    }
}

async fn assert_peer_lets_go(pair: ConnectedPair, stopped: &str) {
    assert!(
        wait_connection(&pair.peer, &pair.node_id, false, CLOSE_BOUND).await,
        "the peer still holds a connection to a network whose actor was {stopped}, after {CLOSE_BOUND:?}"
    );
    pair.peer.stop(None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn killed_network_actor_closes_its_connections() {
    let pair = connected_pair().await;

    pair.node.kill();

    assert_peer_lets_go(pair, "killed").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stopped_node_closes_its_network_connections() {
    let (node, _) = spawn_node_actor(Metrics::register(&SharedRegistry::new(
        Default::default(),
        None,
    )))
    .await
    .expect("spawn the node actor");

    let pair = connected_pair().await;
    pair.node.link(node.get_cell());

    node.stop(None);

    assert_peer_lets_go(pair, "stopped with its node").await;
}
