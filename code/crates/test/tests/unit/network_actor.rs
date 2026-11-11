//! Tests of the `Network` actor.
//!
//! The network the actor starts ends with the actor, however the actor stops.
//! Ractor kills the children of a stopping actor, and a killed actor skips
//! `post_stop`, where the actor shuts its network down.
//!
//! A subscriber is sent the validator proofs that the actor received before it
//! subscribed, from peers still connected, and whose verification has not been
//! reported. A peer sends its proof once per session, and peers connect as soon
//! as the network starts, before the consensus actor subscribes to it.

use std::net::TcpListener;
use std::time::Duration;

use async_trait::async_trait;
use libp2p_identity::{Keypair, PeerId};
use ractor::{Actor, ActorProcessingErr, ActorRef, RpcReplyPort};
use rand::rngs::StdRng;
use rand::SeedableRng;

use arc_malachitebft_test::codec::proto::ProtobufCodec;
use arc_malachitebft_test::{Ed25519Signer, TestContext};

use malachitebft_app::spawn::{spawn_network_actor, spawn_node_actor};
use malachitebft_codec::Codec;
use malachitebft_config::{ConsensusConfig, P2pConfig, ValueSyncConfig};
use malachitebft_engine::network::{
    Multiaddr, NetworkEvent, NetworkIdentity, NetworkMsg, NetworkRef,
};
use malachitebft_metrics::{Metrics, SharedRegistry};
use malachitebft_network::validator_proof::ProofVerificationResult;
use malachitebft_network::PeerIdExt;
use malachitebft_signing::Signer;
use malachitebft_signing_ed25519::PrivateKey;

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
    let identity = NetworkIdentity::new(moniker.to_string(), keypair, None);
    spawn_network_as(identity, listen_addr, persistent_peers).await
}

async fn spawn_network_as(
    identity: NetworkIdentity,
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
        identity,
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

/// The identity of a validator whose consensus key comes from `seed`, with its
/// signed proof, and the key's bytes.
async fn validator_identity(
    moniker: &str,
    keypair: Keypair,
    seed: u64,
) -> (NetworkIdentity, Vec<u8>) {
    let private_key = PrivateKey::generate(StdRng::seed_from_u64(seed));
    let public_key = private_key.public_key().as_bytes().to_vec();
    let peer_id = keypair.public().to_peer_id().to_bytes();
    let proof = Ed25519Signer::new(private_key)
        .sign_validator_proof(public_key.clone(), peer_id)
        .await
        .expect("sign the validator proof");
    let proof = ProtobufCodec
        .encode(&proof)
        .expect("encode the validator proof");
    let identity =
        NetworkIdentity::new_validator(moniker.to_string(), keypair, moniker.to_string(), proof);
    (identity, public_key)
}

/// Records the peers whose validator proofs a subscriber of a network is sent,
/// and the peers it is told disconnected.
struct ProofRecorder;

#[derive(Default)]
struct Recorded {
    proofs: Vec<PeerId>,
    disconnections: Vec<PeerId>,
}

enum RecorderMsg {
    /// The peer of a validator proof the network sent.
    Proof(PeerId),
    /// A peer the network reported disconnected.
    Disconnected(PeerId),
    /// Another event of the network.
    Other,
    Proofs(RpcReplyPort<Vec<PeerId>>),
    Disconnections(RpcReplyPort<Vec<PeerId>>),
}

impl From<NetworkEvent<TestContext>> for RecorderMsg {
    fn from(event: NetworkEvent<TestContext>) -> Self {
        match event {
            NetworkEvent::ValidatorProofReceived { peer_id, .. } => {
                Self::Proof(peer_id.to_libp2p())
            }
            NetworkEvent::PeerDisconnected(peer_id) => Self::Disconnected(peer_id.to_libp2p()),
            _ => Self::Other,
        }
    }
}

#[async_trait]
impl Actor for ProofRecorder {
    type Msg = RecorderMsg;
    type State = Recorded;
    type Arguments = ();

    async fn pre_start(
        &self,
        _myself: ActorRef<RecorderMsg>,
        _args: (),
    ) -> Result<Recorded, ActorProcessingErr> {
        Ok(Recorded::default())
    }

    async fn handle(
        &self,
        _myself: ActorRef<RecorderMsg>,
        msg: RecorderMsg,
        recorded: &mut Recorded,
    ) -> Result<(), ActorProcessingErr> {
        match msg {
            RecorderMsg::Proof(peer_id) => recorded.proofs.push(peer_id),
            RecorderMsg::Disconnected(peer_id) => recorded.disconnections.push(peer_id),
            RecorderMsg::Other => {}
            RecorderMsg::Proofs(reply) => {
                let _ = reply.send(recorded.proofs.clone());
            }
            RecorderMsg::Disconnections(reply) => {
                let _ = reply.send(recorded.disconnections.clone());
            }
        }
        Ok(())
    }
}

/// Subscribes a new recorder to `network`, and returns it once the network has
/// sent it what it sends a new subscriber.
async fn subscribe_recorder(network: &NetworkRef<TestContext>) -> ActorRef<RecorderMsg> {
    let (recorder, _) = Actor::spawn(None, ProofRecorder, ())
        .await
        .expect("spawn the recorder");
    network
        .cast(NetworkMsg::Subscribe(Box::new(recorder.clone())))
        .expect("the network actor runs");
    // The network handles its messages in order, so once it has answered this
    // it has sent the recorder all it sends on a subscription, which the recorder
    // handles before a later message.
    ractor::call!(network, NetworkMsg::DumpState).expect("the network actor replies");
    recorder
}

async fn proofs_sent(recorder: &ActorRef<RecorderMsg>) -> Vec<PeerId> {
    ractor::call!(recorder, RecorderMsg::Proofs).expect("the recorder replies")
}

async fn disconnections_sent(recorder: &ActorRef<RecorderMsg>) -> Vec<PeerId> {
    ractor::call!(recorder, RecorderMsg::Disconnections).expect("the recorder replies")
}

/// Waits until `recorder` has been sent `peer`'s validator proof.
async fn wait_proof(recorder: &ActorRef<RecorderMsg>, peer: &PeerId) {
    let deadline = tokio::time::Instant::now() + CONNECT_BOUND;
    while !proofs_sent(recorder).await.contains(peer) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the node did not receive the validator's proof"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn late_subscriber_is_sent_the_proofs_not_yet_verified() {
    let node_addr = free_address();
    let node = spawn_network(
        "network-actor-node",
        Keypair::generate_ed25519(),
        node_addr.clone(),
        vec![],
    )
    .await;
    let early = subscribe_recorder(&node).await;

    let validator_keypair = Keypair::generate_ed25519();
    let validator_id = validator_keypair.public().to_peer_id();
    let (identity, public_key) =
        validator_identity("network-actor-validator", validator_keypair, 7).await;
    let validator = spawn_network_as(identity, free_address(), vec![node_addr.clone()]).await;
    wait_proof(&early, &validator_id).await;

    // The proof arrived before this subscriber, as it does before the consensus
    // actor subscribes when peers connect at once.
    let late = subscribe_recorder(&node).await;
    assert_eq!(proofs_sent(&late).await, vec![validator_id]);

    node.cast(NetworkMsg::ValidatorProofVerified {
        peer_id: malachitebft_network::PeerId::from_libp2p(&validator_id),
        result: ProofVerificationResult::Valid,
        public_key: Some(public_key),
    })
    .expect("the network actor runs");
    let after = subscribe_recorder(&node).await;
    assert!(
        proofs_sent(&after).await.is_empty(),
        "a verified proof is not verified again"
    );

    // A validator that leaves before its proof is verified takes its proof with it.
    let leaving_keypair = Keypair::generate_ed25519();
    let leaving_id = leaving_keypair.public().to_peer_id();
    let (identity, _) = validator_identity("network-actor-leaving", leaving_keypair, 8).await;
    let leaving = spawn_network_as(identity, free_address(), vec![node_addr]).await;
    wait_proof(&early, &leaving_id).await;
    leaving.stop(None);
    let deadline = tokio::time::Instant::now() + CLOSE_BOUND;
    while !disconnections_sent(&early).await.contains(&leaving_id) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the node did not report the leaving validator disconnected"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let gone = subscribe_recorder(&node).await;
    assert!(
        proofs_sent(&gone).await.is_empty(),
        "the proof of a peer that is gone is sent"
    );

    validator.stop(None);
    node.stop(None);
}
