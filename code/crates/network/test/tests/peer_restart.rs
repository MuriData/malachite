//! A peer that starts again while a node still holds a connection of its last
//! run, as a crash or a partition leaves one half open.
//!
//! GossipSub sends a node's subscriptions, and the validator-proof protocol its
//! proof, only on the first connection to a peer. The node that holds the old
//! connection takes the new instance's connection for an additional one and
//! sends neither, so the new instance can neither publish to it nor graft it
//! into its mesh nor take it for a validator, until the old connection closes.

use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use malachitebft_metrics::SharedRegistry;
use malachitebft_network::handle::CtrlHandle;
use malachitebft_network::validator_proof::ProofVerificationResult;
use malachitebft_network::{
    spawn, Bytes, Channel, ChannelNames, Config, DiscoveryConfig, Event, GossipSubConfig, Keypair,
    Multiaddr, NetworkIdentity, PeerId, PeerIdExt, ProtocolNames, PubSubProtocol,
    TransportProtocol,
};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::{sleep, Instant};

/// How long two nodes may take to hear each other after they connect.
const HEAR_BOUND: Duration = Duration::from_secs(15);

/// How long the nodes keep running once they hear each other, to catch a
/// connection that closes again.
const SETTLE: Duration = Duration::from_secs(3);

fn tcp_address(addr: SocketAddr) -> Multiaddr {
    format!("/ip4/{}/tcp/{}", addr.ip(), addr.port())
        .parse()
        .unwrap()
}

/// Returns a TCP address on the loopback interface that nothing listens on.
fn free_address() -> SocketAddr {
    StdTcpListener::bind("127.0.0.1:0")
        .and_then(|listener| listener.local_addr())
        .expect("bind an ephemeral port")
}

fn make_config(listen_addr: SocketAddr, persistent_peers: Vec<Multiaddr>) -> Config {
    Config {
        listen_addr: tcp_address(listen_addr),
        persistent_peers,
        persistent_peers_only: false,
        discovery: DiscoveryConfig {
            enabled: false,
            max_connections_per_ip: usize::MAX,
            ..Default::default()
        },
        idle_connection_timeout: Duration::from_secs(60),
        transport: TransportProtocol::Tcp,
        gossipsub: GossipSubConfig::default(),
        pubsub_protocol: PubSubProtocol::GossipSub,
        channel_names: ChannelNames::default(),
        rpc_max_size: 10 * 1024 * 1024,
        pubsub_max_size: 4 * 1024 * 1024,
        pubsub_max_size_per_topic: Default::default(),
        sync_request_timeout: Duration::from_secs(10),
        sync_max_request_size: 1024 * 1024,
        sync_parallel_requests: 5,
        enable_consensus: true,
        enable_sync: false,
        protocol_names: ProtocolNames::default(),
    }
}

/// What a node's network reported.
#[derive(Default)]
struct Observed {
    /// The peer of every validator proof that arrived, in order.
    proofs: Vec<PeerId>,
    /// The peer of every disconnection, in order.
    disconnections: Vec<PeerId>,
    /// The consensus messages that arrived.
    messages: Vec<Bytes>,
}

/// A validator's network, with the events it reports recorded.
struct Node {
    peer_id: PeerId,
    proof: Bytes,
    ctrl: Arc<CtrlHandle>,
    observed: Arc<Mutex<Observed>>,
    events: JoinHandle<()>,
}

impl Node {
    async fn spawn(
        moniker: &str,
        keypair: Keypair,
        listen_addr: SocketAddr,
        persistent_peers: Vec<Multiaddr>,
    ) -> Self {
        let peer_id = PeerId::from_libp2p(&keypair.public().to_peer_id());
        let proof = Bytes::from(format!("validator-proof-of-{peer_id}"));
        let identity = NetworkIdentity::new_validator(
            moniker.to_string(),
            keypair,
            format!("validator-{peer_id}"),
            proof.clone(),
        );

        let (mut recv, ctrl) = spawn(
            identity,
            make_config(listen_addr, persistent_peers),
            SharedRegistry::global().with_moniker(moniker),
        )
        .await
        .unwrap()
        .split();

        let ctrl = Arc::new(ctrl);
        let observed = Arc::new(Mutex::new(Observed::default()));

        let events = tokio::spawn({
            let ctrl = Arc::clone(&ctrl);
            let observed = Arc::clone(&observed);
            async move {
                while let Some(event) = recv.recv().await {
                    match event {
                        Event::ValidatorProofReceived {
                            peer_id,
                            proof_bytes,
                        } => {
                            observed.lock().unwrap().proofs.push(peer_id);
                            // The engine would check the proof's signature; the
                            // proof stands in for the key it binds.
                            let _ = ctrl
                                .validator_proof_verified(
                                    peer_id,
                                    ProofVerificationResult::Valid,
                                    Some(proof_bytes.to_vec()),
                                )
                                .await;
                        }
                        Event::PeerDisconnected(peer_id) => {
                            observed.lock().unwrap().disconnections.push(peer_id);
                        }
                        Event::ConsensusMessage(Channel::Consensus, _, _, data) => {
                            observed.lock().unwrap().messages.push(data);
                        }
                        _ => {}
                    }
                }
            }
        });

        Self {
            peer_id,
            proof,
            ctrl,
            observed,
            events,
        }
    }

    fn proofs_from(&self, peer: &PeerId) -> usize {
        let observed = self.observed.lock().unwrap();
        observed.proofs.iter().filter(|p| *p == peer).count()
    }

    fn disconnections(&self) -> usize {
        self.observed.lock().unwrap().disconnections.len()
    }

    fn received(&self, data: &[u8]) -> bool {
        let observed = self.observed.lock().unwrap();
        observed.messages.iter().any(|m| m.as_ref() == data)
    }

    /// Whether this node holds a connection to `peer`.
    async fn connected_to(&self, peer: &PeerId) -> bool {
        let dump = self.ctrl.dump_state().await.unwrap();
        dump.peers.contains_key(&peer.to_libp2p())
    }

    /// Whether this node has `peer` in its mesh of the consensus channel and
    /// holds the key of its verified proof.
    async fn hears(&self, peer: &Node) -> bool {
        let channel_names = ChannelNames::default();
        let consensus = Channel::Consensus.as_str(&channel_names);
        let dump = self.ctrl.dump_state().await.unwrap();
        dump.peers
            .get(&peer.peer_id.to_libp2p())
            .is_some_and(|info| {
                info.topics.contains(consensus)
                    && info.consensus_public_key.as_deref() == Some(peer.proof.as_ref())
            })
    }

    async fn shut_down(self) {
        self.events.abort();
        let _ = self.events.await;
        let ctrl = Arc::try_unwrap(self.ctrl)
            .ok()
            .expect("the event task held the only other reference");
        ctrl.wait_shutdown().await.unwrap();
    }
}

/// Waits until `a` and `b` hear each other, up to `bound`. Returns whether they do.
async fn hear_each_other(a: &Node, b: &Node, bound: Duration) -> bool {
    let deadline = Instant::now() + bound;
    while Instant::now() < deadline {
        if a.hears(b).await && b.hears(a).await {
            return true;
        }
        sleep(Duration::from_millis(100)).await;
    }
    false
}

/// Publishes messages from `from` until `to` receives one, up to `bound`.
/// Returns whether it does.
async fn delivers(from: &Node, to: &Node, bound: Duration) -> bool {
    let deadline = Instant::now() + bound;
    for attempt in 0u32.. {
        if Instant::now() >= deadline {
            return false;
        }
        // GossipSub drops a message it has seen, so each attempt differs.
        let data = format!("from-{}-{attempt}", from.peer_id);
        let _ = from
            .ctrl
            .publish(Channel::Consensus, Bytes::from(data.clone()))
            .await;
        sleep(Duration::from_millis(250)).await;
        if to.received(data.as_bytes()) {
            return true;
        }
    }
    unreachable!("the attempts run until the deadline")
}

/// A TCP relay whose [`Relay::cut`] stops it carrying the connections it
/// carries, as a partition or a crash of the host behind it does: the side that
/// dialed keeps an open connection, and nothing comes back on it. Connections
/// that open after a cut are carried.
struct Relay {
    addr: Multiaddr,
    cut: watch::Sender<u64>,
    accept: JoinHandle<()>,
}

impl Relay {
    async fn start(target: SocketAddr) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp_address(listener.local_addr().unwrap());
        let (cut, cuts) = watch::channel(0);

        let accept = tokio::spawn(async move {
            while let Ok((client, _)) = listener.accept().await {
                tokio::spawn(carry(client, target, cuts.clone()));
            }
        });

        Self { addr, cut, accept }
    }

    /// Stops carrying every connection open now.
    fn cut(&self) {
        self.cut.send_modify(|cuts| *cuts += 1);
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.accept.abort();
    }
}

async fn carry(client: TcpStream, target: SocketAddr, mut cuts: watch::Receiver<u64>) {
    let carried = *cuts.borrow_and_update();
    let Ok(server) = TcpStream::connect(target).await else {
        return;
    };

    let (mut client_read, mut client_write) = client.into_split();
    let (mut server_read, mut server_write) = server.into_split();

    tokio::select! {
        _ = tokio::io::copy(&mut client_read, &mut server_write) => return,
        _ = tokio::io::copy(&mut server_read, &mut client_write) => return,
        _ = cuts.wait_for(|cuts| *cuts != carried) => {}
    }

    // Close the target's side, and keep the client's open, swallowing what it
    // sends, until the client closes it.
    drop((server_read, server_write));
    let _ = tokio::io::copy(&mut client_read, &mut tokio::io::sink()).await;
    drop(client_write);
}

/// Node A connects to B both directly and through a relay, and B to A. B
/// stops, and the relay keeps A's connection through it open, half open as a
/// crash of B's host would leave it. B starts again under the same key and
/// dials A while A still holds that connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn peer_started_again_behind_a_half_open_connection_is_heard_again() {
    let a_addr = free_address();
    let b_addr = free_address();
    let relay = Relay::start(b_addr).await;
    let b_keypair = Keypair::generate_ed25519();

    let a = Node::spawn(
        "peer-restart-a",
        Keypair::generate_ed25519(),
        a_addr,
        vec![tcp_address(b_addr), relay.addr.clone()],
    )
    .await;
    let b = Node::spawn(
        "peer-restart-b",
        b_keypair.clone(),
        b_addr,
        vec![tcp_address(a_addr)],
    )
    .await;

    assert!(
        hear_each_other(&a, &b, HEAR_BOUND).await,
        "A and B did not hear each other in their first run"
    );

    // Several connections within one session do not end it.
    sleep(SETTLE).await;
    assert_eq!(a.disconnections(), 0, "A lost B in their first run");
    assert_eq!(b.disconnections(), 0, "B lost A in their first run");

    let b_id = b.peer_id;
    relay.cut();
    b.shut_down().await;

    sleep(Duration::from_secs(1)).await;
    assert!(
        a.connected_to(&b_id).await,
        "A no longer holds the relayed connection of B's first run"
    );

    let proofs_before = a.proofs_from(&b_id);
    let b = Node::spawn(
        "peer-restart-b-again",
        b_keypair,
        b_addr,
        vec![tcp_address(a_addr)],
    )
    .await;

    assert!(
        hear_each_other(&a, &b, HEAR_BOUND).await,
        "A and B did not hear each other once B started again"
    );
    assert!(
        a.proofs_from(&b_id) > proofs_before,
        "A did not take the proof of B's second run"
    );
    assert!(
        delivers(&a, &b, HEAR_BOUND).await,
        "B did not receive A's messages"
    );
    assert!(
        delivers(&b, &a, HEAR_BOUND).await,
        "A did not receive B's messages"
    );

    let a_disconnections = a.disconnections();
    let b_disconnections = b.disconnections();
    sleep(SETTLE).await;
    assert_eq!(a.disconnections(), a_disconnections, "A lost B again");
    assert_eq!(b.disconnections(), b_disconnections, "B lost A again");

    b.shut_down().await;
    a.shut_down().await;
}
