//! Real-swarm test of when GossipSub announces a node's subscriptions.
//!
//! The network closes every connection to a peer that announces a subscription
//! twice in one session, which relies on GossipSub announcing a node's
//! subscriptions only on its first connection to a peer. This locks that
//! contract: a further connection announces nothing, and the first connection
//! after every connection closed announces again.

use std::time::Duration;

use libp2p::futures::StreamExt;
use libp2p::gossipsub::{self, IdentTopic, MessageAuthenticity};
use libp2p::swarm::dial_opts::{DialOpts, PeerCondition};
use libp2p::swarm::SwarmEvent;
use libp2p::{noise, tcp, yamux, Multiaddr, PeerId, Swarm, SwarmBuilder};

const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// How long to keep both swarms running once a further connection is up, to
/// catch a late announcement.
const SETTLE: Duration = Duration::from_secs(2);

fn build_swarm() -> Swarm<gossipsub::Behaviour> {
    SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .expect("tcp transport")
        .with_behaviour(|keypair| {
            gossipsub::Behaviour::new(
                MessageAuthenticity::Signed(keypair.clone()),
                gossipsub::Config::default(),
            )
            .expect("gossipsub behaviour")
        })
        .expect("behaviour")
        .with_swarm_config(|c| c.with_idle_connection_timeout(IDLE_TIMEOUT))
        .build()
}

async fn wait_listen_addr<B>(swarm: &mut Swarm<B>) -> Multiaddr
where
    B: libp2p::swarm::NetworkBehaviour,
{
    loop {
        if let SwarmEvent::NewListenAddr { address, .. } = swarm.select_next_some().await {
            return address;
        }
    }
}

/// Dial `peer` on a fresh local port, even if a connection to it is already
/// open.
fn dial_new_connection(peer: PeerId, addr: &Multiaddr) -> DialOpts {
    DialOpts::peer_id(peer)
        .addresses(vec![addr.clone()])
        .condition(PeerCondition::Always)
        .allocate_new_port()
        .build()
}

/// An announcer subscribed to a topic and a listener it dials.
struct Pair {
    announcer: Swarm<gossipsub::Behaviour>,
    listener: Swarm<gossipsub::Behaviour>,
    listener_addr: Multiaddr,
    /// The announcements of the topic the listener received.
    announcements: usize,
    /// The connections each side holds.
    announcer_connections: u32,
    listener_connections: u32,
}

impl Pair {
    async fn new(topic: &IdentTopic) -> Self {
        let mut announcer = build_swarm();
        announcer
            .behaviour_mut()
            .subscribe(topic)
            .expect("subscribe");

        let mut listener = build_swarm();
        listener
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .unwrap();
        let listener_addr = wait_listen_addr(&mut listener).await;

        Self {
            announcer,
            listener,
            listener_addr,
            announcements: 0,
            announcer_connections: 0,
            listener_connections: 0,
        }
    }

    fn dial(&mut self) {
        let listener_id = *self.listener.local_peer_id();
        self.announcer
            .dial(dial_new_connection(listener_id, &self.listener_addr))
            .unwrap();
    }

    /// Process one event from either swarm.
    async fn step(&mut self) {
        let announcer_id = *self.announcer.local_peer_id();
        tokio::select! {
            event = self.announcer.select_next_some() => match event {
                SwarmEvent::ConnectionEstablished { num_established, .. } => {
                    self.announcer_connections = num_established.get();
                }
                SwarmEvent::ConnectionClosed { num_established, .. } => {
                    self.announcer_connections = num_established;
                }
                _ => {}
            },
            event = self.listener.select_next_some() => match event {
                SwarmEvent::ConnectionEstablished { num_established, .. } => {
                    self.listener_connections = num_established.get();
                }
                SwarmEvent::ConnectionClosed { num_established, .. } => {
                    self.listener_connections = num_established;
                }
                SwarmEvent::Behaviour(gossipsub::Event::Subscribed { peer_id, .. }) => {
                    assert_eq!(peer_id, announcer_id);
                    self.announcements += 1;
                }
                _ => {}
            },
        }
    }

    async fn step_until(&mut self, what: &str, done: impl Fn(&Self) -> bool) {
        tokio::time::timeout(Duration::from_secs(20), async {
            while !done(self) {
                self.step().await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {what}"));
    }

    async fn settle(&mut self) {
        let _ = tokio::time::timeout(SETTLE, async {
            loop {
                self.step().await;
            }
        })
        .await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn subscriptions_are_announced_once_per_session() {
    let topic = IdentTopic::new("/consensus");
    let mut pair = Pair::new(&topic).await;

    pair.dial();
    pair.step_until("the first announcement", |p| p.announcements == 1)
        .await;

    pair.dial();
    pair.step_until("a second connection", |p| {
        p.announcer_connections == 2 && p.listener_connections == 2
    })
    .await;
    pair.settle().await;
    assert_eq!(
        pair.announcements, 1,
        "a further connection in the session announced the subscription again"
    );

    let listener_id = *pair.listener.local_peer_id();
    pair.announcer.disconnect_peer_id(listener_id).unwrap();
    pair.step_until("every connection to close", |p| {
        p.announcer_connections == 0 && p.listener_connections == 0
    })
    .await;

    pair.dial();
    pair.step_until("the announcement of the next session", |p| {
        p.announcements == 2
    })
    .await;
}
