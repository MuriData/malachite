//! Tests of the worker thread of the `Wal` actor, which owns the log file.
//!
//! Ractor kills the children of a stopping actor, and a killed actor skips
//! `post_stop`, so the worker of a node's WAL actor can still be writing to the
//! log once the node is gone. Its `WalWorker` reports when it has closed the
//! log, and the handle of an engine built with the default WAL actor holds it.

use std::net::TcpListener;
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use libp2p_identity::Keypair;
use tempfile::TempDir;
use tokio::sync::oneshot;

use arc_malachitebft_test::codec::proto::ProtobufCodec;
use arc_malachitebft_test::{
    Address, Ed25519Verifier, Height, Signature, TestContext, Value, Vote,
};

use malachitebft_app::spawn::{spawn_node_actor, spawn_wal_actor};
use malachitebft_app_channel::{
    ConsensusContext, EngineBuilder, NetworkContext, NetworkIdentity, RequestContext, SyncContext,
    WalContext,
};
use malachitebft_codec::Codec;
use malachitebft_core_consensus::Input;
use malachitebft_core_types::{NilOrVal, Round, SignedVote};
use malachitebft_engine::wal::Msg as WalMsg;
use malachitebft_metrics::{Metrics, SharedRegistry};
use malachitebft_test_app::config::Config;
use malachitebft_wal::Log;

/// How long the worker and the actors may take to get where the test waits for them.
const BOUND: Duration = Duration::from_secs(5);

/// A codec that encodes through [`ProtobufCodec`] once the test lets it: an
/// encode reports that it started, then waits at the gate, which holds the WAL
/// worker in the middle of an append.
#[derive(Clone)]
struct GatedCodec {
    started: mpsc::Sender<()>,
    gate: Arc<Mutex<mpsc::Receiver<()>>>,
}

impl<T> Codec<T> for GatedCodec
where
    ProtobufCodec: Codec<T>,
{
    type Error = <ProtobufCodec as Codec<T>>::Error;

    fn decode(&self, bytes: Bytes) -> Result<T, Self::Error> {
        ProtobufCodec.decode(bytes)
    }

    fn encode(&self, msg: &T) -> Result<Bytes, Self::Error> {
        let _ = self.started.send(());
        // A test that ends without opening the gate drops its sender, which
        // opens it too.
        let _ = self.gate.lock().unwrap().recv();
        ProtobufCodec.encode(msg)
    }
}

fn vote() -> Input<TestContext> {
    Input::Vote(SignedVote::new(
        Vote::new_prevote(
            Height::new(1),
            Round::new(0),
            NilOrVal::Val(Value::new(100).id()),
            Address::new([0; 20]),
        ),
        Signature::test(),
    ))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wal_worker_of_a_killed_node_closes_the_log_after_its_append() {
    let registry = SharedRegistry::new(Default::default(), None);
    let (node, _) = spawn_node_actor(Metrics::register(&registry))
        .await
        .expect("spawn the node actor");

    let tmp = TempDir::new().expect("tempdir");
    let path = tmp.path().join("wal").join("consensus.wal");
    let (started_tx, started) = mpsc::channel();
    let (open, gate) = mpsc::channel();
    let codec = GatedCodec {
        started: started_tx,
        gate: Arc::new(Mutex::new(gate)),
    };
    let (wal, worker) = spawn_wal_actor(
        &TestContext::default(),
        codec,
        &path,
        &registry,
        node.clone(),
    )
    .await
    .expect("spawn the WAL actor");
    wal.link(node.get_cell());

    let _replayed: Vec<_> = ractor::call!(wal, WalMsg::StartedHeight, Height::new(1))
        .expect("StartedHeight call")
        .expect("StartedHeight reply");

    let (reply, _) = oneshot::channel();
    wal.cast(WalMsg::Append(Height::new(1), vote(), reply.into()))
        .expect("cast Append");
    tokio::task::spawn_blocking(move || started.recv_timeout(BOUND))
        .await
        .unwrap()
        .expect("the worker starts the append");

    node.kill_and_wait(None).await.expect("kill the node");
    wal.wait(Some(BOUND))
        .await
        .expect("the WAL actor stops with its node");

    // The actor and its node are gone, and the worker is still appending.
    assert!(!worker.is_finished(), "the worker exited during its append");
    assert!(
        Log::open(&path).is_err(),
        "the log opens while the worker is appending to it"
    );

    open.send(()).expect("the worker waits at the gate");
    tokio::time::timeout(BOUND, worker.finished())
        .await
        .expect("the worker exits once its append is done");
    assert!(worker.is_finished());

    let log = Log::open(&path).expect("the worker closed the log");
    assert_eq!(
        log.len(),
        1,
        "the worker finished the append it was performing"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn engine_handle_holds_the_wal_worker_of_the_default_wal_actor() {
    let tmp = TempDir::new().expect("tempdir");
    let path = tmp.path().join("wal").join("consensus.wal");
    let port = TcpListener::bind("127.0.0.1:0")
        .and_then(|listener| listener.local_addr())
        .expect("bind an ephemeral port")
        .port();
    let mut config = Config {
        moniker: "wal-worker-engine".to_string(),
        ..Config::default()
    };
    config.consensus.p2p.listen_addr = format!("/ip4/127.0.0.1/tcp/{port}").parse().unwrap();
    let identity = NetworkIdentity::new(config.moniker.clone(), Keypair::generate_ed25519(), None);

    let (_channels, engine) = EngineBuilder::new(TestContext::new(), config)
        .with_default_wal(WalContext::new(path.clone(), ProtobufCodec))
        .with_default_network(NetworkContext::new(identity, ProtobufCodec))
        .with_default_consensus(ConsensusContext::new_full_node(
            Address::new([1; 20]),
            Box::new(Ed25519Verifier),
        ))
        .with_default_sync(SyncContext::new(ProtobufCodec))
        .with_default_request(RequestContext::new(100))
        .build()
        .await
        .expect("build the engine");
    let worker = engine.wal.expect("the engine runs the default WAL actor");
    assert!(
        !worker.is_finished(),
        "the worker exited while the engine runs"
    );

    engine
        .actor
        .kill_and_wait(None)
        .await
        .expect("kill the engine");
    tokio::time::timeout(BOUND, worker.finished())
        .await
        .expect("the worker exits once the engine is killed");
    Log::open(&path).expect("the worker closed the log");
}
