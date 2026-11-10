//! The GossipSub subscriptions each peer announced in its session with this node.
//!
//! A session with a peer lasts from the first connection to it until the last
//! one closes. GossipSub sends a node's subscriptions only on its first
//! connection to a peer, and the validator-proof protocol sends the proof only
//! then too. A peer that announces a subscription again within a session has
//! therefore started a session of its own while this node still holds a
//! connection of its last one: a half-open connection after a crash or a
//! partition, one that an earlier instance of the peer left open, or one whose
//! close this node has not seen yet. On the peer's new connection this node
//! sends neither its subscriptions nor its proof, so for as long as any
//! connection between them stays open the peer can neither publish to this
//! node, nor graft it into its mesh, nor take it for a validator. Closing every
//! connection to the peer ends the session on both sides, and the next
//! connection starts a new one on both, with both announcements.
//!
//! A peer announces its subscriptions on a connection authenticated by its own
//! key, so only the peer itself can have its connections closed this way.

use std::collections::{HashMap, HashSet};

use libp2p::gossipsub::TopicHash;
use libp2p::PeerId;

/// What a subscription announcement says about the peer's session.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum Announcement {
    /// The peer's first announcement of the topic in this session.
    First,
    /// The peer announced the topic before in this session, so it has started
    /// a new session of its own.
    Repeated,
}

/// The topics each peer announced in its current session.
#[derive(Debug, Default)]
pub(crate) struct Sessions {
    announced: HashMap<PeerId, HashSet<TopicHash>>,
}

impl Sessions {
    /// Records that `peer` announced a subscription to `topic`.
    pub(crate) fn subscribed(&mut self, peer: PeerId, topic: TopicHash) -> Announcement {
        if self.announced.entry(peer).or_default().insert(topic) {
            Announcement::First
        } else {
            Announcement::Repeated
        }
    }

    /// Records that `peer` unsubscribed from `topic`, after which it may
    /// announce the topic again in the same session.
    pub(crate) fn unsubscribed(&mut self, peer: &PeerId, topic: &TopicHash) {
        if let Some(topics) = self.announced.get_mut(peer) {
            topics.remove(topic);
        }
    }

    /// Ends the session with `peer`, whose last connection closed.
    pub(crate) fn end(&mut self, peer: &PeerId) {
        self.announced.remove(peer);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn topic(name: &str) -> TopicHash {
        TopicHash::from_raw(name)
    }

    #[test]
    fn second_announcement_in_a_session_is_repeated() {
        let mut sessions = Sessions::default();
        let peer = PeerId::random();

        assert_eq!(
            sessions.subscribed(peer, topic("/consensus")),
            Announcement::First
        );
        assert_eq!(
            sessions.subscribed(peer, topic("/liveness")),
            Announcement::First
        );
        assert_eq!(
            sessions.subscribed(peer, topic("/consensus")),
            Announcement::Repeated
        );
    }

    #[test]
    fn peers_announce_independently() {
        let mut sessions = Sessions::default();
        let (a, b) = (PeerId::random(), PeerId::random());

        assert_eq!(
            sessions.subscribed(a, topic("/consensus")),
            Announcement::First
        );
        assert_eq!(
            sessions.subscribed(b, topic("/consensus")),
            Announcement::First
        );
    }

    #[test]
    fn unsubscribing_allows_a_new_announcement() {
        let mut sessions = Sessions::default();
        let peer = PeerId::random();

        sessions.subscribed(peer, topic("/consensus"));
        sessions.unsubscribed(&peer, &topic("/consensus"));

        assert_eq!(
            sessions.subscribed(peer, topic("/consensus")),
            Announcement::First
        );
    }

    #[test]
    fn a_new_session_starts_after_the_last_connection_closes() {
        let mut sessions = Sessions::default();
        let peer = PeerId::random();

        sessions.subscribed(peer, topic("/consensus"));
        sessions.end(&peer);

        assert_eq!(
            sessions.subscribed(peer, topic("/consensus")),
            Announcement::First
        );
    }
}
