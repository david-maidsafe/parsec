// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#[cfg(test)]
pub(crate) use self::snapshot::PeerListSnapshot;
use error::Error;
#[cfg(any(test, feature = "testing"))]
use gossip::Graph;
use gossip::{Event, EventIndex, IndexedEventRef};
use hash::Hash;
use id::{PublicId, SecretId};
#[cfg(any(test, feature = "testing"))]
use mock::{PeerId, Transaction};
use network_event::NetworkEvent;
use serialise;
use std::collections::btree_map::{self, BTreeMap, Entry};
use std::collections::BTreeSet;
use std::fmt::{self, Debug, Formatter};
use std::iter;
use std::ops::{BitOr, BitOrAssign};

pub(crate) struct PeerList<S: SecretId> {
    our_id: S,
    peers: BTreeMap<S::PublicId, Peer<S::PublicId>>,
}

impl<S: SecretId> PeerList<S> {
    pub fn new(our_id: S) -> Self {
        PeerList {
            our_id,
            peers: BTreeMap::new(),
        }
    }

    pub fn our_id(&self) -> &S {
        &self.our_id
    }

    pub fn our_pub_id(&self) -> &S::PublicId {
        self.our_id.public_id()
    }

    /// Returns all sorted peer_ids.
    pub fn all_ids(&self) -> impl Iterator<Item = &S::PublicId> {
        self.peers.keys()
    }

    /// Returns ids of all peers that can vote.
    pub fn voter_ids(&self) -> impl Iterator<Item = &S::PublicId> {
        self.voters().map(|(id, _)| id)
    }

    /// Returns an unsorted map of peer_id => Hash(peer_id).
    pub fn peer_id_hashes(&self) -> impl Iterator<Item = (&S::PublicId, &Hash)> {
        self.peers.iter().map(|(id, peer)| (id, &peer.id_hash))
    }

    /// Returns an iterator of peers.
    pub fn iter(&self) -> btree_map::Iter<S::PublicId, Peer<S::PublicId>> {
        self.peers.iter()
    }

    /// Returns an iterator of peers that can vote.
    pub fn voters(&self) -> impl Iterator<Item = (&S::PublicId, &Peer<S::PublicId>)> {
        self.peers.iter().filter(|(_, peer)| peer.state.can_vote())
    }

    pub fn has_peer(&self, peer_id: &S::PublicId) -> bool {
        self.peers.contains_key(peer_id)
    }

    pub fn peer_state(&self, peer_id: &S::PublicId) -> PeerState {
        self.peers
            .get(peer_id)
            .map(|peer| peer.state)
            .unwrap_or_else(PeerState::inactive)
    }

    pub fn our_state(&self) -> PeerState {
        self.peer_state(self.our_id.public_id())
    }

    /// Adds a peer in the given state into the map.
    pub fn add_peer(&mut self, peer_id: S::PublicId, state: PeerState) {
        let changed = match self.peers.entry(peer_id.clone()) {
            Entry::Occupied(entry) => {
                log_or_panic!(
                    "{:?} already has {:?} in the peer list",
                    self.our_id.public_id(),
                    entry.key()
                );
                false
            }
            Entry::Vacant(entry) => {
                let peer = Peer::new(entry.key(), state);
                let _ = entry.insert(peer);
                state.can_vote()
            }
        };

        if changed {
            if peer_id == *self.our_pub_id() {
                let other_peer_ids: Vec<_> = self.peers.keys().cloned().collect();
                for other_peer_id in other_peer_ids {
                    self.record_our_membership_list_change(MembershipListChange::Add(other_peer_id))
                }
            } else {
                self.record_our_membership_list_change(MembershipListChange::Add(peer_id))
            }
        }
    }

    pub fn remove_peer(&mut self, peer_id: &S::PublicId) {
        if let Some(peer) = self.peers.get_mut(peer_id) {
            peer.state = PeerState::inactive();
        } else {
            debug!(
                "{:?} tried to remove unknown peer {:?}",
                self.our_id.public_id(),
                peer_id
            );
            return;
        }

        self.record_our_membership_list_change(MembershipListChange::Remove(peer_id.clone()))
    }

    pub fn change_peer_state(&mut self, peer_id: &S::PublicId, state: PeerState) {
        let changed = if let Some(peer) = self.peers.get_mut(peer_id) {
            let could_vote = peer.state.can_vote();
            peer.state |= state;
            peer.state.can_vote() && !could_vote
        } else {
            log_or_panic!(
                "{:?} tried to change state of unknown peer {:?}",
                self.our_id.public_id(),
                peer_id
            );
            false
        };

        if changed {
            self.record_our_membership_list_change(MembershipListChange::Add(peer_id.clone()))
        }
    }

    /// Add `other_peer_id` to `peer_id`'s membership list.
    /// If `peer_id` is ourselves, this function does nothing to prevent redundancy (the `PeerList`
    /// itself is already our membership list).
    pub fn add_to_peer_membership_list(
        &mut self,
        peer_id: &S::PublicId,
        other_peer_id: S::PublicId,
    ) {
        self.change_peer_membership_list(peer_id, MembershipListChange::Add(other_peer_id))
    }

    /// Remove `other_peer_id` from `peer_id`'s membership list.
    pub fn remove_from_peer_membership_list(
        &mut self,
        peer_id: &S::PublicId,
        other_peer_id: S::PublicId,
    ) {
        self.change_peer_membership_list(peer_id, MembershipListChange::Remove(other_peer_id))
    }

    pub fn change_peer_membership_list(
        &mut self,
        peer_id: &S::PublicId,
        change: MembershipListChange<S::PublicId>,
    ) {
        if *peer_id == *self.our_id.public_id() {
            return;
        }

        if let Some(peer) = self.peers.get_mut(peer_id) {
            peer.change_membership_list(change)
        } else {
            log_or_panic!(
                "{:?} tried to change membership list of unknown peer {:?}",
                self.our_id.public_id(),
                peer_id
            )
        }
    }

    /// Initialise the membership list of `peer_id`.
    pub fn initialise_peer_membership_list<I>(&mut self, peer_id: &S::PublicId, membership_list: I)
    where
        I: IntoIterator<Item = S::PublicId>,
    {
        // Do not populate our membership list as it would be redundant.
        if *peer_id == *self.our_id.public_id() {
            return;
        }

        if let Some(peer) = self.peers.get_mut(peer_id) {
            let changes = membership_list
                .into_iter()
                .chain(iter::once(peer_id.clone()))
                .map(MembershipListChange::Add);

            for change in changes {
                peer.change_membership_list(change)
            }
        } else {
            log_or_panic!(
                "{:?} tried to initialise membership list of unknown peer {:?}",
                self.our_id.public_id(),
                peer_id
            )
        }
    }

    /// Returns whether the membership list of the given peer is already initialised.
    pub fn is_peer_membership_list_initialised(&self, peer_id: &S::PublicId) -> bool {
        self.peers
            .get(peer_id)
            .map_or(false, |peer| !peer.membership_list.is_empty())
    }

    /// Same as `peer_membership_list_shapshot` except if there is a `Remove` at `event_index`,
    /// then that `Remove` won't be applied to the resulting list.
    #[cfg(feature = "malice-detection")]
    pub fn peer_membership_list_snapshot_excluding_last_remove(
        &self,
        peer_id: &S::PublicId,
        event_index: usize,
    ) -> Option<BTreeSet<S::PublicId>> {
        let (mut list, changes) = self.peer_membership_list_and_changes(peer_id)?;

        for (index, change) in changes.iter().rev() {
            if *index == event_index && !change.is_remove() {
                continue;
            }
            if *index < event_index {
                break;
            }
            let _ = change.unapply(&mut list);
        }

        Some(list)
    }

    /// Returns the history of changes to the membership list of the given peer.
    pub fn peer_membership_list_changes(
        &self,
        peer_id: &S::PublicId,
    ) -> &[(usize, MembershipListChange<S::PublicId>)] {
        if let Some(peer) = self.peers.get(peer_id) {
            &peer.membership_list_changes
        } else {
            &[]
        }
    }

    /// Returns the hash of the last event created by this peer. Returns `None` if cannot find.
    pub fn last_event(&self, peer_id: &S::PublicId) -> Option<EventIndex> {
        self.peers
            .get(peer_id)
            .and_then(|peer| peer.events().rev().next())
    }

    /// Returns the hashes of the indexed event.
    pub fn events_by_index<'a>(
        &'a self,
        peer_id: &S::PublicId,
        index: usize,
    ) -> impl Iterator<Item = EventIndex> + 'a {
        self.peers
            .get(peer_id)
            .into_iter()
            .flat_map(move |peer| peer.events_by_index(index))
    }

    pub fn confirm_can_add_event<T: NetworkEvent>(
        &self,
        event: &Event<T, S::PublicId>,
    ) -> Result<(), Error> {
        if let Some(peer) = self.peers.get(event.creator()) {
            if *event.creator() == *self.our_id.public_id() || peer.state.can_send() {
                Ok(())
            } else {
                Err(Error::InvalidPeerState {
                    required: PeerState::SEND,
                    actual: peer.state,
                })
            }
        } else {
            Err(Error::UnknownPeer)
        }
    }

    /// Adds event created by the peer. Returns an error if the creator is not known, or if we
    /// already held an event from this peer with this index, but that event's hash is different to
    /// the one being added (in which case `peers` is left unmodified).
    pub fn add_event<T: NetworkEvent>(&mut self, event: IndexedEventRef<T, S::PublicId>) {
        if let Some(peer) = self.peers.get_mut(event.creator()) {
            peer.add_event(event.index_by_creator(), event.event_index())
        }
    }

    /// Removes last event from its creator.
    #[cfg(test)]
    pub fn remove_last_event(&mut self, creator: &S::PublicId) -> Option<EventIndex> {
        if let Some(peer) = self.peers.get_mut(creator) {
            peer.remove_last_event()
        } else {
            None
        }
    }

    /// Hashes of events of the given creator, in insertion order.
    pub fn peer_events<'a>(
        &'a self,
        peer_id: &S::PublicId,
    ) -> impl DoubleEndedIterator<Item = EventIndex> + 'a {
        self.peers
            .get(peer_id)
            .into_iter()
            .flat_map(|peer| peer.events())
    }

    /// Hashes of our events in insertion order.
    #[cfg(any(test, feature = "malice-detection"))]
    pub fn our_events<'a>(&'a self) -> impl DoubleEndedIterator<Item = EventIndex> + 'a {
        self.peer_events(self.our_id.public_id())
    }

    fn record_our_membership_list_change(&mut self, change: MembershipListChange<S::PublicId>) {
        if let Some(us) = self.peers.get_mut(self.our_id.public_id()) {
            us.record_membership_list_change(change)
        }
    }

    #[cfg(feature = "malice-detection")]
    fn peer_membership_list_and_changes(
        &self,
        peer_id: &S::PublicId,
    ) -> Option<MembershipListWithChanges<S::PublicId>> {
        let peer = self.peers.get(peer_id)?;
        let list = if peer_id == self.our_pub_id() {
            self.voter_ids().cloned().collect()
        } else {
            peer.membership_list.clone()
        };

        if list.is_empty() {
            None
        } else {
            Some((list, &peer.membership_list_changes))
        }
    }
}

impl<S: SecretId> Debug for PeerList<S> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        writeln!(
            formatter,
            "PeerList{{ our_id: {:?}",
            self.our_id.public_id()
        )?;
        for peer in &self.peers {
            writeln!(formatter, "    {:?},", peer)?;
        }
        write!(formatter, "}}")
    }
}

#[cfg(any(test, feature = "testing"))]
impl PeerList<PeerId> {
    // Creates a new PeerList using the input parameters directly.
    pub(super) fn new_from_dot_input(
        our_id: PeerId,
        graph: &Graph<Transaction, PeerId>,
        peer_data: BTreeMap<PeerId, (PeerState, BTreeSet<PeerId>)>,
    ) -> Self {
        let mut peers = BTreeMap::new();
        let peer_ids: BTreeSet<_> = peer_data.keys().cloned().collect();

        for (peer_id, (state, membership_list)) in peer_data {
            let mut events = Events::new();
            for event in graph {
                if *event.creator() == peer_id {
                    events.add(event.index_by_creator(), event.event_index());
                } else if !peer_ids.contains(event.creator()) {
                    debug!(
                        "peer_data list doesn't contain the creator of event {:?}",
                        *event
                    );
                }
            }

            let mut peer = Peer::new(&peer_id, state);
            peer.events = events;

            for change in membership_list
                .into_iter()
                .chain(iter::once(peer_id.clone()))
                .map(MembershipListChange::Add)
            {
                peer.change_membership_list(change)
            }

            let _ = peers.insert(peer_id, peer);
        }

        PeerList { our_id, peers }
    }
}

/// Peer state is a bitflag with these flags:
///
/// - `VOTE`: if enabled, the peer can vote, which means they are counted towards the supermajority.
/// - `SEND`: if enabled, the peer can send gossips. For us it means we can send gossips to others.
///           For others it means we can receive gossips from them.
/// - `RECV`: if enabled, the peer can receive gossips. For us, it means we can receive gossips from
///           others. For others it means we can send gossips to them.
///
/// If all three are enabled, the state is called `active`. If none is enabled, it's `inactive`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PeerState(u8);

impl PeerState {
    /// The peer is counted towards supermajority.
    pub const VOTE: Self = PeerState(0b0000_0001);
    /// The peer can send gossips.
    pub const SEND: Self = PeerState(0b0000_0010);
    /// The peer can receive gossips.
    pub const RECV: Self = PeerState(0b0000_0100);

    pub fn inactive() -> Self {
        PeerState(0)
    }

    pub fn active() -> Self {
        Self::VOTE | Self::SEND | Self::RECV
    }

    pub fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub fn can_vote(self) -> bool {
        self.contains(Self::VOTE)
    }

    pub fn can_send(self) -> bool {
        self.contains(Self::SEND)
    }

    pub fn can_recv(self) -> bool {
        self.contains(Self::RECV)
    }
}

impl BitOr for PeerState {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        PeerState(self.0 | rhs.0)
    }
}

impl BitOrAssign for PeerState {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0
    }
}

impl Debug for PeerState {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let mut separator = false;

        write!(f, "PeerState(")?;

        if self.contains(Self::VOTE) {
            separator = true;
            write!(f, "VOTE")?;
        }

        if self.contains(Self::SEND) {
            if separator {
                write!(f, "|")?;
            }
            separator = true;
            write!(f, "SEND")?;
        }

        if self.contains(Self::RECV) {
            if separator {
                write!(f, "|")?;
            }
            write!(f, "RECV")?;
        }

        write!(f, ")")
    }
}

#[derive(Debug)]
pub struct Peer<P: PublicId> {
    id_hash: Hash,
    state: PeerState,
    events: Events,
    membership_list: BTreeSet<P>,
    membership_list_changes: Vec<(usize, MembershipListChange<P>)>,
}

impl<P: PublicId> Peer<P> {
    fn new(id: &P, state: PeerState) -> Self {
        Self {
            id_hash: Hash::from(serialise(id).as_slice()),
            state,
            events: Events::new(),
            membership_list: BTreeSet::new(),
            membership_list_changes: Vec::new(),
        }
    }

    pub fn state(&self) -> PeerState {
        self.state
    }

    pub fn events<'a>(&'a self) -> impl DoubleEndedIterator<Item = EventIndex> + 'a {
        self.events.iter()
    }

    #[cfg(test)]
    pub fn indexed_events<'a>(
        &'a self,
    ) -> impl DoubleEndedIterator<Item = (usize, EventIndex)> + 'a {
        self.events.indexed()
    }

    pub fn events_by_index<'a>(&'a self, index: usize) -> impl Iterator<Item = EventIndex> + 'a {
        self.events.by_index(index)
    }

    fn add_event(&mut self, index_by_creator: usize, event_index: EventIndex) {
        self.events.add(index_by_creator, event_index);
    }

    #[cfg(test)]
    fn remove_last_event(&mut self) -> Option<EventIndex> {
        self.events.remove_last()
    }

    fn change_membership_list(&mut self, change: MembershipListChange<P>) {
        if change.apply(&mut self.membership_list) {
            self.record_membership_list_change(change);
        }
    }

    fn record_membership_list_change(&mut self, change: MembershipListChange<P>) {
        let index = self
            .events
            .indexed()
            .rev()
            .next()
            .map(|(index, _)| index)
            .unwrap_or(0);
        self.membership_list_changes.push((index, change));
    }

    #[cfg(feature = "dump-graphs")]
    pub(crate) fn membership_list(&self) -> &BTreeSet<P> {
        &self.membership_list
    }
}

#[derive(Clone, Debug)]
pub(crate) enum MembershipListChange<P> {
    Add(P),
    Remove(P),
}

impl<P: Clone + Ord> MembershipListChange<P> {
    fn apply(&self, peers: &mut BTreeSet<P>) -> bool {
        match *self {
            MembershipListChange::Add(ref peer_id) => peers.insert(peer_id.clone()),
            MembershipListChange::Remove(ref peer_id) => peers.remove(peer_id),
        }
    }

    #[cfg(feature = "malice-detection")]
    fn unapply(&self, peers: &mut BTreeSet<P>) -> bool {
        match *self {
            MembershipListChange::Add(ref peer_id) => peers.remove(peer_id),
            MembershipListChange::Remove(ref peer_id) => peers.insert(peer_id.clone()),
        }
    }

    #[cfg(feature = "malice-detection")]
    fn is_remove(&self) -> bool {
        match *self {
            MembershipListChange::Remove(_) => true,
            MembershipListChange::Add(_) => false,
        }
    }
}

#[cfg(feature = "malice-detection")]
type MembershipListWithChanges<'a, P> = (BTreeSet<P>, &'a [(usize, MembershipListChange<P>)]);

#[derive(Debug)]
struct Events(Vec<Slot>);

impl Events {
    fn new() -> Self {
        Events(Vec::new())
    }

    fn add(&mut self, index_by_creator: usize, event_index: EventIndex) {
        if let Some(slot) = self.0.get_mut(index_by_creator) {
            slot.add(event_index);
            return;
        }

        if index_by_creator != self.0.len() {
            log_or_panic!("Peer events must be added sequentially");
        }

        self.0.push(Slot::new(event_index))
    }

    #[cfg(test)]
    fn remove_last(&mut self) -> Option<EventIndex> {
        if let Some(slot) = self.0.last_mut() {
            if let Some(index) = slot.rest.pop() {
                return Some(index);
            }
        } else {
            return None;
        }

        self.0.pop().map(|slot| slot.first)
    }

    fn iter<'a>(&'a self) -> impl DoubleEndedIterator<Item = EventIndex> + 'a {
        self.0.iter().flat_map(|slot| slot.iter())
    }

    fn indexed<'a>(&'a self) -> impl DoubleEndedIterator<Item = (usize, EventIndex)> + 'a {
        self.0
            .iter()
            .enumerate()
            .flat_map(|(index_by_creator, slot)| {
                slot.iter()
                    .map(move |event_index| (index_by_creator, event_index))
            })
    }

    fn by_index<'a>(&'a self, index_by_creator: usize) -> impl Iterator<Item = EventIndex> + 'a {
        self.0
            .get(index_by_creator)
            .into_iter()
            .flat_map(|slot| slot.iter())
    }
}

#[derive(Debug)]
struct Slot {
    first: EventIndex,
    rest: Vec<EventIndex>,
}

impl Slot {
    fn new(event_index: EventIndex) -> Self {
        Self {
            first: event_index,
            rest: Vec::new(),
        }
    }

    fn add(&mut self, event_index: EventIndex) {
        self.rest.push(event_index)
    }

    fn iter<'a>(&'a self) -> impl DoubleEndedIterator<Item = EventIndex> + 'a {
        iter::once(self.first).chain(self.rest.iter().cloned())
    }
}

#[cfg(test)]
pub(crate) mod snapshot {
    use super::*;
    use gossip::EventHash;

    #[derive(Eq, PartialEq, Debug)]
    pub(crate) struct PeerListSnapshot<P: PublicId>(
        BTreeMap<P, (PeerState, BTreeSet<(usize, EventHash)>)>,
    );

    impl<P: PublicId> PeerListSnapshot<P> {
        pub fn new<T: NetworkEvent, S: SecretId<PublicId = P>>(
            peer_list: &PeerList<S>,
            graph: &Graph<T, P>,
        ) -> Self {
            PeerListSnapshot(
                peer_list
                    .iter()
                    .map(|(peer_id, peer)| {
                        let events = peer
                            .indexed_events()
                            .filter_map(|(index_by_creator, event_index)| {
                                graph
                                    .get(event_index)
                                    .map(|event| (index_by_creator, *event.hash()))
                            }).collect();

                        (peer_id.clone(), (peer.state, events))
                    }).collect(),
            )
        }
    }
}
