// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use block::Block;
#[cfg(test)]
use dev_utils::ParsedContents;
use dump_graph;
use error::{Error, Result};
use gossip::{
    Event, EventHash, EventIndex, Graph, IndexedEventRef, PackedEvent, Request, Response,
};
use id::{PublicId, SecretId};
use meta_voting::{MetaElectionHandle, MetaElections, MetaEvent, MetaEventBuilder, MetaVote, Step};
#[cfg(test)]
use mock::{PeerId, Transaction};
use network_event::NetworkEvent;
use observation::{Malice, Observation, ObservationHash};
use peer_list::{PeerList, PeerState};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::{mem, usize};
use vote::Vote;

pub type IsInterestingEventFn<P> =
    fn(peers_that_did_vote: &BTreeSet<P>, peers_that_can_vote: &BTreeSet<P>) -> bool;

type PendingAccusations<T, P> = Vec<(P, Malice<T, P>)>;

/// Returns whether `small` is more than two thirds of `large`.
pub fn is_more_than_two_thirds(small: usize, large: usize) -> bool {
    3 * small > 2 * large
}

/// Function which can be used as `is_interesting_event` in
/// [`Parsec::new()`](struct.Parsec.html#method.new) and which returns `true` if there are >2/3
/// `did_vote` which are members of `can_vote`.
pub fn is_supermajority<P: Ord>(did_vote: &BTreeSet<P>, can_vote: &BTreeSet<P>) -> bool {
    let valid_did_vote_count = can_vote.intersection(did_vote).count();
    is_more_than_two_thirds(valid_did_vote_count, can_vote.len())
}

/// The main object which manages creating and receiving gossip about network events from peers, and
/// which provides a sequence of consensused `Block`s by applying the PARSEC algorithm.
///
/// Most public functions return an error if called after the owning node has been removed, i.e.
/// a block with payload `Observation::Remove(our_id)` has been made stable.
pub struct Parsec<T: NetworkEvent, S: SecretId> {
    // The PeerInfo of other nodes.
    peer_list: PeerList<S>,
    // The Gossip graph.
    graph: Graph<T, S::PublicId>,
    // Information about observations stored in the graph, mapped to their hashes.
    observations: BTreeMap<ObservationHash, ObservationInfo<T, S::PublicId>>,
    // Consensused network events that have not been returned via `poll()` yet.
    consensused_blocks: VecDeque<Block<T, S::PublicId>>,
    // The map of meta votes of the events on each consensus block.
    meta_elections: MetaElections<S::PublicId>,
    // Accusations to raise at the end of the processing of current gossip message.
    pending_accusations: PendingAccusations<T, S::PublicId>,
    is_interesting_event: IsInterestingEventFn<S::PublicId>,
}

impl<T: NetworkEvent, S: SecretId> Parsec<T, S> {
    /// Creates a new `Parsec` for a peer with the given ID and genesis peer IDs (ours included).
    pub fn from_genesis(
        our_id: S,
        genesis_group: &BTreeSet<S::PublicId>,
        is_interesting_event: IsInterestingEventFn<S::PublicId>,
    ) -> Self {
        if !genesis_group.contains(our_id.public_id()) {
            log_or_panic!("Genesis group must contain us");
        }

        let mut parsec = Self::empty(our_id, genesis_group, is_interesting_event);

        for peer_id in genesis_group {
            parsec
                .peer_list
                .add_peer(peer_id.clone(), PeerState::active());
            parsec
                .peer_list
                .initialise_peer_membership_list(peer_id, genesis_group.iter().cloned())
        }

        parsec
            .meta_elections
            .initialise_current_election(parsec.peer_list.all_ids());

        // Add initial event.
        let event = Event::new_initial(&parsec.peer_list);
        if let Err(error) = parsec.add_event(event) {
            log_or_panic!(
                "{:?} initialising Parsec failed when adding initial event: {:?}",
                parsec.our_pub_id(),
                error
            );
        }

        // Add event carrying genesis observation.
        let genesis_observation = Observation::Genesis(genesis_group.clone());
        let self_parent_hash = parsec.our_last_event_hash();
        let event = Event::new_from_observation(
            self_parent_hash,
            genesis_observation,
            &parsec.graph,
            &parsec.peer_list,
        );

        if let Err(error) = parsec.add_event(event) {
            log_or_panic!(
                "{:?} initialising Parsec failed when adding the genesis observation: {:?}",
                parsec.our_pub_id(),
                error,
            );
        }

        parsec
    }

    /// Creates a new `Parsec` for a peer that is joining an existing section.
    pub fn from_existing(
        our_id: S,
        genesis_group: &BTreeSet<S::PublicId>,
        section: &BTreeSet<S::PublicId>,
        is_interesting_event: IsInterestingEventFn<S::PublicId>,
    ) -> Self {
        if genesis_group.is_empty() {
            log_or_panic!("Genesis group can't be empty");
        }

        if genesis_group.contains(our_id.public_id()) {
            log_or_panic!("Genesis group can't already contain us");
        }

        if section.is_empty() {
            log_or_panic!("Section can't be empty");
        }

        if section.contains(our_id.public_id()) {
            log_or_panic!("Section can't already contain us");
        }

        let our_public_id = our_id.public_id().clone();
        let mut parsec = Self::empty(our_id, genesis_group, is_interesting_event);

        // Add ourselves.
        parsec
            .peer_list
            .add_peer(our_public_id.clone(), PeerState::RECV);

        // Add the genesis group.
        for peer_id in genesis_group {
            parsec
                .peer_list
                .add_peer(peer_id.clone(), PeerState::VOTE | PeerState::SEND);
            parsec
                .peer_list
                .initialise_peer_membership_list(peer_id, genesis_group.iter().cloned());
        }

        // Add the current section members.
        for peer_id in section {
            if genesis_group.contains(peer_id) {
                continue;
            }

            parsec.peer_list.add_peer(peer_id.clone(), PeerState::SEND)
        }

        parsec
            .meta_elections
            .initialise_current_election(parsec.peer_list.all_ids());

        let initial_event = Event::new_initial(&parsec.peer_list);
        if let Err(error) = parsec.add_event(initial_event) {
            log_or_panic!(
                "{:?} initialising Parsec failed when adding initial event: {:?}",
                parsec.our_pub_id(),
                error
            );
        }

        parsec
    }

    // Construct empty `Parsec` with no peers (except us) and no gossip events.
    fn empty(
        our_id: S,
        genesis_group: &BTreeSet<S::PublicId>,
        is_interesting_event: IsInterestingEventFn<S::PublicId>,
    ) -> Self {
        dump_graph::init();

        Self {
            peer_list: PeerList::new(our_id),
            graph: Graph::new(),
            consensused_blocks: VecDeque::new(),
            observations: BTreeMap::new(),
            meta_elections: MetaElections::new(genesis_group.clone()),
            is_interesting_event,
            pending_accusations: vec![],
        }
    }

    /// Adds a vote for `observation`.  Returns an error if we have already voted for this.
    pub fn vote_for(&mut self, observation: Observation<T, S::PublicId>) -> Result<()> {
        debug!("{:?} voting for {:?}", self.our_pub_id(), observation);

        self.confirm_self_state(PeerState::VOTE)?;

        if self.have_voted_for(&observation) {
            return Err(Error::DuplicateVote);
        }

        let self_parent_hash = self.our_last_event_hash();
        let event = Event::new_from_observation(
            self_parent_hash,
            observation,
            &self.graph,
            &self.peer_list,
        );

        self.add_event(event)
    }

    /// Creates a new message to be gossiped to a peer containing all gossip events this node thinks
    /// that peer needs.  If `peer_id` is `None`, a message containing all known gossip events is
    /// returned.  If `peer_id` is `Some` and the given peer is not an active node, an error is
    /// returned.
    pub fn create_gossip(&self, peer_id: Option<&S::PublicId>) -> Result<Request<T, S::PublicId>> {
        self.confirm_self_state(PeerState::SEND)?;

        if let Some(recipient_id) = peer_id {
            // We require `PeerState::VOTE` in addition to `PeerState::RECV` here, because if the
            // peer does not have `PeerState::VOTE`, it means we haven't yet reached consensus on
            // adding them to the section so we shouldn't contact them yet.
            self.confirm_peer_state(recipient_id, PeerState::VOTE | PeerState::RECV)?;

            if self.peer_list.last_event(recipient_id).is_some() {
                debug!(
                    "{:?} creating gossip request for {:?}",
                    self.our_pub_id(),
                    recipient_id
                );

                return self
                    .events_to_gossip_to_peer(recipient_id)
                    .map(Request::new);
            }
        }

        debug!(
            "{:?} creating gossip request for {:?}",
            self.our_pub_id(),
            peer_id
        );

        Ok(Request::new(self.graph.iter().map(|e| e.inner()).collect()))
    }

    /// Handles a received `Request` from `src` peer.  Returns a `Response` to be sent back to `src`
    /// or `Err` if the request was not valid or if `src` has been removed already.
    pub fn handle_request(
        &mut self,
        src: &S::PublicId,
        req: Request<T, S::PublicId>,
    ) -> Result<Response<T, S::PublicId>> {
        debug!(
            "{:?} received gossip request from {:?}",
            self.our_pub_id(),
            src
        );
        let forking_peers = self.unpack_and_add_events(src, req.packed_events)?;
        self.create_sync_event(src, true, &forking_peers)?;
        self.create_accusation_events()?;
        self.events_to_gossip_to_peer(src).map(Response::new)
    }

    /// Handles a received `Response` from `src` peer.  Returns `Err` if the response was not valid
    /// or if `src` has been removed already.
    pub fn handle_response(
        &mut self,
        src: &S::PublicId,
        resp: Response<T, S::PublicId>,
    ) -> Result<()> {
        debug!(
            "{:?} received gossip response from {:?}",
            self.our_pub_id(),
            src
        );
        let forking_peers = self.unpack_and_add_events(src, resp.packed_events)?;
        self.create_sync_event(src, false, &forking_peers)?;
        self.create_accusation_events()
    }

    /// Steps the algorithm and returns the next stable block, if any.
    ///
    /// Once we have been removed (i.e. a block with payload `Observation::Remove(our_id)` has been
    /// made stable), then no further blocks will be enqueued.  So, once `poll()` returns such a
    /// block, it will continue to return `None` forever.
    pub fn poll(&mut self) -> Option<Block<T, S::PublicId>> {
        self.consensused_blocks.pop_front()
    }

    /// Check if we can vote (that is, we have reached a consensus on us being full member of the
    /// section).
    pub fn can_vote(&self) -> bool {
        self.peer_list.peer_state(self.our_pub_id()).can_vote()
    }

    /// Checks if the given `observation` has already been voted for by us.
    pub fn have_voted_for(&self, observation: &Observation<T, S::PublicId>) -> bool {
        // TODO: optimize by iterating only `peer_list.our_events`.
        self.graph.iter().any(|event| {
            event.creator() == self.our_pub_id() && event
                .vote()
                .map_or(false, |voted| voted.payload() == observation)
        })
    }

    /// Check if there are any observation that have been voted for but not yet consensused.
    pub fn has_unconsensused_observations(&self) -> bool {
        self.observations.values().any(|info| !info.consensused)
    }

    /// Returns observations voted for by us which haven't been returned by `poll` yet.
    /// This includes observations that are either not yet consensused or that are already
    /// consensused, but not yet popped out of the consensus queue.
    ///
    /// The observations are sorted first by the consensus order, then by the vote order.
    pub fn our_unpolled_observations(&self) -> impl Iterator<Item = &Observation<T, S::PublicId>> {
        self.our_consensused_observations()
            .chain(self.our_unconsensused_observations())
    }

    fn our_consensused_observations(&self) -> impl Iterator<Item = &Observation<T, S::PublicId>> {
        self.observations.values().filter_map(move |info| {
            if info.created_by_us && info.consensused && self
                .consensused_blocks
                .iter()
                .any(|block| block.payload() == &info.observation)
            {
                Some(&info.observation)
            } else {
                None
            }
        })
    }

    fn our_unconsensused_observations(&self) -> impl Iterator<Item = &Observation<T, S::PublicId>> {
        self.observations.values().filter_map(|info| {
            if info.created_by_us && !info.consensused {
                Some(&info.observation)
            } else {
                None
            }
        })
    }

    /// Must only be used for events which have already been added to our graph.
    fn get_known_event(&self, event_index: EventIndex) -> Result<IndexedEventRef<T, S::PublicId>> {
        self.graph.get(event_index).ok_or_else(|| {
            log_or_panic!(
                "{:?} doesn't have event {:?}",
                self.our_pub_id(),
                event_index
            );
            Error::Logic
        })
    }

    fn our_pub_id(&self) -> &S::PublicId {
        self.peer_list.our_pub_id()
    }

    fn confirm_peer_state(&self, peer_id: &S::PublicId, required: PeerState) -> Result<()> {
        let actual = self.peer_list.peer_state(peer_id);
        if actual.contains(required) {
            Ok(())
        } else {
            trace!(
                "{:?} detected invalid state of {:?} (required: {:?}, actual: {:?})",
                self.our_pub_id(),
                peer_id,
                required,
                actual,
            );
            Err(Error::InvalidPeerState { required, actual })
        }
    }

    fn confirm_self_state(&self, required: PeerState) -> Result<()> {
        let actual = self.peer_list.our_state();
        if actual.contains(required) {
            Ok(())
        } else {
            trace!(
                "{:?} has invalid state (required: {:?}, actual: {:?})",
                self.our_pub_id(),
                required,
                actual,
            );
            Err(Error::InvalidSelfState { required, actual })
        }
    }

    fn our_last_event_hash(&self) -> EventHash {
        self.peer_list
            .last_event(self.our_pub_id())
            .and_then(|index| self.get_known_event(index).ok())
            .map(|event| *event.hash())
            .unwrap_or_else(|| {
                log_or_panic!(
                    "{:?} has no last event hash.\n{:?}\n",
                    self.our_pub_id(),
                    self.peer_list
                );
                EventHash::ZERO
            })
    }

    fn is_observer(&self, builder: &MetaEventBuilder<T, S::PublicId>) -> bool {
        // An event is an observer if it has a supermajority of observees and its self-parent
        // does not.
        let voter_count = self.voter_count(builder.election());

        if !is_more_than_two_thirds(builder.observee_count(), voter_count) {
            return false;
        }

        let self_parent_index = if let Some(index) = builder.event().self_parent() {
            index
        } else {
            log_or_panic!(
                "{:?} has event {:?} with observations, but not self-parent",
                self.our_pub_id(),
                *builder.event()
            );
            return false;
        };

        let self_parent = if let Ok(event) = self.get_known_event(self_parent_index) {
            event
        } else {
            return false;
        };

        // If self-parent is initial, we don't have to check it's meta-event, as we already know it
        // can not have any observations. Also, we don't assign meta-events to initial events anyway.
        if self_parent.is_initial() {
            return true;
        }

        // If self-parent is earlier in history than the start of the meta-election, it won't have
        // a meta-event; but it also means that it wasn't an observer, so this event is
        if self.meta_elections.start_index(builder.election()) > self_parent.topological_index() {
            return true;
        }

        if let Some(meta_parent) = self
            .meta_elections
            .meta_event(builder.election(), self_parent_index)
        {
            !is_more_than_two_thirds(meta_parent.observees.len(), voter_count)
        } else {
            log_or_panic!(
                "{:?} doesn't have meta-event for event {:?} (self-parent of {:?}) in meta-election {:?}",
                self.our_pub_id(),
                *self_parent,
                builder.event().hash(),
                builder.election(),
            );

            false
        }
    }

    fn unpack_and_add_events(
        &mut self,
        src: &S::PublicId,
        packed_events: Vec<PackedEvent<T, S::PublicId>>,
    ) -> Result<BTreeSet<S::PublicId>> {
        self.confirm_self_state(PeerState::RECV)?;
        self.confirm_peer_state(src, PeerState::SEND)?;

        let mut prev_forking_peers = BTreeSet::new();
        for packed_event in packed_events {
            if let Some(event) = Event::unpack(
                packed_event,
                &self.graph,
                &self.peer_list,
                &prev_forking_peers,
            )? {
                if self
                    .peer_list
                    .events_by_index(event.creator(), event.index_by_creator())
                    .next()
                    .is_some()
                {
                    let _ = prev_forking_peers.insert(event.creator().clone());
                }
                let event_creator = event.creator().clone();
                self.add_event(event)?;
                // We have received an event of a peer in the message. The peer can now receive
                // gossips from us as well.
                self.peer_list
                    .change_peer_state(&event_creator, PeerState::RECV);
            }
        }

        #[cfg(feature = "malice-detection")]
        self.detect_premature_gossip()?;

        Ok(prev_forking_peers)
    }

    fn add_event(&mut self, event: Event<T, S::PublicId>) -> Result<()> {
        let our = event.creator() == self.our_pub_id();
        if !our {
            #[cfg(feature = "malice-detection")]
            self.detect_malice_before_process(&event)?;
        }

        self.peer_list.confirm_can_add_event(&event)?;

        if let Some((payload_hash, new_info)) = ObservationInfo::create(&event) {
            let info = self.observations.entry(payload_hash).or_insert(new_info);
            if our {
                info.created_by_us = true;
            }
        }

        let is_initial = event.is_initial();
        let event_index = {
            let event = self.graph.insert(event);
            self.peer_list.add_event(event);
            event.event_index()
        };

        if is_initial {
            return Ok(());
        }

        self.initialise_membership_list(event_index);
        self.process_event(event_index)?;

        if !our {
            #[cfg(feature = "malice-detection")]
            self.detect_malice_after_process(event_index);
        }

        Ok(())
    }

    fn process_event(&mut self, event_index: EventIndex) -> Result<()> {
        if self.peer_list.our_state() == PeerState::inactive() {
            return Ok(());
        }

        let elections: Vec<_> = self.meta_elections.all().collect();
        for election in elections {
            self.create_meta_event(election, event_index)?;
        }

        let creator = self.get_known_event(event_index)?.creator().clone();

        if let Some(payload_hash) = self.compute_consensus(MetaElectionHandle::CURRENT, event_index)
        {
            self.output_consensus_info(&payload_hash);
            self.mark_observation_as_consensused(&payload_hash);

            self.handle_self_consensus(&payload_hash);
            if creator != *self.our_pub_id() {
                self.handle_peer_consensus(&creator, &payload_hash);
            }

            let start_index = self.compute_next_meta_election_start_index();
            let prev_election = self.meta_elections.new_election(
                payload_hash,
                self.peer_list.voter_ids().cloned().collect(),
                start_index,
            );

            self.meta_elections
                .mark_as_decided(prev_election, self.peer_list.our_pub_id());
            self.meta_elections.mark_as_decided(prev_election, &creator);

            let block = self.create_block(&payload_hash)?;
            self.consensused_blocks.push_back(block);

            let current_index = self.get_known_event(event_index)?.topological_index();
            self.restart_consensus(start_index, current_index)?;
        } else if creator != *self.our_pub_id() {
            let undecided: Vec<_> = self.meta_elections.undecided_by(&creator).collect();
            for election in undecided {
                if let Some(payload_hash) = self.compute_consensus(election, event_index) {
                    self.meta_elections.mark_as_decided(election, &creator);
                    self.handle_peer_consensus(&creator, &payload_hash);
                }
            }
        }

        Ok(())
    }

    fn output_consensus_info(&self, payload_hash: &ObservationHash) {
        dump_graph::to_file(
            self.our_pub_id(),
            &self.graph,
            &self.meta_elections,
            &self.peer_list,
            self.observations
                .iter()
                .map(|(hash, info)| (hash, &info.observation))
                .collect(),
        );

        let payload = self
            .observations
            .get(payload_hash)
            .map(|info| &info.observation);
        info!(
            "{:?} got consensus on block {} with payload {:?} and payload hash {:?}",
            self.our_pub_id(),
            self.meta_elections.consensus_history().len() - 1,
            payload,
            payload_hash
        )
    }

    fn mark_observation_as_consensused(&mut self, payload_hash: &ObservationHash) {
        if let Some(info) = self.observations.get_mut(payload_hash) {
            info.consensused = true;
        } else {
            log_or_panic!(
                "{:?} doesn't know about observation with hash {:?}",
                self.peer_list.our_pub_id(),
                payload_hash
            );
        }
    }

    /// Handles consensus reached by us.
    fn handle_self_consensus(&mut self, payload_hash: &ObservationHash) {
        match self
            .observations
            .get(payload_hash)
            .map(|info| info.observation.clone())
        {
            Some(Observation::Add { ref peer_id, .. }) => self.handle_add_peer(peer_id),
            Some(Observation::Remove { ref peer_id, .. }) => self.handle_remove_peer(peer_id),
            Some(Observation::Accusation {
                ref offender,
                ref malice,
            }) => {
                info!(
                    "{:?} removing {:?} due to consensus on accusation of malice {:?}",
                    self.our_pub_id(),
                    offender,
                    malice
                );

                self.handle_remove_peer(offender)
            }
            Some(Observation::Genesis(_)) | Some(Observation::OpaquePayload(_)) => (),
            None => {
                log_or_panic!("Failed to get observation from hash.");
            }
        }
    }

    fn handle_add_peer(&mut self, peer_id: &S::PublicId) {
        // - If we are already full member of the section, we can start sending gossips to
        //   the new peer from this moment.
        // - If we are the new peer, we must wait for the other members to send gossips to
        //   us first.
        //
        // To distinguish between the two, we check whether everyone we reached consensus on
        // adding also reached consensus on adding us.
        let recv = self
            .peer_list
            .iter()
            .filter(|&(id, peer)| {
                // Peers that can vote, which means we got consensus on adding them.
                peer.state().can_vote() &&
                        // Excluding the peer being added.
                        *id != *peer_id &&
                        // And excluding us.
                        *id != *self.our_pub_id()
            }).all(|(_, peer)| {
                // Peers that can receive, which implies they've already sent us at least
                // one message which implies they've already reached consensus on adding us.
                peer.state().can_recv()
            });

        let state = if recv {
            PeerState::VOTE | PeerState::SEND | PeerState::RECV
        } else {
            PeerState::VOTE | PeerState::SEND
        };

        if self.peer_list.has_peer(peer_id) {
            self.peer_list.change_peer_state(peer_id, state);
        } else {
            self.peer_list.add_peer(peer_id.clone(), state);
        }
    }

    fn handle_remove_peer(&mut self, peer_id: &S::PublicId) {
        self.peer_list.remove_peer(peer_id);
        self.meta_elections.handle_peer_removed(peer_id);
    }

    // Handle consensus reached by other peer.
    fn handle_peer_consensus(&mut self, peer_id: &S::PublicId, payload_hash: &ObservationHash) {
        let payload = self
            .observations
            .get(payload_hash)
            .map(|info| info.observation.clone());
        trace!(
            "{:?} detected that {:?} reached consensus on {:?}",
            self.our_pub_id(),
            peer_id,
            payload
        );

        match payload {
            Some(Observation::Add {
                peer_id: ref other_peer_id,
                ..
            }) => self
                .peer_list
                .add_to_peer_membership_list(peer_id, other_peer_id.clone()),
            Some(Observation::Remove {
                peer_id: ref other_peer_id,
                ..
            }) => self
                .peer_list
                .remove_from_peer_membership_list(peer_id, other_peer_id.clone()),
            Some(Observation::Accusation { ref offender, .. }) => self
                .peer_list
                .remove_from_peer_membership_list(peer_id, offender.clone()),
            _ => (),
        }
    }

    fn create_meta_event(
        &mut self,
        election: MetaElectionHandle,
        event_index: EventIndex,
    ) -> Result<()> {
        if self
            .meta_elections
            .meta_event(election, event_index)
            .is_some()
        {
            return Ok(());
        }

        let (meta_event, creator) = {
            let event = self.get_known_event(event_index)?;
            trace!(
                "{:?} creating a meta-event in meta-election {:?} for event {:?}",
                self.our_pub_id(),
                election,
                event
            );
            let mut builder = MetaEvent::build(election, event);

            self.set_interesting_content(&mut builder);
            self.set_observees(&mut builder);
            self.set_meta_votes(&mut builder)?;

            (builder.finish(), event.creator().clone())
        };

        self.meta_elections
            .add_meta_event(election, event_index, creator, meta_event);

        Ok(())
    }

    // Any payloads which this event sees as "interesting".  If this returns a non-empty set, then
    // this event is classed as an interesting one.
    fn set_interesting_content(&self, builder: &mut MetaEventBuilder<T, S::PublicId>) {
        if let Some(payloads_hashes) =
            self.previous_interesting_content(builder.election(), builder.event())
        {
            builder.set_interesting_content(payloads_hashes);
            return;
        }

        let peers_that_can_vote = self.voters(builder.election());
        let start_index = self.meta_elections.start_index(builder.election());

        let mut payloads_set: BTreeSet<_> = self
            .graph
            .iter_from(start_index)
            .filter_map(|event| {
                event
                    .inner()
                    .payload_hash()
                    .map(|payload_hash| (event, payload_hash))
            }).filter(|(_, this_payload_hash)| {
                self.meta_elections.is_interesting_content_candidate(
                    builder.election(),
                    builder.event().creator(),
                    this_payload_hash,
                )
            }).filter(|(event, this_payload_hash)| {
                self.is_interesting_payload(
                    builder,
                    &peers_that_can_vote,
                    this_payload_hash,
                    start_index,
                ) || event.sees_fork()
                    && self.has_interesting_ancestor(builder, this_payload_hash, start_index)
            }).map(|(_, this_payload_hash)| this_payload_hash)
            .cloned()
            .collect();

        // The code above created a set of payloads that are interesting at this event.
        // We will now sort the payloads in the order in which the creator voted for them.
        let mut payloads_hashes = vec![];
        for observation_hash in self
            .peer_list
            .peer_events(builder.event().creator())
            .filter_map(|hash| self.get_known_event(hash).ok())
            .filter_map(|event| event.inner().payload_hash())
        {
            if payloads_set.remove(observation_hash) {
                payloads_hashes.push(*observation_hash);
            }
        }
        // If any payloads are left in the set, it means that the creator hasn't voted for them -
        // we will just append them at the end.
        payloads_hashes.extend(payloads_set);

        builder.set_interesting_content(payloads_hashes);
    }

    // Try to get interesting content of the given event from the previous meta-election.
    fn previous_interesting_content(
        &self,
        election: MetaElectionHandle,
        event: IndexedEventRef<T, S::PublicId>,
    ) -> Option<Vec<ObservationHash>> {
        let prev_election = self.meta_elections.preceding(election)?;

        if self.meta_elections.voter_count(election)
            != self.meta_elections.voter_count(prev_election)
        {
            // Membership change occurred. Can't reuse interesting content.
            return None;
        }

        let prev_meta_event = self
            .meta_elections
            .meta_event(prev_election, event.event_index())?;
        let payloads = prev_meta_event
            .interesting_content
            .iter()
            .filter(|payload| {
                // Filter payloads that are still interesting.
                self.meta_elections.is_interesting_content_candidate(
                    election,
                    event.creator(),
                    payload,
                )
            }).cloned()
            .collect();

        Some(payloads)
    }

    // Returns true if `builder.event()` has an ancestor by a different creator that has `payload`
    // in interesting content
    fn has_interesting_ancestor(
        &self,
        builder: &MetaEventBuilder<T, S::PublicId>,
        payload_hash: &ObservationHash,
        start_index: usize,
    ) -> bool {
        self.graph
            .ancestors(builder.event())
            .take_while(|that_event| that_event.topological_index() >= start_index)
            .filter(|that_event| that_event.creator() != builder.event().creator())
            .any(|that_event| {
                self.meta_elections
                    .meta_event(builder.election(), that_event.event_index())
                    .map(|meta_event| meta_event.interesting_content.contains(payload_hash))
                    .unwrap_or(false)
            })
    }

    // Returns true if enough of `valid_voters` have voted for the indicated payload from the
    // perspective of `builder.event()`.
    fn is_interesting_payload(
        &self,
        builder: &MetaEventBuilder<T, S::PublicId>,
        valid_voters: &BTreeSet<S::PublicId>,
        payload_hash: &ObservationHash,
        start_index: usize,
    ) -> bool {
        let peers_that_did_vote = self.ancestors_carrying_payload(
            &valid_voters,
            &*builder.event(),
            payload_hash,
            start_index,
        );
        if let Some(&Observation::OpaquePayload(_)) = self
            .observations
            .get(payload_hash)
            .map(|info| &info.observation)
        {
            (self.is_interesting_event)(&peers_that_did_vote, &valid_voters)
        } else {
            is_supermajority(&peers_that_did_vote, &valid_voters)
        }
    }

    fn ancestors_carrying_payload(
        &self,
        voters: &BTreeSet<S::PublicId>,
        event: &Event<T, S::PublicId>,
        payload_hash: &ObservationHash,
        start_index: usize,
    ) -> BTreeSet<S::PublicId> {
        let payload = self
            .observations
            .get(payload_hash)
            .map(|info| &info.observation);

        self.peer_list
            .iter()
            .filter(|(peer_id, _)| voters.contains(peer_id))
            .filter(|(peer_id, _)| {
                self.graph
                    .iter_from(start_index)
                    .filter(|that_event| that_event.creator() == *peer_id)
                    .any(|that_event| {
                        payload == that_event.vote().map(Vote::payload) && event.sees(that_event)
                    })
            }).map(|(peer_id, _)| peer_id.clone())
            .collect()
    }

    fn set_observees(&self, builder: &mut MetaEventBuilder<T, S::PublicId>) {
        let observees = self
            .meta_elections
            .interesting_events(builder.election())
            .filter_map(|(peer, indices)| {
                let old_index = indices.front()?;
                let old_event = self.get_known_event(*old_index).ok()?;
                if self.strongly_sees(builder.election(), builder.event(), old_event) {
                    Some(peer)
                } else {
                    None
                }
            }).cloned()
            .collect();

        builder.set_observees(observees);
    }

    fn set_meta_votes(&self, builder: &mut MetaEventBuilder<T, S::PublicId>) -> Result<()> {
        let voters = self.voters(builder.election());

        let parent_meta_votes = builder
            .event()
            .self_parent()
            .and_then(|parent_hash| {
                self.meta_elections
                    .meta_votes(builder.election(), parent_hash)
            }).and_then(|parent_meta_votes| {
                if !parent_meta_votes.is_empty() {
                    Some(parent_meta_votes)
                } else {
                    None
                }
            });

        // If self-parent already has meta votes associated with it, derive this event's meta votes
        // from those ones.
        if let Some(parent_meta_votes) = parent_meta_votes {
            for (peer_id, parent_event_votes) in parent_meta_votes {
                let new_meta_votes = {
                    let other_votes = self.collect_other_meta_votes(
                        builder.election(),
                        &voters,
                        &peer_id,
                        &*builder.event(),
                    );
                    let coin_tosses = self.toss_coins(
                        builder.election(),
                        &voters,
                        &peer_id,
                        &parent_event_votes,
                        builder.event(),
                    )?;
                    MetaVote::next(
                        &parent_event_votes,
                        &other_votes,
                        &coin_tosses,
                        voters.len(),
                    )
                };

                builder.add_meta_votes(peer_id.clone(), new_meta_votes);
            }
        } else if self.is_observer(builder) {
            // Start meta votes for this event.
            for peer_id in &voters {
                let other_votes = self.collect_other_meta_votes(
                    builder.election(),
                    &voters,
                    peer_id,
                    &*builder.event(),
                );
                let initial_estimate = builder.has_observee(peer_id);

                builder.add_meta_votes(
                    peer_id.clone(),
                    MetaVote::new(initial_estimate, &other_votes, voters.len()),
                );
            }
        };

        trace!(
            "{:?} has set the meta votes for {:?} in meta-election {:?}",
            self.our_pub_id(),
            *builder.event(),
            builder.election(),
        );

        Ok(())
    }

    fn toss_coins(
        &self,
        election: MetaElectionHandle,
        voters: &BTreeSet<S::PublicId>,
        peer_id: &S::PublicId,
        parent_votes: &[MetaVote],
        event: IndexedEventRef<T, S::PublicId>,
    ) -> Result<BTreeMap<usize, bool>> {
        let mut coin_tosses = BTreeMap::new();
        for parent_vote in parent_votes {
            let _ = self
                .toss_coin(election, voters, peer_id, parent_vote, event)?
                .map(|coin| coin_tosses.insert(parent_vote.round, coin));
        }
        Ok(coin_tosses)
    }

    fn toss_coin(
        &self,
        election: MetaElectionHandle,
        voters: &BTreeSet<S::PublicId>,
        peer_id: &S::PublicId,
        parent_vote: &MetaVote,
        event: IndexedEventRef<T, S::PublicId>,
    ) -> Result<Option<bool>> {
        // Get the round hash.
        let round = if parent_vote.estimates.is_empty() {
            // We're waiting for the coin toss result already.
            if parent_vote.round == 0 {
                // This should never happen as estimates get cleared only in increase step when the
                // step is Step::GenuineFlip and the round gets incremented.
                log_or_panic!(
                    "{:?} missing parent vote estimates at round 0.",
                    self.our_pub_id()
                );
                return Err(Error::Logic);
            }
            parent_vote.round - 1
        } else if parent_vote.step == Step::GenuineFlip {
            parent_vote.round
        } else {
            return Ok(None);
        };
        let round_hash = if let Some(hashes) = self.meta_elections.round_hashes(election, peer_id) {
            hashes[round].value()
        } else {
            log_or_panic!("{:?} missing round hash.", self.our_pub_id());
            return Err(Error::Logic);
        };

        // Get the gradient of leadership.
        let mut peer_id_hashes: Vec<_> = self
            .peer_list
            .peer_id_hashes()
            .filter(|(peer_id, _)| voters.contains(peer_id))
            .collect();
        peer_id_hashes.sort_by(|lhs, rhs| round_hash.xor_cmp(&lhs.1, &rhs.1));

        // Try to get the "most-leader"'s aux value.
        let creator = &peer_id_hashes[0].0;
        if let Some(creator_event_index) = event.last_ancestors().get(creator) {
            if let Some(aux_value) =
                self.aux_value(election, creator, *creator_event_index, peer_id, round)
            {
                return Ok(Some(aux_value));
            }
        }

        // If we've already waited long enough, get the aux value of the highest ranking leader.
        if self.stop_waiting(election, round, event) {
            for (creator, _) in &peer_id_hashes[1..] {
                if let Some(creator_event_index) = event.last_ancestors().get(creator) {
                    if let Some(aux_value) =
                        self.aux_value(election, creator, *creator_event_index, peer_id, round)
                    {
                        return Ok(Some(aux_value));
                    }
                }
            }
        }

        Ok(None)
    }

    // Returns the aux value for the given peer, created by `creator`, at the given round and at
    // the genuine flip step.
    fn aux_value(
        &self,
        election: MetaElectionHandle,
        creator: &S::PublicId,
        creator_event_index: usize,
        peer_id: &S::PublicId,
        round: usize,
    ) -> Option<bool> {
        self.meta_votes_since_round_and_step(
            election,
            creator,
            creator_event_index,
            peer_id,
            round,
            &Step::GenuineFlip,
        ).first()
        .and_then(|meta_vote| meta_vote.aux_value)
    }

    // Skips back through events created by the peer until passed `responsiveness_threshold`
    // response events and sees if the peer had its `aux_value` set at this round.  If so, returns
    // `true`.
    fn stop_waiting(
        &self,
        election: MetaElectionHandle,
        round: usize,
        event: IndexedEventRef<T, S::PublicId>,
    ) -> bool {
        let mut event_index = Some(event.event_index());
        let mut response_count = 0;
        let responsiveness_threshold = self.responsiveness_threshold(election);

        loop {
            if let Some(event) = event_index.and_then(|index| self.get_known_event(index).ok()) {
                if event.is_response() {
                    response_count += 1;
                    if response_count == responsiveness_threshold {
                        break;
                    }
                }
                event_index = event.self_parent();
            } else {
                return false;
            }
        }
        let event_index = match event_index {
            Some(index) => index,
            None => {
                log_or_panic!("{:?} event_index was None.", self.our_pub_id());
                return false;
            }
        };
        self.meta_elections
            .meta_votes(election, event_index)
            .and_then(|meta_votes| meta_votes.get(event.creator()))
            .map_or(false, |event_votes| {
                event_votes
                    .iter()
                    .any(|meta_vote| meta_vote.round == round && meta_vote.aux_value.is_some())
            })
    }

    // Returns the meta votes for the given peer, created by `creator`, since the given round and
    // step.  Starts iterating down the creator's events starting from `creator_event_index`.
    fn meta_votes_since_round_and_step(
        &self,
        election: MetaElectionHandle,
        creator: &S::PublicId,
        creator_event_index: usize,
        peer_id: &S::PublicId,
        round: usize,
        step: &Step,
    ) -> Vec<MetaVote> {
        let mut events = self.peer_list.events_by_index(creator, creator_event_index);

        // Check whether it has at least one item
        let event = if let Some(event) = events.next() {
            event
        } else {
            return vec![];
        };

        if events.next().is_some() {
            // Fork
            return vec![];
        }

        self.meta_elections
            .meta_votes(election, event)
            .and_then(|meta_votes| meta_votes.get(peer_id))
            .map(|meta_votes| {
                meta_votes
                    .iter()
                    .filter(|meta_vote| {
                        meta_vote.round > round
                            || meta_vote.round == round && meta_vote.step >= *step
                    }).cloned()
                    .collect()
            }).unwrap_or_else(|| vec![])
    }

    // Returns the set of meta votes held by all peers other than the creator of `event` which are
    // votes by `peer_id`.
    fn collect_other_meta_votes(
        &self,
        election: MetaElectionHandle,
        voters: &BTreeSet<S::PublicId>,
        peer_id: &S::PublicId,
        event: &Event<T, S::PublicId>,
    ) -> Vec<Vec<MetaVote>> {
        voters
            .iter()
            .filter(|voter_id| *voter_id != event.creator())
            .filter_map(|creator| {
                event
                    .last_ancestors()
                    .get(creator)
                    .map(|creator_event_index| {
                        self.meta_votes_since_round_and_step(
                            election,
                            creator,
                            *creator_event_index,
                            &peer_id,
                            0,
                            &Step::ForcedTrue,
                        )
                    })
            }).collect()
    }

    // Initialise the membership list of the creator of the given event to the same membership list
    // the creator of the other-parent had at the time of the other-parent's creation. Do nothing if
    // the event is not request or response or if the membership list is already initialised.
    fn initialise_membership_list(&mut self, event_index: EventIndex) {
        let (creator, changes) = {
            let event = if let Ok(event) = self.get_known_event(event_index) {
                event
            } else {
                return;
            };

            if event.creator() == self.our_pub_id() {
                return;
            }

            if self
                .peer_list
                .is_peer_membership_list_initialised(event.creator())
            {
                return;
            }

            let other_parent_creator = if let Some(other_parent) = self.graph.other_parent(event) {
                other_parent.inner().creator()
            } else {
                return;
            };

            // Collect all changes to `other_parent_creator`'s membership list seen by `event`.
            let changes: Vec<_> = self
                .peer_list
                .peer_membership_list_changes(other_parent_creator)
                .iter()
                .take_while(|(index, _)| {
                    self.peer_list
                        .events_by_index(other_parent_creator, *index)
                        .filter_map(|hash| self.get_known_event(hash).ok())
                        .any(|other_event| event.sees(other_event))
                }).map(|(_, change)| change.clone())
                .collect();
            (event.creator().clone(), changes)
        };

        for change in changes {
            self.peer_list.change_peer_membership_list(&creator, change);
        }
    }

    // List of voters for the given meta-election.
    fn voters(&self, election: MetaElectionHandle) -> BTreeSet<S::PublicId> {
        self.meta_elections
            .voters(election)
            .cloned()
            .unwrap_or_else(|| self.peer_list.voter_ids().cloned().collect())
    }

    // Number of voters for the given meta-election.
    fn voter_count(&self, election: MetaElectionHandle) -> usize {
        self.meta_elections
            .voters(election)
            .map(|voters| voters.len())
            .unwrap_or_else(|| self.peer_list.voters().count())
    }

    fn compute_consensus(
        &self,
        election: MetaElectionHandle,
        event_index: EventIndex,
    ) -> Option<ObservationHash> {
        let last_meta_votes = self.meta_elections.meta_votes(election, event_index)?;

        let decided_meta_votes = last_meta_votes.iter().filter_map(|(id, event_votes)| {
            event_votes.last().and_then(|v| v.decision).map(|v| (id, v))
        });

        if decided_meta_votes.clone().count() < self.voter_count(election) {
            return None;
        }

        self.meta_elections
            .decided_payload_hash(election)
            .cloned()
            .or_else(|| self.compute_payload_for_consensus(election, decided_meta_votes))
    }

    fn compute_payload_for_consensus<'a, I>(
        &self,
        election: MetaElectionHandle,
        decided_meta_votes: I,
    ) -> Option<ObservationHash>
    where
        I: IntoIterator<Item = (&'a S::PublicId, bool)>,
        S::PublicId: 'a,
    {
        let payloads: Vec<_> = decided_meta_votes
            .into_iter()
            .filter_map(|(id, decision)| {
                if decision {
                    self.meta_elections
                        .first_interesting_content_by(election, &id)
                        .cloned()
                } else {
                    None
                }
            }).collect();

        payloads
            .iter()
            .max_by(|lhs_payload, rhs_payload| {
                let lhs_count = payloads
                    .iter()
                    .filter(|payload_carried| lhs_payload == payload_carried)
                    .count();
                let rhs_count = payloads
                    .iter()
                    .filter(|payload_carried| rhs_payload == payload_carried)
                    .count();
                lhs_count.cmp(&rhs_count)
            }).cloned()
    }

    fn create_block(&self, payload_hash: &ObservationHash) -> Result<Block<T, S::PublicId>> {
        let payload = self
            .observations
            .get(payload_hash)
            .map(|info| info.observation.clone())
            .ok_or_else(|| Error::Logic)?;
        let votes = self
            .graph
            .iter()
            .filter_map(|event| {
                event.vote().and_then(|vote| {
                    if *vote.payload() == payload {
                        Some((event.creator().clone(), vote.clone()))
                    } else {
                        None
                    }
                })
            }).collect();

        Block::new(payload, &votes)
    }

    fn restart_consensus(&mut self, start_index: usize, current_index: usize) -> Result<()> {
        self.meta_elections
            .initialise_current_election(self.peer_list.all_ids());

        if current_index < start_index {
            return Ok(());
        }

        // This makes sure that we only reprocess events between start_index and current_index,
        // inclusive.
        // `collect()` needed because the iterator returned by `iter_from()` borrows `self`
        // immutably, which conflicts with `process_event`.
        let indices: Vec<_> = self
            .graph
            .iter_from(start_index)
            .take(current_index - start_index + 1)
            .map(|event| event.event_index())
            .collect();
        for index in indices {
            // This will reprocess events relevant to the new meta-election, but in the context of
            // all active meta-elections. This is sometimes necessary, as restart_consensus can be
            // called while events are being reprocessed and in such cases we could miss some
            // events when creating meta-events.
            self.process_event(index)?;
        }

        Ok(())
    }

    fn compute_next_meta_election_start_index(&self) -> usize {
        // Find the topological index of the first event that carries unconsensused payload.
        let previous = self.meta_elections.start_index(MetaElectionHandle::CURRENT);
        self.graph
            .iter_from(previous)
            .filter(|event| {
                event
                    .payload_hash()
                    .and_then(|payload_hash| self.observations.get(&payload_hash))
                    .map(|info| !info.consensused)
                    .unwrap_or(false)
            }).map(|indexed_event| indexed_event.topological_index())
            .next()
            .unwrap_or_else(|| self.graph.len())
    }

    // Returns the number of peers that created events which are seen by event X (descendant) and
    // see event Y (ancestor). This means number of peers through which there is a directed path
    // between x and y, excluding peers contains fork.
    fn num_peers_created_events_seen_by_x_that_can_see_y(
        &self,
        x: &Event<T, S::PublicId>,
        y: &Event<T, S::PublicId>,
    ) -> usize {
        x.last_ancestors()
            .iter()
            .filter(|(peer_id, &event_index)| {
                for event_hash in self.peer_list.events_by_index(peer_id, event_index) {
                    if let Ok(event) = self.get_known_event(event_hash) {
                        if x.sees(event) && event.sees(y) {
                            return true;
                        }
                    }
                }
                false
            }).count()
    }

    // Returns whether event X can strongly see the event Y during the evaluation of the given
    // election.
    fn strongly_sees<A, B>(&self, election: MetaElectionHandle, x: A, y: B) -> bool
    where
        A: AsRef<Event<T, S::PublicId>>,
        B: AsRef<Event<T, S::PublicId>>,
    {
        is_more_than_two_thirds(
            self.num_peers_created_events_seen_by_x_that_can_see_y(x.as_ref(), y.as_ref()),
            self.voter_count(election),
        )
    }

    // Constructs a sync event to prove receipt of a `Request` or `Response` (depending on the value
    // of `is_request`) from `src`, then add it to our graph.
    fn create_sync_event(
        &mut self,
        src: &S::PublicId,
        is_request: bool,
        forking_peers: &BTreeSet<S::PublicId>,
    ) -> Result<()> {
        let self_parent = self
            .peer_list
            .last_event(self.our_pub_id())
            .and_then(|index| self.get_known_event(index).ok())
            .map(|event| *event.hash())
            .ok_or_else(|| {
                log_or_panic!("{:?} missing our own last event hash.", self.our_pub_id());
                Error::Logic
            })?;

        let other_parent = self
            .peer_list
            .last_event(src)
            .and_then(|index| self.get_known_event(index).ok())
            .map(|event| *event.hash())
            .ok_or_else(|| {
                log_or_panic!("{:?} missing {:?} last event hash.", self.our_pub_id(), src);
                Error::Logic
            })?;

        let sync_event = if is_request {
            Event::new_from_request(
                self_parent,
                other_parent,
                &self.graph,
                &self.peer_list,
                forking_peers,
            )
        } else {
            Event::new_from_response(
                self_parent,
                other_parent,
                &self.graph,
                &self.peer_list,
                forking_peers,
            )
        };

        self.add_event(sync_event)
    }

    // Returns an iterator over `self.events` which will yield all the events we think `peer_id`
    // doesn't yet know about.  We should already have checked that we know `peer_id` and that we
    // have recorded at least one event from this peer before calling this function.
    fn events_to_gossip_to_peer(
        &self,
        peer_id: &S::PublicId,
    ) -> Result<Vec<&Event<T, S::PublicId>>> {
        let last_event = if let Some(event_index) = self.peer_list.last_event(peer_id) {
            self.get_known_event(event_index)?
        } else {
            log_or_panic!("{:?} doesn't have peer {:?}", self.our_pub_id(), peer_id);
            return Err(Error::Logic);
        };

        // Events to include in the result. Initially start with including everything...
        let mut inclusion_list = vec![true; self.graph.len()];

        // ...then exclude events that are ancestors of `last_event`, because the peer already has
        // them.
        for event in self.graph.ancestors(last_event) {
            inclusion_list[event.topological_index()] = false;
        }

        Ok(self
            .graph
            .iter()
            .filter(|event| inclusion_list[event.topological_index()])
            .map(|event| event.inner())
            .collect())
    }

    // Get the responsiveness threshold based on the current number of peers.
    fn responsiveness_threshold(&self, election: MetaElectionHandle) -> usize {
        (self.voter_count(election) as f64).log2().ceil() as usize
    }

    #[cfg(feature = "malice-detection")]
    fn detect_malice_before_process(&mut self, event: &Event<T, S::PublicId>) -> Result<()> {
        // NOTE: `detect_incorrect_genesis` must come first.
        self.detect_incorrect_genesis(event)?;

        self.detect_other_parent_by_same_creator(event)?;
        self.detect_self_parent_by_different_creator(event)?;

        self.detect_unexpected_genesis(event);
        self.detect_missing_genesis(event);
        self.detect_duplicate_vote(event);
        self.detect_stale_other_parent(event);
        self.detect_fork(event);
        self.detect_invalid_accusation(event);

        // TODO: detect other forms of malice here

        Ok(())
    }

    #[cfg(feature = "malice-detection")]
    fn detect_malice_after_process(&mut self, event_index: EventIndex) {
        self.detect_invalid_gossip_creator(event_index);
    }

    fn create_accusation_event(
        &mut self,
        offender: S::PublicId,
        malice: Malice<T, S::PublicId>,
    ) -> Result<()> {
        let event = Event::new_from_observation(
            self.our_last_event_hash(),
            Observation::Accusation { offender, malice },
            &self.graph,
            &self.peer_list,
        );

        self.add_event(event)
    }

    fn create_accusation_events(&mut self) -> Result<()> {
        let pending_accusations = mem::replace(&mut self.pending_accusations, vec![]);
        for (offender, malice) in pending_accusations {
            self.create_accusation_event(offender, malice)?;
        }

        Ok(())
    }
}

#[cfg(feature = "malice-detection")]
impl<T: NetworkEvent, S: SecretId> Parsec<T, S> {
    // Detect if the event carries an `Observation::Genesis` that doesn't match what we'd expect.
    fn detect_incorrect_genesis(&mut self, event: &Event<T, S::PublicId>) -> Result<()> {
        if let Some(Observation::Genesis(ref group)) = event.vote().map(Vote::payload) {
            if group.iter().collect::<BTreeSet<_>>() != self.genesis_group() {
                // Raise the accusation immediately and return an error, to prevent accepting
                // potentially large number of invalid / spam events into our graph.
                self.create_accusation_event(
                    event.creator().clone(),
                    Malice::IncorrectGenesis(*event.hash()),
                )?;
                return Err(Error::InvalidEvent);
            }
        }

        Ok(())
    }

    // Detect if the event's other_parent has the same creator as this event.
    fn detect_other_parent_by_same_creator(&mut self, event: &Event<T, S::PublicId>) -> Result<()> {
        if let Some(other_parent) = self.graph.other_parent(event) {
            if other_parent.creator() != event.creator() {
                return Ok(());
            }
        } else {
            return Ok(());
        }

        // Raise the accusation immediately and return an error, to prevent accepting
        // potentially large number of invalid / spam events into our graph.
        self.create_accusation_event(
            event.creator().clone(),
            Malice::OtherParentBySameCreator(Box::new(event.pack())),
        )?;
        Err(Error::InvalidEvent)
    }

    // Detect if the event's self_parent has the different creator as this event.
    fn detect_self_parent_by_different_creator(
        &mut self,
        event: &Event<T, S::PublicId>,
    ) -> Result<()> {
        if let Some(self_parent) = self.graph.self_parent(event) {
            if self_parent.creator() == event.creator() {
                return Ok(());
            }
        } else {
            return Ok(());
        }

        // Raise the accusation immediately and return an error, to prevent accepting
        // potentially large number of invalid / spam events into our graph.
        self.create_accusation_event(
            event.creator().clone(),
            Malice::SelfParentByDifferentCreator(Box::new(event.pack())),
        )?;
        Err(Error::InvalidEvent)
    }

    // Detect whether the event carries unexpected `Observation::Genesis`.
    fn detect_unexpected_genesis(&mut self, event: &Event<T, S::PublicId>) {
        let payload = if let Some(payload) = event.vote().map(Vote::payload) {
            payload
        } else {
            return;
        };

        let genesis_group = if let Observation::Genesis(ref group) = *payload {
            group
        } else {
            return;
        };

        // - the creator is not member of the genesis group, or
        // - the self-parent of the event is not initial event
        if !genesis_group.contains(event.creator()) || self
            .graph
            .self_parent(event)
            .map_or(true, |self_parent| !self_parent.is_initial())
        {
            self.accuse(
                event.creator().clone(),
                Malice::UnexpectedGenesis(*event.hash()),
            );
        }
    }

    // Detect when the first event by a peer belonging to genesis doesn't carry genesis
    fn detect_missing_genesis(&mut self, event: &Event<T, S::PublicId>) {
        if event.index_by_creator() != 1 {
            return;
        }

        if let Some(&Observation::Genesis(_)) = event.vote().map(Vote::payload) {
            return;
        }

        if self.genesis_group().contains(event.creator()) {
            self.accuse(
                event.creator().clone(),
                Malice::MissingGenesis(*event.hash()),
            );
        }
    }

    // Detect that if the event carries a vote, there is already one or more votes with the same
    // observation by the same creator.
    fn detect_duplicate_vote(&mut self, event: &Event<T, S::PublicId>) {
        let payload = if let Some(payload) = event.vote().map(Vote::payload) {
            payload
        } else {
            return;
        };

        let other_hash = {
            let mut duplicates = self
                .peer_list
                .peer_events(event.creator())
                .rev()
                .filter_map(|index| self.get_known_event(index).ok())
                .filter(|event| event.vote().map_or(false, |vote| vote.payload() == payload))
                .map(|event| *event.hash())
                .take(2);

            let hash = if let Some(hash) = duplicates.next() {
                // One duplicate found - raise the accusation.
                hash
            } else {
                // No duplicates found - do not raise the accusation.
                return;
            };

            if duplicates.next().is_some() {
                // More than one duplicate found - the accusation should have already been raised,
                // so don't raise it again.
                return;
            }

            hash
        };

        self.accuse(
            event.creator().clone(),
            Malice::DuplicateVote(other_hash, *event.hash()),
        );
    }

    // Detect if the event's other_parent older than first ancestor of self_parent.
    fn detect_stale_other_parent(&mut self, event: &Event<T, S::PublicId>) {
        let (other_parent_index, other_parent_creator) =
            if let Some(other_parent) = self.graph.other_parent(event) {
                (
                    other_parent.index_by_creator(),
                    other_parent.creator().clone(),
                )
            } else {
                return;
            };
        let self_parent_ancestor_index = if let Some(index) =
            self.graph.self_parent(event).and_then(|self_parent| {
                self_parent
                    .inner()
                    .last_ancestors()
                    .get(&other_parent_creator)
            }) {
            *index
        } else {
            return;
        };
        if other_parent_index < self_parent_ancestor_index {
            self.accuse(
                event.creator().clone(),
                Malice::StaleOtherParent(*event.hash()),
            );
        }
    }

    // Detect whether the event incurs a fork.
    fn detect_fork(&mut self, event: &Event<T, S::PublicId>) {
        if self.peer_list.last_event(event.creator()) != event.self_parent() {
            if let Some(self_parent_hash) = self.graph.self_parent(event).map(|event| *event.hash())
            {
                self.accuse(event.creator().clone(), Malice::Fork(self_parent_hash));
            }
        }
    }

    fn detect_invalid_accusation(&mut self, event: &Event<T, S::PublicId>) {
        let their_accusation = if let Some(&Observation::Accusation {
            ref offender,
            ref malice,
        }) = event.vote().map(Vote::payload)
        {
            (offender, malice)
        } else {
            return;
        };

        // First try to find the same accusation in our pending accusations...
        let found = self
            .pending_accusations
            .iter()
            .any(|&(ref our_offender, ref our_malice)| {
                their_accusation == (our_offender, our_malice)
            });
        if found {
            return;
        }

        // ...then in our events...
        let found = self
            .peer_list
            .our_events()
            .rev()
            .filter_map(|hash| self.get_known_event(hash).ok())
            .filter_map(|event| {
                if let Some(&Observation::Accusation {
                    ref offender,
                    ref malice,
                }) = event.inner().vote().map(Vote::payload)
                {
                    Some((offender, malice))
                } else {
                    None
                }
            }).any(|our_accusation| their_accusation == our_accusation);
        if found {
            return;
        }

        // ..if not found, their accusation is invalid.
        self.accuse(
            event.creator().clone(),
            Malice::InvalidAccusation(*event.hash()),
        )
    }

    fn detect_invalid_gossip_creator(&mut self, event_index: EventIndex) {
        let accusation = {
            let event = if let Ok(event) = self.get_known_event(event_index) {
                event
            } else {
                return;
            };

            let other_parent = if let Some(parent) = self.graph.other_parent(event) {
                parent
            } else {
                return;
            };

            let membership_list = if let Some(list) = self
                .peer_list
                .peer_membership_list_snapshot_excluding_last_remove(
                    event.creator(),
                    event.index_by_creator(),
                ) {
                list
            } else {
                // The membership list is not yet initialised - skip the detection.
                return;
            };

            if membership_list.contains(other_parent.creator()) {
                None
            } else {
                Some((event.creator().clone(), *event.hash()))
            }
        };

        if let Some((offender, event_hash)) = accusation {
            self.accuse(offender, Malice::InvalidGossipCreator(event_hash))
        }
    }

    fn detect_premature_gossip(&self) -> Result<()> {
        self.confirm_self_state(PeerState::VOTE)
            .map_err(|_| Error::PrematureGossip)
    }

    fn genesis_group(&self) -> BTreeSet<&S::PublicId> {
        self.graph
            .iter()
            .filter_map(|event| {
                if let Some(&Observation::Genesis(ref gen)) =
                    event.inner().vote().map(Vote::payload)
                {
                    Some(gen.iter().collect())
                } else {
                    None
                }
            }).next()
            .unwrap_or_else(|| self.peer_list.voter_ids().collect())
    }

    fn accuse(&mut self, offender: S::PublicId, malice: Malice<T, S::PublicId>) {
        self.pending_accusations.push((offender, malice));
    }
}

impl<T: NetworkEvent, S: SecretId> Drop for Parsec<T, S> {
    fn drop(&mut self) {
        if ::std::thread::panicking() {
            dump_graph::to_file(
                self.our_pub_id(),
                &self.graph,
                &self.meta_elections,
                &self.peer_list,
                self.observations
                    .iter()
                    .map(|(hash, info)| (hash, &info.observation))
                    .collect(),
            );
        }
    }
}

#[cfg(test)]
impl Parsec<Transaction, PeerId> {
    pub(crate) fn from_parsed_contents(mut parsed_contents: ParsedContents) -> Self {
        let mut parsec = Parsec::empty(parsed_contents.our_id, &BTreeSet::new(), is_supermajority);

        // Populate `observations` cache using `interesting_content`, to support partial graphs...
        for meta_event in parsed_contents
            .meta_elections
            .current_meta_events()
            .values()
        {
            for payload_hash in &meta_event.interesting_content {
                if let Some(payload) = parsed_contents.observation_map.remove(payload_hash) {
                    let obs_info = ObservationInfo {
                        observation: payload,
                        consensused: false,
                        created_by_us: false,
                    };
                    let _ = parsec.observations.insert(*payload_hash, obs_info);
                }
            }
        }

        // ..and also the payloads carried by events.
        let our_pub_id = parsec.our_pub_id().clone();
        for event in &parsed_contents.graph {
            if let Some((payload_hash, new_info)) = ObservationInfo::create(&*event) {
                let info = parsec.observations.entry(payload_hash).or_insert(new_info);
                if *event.creator() == our_pub_id {
                    info.created_by_us = true;
                }
            }
        }

        for consensused in parsed_contents.meta_elections.consensus_history() {
            let _ = parsec
                .observations
                .get_mut(consensused)
                .map(|info| info.consensused = true);
        }

        parsec.graph = parsed_contents.graph;
        parsec.meta_elections = parsed_contents.meta_elections;
        parsec.peer_list = parsed_contents.peer_list;
        parsec
    }
}

#[derive(Debug)]
struct ObservationInfo<T: NetworkEvent, P: PublicId> {
    observation: Observation<T, P>,
    consensused: bool,
    created_by_us: bool,
}

impl<T: NetworkEvent, P: PublicId> ObservationInfo<T, P> {
    fn create(event: &Event<T, P>) -> Option<(ObservationHash, Self)> {
        event.payload_with_hash().map(|(observation, hash)| {
            (
                *hash,
                Self {
                    observation: observation.clone(),
                    consensused: false,
                    created_by_us: false,
                },
            )
        })
    }
}

/// Assert that the two parsec instances have the same events modulo their insertion order.
#[cfg(all(test, feature = "testing"))]
pub(crate) fn assert_same_events<T: NetworkEvent, S: SecretId>(a: &Parsec<T, S>, b: &Parsec<T, S>) {
    use gossip::GraphSnapshot;

    let a = GraphSnapshot::new(&a.graph);
    let b = GraphSnapshot::new(&b.graph);

    assert_eq!(a, b)
}

#[cfg(test)]
mod functional_tests {
    use super::*;
    use dev_utils::parse_test_dot_file;
    use gossip::{Event, GraphSnapshot};
    use id::PublicId;
    use meta_voting::MetaElectionsSnapshot;
    use mock::{self, Transaction};
    use peer_list::PeerListSnapshot;
    use peer_list::PeerState;

    #[derive(Debug, PartialEq, Eq)]
    struct Snapshot {
        peer_list: PeerListSnapshot<PeerId>,
        events: GraphSnapshot,
        meta_elections: MetaElectionsSnapshot<PeerId>,
        consensused_blocks: VecDeque<Block<Transaction, PeerId>>,
    }

    impl Snapshot {
        fn new(parsec: &Parsec<Transaction, PeerId>) -> Self {
            Snapshot {
                peer_list: PeerListSnapshot::new(&parsec.peer_list, &parsec.graph),
                events: GraphSnapshot::new(&parsec.graph),
                meta_elections: MetaElectionsSnapshot::new(&parsec.meta_elections, &parsec.graph),
                consensused_blocks: parsec.consensused_blocks.clone(),
            }
        }
    }

    macro_rules! assert_err {
        ($expected_error:pat, $result:expr) => {
            match $result {
                Err($expected_error) => (),
                unexpected => panic!(
                    "Expected {}, but got {:?}",
                    stringify!($expected_error),
                    unexpected
                ),
            }
        };
    }

    macro_rules! btree_set {
        ($($item:expr),*) => {{
            let mut set = BTreeSet::new();
            $(
                let _ = set.insert($item);
            )*
            set
        }}
    }

    fn nth_event<T: NetworkEvent, P: PublicId>(graph: &Graph<T, P>, n: usize) -> &Event<T, P> {
        unwrap!(graph.iter_from(n).next()).inner()
    }

    #[test]
    fn from_existing() {
        let mut peers = mock::create_ids(10);
        let our_id = unwrap!(peers.pop());
        let peers = peers.into_iter().collect();

        let parsec = Parsec::<Transaction, _>::from_existing(
            our_id.clone(),
            &peers,
            &peers,
            is_supermajority,
        );

        // Existing section + us
        assert_eq!(parsec.peer_list.all_ids().count(), peers.len() + 1);

        // Only the initial event should be in the gossip graph.
        assert_eq!(parsec.graph.len(), 1);
        let event = nth_event(&parsec.graph, 0);
        assert_eq!(*event.creator(), our_id);
        assert!(event.is_initial());
    }

    // TODO: remove this `cfg` once the `maidsafe_utilities` crate with PR 130 is published.
    #[cfg(feature = "testing")]
    #[test]
    #[should_panic(expected = "Genesis group can't be empty")]
    fn from_existing_requires_non_empty_genesis_group() {
        use mock;

        let mut peers = mock::create_ids(10);
        let our_id = unwrap!(peers.pop());
        let peers = peers.into_iter().collect();

        let _ = Parsec::<Transaction, _>::from_existing(
            our_id,
            &BTreeSet::new(),
            &peers,
            is_supermajority,
        );
    }

    // TODO: remove this `cfg` once the `maidsafe_utilities` crate with PR 130 is published.
    #[cfg(feature = "testing")]
    #[test]
    #[should_panic(expected = "Genesis group can't already contain us")]
    fn from_existing_requires_that_genesis_group_does_not_contain_us() {
        use mock;

        let peers = mock::create_ids(10);
        let our_id = unwrap!(peers.first()).clone();
        let genesis_group = peers.iter().cloned().collect();
        let section = peers.into_iter().skip(1).collect();

        let _ = Parsec::<Transaction, _>::from_existing(
            our_id,
            &genesis_group,
            &section,
            is_supermajority,
        );
    }

    // TODO: remove this `cfg` once the `maidsafe_utilities` crate with PR 130 is published.
    #[cfg(feature = "testing")]
    #[test]
    #[should_panic(expected = "Section can't be empty")]
    fn from_existing_requires_non_empty_section() {
        use mock;

        let mut peers = mock::create_ids(10);
        let our_id = unwrap!(peers.pop());
        let genesis_group = peers.into_iter().collect();

        let _ = Parsec::<Transaction, _>::from_existing(
            our_id,
            &genesis_group,
            &BTreeSet::new(),
            is_supermajority,
        );
    }

    // TODO: remove this `cfg` once the `maidsafe_utilities` crate with PR 130 is published.
    #[cfg(feature = "testing")]
    #[test]
    #[should_panic(expected = "Section can't already contain us")]
    fn from_existing_requires_that_section_does_not_contain_us() {
        use mock;

        let peers = mock::create_ids(10);
        let our_id = unwrap!(peers.first()).clone();
        let genesis_group = peers.iter().skip(1).cloned().collect();
        let section = peers.into_iter().collect();

        let _ = Parsec::<Transaction, _>::from_existing(
            our_id,
            &genesis_group,
            &section,
            is_supermajority,
        );
    }

    #[test]
    fn from_genesis() {
        let peers = mock::create_ids(10);
        let our_id = unwrap!(peers.first()).clone();
        let peers = peers.into_iter().collect();

        let parsec =
            Parsec::<Transaction, _>::from_genesis(our_id.clone(), &peers, is_supermajority);
        // the peer_list should contain the entire genesis group
        assert_eq!(parsec.peer_list.all_ids().count(), peers.len());
        // initial event + genesis_observation
        assert_eq!(parsec.graph.len(), 2);
        let initial_event = nth_event(&parsec.graph, 0);
        assert_eq!(*initial_event.creator(), our_id);
        assert!(initial_event.is_initial());
        let genesis_observation = nth_event(&parsec.graph, 1);
        assert_eq!(*genesis_observation.creator(), our_id);
        match &genesis_observation.vote() {
            Some(vote) => {
                assert_eq!(*vote.payload(), Observation::Genesis(peers));
            }
            None => panic!("Expected observation, but event carried no vote"),
        }
    }

    // TODO: remove this `cfg` once the `maidsafe_utilities` crate with PR 130 is published.
    #[cfg(feature = "testing")]
    #[test]
    #[should_panic(expected = "Genesis group must contain us")]
    fn from_genesis_requires_the_genesis_group_contains_us() {
        let mut peers = mock::create_ids(10);
        let our_id = unwrap!(peers.pop());
        let peers = peers.into_iter().collect();

        let _ = Parsec::<Transaction, _>::from_genesis(our_id.clone(), &peers, is_supermajority);
    }

    #[test]
    fn from_parsed_contents() {
        let input_file = "0.dot";
        let parsed_contents = parse_test_dot_file(input_file);
        let parsed_contents_comparison = parse_test_dot_file(input_file);
        let parsec = Parsec::from_parsed_contents(parsed_contents);
        assert_eq!(parsed_contents_comparison.graph, parsec.graph);
        assert_eq!(
            parsed_contents_comparison.meta_elections,
            parsec.meta_elections
        );

        let parsed_contents_other = parse_test_dot_file("1.dot");
        assert_ne!(parsed_contents_other.graph, parsec.graph);
        assert_ne!(parsed_contents_other.meta_elections, parsec.meta_elections);
    }

    #[test]
    fn add_peer() {
        // Generated with RNG seed: [411278735, 3293288956, 208850454, 2872654992].
        let mut parsed_contents = parse_test_dot_file("alice.dot");

        // The final decision to add Frank is reached in D_18, so pop this event for now.
        let d_18 = unwrap!(parsed_contents.remove_last_event());

        let mut alice = Parsec::from_parsed_contents(parsed_contents);
        let genesis_group: BTreeSet<_> = alice.peer_list.all_ids().cloned().collect();

        let fred_id = PeerId::new("Fred");
        assert!(!alice.peer_list.all_ids().any(|peer_id| *peer_id == fred_id));

        let alice_snapshot = Snapshot::new(&alice);

        // Try calling `create_gossip()` for a peer which doesn't exist yet.
        assert_err!(Error::InvalidPeerState { .. }, alice.create_gossip(Some(&fred_id)));
        assert_eq!(alice_snapshot, Snapshot::new(&alice));

        // Now add D_18, which should result in Alice adding Fred.
        unwrap!(alice.add_event(d_18));
        unwrap!(alice.create_sync_event(&PeerId::new("Eric"), true, &BTreeSet::new()));
        assert!(alice.peer_list.all_ids().any(|peer_id| *peer_id == fred_id));

        // Construct Fred's Parsec instance.
        let mut fred =
            Parsec::from_existing(fred_id, &genesis_group, &genesis_group, is_supermajority);

        // Create a "naughty Carol" instance where the graph only shows four peers existing before
        // adding Fred.
        let alice_id = PeerId::new("Alice");
        #[cfg(feature = "malice-detection")]
        {
            parsed_contents = parse_test_dot_file("carol.dot");
            let naughty_carol = Parsec::from_parsed_contents(parsed_contents);
            let malicious_message = unwrap!(naughty_carol.create_gossip(None));
            assert_err!(
                Error::InvalidEvent,
                fred.handle_request(&alice_id, malicious_message)
            );
        }

        // Now pass a valid initial request from Alice to Fred.  The generated response would
        // normally only contain Fred's initial event, and the one recording receipt of Alice's
        // request.  However this graph doesn't represent the state it would be in if Alice were
        // actually sending such a request - it should have an event by Alice as the latest.  We
        // really only need to check here though that Fred doesn't respond with the full graph.
        let message = unwrap!(alice.create_gossip(None));
        let response = unwrap!(fred.handle_request(&alice_id, message));
        assert!(response.packed_events.len() < fred.graph.len());
    }

    #[test]
    fn remove_peer() {
        // Generated with RNG seed: [3580486268, 2993583568, 344059332, 3173905166].
        let mut parsed_contents = parse_test_dot_file("alice.dot");
        // The final decision to remove Eric is reached in the last event of Alice.
        let a_last = unwrap!(parsed_contents.remove_last_event());

        let mut alice = Parsec::from_parsed_contents(parsed_contents);
        let eric_id = PeerId::new("Eric");

        assert!(alice.peer_list.all_ids().any(|peer_id| *peer_id == eric_id));
        assert_ne!(alice.peer_list.peer_state(&eric_id), PeerState::inactive());

        // Add event now which shall result in Alice removing Eric.
        unwrap!(alice.add_event(a_last));
        assert_eq!(alice.peer_list.peer_state(&eric_id), PeerState::inactive());

        // Try calling `create_gossip()` for Eric shall result in error.
        assert_err!(Error::InvalidPeerState { .. }, alice.create_gossip(Some(&eric_id)));

        // Construct Eric's parsec instance.
        let mut section: BTreeSet<_> = alice.peer_list.all_ids().cloned().collect();
        let _ = section.remove(&eric_id);
        let mut eric = Parsec::<Transaction, _>::from_existing(
            eric_id.clone(),
            &section,
            &section,
            is_supermajority,
        );

        // Peer state is (VOTE | SEND) when created from existing. Need to update the states to
        // (VOTE | SEND | RECV).
        for peer_id in &section {
            eric.peer_list.change_peer_state(peer_id, PeerState::RECV);
        }

        // Eric can no longer gossip to anyone.
        assert_err!(
            Error::InvalidSelfState { .. },
            eric.create_gossip(Some(&PeerId::new("Alice")))
        );
    }

    #[test]
    fn unpolled_and_unconsensused_observations() {
        // Generated with RNG seed: [3016139397, 1416620722, 2110786801, 3768414447], but using
        // Alice-002.dot to get the dot file where we get consensus on `Add(Eric)`.
        let mut alice_contents = parse_test_dot_file("alice.dot");
        let a_17 = unwrap!(alice_contents.remove_last_event());

        let mut alice = Parsec::from_parsed_contents(alice_contents);

        // `Add(Eric)` should still be unconsensused since A_17 would be the first gossip event to
        // reach consensus on `Add(Eric)`, but it was removed from the graph.
        assert!(alice.has_unconsensused_observations());

        // Since we haven't called `poll()` yet, our vote for `Add(Eric)` should be returned by
        // `our_unpolled_observations()`.
        let add_eric = Observation::Add {
            peer_id: PeerId::new("Eric"),
            related_info: vec![],
        };
        assert_eq!(alice.our_unpolled_observations().count(), 1);
        assert_eq!(*unwrap!(alice.our_unpolled_observations().next()), add_eric);

        // Call `poll()` and retry - should have no effect to unconsensused and unpolled
        // observations.
        assert!(alice.poll().is_none());
        assert!(alice.has_unconsensused_observations());
        assert_eq!(alice.our_unpolled_observations().count(), 1);
        assert_eq!(*unwrap!(alice.our_unpolled_observations().next()), add_eric);

        // Have Alice process A_17 to get consensus on `Add(Eric)`.
        unwrap!(alice.add_event(a_17));

        // Since we haven't call `poll()` again yet, should still return our vote for `Add(Eric)`.
        // However, `has_unconsensused_observations()` should now return false.
        assert!(!alice.has_unconsensused_observations());
        assert_eq!(alice.our_unpolled_observations().count(), 1);
        assert_eq!(*unwrap!(alice.our_unpolled_observations().next()), add_eric);

        // Call `poll()` and retry - should return none.
        unwrap!(alice.poll());
        assert!(alice.poll().is_none());
        assert!(alice.our_unpolled_observations().next().is_none());

        // Vote for a new observation and check it is returned as unpolled, and that
        // `has_unconsensused_observations()` returns false again.
        let vote = Observation::OpaquePayload(Transaction::new("ABCD"));
        unwrap!(alice.vote_for(vote.clone()));

        assert!(alice.has_unconsensused_observations());
        assert_eq!(alice.our_unpolled_observations().count(), 1);
        assert_eq!(*unwrap!(alice.our_unpolled_observations().next()), vote);

        // Reset, and re-run, this time adding Alice's vote early to check that it is returned in
        // the correct order, i.e. after `Add(Eric)` at the point where `Add(Eric)` is consensused
        // but has not been returned by `poll()`.
        alice = Parsec::from_parsed_contents(parse_test_dot_file("alice.dot"));
        unwrap!(alice.vote_for(vote.clone()));
        let mut unpolled_observations = alice.our_unpolled_observations();
        assert_eq!(*unwrap!(unpolled_observations.next()), add_eric);
        assert_eq!(*unwrap!(unpolled_observations.next()), vote);
        assert!(unpolled_observations.next().is_none());
    }

    #[test]
    fn gossip_after_fork() {
        let alice_id = PeerId::new("Alice");
        let bob_id = PeerId::new("Bob");

        let genesis_group = btree_set![
            alice_id.clone(),
            bob_id.clone(),
            PeerId::new("Carol"),
            PeerId::new("Dave")
        ];

        let mut alice = Parsec::from_genesis(alice_id.clone(), &genesis_group, is_supermajority);

        // Alice creates couple of valid events.
        let a_1_index = unwrap!(alice.peer_list.our_events().next());
        let a_1_hash = *unwrap!(alice.graph.get(a_1_index)).hash();

        let a_2 = Event::new_from_observation(
            a_1_hash,
            Observation::OpaquePayload(Transaction::new("one")),
            &alice.graph,
            &alice.peer_list,
        );
        let a_2_hash = *a_2.hash();
        unwrap!(alice.add_event(a_2));

        let a_3 = Event::new_from_observation(
            a_2_hash,
            Observation::OpaquePayload(Transaction::new("two")),
            &alice.graph,
            &alice.peer_list,
        );
        let a_3_hash = *a_3.hash();
        unwrap!(alice.add_event(a_3));

        let mut bob = Parsec::from_genesis(bob_id.clone(), &genesis_group, is_supermajority);

        // Alice sends a gossip request to Bob and receives a response back.
        let req = unwrap!(alice.create_gossip(Some(&bob_id)));
        let res = unwrap!(bob.handle_request(&alice_id, req));
        unwrap!(alice.handle_response(&bob_id, res));

        // Now Bob has a_0, a_1, a_2 and a_3 and Alice knows it.
        assert!(bob.graph.get_index(&a_1_hash).is_some());
        assert!(bob.graph.get_index(&a_2_hash).is_some());
        assert!(bob.graph.get_index(&a_3_hash).is_some());

        // Alice creates a fork.
        let a_2_fork = Event::new_from_observation(
            a_1_hash,
            Observation::OpaquePayload(Transaction::new("two-fork")),
            &alice.graph,
            &alice.peer_list,
        );
        let a_2_fork_hash = *a_2_fork.hash();
        unwrap!(alice.add_event(a_2_fork));

        // Alice sends another gossip request to Bob.
        let req = unwrap!(alice.create_gossip(Some(&bob_id)));
        let _ = unwrap!(bob.handle_request(&alice_id, req));

        // Verify that Bob now has the forked event.
        assert!(bob.graph.get_index(&a_2_fork_hash).is_some());
    }

    #[cfg(feature = "malice-detection")]
    mod handle_malice {
        use super::*;
        use dev_utils::{parse_dot_file_with_test_name, parse_test_dot_file};
        use gossip::{find_event_by_short_name, Event};
        use mock::Transaction;
        use peer_list::PeerState;

        // Returns iterator over all votes cast by the given node.
        fn our_votes<T: NetworkEvent, S: SecretId>(
            parsec: &Parsec<T, S>,
        ) -> impl Iterator<Item = &Observation<T, S::PublicId>> {
            parsec
                .peer_list
                .our_events()
                .filter_map(move |index| parsec.graph.get(index))
                .filter_map(|event| event.inner().vote())
                .map(|vote| vote.payload())
        }

        // Add the peers to the `PeerList` as the genesis group.
        fn add_genesis_group<S: SecretId>(
            peer_list: &mut PeerList<S>,
            genesis: &BTreeSet<S::PublicId>,
        ) {
            for peer_id in genesis {
                if peer_list.has_peer(peer_id) {
                    continue;
                }

                peer_list.add_peer(peer_id.clone(), PeerState::active());
                peer_list.initialise_peer_membership_list(peer_id, genesis.iter().cloned());
            }
        }

        // To make sure event indices are set correctly, always use this function instead of
        // `Parsec::add_event`. Especially when adding event extracted from other `Parsec`
        // instances.
        fn add_event<T: NetworkEvent, S: SecretId>(
            parsec: &mut Parsec<T, S>,
            event: &Event<T, S::PublicId>,
        ) -> Result<()> {
            if let Some(event) = Event::unpack(
                event.pack(),
                &parsec.graph,
                &parsec.peer_list,
                &BTreeSet::new(),
            )? {
                parsec.add_event(event)
            } else {
                Ok(())
            }
        }

        #[test]
        fn genesis_event_not_after_initial() {
            // Generated with RNG seed: [926181213, 2524489310, 392196615, 406869071].
            let alice_contents = parse_test_dot_file("alice.dot");
            let alice_id = alice_contents.peer_list.our_id().clone();
            let genesis: BTreeSet<_> = alice_contents.peer_list.all_ids().cloned().collect();
            let mut alice = Parsec::from_parsed_contents(alice_contents);

            // Simulate Dave creating unexpected genesis.
            let dave_id = PeerId::new("Dave");
            let mut dave_contents = ParsedContents::new(dave_id.clone());

            dave_contents
                .peer_list
                .add_peer(dave_id.clone(), PeerState::active());
            add_genesis_group(&mut dave_contents.peer_list, &genesis);

            let d_0 = Event::<Transaction, _>::new_initial(&dave_contents.peer_list);
            let d_0_hash = *d_0.hash();
            dave_contents.add_event(d_0);

            let d_1 = Event::<Transaction, _>::new_from_observation(
                d_0_hash,
                Observation::OpaquePayload(Transaction::new("dave's malicious vote")),
                &dave_contents.graph,
                &dave_contents.peer_list,
            );
            let d_1_hash = *d_1.hash();
            dave_contents.add_event(d_1);

            let d_2 = Event::<Transaction, _>::new_from_observation(
                d_1_hash,
                Observation::Genesis(genesis),
                &dave_contents.graph,
                &dave_contents.peer_list,
            );
            let d_2_hash = *d_2.hash();
            dave_contents.add_event(d_2);

            let dave = Parsec::from_parsed_contents(dave_contents);

            // Dave sends malicious gossip to Alice.
            let request = unwrap!(dave.create_gossip(Some(&alice_id)));
            unwrap!(alice.handle_request(&dave_id, request));

            // Verify that Alice detected the malice and accused Dave.
            let (offender, hash) = unwrap!(
                our_votes(&alice)
                    .filter_map(|payload| match *payload {
                        Observation::Accusation {
                            ref offender,
                            malice: Malice::UnexpectedGenesis(hash),
                        } => Some((offender.clone(), hash)),
                        _ => None,
                    }).next()
            );

            assert_eq!(offender, dave_id);
            assert_eq!(hash, d_2_hash);
        }

        #[test]
        fn genesis_event_creator_not_genesis_member() {
            // Generated with RNG seed: [848911612, 2362592349, 3178199135, 2458552022].
            let alice_contents = parse_test_dot_file("alice.dot");
            let alice_id = alice_contents.peer_list.our_id().clone();
            let genesis: BTreeSet<_> = alice_contents.peer_list.all_ids().cloned().collect();

            let mut alice = Parsec::from_parsed_contents(alice_contents);

            // This is needed so the AddPeer(Eric) is consensused.
            // `usize::MAX - 1` is somehow arbitrary upper bound that will make `restart_consensus`
            // reprocess everything (`-1` is there to avoid panic due to arithmetic overflow).
            unwrap!(alice.restart_consensus(0, usize::MAX - 1));

            // Simulate Eric creating unexpected genesis.
            let eric_id = PeerId::new("Eric");
            let mut eric_contents = ParsedContents::new(eric_id.clone());

            eric_contents
                .peer_list
                .add_peer(eric_id.clone(), PeerState::active());
            add_genesis_group(&mut eric_contents.peer_list, &genesis);

            let e_0 = Event::<Transaction, _>::new_initial(&eric_contents.peer_list);
            let e_0_hash = *e_0.hash();
            eric_contents.add_event(e_0);

            let e_1 = Event::<Transaction, _>::new_from_observation(
                e_0_hash,
                Observation::Genesis(genesis),
                &eric_contents.graph,
                &eric_contents.peer_list,
            );
            let e_1_hash = *e_1.hash();
            eric_contents.add_event(e_1);

            let eric = Parsec::from_parsed_contents(eric_contents);

            // Eric sends malicious gossip to Alice.
            let request = unwrap!(eric.create_gossip(Some(&alice_id)));
            unwrap!(alice.handle_request(&eric_id, request));

            // Verify that Alice detected the malice and accused Eric.
            let (offender, hash) = unwrap!(
                our_votes(&alice)
                    .filter_map(|payload| match *payload {
                        Observation::Accusation {
                            ref offender,
                            malice: Malice::UnexpectedGenesis(hash),
                        } => Some((offender.clone(), hash)),
                        _ => None,
                    }).next()
            );

            assert_eq!(offender, eric_id);
            assert_eq!(hash, e_1_hash);
        }

        fn initialise_parsed_contents(
            id: PeerId,
            genesis: &BTreeSet<PeerId>,
            second_event: Option<Observation<Transaction, PeerId>>,
        ) -> ParsedContents {
            let mut result = ParsedContents::new(id);
            add_genesis_group(&mut result.peer_list, genesis);

            let ev_0 = Event::<Transaction, _>::new_initial(&result.peer_list);
            let ev_0_hash = *ev_0.hash();
            result.add_event(ev_0);
            let ev_1 = if let Some(obs_1) = second_event {
                Event::<Transaction, _>::new_from_observation(
                    ev_0_hash,
                    obs_1,
                    &result.graph,
                    &result.peer_list,
                )
            } else {
                Event::<Transaction, _>::new_from_observation(
                    ev_0_hash,
                    Observation::Genesis(genesis.clone()),
                    &result.graph,
                    &result.peer_list,
                )
            };

            result.add_event(ev_1);
            result
        }

        fn initialise_parsec(
            id: PeerId,
            genesis: &BTreeSet<PeerId>,
            second_event: Option<Observation<Transaction, PeerId>>,
        ) -> Parsec<Transaction, PeerId> {
            let contents = initialise_parsed_contents(id, genesis, second_event);
            Parsec::from_parsed_contents(contents)
        }

        #[test]
        fn missing_genesis_event() {
            let alice_id = PeerId::new("Alice");
            let dave_id = PeerId::new("Dave");

            let genesis = btree_set![alice_id.clone(), dave_id.clone()];

            // Create Alice where the first event is not a genesis event (malice)
            let alice = initialise_parsec(
                alice_id.clone(),
                &genesis,
                Some(Observation::OpaquePayload(Transaction::new("Foo"))),
            );
            let a_0_hash = *nth_event(&alice.graph, 0).hash();
            let a_1_hash = *nth_event(&alice.graph, 1).hash();

            // Create Dave where the first event is a genesis event containing both Alice and Dave.
            let mut dave = initialise_parsec(dave_id.clone(), &genesis, None);
            assert!(!dave.graph.contains(&a_0_hash));
            assert!(!dave.graph.contains(&a_1_hash));

            // Send gossip from Alice to Dave.
            let message = unwrap!(alice.create_gossip(Some(&dave_id)));
            unwrap!(dave.handle_request(&alice_id, message));
            assert!(dave.graph.contains(&a_0_hash));
            assert!(dave.graph.contains(&a_1_hash));

            // Verify that Dave detected and accused Alice for malice.
            let (offender, hash) = unwrap!(
                our_votes(&dave)
                    .filter_map(|payload| match payload {
                        Observation::Accusation {
                            ref offender,
                            malice: Malice::MissingGenesis(hash),
                        } => Some((offender, hash)),
                        _ => None,
                    }).next()
            );
            assert_eq!(*offender, alice_id);
            assert_eq!(*hash, a_1_hash);
        }

        #[test]
        fn incorrect_genesis_event() {
            let alice_id = PeerId::new("Alice");
            let dave_id = PeerId::new("Dave");

            let genesis = btree_set![alice_id.clone(), dave_id.clone()];
            let false_genesis = btree_set![alice_id.clone(), PeerId::new("Derp")];

            // Create Alice where the first event is an incorrect genesis event (malice)
            let alice = initialise_parsec(
                alice_id.clone(),
                &genesis,
                Some(Observation::Genesis(false_genesis)),
            );
            let a_0_hash = *nth_event(&alice.graph, 0).hash();
            let a_1_hash = *nth_event(&alice.graph, 1).hash();

            // Create Dave where the first event is a genesis event containing both Alice and Dave.
            let mut dave = initialise_parsec(dave_id.clone(), &genesis, None);
            assert!(!dave.graph.contains(&a_0_hash));
            assert!(!dave.graph.contains(&a_1_hash));

            // Send gossip from Alice to Dave.
            let message = unwrap!(alice.create_gossip(Some(&dave_id)));
            // Alice's genesis should be rejected as invalid
            assert_err!(Error::InvalidEvent, dave.handle_request(&alice_id, message));
            assert!(dave.graph.contains(&a_0_hash));
            // Dave's events shouldn't contain Alice's genesis because of the rejection
            assert!(!dave.graph.contains(&a_1_hash));

            // Verify that Dave detected and accused Alice for malice.
            let (offender, hash) = unwrap!(
                our_votes(&dave)
                    .filter_map(|payload| match payload {
                        Observation::Accusation {
                            ref offender,
                            malice: Malice::IncorrectGenesis(hash),
                        } => Some((offender, hash)),
                        _ => None,
                    }).next()
            );
            assert_eq!(*offender, alice_id);
            assert_eq!(*hash, a_1_hash);
        }

        #[test]
        fn duplicate_votes() {
            // Generated with RNG seed: [1353978636, 426502568, 2862743769, 1583787884].
            //
            // Carol has already voted for "ABCD".  Create two new duplicate votes by Carol for this
            // opaque payload.
            let mut carol = Parsec::from_parsed_contents(parse_test_dot_file("carol.dot"));
            let first_duplicate = Event::new_from_observation(
                carol.our_last_event_hash(),
                Observation::OpaquePayload(Transaction::new("ABCD")),
                &carol.graph,
                &carol.peer_list,
            );
            let first_duplicate_clone = Event::new_from_observation(
                carol.our_last_event_hash(),
                Observation::OpaquePayload(Transaction::new("ABCD")),
                &carol.graph,
                &carol.peer_list,
            );

            let first_duplicate_hash = *first_duplicate.hash();
            let _ = carol.graph.insert(first_duplicate);
            let second_duplicate = Event::new_from_observation(
                first_duplicate_hash,
                Observation::OpaquePayload(Transaction::new("ABCD")),
                &carol.graph,
                &carol.peer_list,
            );

            // Check that the first duplicate triggers an accusation by Alice, but that the
            // duplicate is still added to the graph.
            let mut alice = Parsec::from_parsed_contents(parse_test_dot_file("alice.dot"));
            let carols_valid_vote_hash =
                *unwrap!(find_event_by_short_name(&alice.graph, "C_4")).hash();
            unwrap!(add_event(&mut alice, &first_duplicate_clone));
            let expected_accusations = vec![(
                carol.our_pub_id().clone(),
                Malice::DuplicateVote(carols_valid_vote_hash, first_duplicate_hash),
            )];
            assert_eq!(alice.pending_accusations, expected_accusations);
            assert!(alice.graph.contains(&first_duplicate_hash));

            // Check that the second one doesn't trigger any further accusation, but is also added
            // to the graph.
            let second_duplicate_hash = *second_duplicate.hash();
            unwrap!(add_event(&mut alice, &second_duplicate));
            assert_eq!(alice.pending_accusations, expected_accusations);
            assert!(alice.graph.contains(&second_duplicate_hash));
        }

        #[test]
        fn stale_other_parent() {
            // Generated with RNG seed: [856368386, 135728199, 764559083, 3829746197].
            //
            // Carol will create event C_4 with other-parent as B_1, despite having C_3 with other-
            // parent as B_2.
            let carol = Parsec::from_parsed_contents(parse_test_dot_file("carol.dot"));
            let c_3_hash = *unwrap!(find_event_by_short_name(&carol.graph, "C_3")).hash();
            let b_1_hash = *unwrap!(find_event_by_short_name(&carol.graph, "B_1")).hash();

            let c_4 = Event::new_from_request(
                c_3_hash,
                b_1_hash,
                &carol.graph,
                &carol.peer_list,
                &BTreeSet::new(),
            );
            let c_4_hash = *c_4.hash();

            // Check that adding C_4 triggers an accusation by Alice, but that C_4 is still added
            // to the graph.
            let mut alice = Parsec::from_parsed_contents(parse_test_dot_file("alice.dot"));

            let expected_accusations = vec![(
                carol.our_pub_id().clone(),
                Malice::StaleOtherParent(c_4_hash),
            )];
            unwrap!(add_event(&mut alice, &c_4));
            assert_eq!(alice.pending_accusations, expected_accusations);
            assert!(alice.graph.contains(&c_4_hash));
        }

        #[test]
        fn invalid_accusation() {
            // Generated with RNG seed: [935566334, 935694090, 88607029, 861330491].
            let mut alice_contents = parse_test_dot_file("alice.dot");

            let a_4_hash = *unwrap!(find_event_by_short_name(&alice_contents.graph, "A_4")).hash();
            let d_1_hash = *unwrap!(find_event_by_short_name(&alice_contents.graph, "D_1")).hash();

            // Create an invalid accusation from Alice
            let a_5 = Event::<Transaction, _>::new_from_observation(
                a_4_hash,
                Observation::Accusation {
                    offender: PeerId::new("Dave"),
                    malice: Malice::Fork(d_1_hash),
                },
                &alice_contents.graph,
                &alice_contents.peer_list,
            );
            let a_5_hash = *a_5.hash();
            alice_contents.add_event(a_5);
            let alice = Parsec::from_parsed_contents(alice_contents);
            assert!(alice.graph.contains(&a_5_hash));

            let mut carol = Parsec::from_parsed_contents(parse_test_dot_file("carol.dot"));
            assert!(!carol.graph.contains(&a_5_hash));

            // Send gossip from Alice to Carol
            let message = unwrap!(alice.create_gossip(Some(carol.our_pub_id())));

            unwrap!(carol.handle_request(alice.our_pub_id(), message));
            assert!(carol.graph.contains(&a_5_hash));

            // Verify that Carol detected malice and accused Alice of it.
            let (offender, hash) = unwrap!(
                our_votes(&carol)
                    .filter_map(|payload| match payload {
                        Observation::Accusation {
                            ref offender,
                            malice: Malice::InvalidAccusation(hash),
                        } => Some((offender, hash)),
                        _ => None,
                    }).next()
            );
            assert_eq!(offender, alice.our_pub_id());
            assert_eq!(*hash, a_5_hash);
        }

        #[test]
        fn invalid_gossip_creator() {
            // Generated with RNG seed: [753134140, 4096687351, 2912528994, 2847063513].
            //
            // Alice reports gossip to Bob from Carol that isn't in their section.
            let alice = Parsec::from_parsed_contents(parse_test_dot_file("alice.dot"));
            let mut bob = Parsec::from_parsed_contents(parse_test_dot_file("bob.dot"));

            // Verify peer lists
            let alice_id = PeerId::new("Alice");
            let bob_id = PeerId::new("Bob");
            let mut alice_peer_list = PeerList::new(alice_id.clone());
            alice_peer_list.add_peer(alice_id.clone(), PeerState::active());
            alice_peer_list.add_peer(bob_id.clone(), PeerState::active());
            assert_eq!(
                alice.peer_list.peer_id_hashes().collect::<Vec<_>>(),
                alice_peer_list.peer_id_hashes().collect::<Vec<_>>()
            );
            let mut bob_peer_list = PeerList::new(bob_id.clone());
            bob_peer_list.add_peer(alice_id.clone(), PeerState::active());
            bob_peer_list.add_peer(bob_id.clone(), PeerState::active());
            assert_eq!(
                bob.peer_list.peer_id_hashes().collect::<Vec<_>>(),
                bob_peer_list.peer_id_hashes().collect::<Vec<_>>()
            );

            // Read the dot file again so we have a set of events we can manually add to Bob instead
            // of sending gossip.
            let alice_parsed_contents = parse_test_dot_file("alice.dot");

            let c_0_index = unwrap!(find_event_by_short_name(
                &alice_parsed_contents.graph,
                "C_0"
            )).event_index();

            let (a_2_index, a_2_hash) = {
                let ie = unwrap!(find_event_by_short_name(
                    &alice_parsed_contents.graph,
                    "A_2"
                ));
                (ie.event_index(), *ie.hash())
            };

            let b_2_index = unwrap!(find_event_by_short_name(
                &alice_parsed_contents.graph,
                "B_2"
            )).event_index();

            // Carol is marked as active peer so that Bob's peer_list will accept C_0, but Carol is
            // not part of the membership_list
            let carol_id = PeerId::new("Carol");
            bob.peer_list.add_peer(carol_id, PeerState::active());

            let mut alice_events: BTreeMap<_, _> =
                alice_parsed_contents.graph.into_iter().collect();

            let c_0 = unwrap!(alice_events.remove(&c_0_index));
            unwrap!(add_event(&mut bob, &c_0));

            // This malice is setup in two events.
            // A_2 has C_0 from Carol as other parent as Carol has gossiped to Alice. Carol is
            // however not part of the section and Alice should not have accepted it.
            let a_2 = unwrap!(alice_events.remove(&a_2_index));
            unwrap!(add_event(&mut bob, &a_2));

            // B_2 is the sync event created by Bob when he receives A_2 from Alice.
            let b_2 = unwrap!(alice_events.remove(&b_2_index));
            unwrap!(add_event(&mut bob, &b_2));

            // Bob should now have seen that Alice in A_2 incorrectly reported gossip from Carol.
            // Check that this triggers an accusation
            let expected_accusations = (
                alice.our_pub_id().clone(),
                Malice::InvalidGossipCreator(a_2_hash),
            );

            assert!(bob.pending_accusations.contains(&expected_accusations));
            assert!(bob.graph.contains(&a_2_hash));
        }

        fn create_invalid_accusation() -> (EventHash, Parsec<Transaction, PeerId>) {
            let mut alice_contents = parse_dot_file_with_test_name(
                "alice.dot",
                "parsec_functional_tests_handle_malice_accomplice",
            );

            let a_10_hash =
                *unwrap!(find_event_by_short_name(&alice_contents.graph, "A_10")).hash();
            let d_1_hash = *unwrap!(find_event_by_short_name(&alice_contents.graph, "D_1")).hash();

            // Create an invalid accusation from Alice
            let a_11 = Event::<Transaction, _>::new_from_observation(
                a_10_hash,
                Observation::Accusation {
                    offender: PeerId::new("Dave"),
                    malice: Malice::Fork(d_1_hash),
                },
                &alice_contents.graph,
                &alice_contents.peer_list,
            );
            let a_11_hash = *a_11.hash();
            alice_contents.add_event(a_11);
            let alice = Parsec::from_parsed_contents(alice_contents);
            assert!(alice.graph.contains(&a_11_hash));
            (a_11_hash, alice)
        }

        fn verify_accused_accomplice(
            accuser: &Parsec<Transaction, PeerId>,
            suspect: &PeerId,
            event_hash: &EventHash,
        ) {
            let (offender, hash) = unwrap!(
                our_votes(accuser)
                    .filter_map(|payload| match payload {
                        Observation::Accusation {
                            ref offender,
                            malice: Malice::Accomplice(hash),
                        } => Some((offender, hash)),
                        _ => None,
                    }).next()
            );
            assert_eq!(offender, suspect);
            assert_eq!(hash, event_hash);
        }

        #[test]
        #[ignore]
        // Carol received gossip from Bob, which should have raised an accomplice accusation against
        // Alice but didn't.
        fn accomplice() {
            let (invalid_accusation, alice) = create_invalid_accusation();

            let mut bob = Parsec::from_parsed_contents(parse_dot_file_with_test_name(
                "bob.dot",
                "parsec_functional_tests_handle_malice_accomplice",
            ));
            assert!(!bob.graph.contains(&invalid_accusation));

            // Send gossip from Alice to Bob
            let message = unwrap!(alice.create_gossip(Some(&PeerId::new("Bob"))));
            unwrap!(bob.handle_request(alice.our_pub_id(), message));
            assert!(bob.graph.contains(&invalid_accusation));

            let mut carol = Parsec::from_parsed_contents(parse_dot_file_with_test_name(
                "carol.dot",
                "parsec_functional_tests_handle_malice_accomplice",
            ));
            assert!(!carol.graph.contains(&invalid_accusation));

            // Send gossip from Bob to Carol, remove the accusation event
            let mut message = unwrap!(bob.create_gossip(Some(&PeerId::new("Carol"))));
            let accusation_event = unwrap!(message.packed_events.pop());
            let bob_last_hash = unwrap!(accusation_event.self_parent());
            unwrap!(carol.handle_request(bob.our_pub_id(), message));
            assert!(carol.graph.contains(&invalid_accusation));

            // Verify that Carol detected malice and accused Alice of `InvalidAccusation` and Bob of
            // `Accomplice`.
            let (offender, hash) = unwrap!(
                our_votes(&carol)
                    .filter_map(|payload| match payload {
                        Observation::Accusation {
                            ref offender,
                            malice: Malice::InvalidAccusation(hash),
                        } => Some((offender, hash)),
                        _ => None,
                    }).next()
            );
            assert_eq!(offender, alice.our_pub_id());
            assert_eq!(*hash, invalid_accusation);

            verify_accused_accomplice(&carol, bob.our_pub_id(), bob_last_hash);
        }

        #[test]
        #[ignore]
        // Carol received `invalid_accusation` from Alice first, then received gossip from Bob,
        // which should have raised an accomplice accusation against Alice but didn't.
        fn accomplice_separate() {
            let (invalid_accusation, alice) = create_invalid_accusation();

            let mut carol = Parsec::from_parsed_contents(parse_dot_file_with_test_name(
                "carol.dot",
                "parsec_functional_tests_handle_malice_accomplice",
            ));
            assert!(!carol.graph.contains(&invalid_accusation));

            // Send gossip from Alice to Carol
            let message = unwrap!(alice.create_gossip(Some(&PeerId::new("Carol"))));
            unwrap!(carol.handle_request(alice.our_pub_id(), message));
            assert!(carol.graph.contains(&invalid_accusation));

            let mut bob = Parsec::from_parsed_contents(parse_dot_file_with_test_name(
                "bob.dot",
                "parsec_functional_tests_handle_malice_accomplice",
            ));
            assert!(!bob.graph.contains(&invalid_accusation));

            // Send gossip from Alice to Bob
            let message = unwrap!(alice.create_gossip(Some(&PeerId::new("Bob"))));
            unwrap!(bob.handle_request(alice.our_pub_id(), message));
            assert!(bob.graph.contains(&invalid_accusation));

            // Send gossip from Bob to Carol, remove the accusation event
            let mut message = unwrap!(bob.create_gossip(Some(&PeerId::new("Carol"))));
            let accusation_event = unwrap!(message.packed_events.pop());
            let bob_last_hash = unwrap!(accusation_event.self_parent());
            unwrap!(carol.handle_request(bob.our_pub_id(), message));
            assert!(carol.graph.contains(&invalid_accusation));

            // Verify that Carol detected malice and accused Bob of `Accomplice`.
            verify_accused_accomplice(&carol, bob.our_pub_id(), bob_last_hash);
        }

        #[test]
        #[ignore]
        // Carol received `invalid_accusation` from Alice first, then receive gossip from Bob, which
        // doesn't contain the malice of Alice. Carol shall not raise accusation against Bob.
        fn accomplice_negative() {
            let (invalid_accusation, alice) = create_invalid_accusation();

            let mut carol = Parsec::from_parsed_contents(parse_dot_file_with_test_name(
                "carol.dot",
                "parsec_functional_tests_handle_malice_accomplice",
            ));
            assert!(!carol.graph.contains(&invalid_accusation));

            // Send gossip from Alice to Carol
            let message = unwrap!(alice.create_gossip(Some(&PeerId::new("Carol"))));
            unwrap!(carol.handle_request(alice.our_pub_id(), message));
            assert!(carol.graph.contains(&invalid_accusation));

            let bob = Parsec::from_parsed_contents(parse_dot_file_with_test_name(
                "bob.dot",
                "parsec_functional_tests_handle_malice_accomplice",
            ));
            assert!(!bob.graph.contains(&invalid_accusation));

            // Send gossip from Bob to Carol
            let message = unwrap!(bob.create_gossip(Some(&PeerId::new("Carol"))));
            unwrap!(carol.handle_request(bob.our_pub_id(), message));

            // Verify that Carol didn't accuse Bob of `Accomplice`.
            assert!(our_votes(&carol).all(|payload| match payload {
                Observation::Accusation {
                    malice: Malice::Accomplice(_),
                    ..
                } => false,
                _ => true,
            }));
        }

        #[test]
        fn handle_fork() {
            // In this scenario, Alice creates two descendants of A_3 and sends one of them to Bob,
            // and the other one to Dave. When Bob gossips to Dave afterwards, Dave is made aware of
            // both sides of the fork and should raise an accusation.
            let bob_contents = parse_test_dot_file("bob.dot");
            let dave_contents = parse_test_dot_file("dave.dot");
            let a_3_hash = *unwrap!(find_event_by_short_name(&bob_contents.graph, "A_3")).hash();
            // Bob and Dave have different notions of which event is the fourth one by Alice - here
            // we save the hashes of these two events that could be considered A_4.
            let a_4_bob_hash =
                *unwrap!(find_event_by_short_name(&bob_contents.graph, "A_4")).hash();
            let a_4_dave_hash =
                *unwrap!(find_event_by_short_name(&dave_contents.graph, "A_4")).hash();

            let bob = Parsec::from_parsed_contents(bob_contents);
            let mut dave = Parsec::from_parsed_contents(dave_contents);
            assert!(bob.graph.contains(&a_3_hash));
            assert!(dave.graph.contains(&a_3_hash));
            // Bob doesn't know Dave's A_4, and Dave doesn't know Bob's
            assert!(!bob.graph.contains(&a_4_dave_hash));
            assert!(!dave.graph.contains(&a_4_bob_hash));

            // Send gossip from Bob to Dave
            let message = unwrap!(bob.create_gossip(Some(dave.our_pub_id())));
            unwrap!(dave.handle_request(bob.our_pub_id(), message));
            // Dave should now become aware of the other branch of the fork
            assert!(dave.graph.contains(&a_4_bob_hash));

            // Verify that Dave detected malice and accused Alice of it.
            let (offender, hash) = unwrap!(
                our_votes(&dave)
                    .filter_map(|payload| match payload {
                        Observation::Accusation {
                            ref offender,
                            malice: Malice::Fork(hash),
                        } => Some((offender, hash)),
                        _ => None,
                    }).next()
            );
            assert_eq!(offender, &PeerId::new("Alice"));
            assert_eq!(*hash, a_3_hash);
        }

        #[test]
        fn self_parent_by_different_creator() {
            let test_folder = "parsec_functional_tests_handle_malice_stale_other_parent";
            let carol = Parsec::from_parsed_contents(parse_dot_file_with_test_name(
                "carol.dot",
                test_folder,
            ));

            // Carol creates an event with one of Bob's as the self-parent.
            let b_2_hash = *unwrap!(find_event_by_short_name(&carol.graph, "B_2")).hash();
            let c_4 = Event::new_from_observation(
                b_2_hash,
                Observation::OpaquePayload(Transaction::new("ABCD")),
                &carol.graph,
                &carol.peer_list,
            );
            let c_4_hash = *c_4.hash();
            let packed_c_4 = c_4.pack();

            let mut alice = Parsec::from_parsed_contents(parse_dot_file_with_test_name(
                "alice.dot",
                test_folder,
            ));

            // Try to add the event.
            assert_err!(Error::InvalidEvent, alice.add_event(c_4));

            // The invalid event should trigger an accusation vote to be raised immediately, and the
            // invalid event should not be added to the graph.
            let a_2 = unwrap!(find_event_by_short_name(&alice.graph, "A_2"));
            let expected_observation = Observation::Accusation {
                offender: carol.our_pub_id().clone(),
                malice: Malice::SelfParentByDifferentCreator(Box::new(packed_c_4)),
            };

            assert_eq!(*unwrap!(a_2.vote()).payload(), expected_observation);
            assert!(!alice.graph.contains(&c_4_hash));
        }

        #[test]
        fn other_parent_by_same_creator() {
            let alice_id = PeerId::new("Alice");
            let bob_id = PeerId::new("Bob");
            let genesis = btree_set![alice_id.clone(), bob_id.clone()];

            let mut alice = initialise_parsec(alice_id, &genesis, None);
            let mut bob_contents = initialise_parsed_contents(bob_id.clone(), &genesis, None);

            let b_0_hash = *unwrap!(find_event_by_short_name(&bob_contents.graph, "b_0")).hash();
            let b_1_hash = *unwrap!(find_event_by_short_name(&bob_contents.graph, "b_1")).hash();

            let b_2 = Event::new_from_request(
                b_1_hash,
                b_0_hash,
                &bob_contents.graph,
                &bob_contents.peer_list,
                &BTreeSet::new(),
            );
            let b_2_hash = *b_2.hash();

            let b_1 = unwrap!(bob_contents.remove_last_event());
            assert_eq!(*b_1.hash(), b_1_hash);

            let b_0 = unwrap!(bob_contents.remove_last_event());
            assert_eq!(*b_0.hash(), b_0_hash);

            unwrap!(add_event(&mut alice, &b_0));
            unwrap!(add_event(&mut alice, &b_1));

            // This should fail, as B_2 has other-parent by the same creator.
            assert_err!(Error::InvalidEvent, add_event(&mut alice, &b_2));

            // Alice should raise accusation against Bob
            let (offender, event) = unwrap!(
                our_votes(&alice)
                    .filter_map(|payload| match payload {
                        Observation::Accusation {
                            ref offender,
                            malice: Malice::OtherParentBySameCreator(event),
                        } => Some((offender, event)),
                        _ => None,
                    }).next()
            );

            assert_eq!(*offender, bob_id);
            assert_eq!(event.hash(), b_2_hash);

            // B_2 should not have been inserted into Alice's graph
            assert!(!alice.graph.contains(&b_2_hash));
        }
    }
}
