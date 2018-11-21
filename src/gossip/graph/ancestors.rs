// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::{Graph, IndexedEventRef};
use id::PublicId;
use network_event::NetworkEvent;
use std::collections::BTreeSet;

pub(crate) struct Ancestors<'a, T: NetworkEvent + 'a, P: PublicId + 'a> {
    pub(super) graph: &'a Graph<T, P>,
    pub(super) queue: BTreeSet<IndexedEventRef<'a, T, P>>,
    pub(super) visited: Vec<bool>, // TODO: replace with bitset, for space efficiency
}

impl<'a, T: NetworkEvent, P: PublicId> Iterator for Ancestors<'a, T, P> {
    type Item = IndexedEventRef<'a, T, P>;

    fn next(&mut self) -> Option<Self::Item> {
        // This is a modified breadth-first search: Instead of using a simple queue to track the
        // events to visit next, we use a priority queue (implemented as a BTreeMap keyed by
        // `topological_index`) so the events are visited in reverse topological order (children
        // before parents). We also keep track of the events we already visited, to avoid returning
        // single event more than once.

        loop {
            let event = *self.queue.iter().rev().next()?;
            let _ = self.queue.remove(&event);

            if self.visited[event.topological_index()] {
                continue;
            }
            self.visited[event.topological_index()] = true;

            if let Some(parent) = event.self_parent().and_then(|index| self.graph.get(index)) {
                let _ = self.queue.insert(parent);
            }

            if let Some(parent) = event.other_parent().and_then(|index| self.graph.get(index)) {
                let _ = self.queue.insert(parent);
            }

            return Some(event);
        }
    }
}
