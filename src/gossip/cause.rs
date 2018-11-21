// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

#[cfg(any(test, feature = "testing"))]
use super::event::CauseInput;
use super::event_hash::EventHash;
use id::PublicId;
#[cfg(any(test, feature = "testing"))]
use mock::{PeerId, Transaction};
use network_event::NetworkEvent;
use std::fmt::{self, Display, Formatter};
use vote::Vote;

#[serde(bound = "")]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Cause<T: NetworkEvent, P: PublicId> {
    // Hashes are the latest `Event` of own and the peer which sent the request.
    Request {
        self_parent: EventHash,
        other_parent: EventHash,
    },
    // Hashes are the latest `Event` of own and the peer which sent the response.
    Response {
        self_parent: EventHash,
        other_parent: EventHash,
    },
    // Hash of our latest `Event`. Vote for a single network event of type `T`.
    Observation {
        self_parent: EventHash,
        vote: Vote<T, P>,
    },
    // Initial empty `Event` of this peer.
    Initial,
}

impl<T: NetworkEvent, P: PublicId> Display for Cause<T, P> {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(
            formatter,
            "{}",
            match &self {
                Cause::Request { .. } => "Request".to_string(),
                Cause::Response { .. } => "Response".to_string(),
                Cause::Observation { vote, .. } => format!("Observation({:?})", vote.payload()),
                Cause::Initial => "Initial".to_string(),
            }
        )
    }
}

#[cfg(any(test, feature = "testing"))]
impl Cause<Transaction, PeerId> {
    pub(crate) fn new_from_dot_input(
        input: CauseInput,
        creator: &PeerId,
        self_parent: Option<EventHash>,
        other_parent: Option<EventHash>,
    ) -> Self {
        // When the dot file contains only partial graph, we have to manually change the info of
        // ancestor to null for some events. In that case, populate ancestors with empty hash.
        let self_parent = self_parent.unwrap_or(EventHash::ZERO);
        let other_parent = other_parent.unwrap_or(EventHash::ZERO);

        match input {
            CauseInput::Initial => Cause::Initial,
            CauseInput::Request => Cause::Request {
                self_parent,
                other_parent,
            },
            CauseInput::Response => Cause::Response {
                self_parent,
                other_parent,
            },
            CauseInput::Observation(observation) => Cause::Observation {
                self_parent,
                vote: Vote::new(creator, observation),
            },
        }
    }
}
