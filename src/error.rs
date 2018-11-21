// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use peer_list::PeerState;
use std::result;

quick_error! {
    /// Parsec error variants.
    #[derive(Debug)]
    #[allow(missing_docs)] // quick_error chokes on doc comments inside the variants.
    pub enum Error {
        /// Payload of a `Vote` doesn't match the payload of a `Block`.
        MismatchedPayload {
            display("The payload of the vote doesn't match the payload of targeted block.")
        }
        /// Failed to verify signature.
        SignatureFailure {
            display("The message or signature might be corrupted, or the signer is wrong.")
        }
        /// Serialisation Error.
        Serialisation(error: ::maidsafe_utilities::serialisation::SerialisationError) {
            display("Serialisation error: {}", error)
            from()
        }
        /// Peer is not known to our node.
        UnknownPeer {
            display("The peer_id is not known to our node's peer_list.")
        }
        /// Peer is known to us, but has unexpected state.
        InvalidPeerState {
            required: PeerState,
            actual: PeerState,
        } {
            display("The peer is in invalid state (required: {:?}, actual: {:?}).", required, actual)
        }
        /// Our node is in unexpected state.
        InvalidSelfState {
            required: PeerState,
            actual: PeerState
        } {
            display("Our node is in invalid state (required: {:?}, actual: {:?}).", required, actual)
        }
        /// The given event is invalid or malformed.
        InvalidEvent {
            display("The given event is invalid or malformed.")
        }
        /// This event's self-parent or other-parent is unknown to our node.
        UnknownParent {
            display("This event's self-parent or other-parent is unknown to this node.")
        }
        /// Our node has already voted for this network event.
        DuplicateVote {
            display("Our node has already voted for this network event.")
        }
        /// The peer sent a message to us before knowing we could handle it.
        PrematureGossip {
            display("The peer did not know we could handle a message from it.")
        }
        /// Logic error.
        Logic {
            display("This a logic error and represents a flaw in the code.")
        }
    }
}

/// A specialised `Result` type for Parsec.
pub type Result<T> = result::Result<T, Error>;
