// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use hash::Hash;
use id::PublicId;
use observation::ObservationHash;
use serialise;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Debug)]
pub(crate) struct RoundHash {
    public_id_hash: Hash,
    latest_block_hash: ObservationHash,
    round: usize,
    final_hash: Hash,
}

impl RoundHash {
    // Constructs a new `RoundHash` with the given `public_id` and `latest_block_hash` for round 0.
    pub fn new<P: PublicId>(public_id: &P, latest_block_hash: ObservationHash) -> Self {
        Self::new_with_round(public_id, latest_block_hash, 0)
    }

    // Constructs a new `RoundHash` with the given `public_id` and `latest_block_hash` for a given
    // round
    pub fn new_with_round<P: PublicId>(
        public_id: &P,
        latest_block_hash: ObservationHash,
        round: usize,
    ) -> Self {
        let public_id_hash = Hash::from(serialise(&public_id).as_slice());
        let final_hash = Self::final_hash(&public_id_hash, &latest_block_hash, round);
        Self {
            public_id_hash,
            latest_block_hash,
            round,
            final_hash,
        }
    }

    // Constructs a new `RoundHash` with the same values as `self` but with `round += 1`.
    pub fn increment_round(&self) -> Self {
        Self {
            public_id_hash: self.public_id_hash,
            latest_block_hash: self.latest_block_hash,
            round: self.round + 1,
            final_hash: Self::final_hash(
                &self.public_id_hash,
                &self.latest_block_hash,
                self.round + 1,
            ),
        }
    }

    #[cfg(feature = "dump-graphs")]
    pub fn round(&self) -> usize {
        self.round
    }

    #[cfg(feature = "dump-graphs")]
    pub fn latest_block_hash(&self) -> &ObservationHash {
        &self.latest_block_hash
    }

    // Returns the final value of the `RoundHash`.
    pub fn value(&self) -> &Hash {
        &self.final_hash
    }

    fn final_hash(
        public_id_hash: &Hash,
        latest_block_hash: &ObservationHash,
        round: usize,
    ) -> Hash {
        let round_hash = Hash::from(serialise(&round).as_slice());
        Hash::from(serialise(&(public_id_hash, latest_block_hash, round_hash)).as_slice())
    }
}
