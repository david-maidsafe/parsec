// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use dev_utils::network::Network;
use maidsafe_utilities::SeededRng;
use mock::PeerId;
use parsec::{is_supermajority, IsInterestingEventFn};
use rand::{Rng, SeedableRng, XorShiftRng};
use std::fmt;

pub trait RngDebug: Rng + fmt::Debug {}

impl RngDebug for SeededRng {}
impl RngDebug for XorShiftRng {}

pub struct Environment {
    pub network: Network,
    pub rng: Box<RngDebug>,
}

#[derive(Clone, Copy, Debug)]
pub enum RngChoice {
    SeededRandom,
    #[allow(unused)]
    Seeded([u32; 4]),
    SeededXor([u32; 4]),
}

impl Environment {
    /// Initialise the test environment. The random number generator will be seeded with `seed`
    /// or randomly if this is `SeededRandom`.
    pub fn with_is_interesting_event(
        seed: RngChoice,
        is_interesting_event: IsInterestingEventFn<PeerId>,
    ) -> Self {
        let rng: Box<RngDebug> = match seed {
            RngChoice::SeededRandom => Box::new(SeededRng::new()),
            RngChoice::Seeded(seed) => Box::new(SeededRng::from_seed(seed)),
            RngChoice::SeededXor(seed) => {
                let rng = Box::new(XorShiftRng::from_seed(seed));
                println!("Using {:?}", rng);
                rng
            }
        };

        let network = Network::new(is_interesting_event);

        Self { network, rng }
    }

    pub fn new(seed: RngChoice) -> Self {
        Self::with_is_interesting_event(seed, is_supermajority)
    }
}

impl fmt::Debug for Environment {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Environment({} peers, {:?})",
            self.network.peers.len(),
            self.rng
        )
    }
}
