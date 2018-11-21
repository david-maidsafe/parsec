// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::dot_parser::{parse_dot_file, ParsedContents};
use gossip::{Event, Request, Response};
use mock::{PeerId, Transaction};
use observation::Observation;
use parsec::{self, Parsec};
use std::collections::BTreeSet;
use std::io;
use std::path::Path;
use vote::Vote;

/// Record of a Parsec session which consist of sequence of operations (`vote_for`, `handle_request`
/// and `handle_response`). Can be produced from a previously dumped DOT file and after replaying,
/// produces the same gossip graph. Useful for benchmarking.
#[derive(Clone)]
pub struct Record {
    our_id: PeerId,
    genesis_group: BTreeSet<PeerId>,
    actions: Vec<Action>,
}

impl Record {
    pub fn parse<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let contents = parse_dot_file(path.as_ref())?;
        Ok(Self::from(contents))
    }

    pub fn play(self) -> Parsec<Transaction, PeerId> {
        let mut parsec =
            Parsec::from_genesis(self.our_id, &self.genesis_group, parsec::is_supermajority);

        for action in self.actions {
            action.run(&mut parsec)
        }

        parsec
    }
}

impl From<ParsedContents> for Record {
    fn from(contents: ParsedContents) -> Self {
        // Find the genesis group
        let genesis_group = unwrap!(
            contents
                .graph
                .iter()
                .filter_map(|event| extract_genesis_group(event.inner()))
                .next()
                .cloned(),
            "No event carrying Observation::Genesis found"
        );

        assert!(
            genesis_group.contains(&contents.our_id),
            "Records currently supported only for the members of the genesis group"
        );

        let mut actions = Vec::new();
        let mut skip_our_accusations = false;
        let mut known = vec![false; contents.graph.len()];

        for event in &contents.graph {
            if event.topological_index() == 0 {
                // Skip the initial event
                assert!(event.is_initial());
                assert_eq!(*event.creator(), contents.our_id);
                continue;
            }

            if event.topological_index() == 1 {
                // Skip the genesis event
                assert!(extract_genesis_group(&*event).is_some());
                assert_eq!(*event.creator(), contents.our_id);
                continue;
            }

            if *event.creator() == contents.our_id {
                if let Some(observation) = event.vote().map(Vote::payload) {
                    known[event.topological_index()] = true;

                    if let Observation::Accusation { .. } = *observation {
                        if skip_our_accusations {
                            continue;
                        } else {
                            // Accusations by us must follow our sync event.
                            panic!("Unexpected accusation {:?}", *event);
                        }
                    }

                    actions.push(Action::Vote(observation.clone()));
                } else if event.is_request() || event.is_response() {
                    known[event.topological_index()] = true;

                    let other_parent = unwrap!(
                        event
                            .other_parent()
                            .and_then(|hash| contents.graph.get(hash)),
                        "Sync event without other-parent: {:?}",
                        *event
                    );

                    let src = other_parent.creator().clone();

                    let mut events_to_gossip = Vec::new();
                    for event in contents.graph.ancestors(other_parent) {
                        if known[event.topological_index()] {
                            continue;
                        } else {
                            known[event.topological_index()] = true;
                        }

                        events_to_gossip.push(event.inner());
                    }
                    events_to_gossip.reverse();

                    if event.is_request() {
                        actions.push(Action::Request(src, Request::new(events_to_gossip)))
                    } else {
                        actions.push(Action::Response(src, Response::new(events_to_gossip)))
                    }

                    // Skip all accusations directly following our sync event, as they will be
                    // created during replay.
                    skip_our_accusations = true;
                } else {
                    panic!("Unexpected event {:?}", *event);
                }
            } else {
                skip_our_accusations = false;
            }
        }

        Record {
            our_id: contents.our_id,
            genesis_group,
            actions,
        }
    }
}

#[derive(Clone)]
enum Action {
    Vote(Observation<Transaction, PeerId>),
    Request(PeerId, Request<Transaction, PeerId>),
    Response(PeerId, Response<Transaction, PeerId>),
}

impl Action {
    fn run(self, parsec: &mut Parsec<Transaction, PeerId>) {
        match self {
            Action::Vote(observation) => unwrap!(parsec.vote_for(observation)),
            Action::Request(src, request) => {
                let _ = unwrap!(parsec.handle_request(&src, request));
            }
            Action::Response(src, response) => unwrap!(parsec.handle_response(&src, response)),
        }
    }
}

fn extract_genesis_group(event: &Event<Transaction, PeerId>) -> Option<&BTreeSet<PeerId>> {
    event.vote().map(Vote::payload).and_then(|observation| {
        if let Observation::Genesis(ref genesis_group) = *observation {
            Some(genesis_group)
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use parsec::assert_same_events;

    #[test]
    fn smoke() {
        let path = "input_graphs/benches/minimal.dot";

        let contents = unwrap!(parse_dot_file(path));
        let expected = Parsec::from_parsed_contents(contents);

        let contents = unwrap!(parse_dot_file(path));
        let replay = Record::from(contents);
        let actual = replay.play();

        assert_same_events(&actual, &expected);
    }
}
