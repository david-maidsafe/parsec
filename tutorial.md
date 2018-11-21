# Prerequisites
To clone the repo, `git` must be installed.

To compile the code and run the tests, `rust` and `cargo` are required. The currently-supported version of rust can be found in one of the [continuous integration test files](appveyor.yml#L5).

To optionally generate graphs from generated dot files, `graphviz` is necessary. If you prefer, you can use an online converter (e.g. http://viz-js.com) to view the gossip graphs rather than installing graphviz.

To install [graphviz](https://graphviz.gitlab.io/download/) on Ubuntu,
```
sudo apt-get install graphviz
```
On other Linux platforms, look for graphviz in your favourite package manager.

On MacOS, homebrew has a graphviz package:
```
brew install graphviz
```

On Windows, you can find an installer [here](https://graphviz.gitlab.io/_pages/Download/Download_windows.html)

# Run the tests

From a terminal, from a directory in which you're comfortable cloning a repository, clone the PARSEC repository

```
git clone https://github.com/maidsafe/parsec.git
```

From the parsec repository, run the tests. Be sure to use the feature: `dump-graphs` so the tests output the graphs. Also pass in the `--nocapture` flag to the test executable so it can print the location of the graphs.

```
cd parsec
cargo test --release --features=dump-graphs -- --nocapture
```

# View the graphs

The output must contain lines analogous to these:

```
Writing dot files in /tmp/parsec_graphs/53srr3/test_minimal_network
Writing dot files in /tmp/parsec_graphs/53srr3/test_multiple_votes_before_gossip
Writing dot files in /tmp/parsec_graphs/53srr3/test_faulty_third_terminate_concurrently
Writing dot files in /tmp/parsec_graphs/53srr3/test_duplicate_vote_is_reduced_to_single
Writing dot files in /tmp/parsec_graphs/53srr3/test_faulty_third_never_gossip
Writing dot files in /tmp/parsec_graphs/53srr3/test_faulty_third_terminate_at_random_points
Writing dot files in /tmp/parsec_graphs/53srr3/test_multiple_votes_during_gossip
```

Go to one of the directories listed above:
```
cd /tmp/parsec_graphs/53srr3/test_minimal_network
```

This particular example consists of four nodes reaching consensus on the order of one single event. It is quite trivial. This is why the directory contains only four dot files:
```
.
├── Alice-001.dot
├── Bob-001.dot
├── Carol-001.dot
└── Dave-001.dot
```

These are `dot` representations of the gossip graphs. You may read them with a text editor to get a feel for the syntax.

From these dot representations, images may be generated using graphviz. If you already had `dot` from graphviz available on your path, the test will have generated one SVG image of the gossip graph per dot file:
```
.
├── Alice-001.dot.svg
├── Bob-001.dot.svg
├── Carol-001.dot.svg
└── Dave-001.dot.svg
```

You can open these SVG files in your favourite web browser to view them.

If these SVG files don't already exist, you can either copy a dot file's contents into an online converter (e.g. http://viz-js.com) to view the gossip graph, or you can install graphviz (as detailed above) and then run:
```
dot -Tsvg Alice-001.dot -O
```

# Explore

These graphs demonstrate how each node reaches a conclusion, based on each node casting a single vote (highlighted in cyan blue). The gossip events that make that vote valid are highlighted in crimson red. The gossip events that contain special values for estimates, bin values, auxiliary values and decisions are labelled with the information needed to understand the decision process.

Now, `test_minimal_network` is a silly example as reaching consensus on a single event is trivial. You may use the same method to explore the outcome of all other tests. `test_multiple_votes_during_gossip` is the most realistic scenario: it involves reaching consensus on the order 10 of events between 4 nodes, where the votes are cast in a random order, at random intervals by each node.

# Play around

For more control over the scenario, please run the example. To see which options you may use, run
```
cargo run --release --example basic --features=dump-graphs -- --help
```

For instance, for an example with 10 peers agreeing on the order of 5 events, run
```
cargo run --release --example basic --features=dump-graphs -- -p10 -e5
```

# Share your thoughts/questions

If anything seems unclear, feel free to contact us on the [SAFE Network forum](https://safenetforum.org/) or to [email us](mailto:outreach@maidsafe.net).

If you have a question concerning a specific test or example that you ran, please look for the RNG seed in the output and include it in your question. It will help us recreate the exact same scenario you ran so we can comment on specifics.

The RNG seed can be found in the output in a line like this one:
```
Using RNG seed: Some([656416849, 1310826355, 242653573, 2171336679])
```
