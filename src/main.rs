use clap::Parser;
use libafl::bolts::current_nanos;
use libafl::bolts::rands::StdRand;
use libafl::bolts::shmem::{ShMem, ShMemProvider, StdShMemProvider};
use libafl::bolts::tuples::tuple_list;
use libafl::corpus::{
    Corpus, InMemoryCorpus, IndexesLenTimeMinimizerCorpusScheduler, OnDiskCorpus,
    QueueCorpusScheduler,
};
use libafl::events::SimpleEventManager;
use libafl::executors::{ForkserverExecutor, TimeoutForkserverExecutor};
use libafl::feedbacks::{MapFeedbackState, MaxMapFeedback, TimeFeedback, TimeoutFeedback};
use libafl::inputs::BytesInput;
use libafl::mutators::{havoc_mutations, StdScheduledMutator};
use libafl::observers::{ConstMapObserver, HitcountsMapObserver, TimeObserver};
use libafl::stages::StdMutationalStage;
use libafl::state::{HasCorpus, StdState};
use libafl::stats::SimpleStats;
use libafl::{feedback_and_fast, feedback_or, Fuzzer, StdFuzzer};
use std::path::PathBuf;
use std::time::Duration;

/// Size of coverage map shared between observer and executor
const MAP_SIZE: usize = 65536;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    function: String,
    corpus_dir: String,
}

/* Almost all of this is directly from epi052's amazing blog series:
 * https://epi052.gitlab.io/notes-to-self/blog/2021-11-01-fuzzing-101-with-libafl/
 * check it out!
 */
fn main() {
    let args = Args::parse();

    let corpus_dirs = vec![PathBuf::from(args.corpus_dir)];

    let input_corpus = InMemoryCorpus::<BytesInput>::new();

    let timeouts_corpus =
        OnDiskCorpus::new(PathBuf::from("./timeouts")).expect("Could not create timeouts corpus");

    let mut shmem = StdShMemProvider::new().unwrap().new_map(MAP_SIZE).unwrap();

    shmem
        .write_to_env("__AFL_SHM_ID")
        .expect("couldn't write shared memory ID");

    let mut shmem_map = shmem.map_mut();

    let edges_observer = HitcountsMapObserver::new(ConstMapObserver::<_, MAP_SIZE>::new(
        "shared_mem",
        &mut shmem_map,
    ));

    let time_observer = TimeObserver::new("time");

    let feedback_state = MapFeedbackState::with_observer(&edges_observer);

    let feedback = feedback_or!(
        MaxMapFeedback::new_tracking(&feedback_state, &edges_observer, true, false),
        TimeFeedback::new_with_observer(&time_observer)
    );

    let objective_state = MapFeedbackState::new("timeout_edges", MAP_SIZE);

    let objective = feedback_and_fast!(
        TimeoutFeedback::new(),
        MaxMapFeedback::new(&objective_state, &edges_observer)
    );

    let mut state = StdState::new(
        StdRand::with_seed(current_nanos()),
        input_corpus,
        timeouts_corpus,
        tuple_list!(feedback_state, objective_state),
    );

    let stats = SimpleStats::new(|s| println!("{}", s));

    let mut mgr = SimpleEventManager::new(stats);

    let scheduler = IndexesLenTimeMinimizerCorpusScheduler::new(QueueCorpusScheduler::new());

    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let fork_server = ForkserverExecutor::new(
        "./fuzzer-atoi".to_string(),
        // input goes into stdin if no arguments are given
        &[],
        true,
        tuple_list!(edges_observer, time_observer),
    )
    .unwrap();

    let timeout = Duration::from_millis(5000);

    let mut executor = TimeoutForkserverExecutor::new(fork_server, timeout).unwrap();

    if state.corpus().count() < 1 {
        state
            .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &corpus_dirs)
            .unwrap_or_else(|err| {
                panic!(
                    "Failed to load initial corpus at {:?}: {:?}",
                    &corpus_dirs, err
                )
            });
        println!("We imported {} inputs from disk.", state.corpus().count());
    }

    let mutator = StdScheduledMutator::new(havoc_mutations());

    let mut stages = tuple_list!(StdMutationalStage::new(mutator));

    fuzzer
        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
        .expect("Error in the fuzzing loop");
}
