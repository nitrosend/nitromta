//! Every input each target's corpus keeps, run through its target in every
//! check: the seeds fuzzing starts from, and each input it found that
//! failed once, so none fails again.

use std::path::Path;

#[test]
fn every_input_a_corpus_keeps_passes_its_target_and_every_target_has_one() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut binaries: Vec<String> = std::fs::read_dir(root.join("fuzz_targets"))
        .expect("the targets")
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().into_string().ok()?;
            name.strip_suffix(".rs").map(str::to_owned)
        })
        .collect();
    binaries.sort();
    let mut targets: Vec<&str> = fuzz::TARGETS.iter().map(|(name, _)| *name).collect();
    targets.sort_unstable();
    assert_eq!(binaries, targets, "a binary for each target, and no other");
    for (name, target) in fuzz::TARGETS {
        let inputs: Vec<_> = std::fs::read_dir(root.join("corpus").join(name))
            .unwrap_or_else(|error| panic!("{name}'s corpus: {error}"))
            .flatten()
            .map(|entry| entry.path())
            .collect();
        assert!(!inputs.is_empty(), "{name}'s corpus keeps no input");
        for input in inputs {
            target(&std::fs::read(&input).expect("readable"));
        }
    }
}
