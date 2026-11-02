//! Backups and restores through the release binary: a copy taken
//! while the engine runs and while it is stopped; a restore that starts
//! fenced, holding what the copy held while new mail goes; and each
//! decision on the fence.

mod support;

use std::os::unix::fs::PermissionsExt as _;
use std::time::Duration;

use support::{Dns, Engine, Receiver, Script, wait_for};

/// Runs a command against the engine's configuration, which must succeed,
/// and returns what it printed.
fn run(engine: &Engine, arguments: &[&str]) -> String {
    let mut arguments = arguments.to_vec();
    arguments.extend(["--config", "config.toml"]);
    let (succeeded, text) = engine.command(&arguments);
    assert!(succeeded, "nitromta {arguments:?}: {text}");
    text
}

#[test]
fn a_restored_store_holds_what_its_copy_held_until_the_operator_decides() {
    let dns = Dns::start(&[("plain.test", "mx.plain.test")]);
    let receiver = Receiver::start(Script::default());
    let operator = "[operator]\nlisten = \"127.0.0.1:0\"";
    let mut engine = Engine::start("backup", &dns, &receiver, "dane = false", operator);
    // Two messages held, unfinished, as the copy is taken.
    run(
        &engine,
        &[
            "pause",
            "--account",
            "1",
            "--reason",
            "a copy first",
            "--accepting",
        ],
    );
    let restored = engine.submit(&["one@plain.test", "two@plain.test"]);
    let backup = run(&engine, &["backup", "--to", "copy.db"]);
    assert!(backup.starts_with("backed up to /"), "{backup}");
    let mode = std::fs::metadata(engine.dir.join("copy.db"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
    // A backup writes over nothing.
    let (succeeded, text) =
        engine.command(&["backup", "--to", "copy.db", "--config", "config.toml"]);
    assert!(!succeeded && text.contains("writes over nothing"), "{text}");
    // Delivered after the copy was taken.
    run(&engine, &["resume", "--account", "1"]);
    wait_for("the deliveries", || receiver.delivered().len() == 2);

    // A stopped engine's store is copied directly; a running engine's
    // store is never restored over.
    let (succeeded, text) =
        engine.command(&["restore", "--from", "copy.db", "--config", "config.toml"]);
    assert!(
        !succeeded && text.contains("stop the engine first"),
        "{text}"
    );
    engine.stop();
    let stopped = run(&engine, &["backup", "--to", "stopped.db"]);
    assert!(stopped.contains("the stopped store"), "{stopped}");

    // Restored, fenced: what the copy held waits, its hold lifted or not,
    // while new mail goes.
    let said = run(&engine, &["restore", "--from", "copy.db"]);
    assert!(said.contains("fenced: the copy was taken at "), "{said}");
    assert!(
        said.contains("2 deliveries the copy held unfinished wait"),
        "{said}"
    );
    assert!(said.contains("the store that was there is at "), "{said}");
    engine
        .start_again()
        .expect("it starts on the restored store");
    run(&engine, &["resume", "--account", "1"]);
    let fence = run(&engine, &["fence"]);
    assert!(
        fence.starts_with("fenced, restored at ") && fence.contains(": 2 deliveries"),
        "{fence}"
    );
    let (_, metrics) = engine.operator("/metrics");
    assert!(metrics.contains("nitromta_store_fenced 1\n"), "{metrics}");
    let explained = run(&engine, &["explain", "--message", &restored[0]]);
    assert!(
        explained.contains("fenced     by the restore of a copy taken at "),
        "{explained}"
    );
    engine.submit(&["three@plain.test"]);
    wait_for("the new mail", || receiver.delivered().len() == 3);
    std::thread::sleep(Duration::from_secs(1));
    assert_eq!(receiver.delivered().len(), 3, "the fenced mail waits");

    // Released: what it held is sent, though it was delivered before.
    let released = run(&engine, &["fence", "release"]);
    assert_eq!(released, "the store is not fenced\n");
    wait_for("the released mail", || receiver.delivered().len() == 5);
    let (_, metrics) = engine.operator("/metrics");
    assert!(metrics.contains("nitromta_store_fenced 0\n"), "{metrics}");

    // Restored again, and discarded: each is cancelled, unsent, though the
    // account's hold the copy held is still on, as a discard goes before a
    // hold.
    engine.stop();
    run(&engine, &["restore", "--from", "copy.db"]);
    engine
        .start_again()
        .expect("it starts on the restored store");
    let discarded = run(&engine, &["fence", "discard"]);
    assert!(
        discarded.contains("its deliveries discarded"),
        "{discarded}"
    );
    wait_for("the cancellations", || {
        run(&engine, &["explain", "--message", &restored[1]]).contains("finished, cancelled")
    });
    assert_eq!(receiver.delivered().len(), 5, "nothing discarded was sent");
    // A store too damaged to open is put aside as it is, and the copy
    // takes its place.
    engine.stop();
    std::fs::write(engine.dir.join("store.db"), b"not a database").unwrap();
    for sidecar in ["store.db-wal", "store.db-shm"] {
        let _ = std::fs::remove_file(engine.dir.join(sidecar));
    }
    run(&engine, &["restore", "--from", "copy.db"]);
    engine
        .start_again()
        .expect("it starts on the restored store");
    // Each restore kept the store it replaced, and nothing beside it.
    let mut aside: Vec<String> = std::fs::read_dir(&engine.dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with("store.db.before-restore-"))
        .collect();
    aside.sort();
    assert_eq!(aside.len(), 3, "{aside:?}");
}

#[test]
fn a_restore_keeps_the_keys_of_tenants_its_copy_predates_until_its_fence_is_released() {
    let dns = Dns::start(&[("plain.test", "mx.plain.test")]);
    let receiver = Receiver::start(Script::default());
    let mut engine = Engine::start("backup-keys", &dns, &receiver, "dane = false", "");
    let config = engine.dir.join("config.toml");
    let text = std::fs::read_to_string(&config).unwrap();
    std::fs::write(
        &config,
        text.replace(
            "keys = \"keys\"",
            "keys = \"keys\"\nencryption = \"tenant\"",
        ),
    )
    .unwrap();
    engine.restart();
    let keys = engine.dir.join("keys.tenants");
    let kept = || std::fs::read_dir(&keys).map_or(0, |entries| entries.count());
    let put = |name: &str| {
        let answers =
            engine.admin(&[serde_json::json!({"op": "put_tenant", "account": 1, "name": name})]);
        assert!(answers[0]["ok"].is_object(), "{answers:?}");
    };
    put("acme");
    run(&engine, &["backup", "--to", "copy.db"]);
    // Created after the copy, its key is the one the store the restore
    // replaces needs.
    put("beta");
    assert_eq!(kept(), 2);
    engine.stop();
    run(&engine, &["restore", "--from", "copy.db"]);
    engine
        .start_again()
        .expect("it starts on the restored store");
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(kept(), 2, "kept while the restore is fenced");
    // Released, the restore is the operator's decision, and the key of the
    // tenant its copy predates goes.
    run(&engine, &["fence", "release"]);
    wait_for("beta's key erased", || kept() == 1);
}
