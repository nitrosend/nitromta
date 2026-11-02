//! The store under pressure, through the release binary:
//! new mail refused while its disk is below the reserve, with health saying
//! why; a store a stop did not close checked at the next start, and a
//! damaged one refused; and the operator's check. And its keys:
//! refused when another may read them, and a new key taken at a restart.

mod support;

use support::{Dns, Engine, Receiver, Script, wait_for};

fn start(name: &str, store: &str) -> (Receiver, Engine) {
    let dns = Dns::start(&[("plain.test", "mx.plain.test")]);
    let receiver = Receiver::start(Script::default());
    let engine = Engine::start(
        name,
        &dns,
        &receiver,
        "# The stub DNS signs nothing.\ndane = false",
        &format!("[operator]\nlisten = \"127.0.0.1:0\"\n\n{store}"),
    );
    (receiver, engine)
}

#[test]
fn new_mail_is_refused_while_the_disk_is_below_its_reserve() {
    // A reserve no disk has.
    let (_receiver, mut engine) = start("storage-reserve", "");
    let mut refused = String::new();
    // The first measurement comes with the store's first command.
    engine.submit(&["one@plain.test"]);
    let config = engine.dir.join("config.toml");
    let text = std::fs::read_to_string(&config).unwrap();
    std::fs::write(
        &config,
        text.replace(
            "path = \"store.db\"",
            "path = \"store.db\"\nreserve_mib = 1000000000000",
        ),
    )
    .unwrap();
    engine.restart();
    wait_for("the refusal", || {
        refused = engine.rcpt("two@plain.test");
        refused.starts_with("452")
    });
    assert!(
        refused.contains("4.3.1 Insufficient system storage"),
        "{refused}"
    );
    let (status, body) = engine.operator("/health/accept");
    assert_eq!(
        (status, body.trim()),
        (503, "the store's disk is below its reserve")
    );
    let (status, _) = engine.operator("/health/dispatch");
    assert_eq!(status, 200, "dispatch goes on");
    let (_, metrics) = engine.operator("/metrics");
    assert!(
        metrics.contains("nitromta_refused_for_storage_total 1"),
        "{metrics}"
    );
    assert!(
        engine
            .logged()
            .contains("the store's disk is below its reserve")
    );
}

#[test]
fn a_store_left_open_is_checked_at_start_and_a_damaged_one_refused() {
    let (_receiver, mut engine) = start("storage-check", "");
    engine.submit(&["one@plain.test"]);
    // A clean stop closes the store, and the next start finds nothing to
    // check.
    engine.stop();
    assert!(!engine.dir.join("store.db-wal").exists());
    let (sound, said) = engine.command(&["check", "--config", "config.toml"]);
    assert!(sound && said.contains("is sound"), "{said}");
    engine.start_again().unwrap();
    assert!(!engine.logged().contains("not closed"));
    let (held, said) = engine.command(&["check", "--config", "config.toml"]);
    assert!(!held && said.contains("stop the engine first"), "{said}");
    // A killed engine leaves it open: the next start checks it.
    engine.submit(&["two@plain.test"]);
    engine.kill();
    engine.start_again().unwrap();
    assert!(
        engine
            .logged()
            .contains("the store was not closed at the last stop; its check found nothing wrong"),
        "{}",
        engine.logged()
    );
    // Damaged where opening it reads nothing, and left open, it is refused
    // by the check alone: a page near its end, which the mail just sent
    // filled.
    let many: Vec<String> = (0..200).map(|n| format!("r{n}@plain.test")).collect();
    engine.submit(&many.iter().map(String::as_str).collect::<Vec<_>>());
    engine.stop();
    let path = engine.dir.join("store.db");
    let mut bytes = std::fs::read(&path).unwrap();
    assert!(bytes.len() > 16 * 4096, "a store of many pages");
    let page = bytes.len() / 4096 - 2;
    for byte in &mut bytes[page * 4096..(page + 1) * 4096] {
        *byte = 0xA5;
    }
    std::fs::write(&path, &bytes).unwrap();
    std::fs::write(engine.dir.join("store.db-wal"), [0u8; 32]).unwrap();
    let refused = engine.start_again().unwrap_err();
    assert!(
        refused.contains("it is damaged, and the engine does not start on it"),
        "{refused}"
    );
    // Its log is kept, so the next start checks it again.
    let refused = engine.start_again().unwrap_err();
    assert!(refused.contains("does not start on it"), "{refused}");
    let (sound, said) = engine.command(&["check", "--config", "config.toml"]);
    assert!(!sound, "{said}");
}

#[test]
fn the_engine_does_not_start_on_keys_another_may_read() {
    let (_receiver, mut engine) = start("storage-keys", "");
    engine.stop();
    let keys = engine.dir.join("keys");
    let mode = |mode| {
        std::fs::set_permissions(&keys, std::os::unix::fs::PermissionsExt::from_mode(mode))
            .unwrap();
    };
    mode(0o640);
    let refused = engine.start_again().unwrap_err();
    assert!(refused.contains("its owner's alone"), "{refused}");
    mode(0o600);
    engine.start_again().unwrap();
    // The login's secret is sealed under the first key; one written while
    // the engine ran seals it again at the next start.
    drop(engine.session());
    let (written, said) = engine.command(&["key", "--to", "keys"]);
    assert!(written && said.contains("key 2 written"), "{said}");
    engine.restart();
    assert!(
        engine.submit(&["one@plain.test"]).len() == 1,
        "its login opens"
    );
}
