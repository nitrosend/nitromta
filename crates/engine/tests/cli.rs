//! The command line through the release binary: each command says how to
//! run it with `--help`; each command about a running engine reaches it
//! through its admin socket and shows its answer as text, or with `--json`
//! as the API's own lines; and an answer that is an error ends the command
//! with its code and message.

mod support;

use std::time::Duration;

use aws_lc_rs::encoding::AsDer as _;
use aws_lc_rs::rsa::{KeyPair, KeySize};
use aws_lc_rs::signature::KeyPair as _;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};
use support::{Dns, Engine, Receiver, Script, wait_for};

fn start(name: &str) -> (Receiver, Engine) {
    let dns = Dns::start(&[("plain.test", "mx.plain.test")]);
    let receiver = Receiver::start(Script::default());
    let engine = Engine::start(name, &dns, &receiver, "dane = false", "");
    (receiver, engine)
}

#[test]
fn the_operator_endpoint_closes_a_connection_that_sends_no_request() {
    let dns = Dns::start(&[("plain.test", "mx.plain.test")]);
    let receiver = Receiver::start(Script::default());
    let operator = "[operator]\nlisten = \"127.0.0.1:0\"\n";
    let engine = Engine::start("operator-silent", &dns, &receiver, "dane = false", operator);
    let port = engine
        .listening("serving health and metrics")
        .expect("an operator endpoint");
    let mut silent = std::net::TcpStream::connect(("127.0.0.1", port)).expect("it connects");
    silent
        .set_read_timeout(Some(Duration::from_secs(30)))
        .expect("a timeout");
    let started = std::time::Instant::now();
    let read = std::io::Read::read(&mut silent, &mut [0; 1]).expect("closed, not timed out");
    assert_eq!(read, 0);
    let waited = started.elapsed();
    assert!(
        (Duration::from_secs(9)..Duration::from_secs(20)).contains(&waited),
        "{waited:?}"
    );
}

#[test]
fn the_binary_says_its_version() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_nitromta"))
        .arg("--version")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        format!("nitromta {}\n", env!("CARGO_PKG_VERSION"))
    );
}

/// Runs a command against the engine's configuration, which must succeed,
/// and returns what it printed.
#[test]
fn each_command_says_how_to_run_it() {
    let help = |arguments: &[&str]| {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_nitromta"))
            .args(arguments)
            .arg("--help")
            .output()
            .unwrap();
        assert!(output.status.success(), "{arguments:?}");
        String::from_utf8(output.stdout).unwrap()
    };
    // Each of its forms, and only its own.
    let setup = help(&["setup"]);
    assert!(setup.starts_with("usage:\n  setup --config <file> --hostname"));
    assert!(setup.contains("\n  setup --config <file> --capture"));
    assert!(!setup.contains("\n  run "), "{setup}");
    // `run` says how without a configuration to run with.
    assert_eq!(
        help(&["run"]),
        "usage:\n  run --config <file>             serve\n"
    );
    let key = help(&["key"]);
    assert_eq!(key.lines().count(), 4, "{key}");
    let list = help(&["key", "list"]);
    assert_eq!(list.lines().count(), 2, "{list}");
    assert!(list.contains("key list --config <file>"), "{list}");
    // A form's further lines come with it, and the words it takes after
    // the command's own name the command.
    assert!(help(&["list"]).contains("kinds: accounts"));
    assert_eq!(help(&["list", "accounts"]), help(&["list"]));
    assert!(help(&["fence", "release"]).starts_with("usage:\n  fence --config <file>"));
    // A word that names no command is shown every command.
    assert!(help(&["frobnicate"]).starts_with("usage: nitromta <command>"));
}

fn run(engine: &Engine, arguments: &[&str]) -> String {
    let mut arguments = arguments.to_vec();
    arguments.extend(["--config", "config.toml"]);
    let (succeeded, text) = engine.command(&arguments);
    assert!(succeeded, "nitromta {arguments:?}: {text}");
    text
}

#[test]
fn commands_reach_the_running_engine_and_show_its_answers() {
    let (receiver, mut engine) = start("cli");
    let messages = engine.submit(&["one@plain.test"]);
    wait_for("the delivery", || receiver.delivered().len() == 1);

    // An identity signing with a key of its own: its DKIM record to publish
    // is the public half of that key.
    let key = KeyPair::generate(KeySize::Rsa2048).unwrap();
    let pkcs8 =
        aws_lc_rs::encoding::AsDer::<aws_lc_rs::encoding::Pkcs8V1Der>::as_der(&key).unwrap();
    let body = STANDARD.encode(pkcs8.as_ref());
    let lines: Vec<&str> = body
        .as_bytes()
        .chunks(64)
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect();
    let pem = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
        lines.join("\n")
    );
    let answers = engine.admin(&[json!({
        "op": "put_identity", "account": 1, "name": "signed.test",
        "selector": "s1", "private_key": pem,
    })]);
    assert!(answers[0]["ok"].is_object(), "{answers:?}");
    let public = STANDARD.encode(key.public_key().as_der().unwrap().as_ref());
    let identities = run(&engine, &["list", "identities"]);
    assert!(identities.starts_with("NAME"), "{identities}");
    assert!(identities.contains("sender.test"), "{identities}");
    assert!(
        identities.contains(&format!(
            "signed.test s1._domainkey: v=DKIM1; k=rsa; p={public}\n"
        )),
        "{identities}"
    );

    // A message explained, and the queue empty once it is delivered.
    let explained = run(&engine, &["explain", "--message", &messages[0]]);
    assert!(
        explained.starts_with("delivery ")
            && explained.contains(&format!("of message {}", messages[0])),
        "{explained}"
    );
    assert!(explained.contains("finished, delivered"), "{explained}");
    assert_eq!(run(&engine, &["queue"]), "no mail queued\n");

    // Paused, the hold is listed; resumed, it is gone.
    let paused = run(
        &engine,
        &[
            "pause",
            "--account",
            "1",
            "--identity",
            "sender.test",
            "--reason",
            "a look first",
        ],
    );
    assert_eq!(paused, "paused\n");
    let holds = run(&engine, &["list", "holds"]);
    assert!(
        holds.contains("sender.test") && holds.contains("a look first"),
        "{holds}"
    );
    assert_eq!(
        run(
            &engine,
            &["resume", "--account", "1", "--identity", "sender.test"]
        ),
        "resumed\n"
    );
    assert_eq!(run(&engine, &["list", "holds"]), "no holds\n");

    // Credentials, their secrets shown once and never listed.
    let created = run(
        &engine,
        &["login", "create", "--account", "1", "--user", "second"],
    );
    let password = created
        .trim_end()
        .rsplit_once("shown this once: ")
        .map(|(_, password)| password.to_owned())
        .expect("its password");
    let logins = run(&engine, &["list", "logins"]);
    assert!(
        logins.contains("second") && !logins.contains(&password),
        "{logins}"
    );
    assert_eq!(
        run(&engine, &["login", "remove", "--user", "second"]),
        "removed\n"
    );
    let created = run(&engine, &["access-key", "create", "--account", "1"]);
    let id = created
        .split_whitespace()
        .nth(2)
        .expect("its ID")
        .to_owned();
    let keys = run(&engine, &["list", "access_keys"]);
    assert!(keys.contains(&id), "{keys}");
    assert_eq!(
        run(&engine, &["access-key", "revoke", "--access-key-id", &id]),
        "revoked\n"
    );

    // With --json, the API's own lines.
    let json: Value =
        serde_json::from_str(run(&engine, &["list", "egresses", "--json"]).trim()).unwrap();
    assert_eq!(json, json!({"ok": {"egresses": []}}));

    // An error answer ends the command, with its code, and with --json is
    // printed as the API's line; an unknown option, or one without its
    // value, is refused before anything is sent.
    let (succeeded, text) = engine.command(&["list", "secrets", "--config", "config.toml"]);
    assert!(!succeeded && text.contains("malformed"), "{text}");
    let (succeeded, text) =
        engine.command(&["list", "secrets", "--config", "config.toml", "--json"]);
    let line: Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
    assert!(!succeeded && line["error"]["code"] == "malformed", "{text}");
    let (succeeded, text) = engine.command(&[
        "pause",
        "--config",
        "config.toml",
        "--account",
        "1",
        "--reason",
        "--accepting",
    ]);
    assert!(
        !succeeded && text.contains("--reason needs a value"),
        "{text}"
    );
    assert_eq!(run(&engine, &["list", "holds"]), "no holds\n");
    let (succeeded, text) = engine.command(&["queue", "--config", "config.toml", "--tenant", "x"]);
    assert!(
        !succeeded && text.contains("--tenant is not an option"),
        "{text}"
    );
    // A configuration that does not read is shown by where, never by its
    // text, which holds the return path's key.
    let config = std::fs::read_to_string(engine.dir.join("config.toml")).unwrap();
    let key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    std::fs::write(
        engine.dir.join("broken.toml"),
        config.replace(&format!("\"{key}\""), &format!("\"{key}\" junk")),
    )
    .unwrap();
    let (succeeded, text) = engine.command(&["doctor", "--config", "broken.toml"]);
    assert!(
        !succeeded && text.contains("broken.toml: line ") && !text.contains(&key[..16]),
        "{text}"
    );
}

#[test]
fn a_drain_takes_no_new_mail_and_says_when_the_queue_is_delivered() {
    let dns = Dns::start(&[("plain.test", "mx.plain.test")]);
    // Each delivery's content held two seconds, so one is under way while
    // the drain waits.
    let receiver = Receiver::start(Script {
        content_delay: Duration::from_secs(2),
        ..Script::default()
    });
    let operator = "[operator]\nlisten = \"127.0.0.1:0\"";
    let mut engine = Engine::start("drain", &dns, &receiver, "dane = false", operator);
    engine.submit(&["one@plain.test"]);
    // A transaction whose recipient was taken before the drain began.
    let mut before = engine.session();
    before.send("MAIL FROM:<app@sender.test>", 250);
    before.send("RCPT TO:<three@plain.test>", 250);
    let waiting = engine.spawn(&["drain", "--wait", "--config", "config.toml"]);
    wait_for("the drain", || engine.operator("/health/accept").0 == 503);
    // Its message is refused for now at its commit, as the drain began.
    before.send("DATA", 354);
    let refused = before.send(
        "From: app@sender.test\r\nTo: three@plain.test\r\nSubject: a test\r\n\r\nhello\r\n.",
        451,
    );
    assert!(refused.contains("4.3.2"), "{refused}");
    before.send("QUIT", 221);
    // The drain waits while the first delivery is under way, and says it
    // is drained once it is delivered.
    let mut waiting = waiting;
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        waiting.try_wait().unwrap().is_none() && receiver.delivered().is_empty(),
        "the drain ended with a delivery under way"
    );
    let output = waiting.wait_with_output().unwrap();
    let drained = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{drained}");
    assert!(drained.trim_end().ends_with("; drained"), "{drained}");
    assert_eq!(receiver.delivered().len(), 1);
    // While it drains, a recipient is refused for now, and health says why.
    let mut session = engine.session();
    session.send("MAIL FROM:<app@sender.test>", 250);
    let refused = session.send("RCPT TO:<two@plain.test>", 451);
    assert!(refused.contains("4.3.2"), "{refused}");
    session.send("QUIT", 221);
    let (status, why) = engine.operator("/health/accept");
    assert_eq!(status, 503);
    assert!(why.contains("draining"), "{why}");
    // Undrained, it takes mail again.
    let undrained = run(&engine, &["undrain"]);
    assert!(undrained.starts_with("taking new mail"), "{undrained}");
    engine.submit(&["two@plain.test"]);
    wait_for("the second delivery", || receiver.delivered().len() == 2);
}

#[test]
fn an_older_key_is_retired_once_a_restart_seals_under_the_newest() {
    let (_receiver, mut engine) = start("cli-keys");
    engine.submit(&["one@plain.test"]);
    let listed = run(&engine, &["key", "list"]);
    assert_eq!(
        listed,
        "key 1, the newest, which new secrets are sealed under, which the running engine seals every secret under\n"
    );
    let (succeeded, text) = engine.command(&["key", "--to", "keys"]);
    assert!(succeeded && text.starts_with("key 2 written"), "{text}");
    // The running engine still seals under the first: it cannot go yet.
    let (succeeded, text) =
        engine.command(&["key", "retire", "--id", "1", "--config", "config.toml"]);
    assert!(
        !succeeded && text.contains("seals every secret under key 1"),
        "{text}"
    );
    // Restarted, it seals under the second, and the first may go, but
    // only through the configuration of the engine holding those keys.
    engine.restart();
    assert!(run(&engine, &["key", "list"]).contains(
        "key 2, the newest, which new secrets are sealed under, which the running engine"
    ));
    let config = std::fs::read_to_string(engine.dir.join("config.toml")).unwrap();
    std::fs::copy(engine.dir.join("keys"), engine.dir.join("copied-keys")).unwrap();
    std::fs::write(
        engine.dir.join("copied.toml"),
        config.replace("keys = \"keys\"", "keys = \"copied-keys\""),
    )
    .unwrap();
    let (succeeded, text) =
        engine.command(&["key", "retire", "--id", "1", "--config", "copied.toml"]);
    assert!(
        !succeeded && text.contains("not this configuration's"),
        "{text}"
    );
    // A second engine on the same keys, with a store of its own, refuses
    // to start.
    std::fs::write(
        engine.dir.join("second.toml"),
        config
            .replace("path = \"store.db\"", "path = \"second.db\"")
            .replace("socket = \"admin.sock\"", "socket = \"second.sock\""),
    )
    .unwrap();
    let mut second = engine.spawn(&["run", "--config", "second.toml"]);
    wait_for("the second engine to stop", || {
        second.try_wait().unwrap().is_some()
    });
    let refused = second.wait_with_output().unwrap();
    let said = String::from_utf8_lossy(&refused.stderr);
    assert!(
        !refused.status.success() && said.contains("another running engine's"),
        "{said}"
    );
    assert_eq!(
        run(&engine, &["key", "retire", "--id", "1"]),
        "key 1 retired from keys\n"
    );
    assert!(!run(&engine, &["key", "list"]).contains("key 1"));
    // Its store migrates only while the engine is stopped.
    let (succeeded, text) = engine.command(&["migrate", "--config", "config.toml"]);
    assert!(
        !succeeded && text.contains("stop the engine first"),
        "{text}"
    );
    engine.stop();
    let migrated = run(&engine, &["migrate"]);
    assert!(migrated.ends_with("this release's\n"), "{migrated}");
    engine.start_again().expect("it starts on its own keys");
}

#[test]
fn with_encryption_on_a_key_that_sealed_mail_retires_only_once_that_mail_is_gone() {
    let (receiver, mut engine) = start("cli-sealed-keys");
    let config = engine.dir.join("config.toml");
    let text = std::fs::read_to_string(&config).unwrap();
    // Finished mail is kept a second.
    std::fs::write(
        &config,
        text.replace(
            "keys = \"keys\"",
            "keys = \"keys\"\nencryption = \"installation\"\nfeedback_window_seconds = 1",
        ),
    )
    .unwrap();
    engine.restart();
    engine.submit(&["one@plain.test"]);
    wait_for("the first delivery", || receiver.delivered().len() == 1);
    let (succeeded, text) = engine.command(&["key", "--to", "keys"]);
    assert!(
        succeeded && text.contains("once mail sealed under them is gone"),
        "{text}"
    );
    engine.restart();
    // Key 1 sealed that mail, which is still kept: the engine says what
    // still needs it.

    let retire = |engine: &Engine, id: &str| {
        engine.command(&["key", "retire", "--id", id, "--config", "config.toml"])
    };
    let (succeeded, text) = retire(&engine, "1");
    assert!(
        !succeeded
            && text.contains("key 1 still seals ")
            && text.contains("deliveries 1")
            && text.contains("retire it once they are gone"),
        "{text}"
    );
    // Once newer mail is the newest kept and the first is trimmed, nothing
    // needs it, and it goes.
    engine.submit(&["two@plain.test"]);
    wait_for("the second delivery", || receiver.delivered().len() == 2);
    wait_for("key 1 retired", || retire(&engine, "1").0);
    assert!(!run(&engine, &["key", "list"]).contains("key 1"), "retired");
    // Key 2 seals mail now.
    let (succeeded, text) = retire(&engine, "2");
    assert!(!succeeded, "{text}");
}

#[test]
fn setup_writes_a_new_installation_and_writes_over_nothing() {
    let dir = std::env::temp_dir().join(format!("nitromta-setup-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let nitromta = |arguments: &[&str]| {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_nitromta"))
            .args(arguments)
            .current_dir(&dir)
            .output()
            .expect("the binary runs");
        let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
        text.push_str(&String::from_utf8_lossy(&output.stderr));
        (output.status.success(), text)
    };
    let setup = [
        "setup",
        "--config",
        "config.toml",
        "--hostname",
        "mail.example.test",
        "--return-path-domain",
        "bounces.example.test",
        "--store",
        "store.db",
    ];
    // A file of someone else's beside where the keys go is left alone.
    std::fs::write(dir.join("keys.new"), "not setup's").unwrap();
    let (succeeded, said) = nitromta(&setup);
    assert!(succeeded, "{said}");
    assert!(
        said.contains("wrote config.toml") && said.contains("with key 1"),
        "{said}"
    );
    assert_eq!(
        std::fs::read_to_string(dir.join("keys.new")).unwrap(),
        "not setup's"
    );
    assert!(
        said.contains("nitromta doctor --config config.toml"),
        "{said}"
    );
    use std::os::unix::fs::PermissionsExt as _;
    for file in ["config.toml", "keys"] {
        let mode = std::fs::metadata(dir.join(file))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "{file}");
    }
    // The CLI reads what it wrote.
    let (succeeded, said) = nitromta(&["key", "list", "--config", "config.toml"]);
    assert!(succeeded && said.starts_with("key 1, the newest"), "{said}");
    // Run again, it writes over nothing.
    let before = std::fs::read(dir.join("config.toml")).unwrap();
    let (succeeded, said) = nitromta(&setup);
    assert!(!succeeded && said.contains("writes over nothing"), "{said}");
    assert_eq!(std::fs::read(dir.join("config.toml")).unwrap(), before);
    // One to try the engine with, in capture mode: its certificate made too,
    // its key its owner's alone, and what to do next.
    let (succeeded, said) = nitromta(&["setup", "--config", "trying.toml", "--capture"]);
    assert!(succeeded, "{said}");
    assert!(
        said.contains("wrote ./tls.crt") && said.contains("http://127.0.0.1:9090/capture"),
        "{said}"
    );
    let mode = std::fs::metadata(dir.join("tls.key"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
    let config = std::fs::read_to_string(dir.join("trying.toml")).unwrap();
    assert!(config.contains("[capture]\ndirectory = "), "{config}");
    let (succeeded, said) = nitromta(&["key", "list", "--config", "trying.toml"]);
    assert!(succeeded, "{said}");
    let _ = std::fs::remove_dir_all(&dir);
}
