//! Holds through the release binary: a hold set through the
//! admin socket pauses its mail, which `explain` shows paused with the
//! hold's reason, across a restart, until the hold is lifted; and a hold
//! that refuses new mail answers SMTP with a temporary failure. Each test
//! runs the engine against a stub DNS and a receiver that records what it
//! was told.

mod support;

use std::time::Duration;

use serde_json::{Value, json};
use support::{Dns, Engine, Receiver, Script, wait_for};

fn start(name: &str) -> (Receiver, Engine) {
    let dns = Dns::start(&[("plain.test", "mx.plain.test")]);
    let receiver = Receiver::start(Script::default());
    let engine = Engine::start(name, &dns, &receiver, "dane = false", "");
    (receiver, engine)
}

/// Sends a hold or release request, which must succeed.
fn change(engine: &Engine, request: Value) {
    let answers = engine.admin(&[request]);
    assert!(answers[0]["ok"].is_object(), "{answers:?}");
}

#[test]
fn a_hold_pauses_its_mail_across_a_restart_until_it_is_lifted() {
    let (receiver, mut engine) = start("held");
    // The test's sender exists once a session has logged in.
    drop(engine.session());
    change(
        &engine,
        json!({"op": "hold", "account": 1, "identity": "sender.test", "reason": "investigating complaints"}),
    );
    let messages = engine.submit(&["one@plain.test"]);
    let mut paused = Value::Null;
    wait_for("the delivery to be paused", || {
        paused = engine.explain(&messages[0])[0].clone();
        paused["state"] == "paused"
    });
    assert_eq!(paused["paused"]["reason"], "investigating complaints");
    assert_eq!(paused["paused"]["accepting"], true);
    assert_eq!(paused["attempts"], 0);
    engine.restart();
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(engine.explain(&messages[0])[0]["state"], "paused");
    assert_eq!(receiver.asked("one@plain.test"), 0, "nothing while held");
    change(
        &engine,
        json!({"op": "release", "account": 1, "identity": "sender.test"}),
    );
    wait_for("the delivery once the hold is lifted", || {
        receiver.delivered() == ["one@plain.test"]
    });
    assert_eq!(engine.explain(&messages[0])[0]["completion"], "delivered");
}

#[test]
fn a_hold_that_refuses_new_mail_answers_for_now() {
    let (receiver, mut engine) = start("refusing");
    drop(engine.session());
    change(
        &engine,
        json!({"op": "hold", "account": 1, "accepting": false, "reason": "billing"}),
    );
    let mut session = engine.session();
    session.send("MAIL FROM:<app@sender.test>", 250);
    session.send("RCPT TO:<one@plain.test>", 250);
    session.send("DATA", 354);
    let reply = session
        .ask("From: app@sender.test\r\nTo: one@plain.test\r\nSubject: a test\r\n\r\nhello\r\n.");
    assert!(reply.starts_with("451 4.7.1 Sending is paused"), "{reply}");
    session.send("QUIT", 221);
    change(&engine, json!({"op": "release", "account": 1}));
    engine.submit(&["two@plain.test"]);
    wait_for("mail accepted once the hold is lifted", || {
        receiver.delivered() == ["two@plain.test"]
    });
}
