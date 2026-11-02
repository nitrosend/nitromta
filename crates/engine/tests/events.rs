//! Event delivery through the release binary: a subscriber that
//! refuses every batch past its subscription's budget gets the batch
//! parked, with why its last post failed; `replay` posts it again, marked
//! as a replay, and once it is taken it is no longer parked. The test runs
//! the engine against a stub DNS, a receiver that takes every recipient,
//! and a subscriber of its own on loopback.

mod support;

use std::sync::atomic::Ordering;

use serde_json::{Value, json};
use support::endpoint::Endpoint;
use support::{Dns, Engine, Receiver, Script, wait_for};

fn parked(engine: &Engine) -> Vec<Value> {
    let answers = engine.admin(&[json!({"op": "parked", "account": 1, "subscription": "hooks"})]);
    answers[0]["ok"]["parked"]
        .as_array()
        .unwrap_or_else(|| panic!("a listing: {answers:?}"))
        .clone()
}

#[test]
fn a_batch_past_its_budget_is_parked_and_a_replay_taken_unparks_it() {
    let dns = Dns::start(&[("plain.test", "mx.plain.test")]);
    let receiver = Receiver::start(Script::default());
    let subscriber = Endpoint::start("/hooks", false);
    let mut engine = Engine::start(
        "events",
        &dns,
        &receiver,
        "dane = false",
        "[events]\npark_after_seconds = 1\n\n[operator]\nlisten = \"127.0.0.1:0\"",
    );
    // The sender's mail goes under a configuration with a subscription to
    // its acceptances.
    drop(engine.session());
    let answers = engine.admin(&[
        json!({"op": "put_configuration", "account": 1, "name": "receipts"}),
        json!({"op": "put_identity", "account": 1, "name": "sender.test", "configuration": "receipts"}),
        json!({"op": "create_subscription", "account": 1, "name": "hooks", "configuration": "receipts", "url": subscriber.url, "events": ["accepted"]}),
    ]);
    assert!(
        answers.iter().all(|answer| answer["ok"].is_object()),
        "{answers:?}"
    );
    let messages = engine.submit(&["one@plain.test"]);

    let mut listed = Vec::new();
    wait_for("the batch parked", || {
        listed = parked(&engine);
        !listed.is_empty()
    });
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0]["failure"], "answered 503");
    // Posted again only if the retry falls inside its one-second budget;
    // parked at the deadline otherwise, so one failed post is the floor.
    assert!(listed[0]["attempts"].as_u64().unwrap_or_default() >= 1);
    let refused = subscriber.bodies();
    assert!(refused.iter().all(|body| body.get("replay").is_none()));
    let gauge = |count: u32| {
        let engine = &engine;
        move || {
            engine
                .operator("/metrics")
                .1
                .contains(&format!("nitromta_event_batches_parked {count}\n"))
        }
    };
    wait_for("the parked batch measured", gauge(1));

    subscriber.taking.store(true, Ordering::SeqCst);
    let answers = engine.admin(&[json!({"op": "replay", "account": 1, "subscription": "hooks"})]);
    assert_eq!(answers[0]["ok"]["replaying"], 1, "{answers:?}");
    wait_for("the replay taken", || parked(&engine).is_empty());
    wait_for("no parked batch measured", gauge(0));
    let bodies = subscriber.bodies();
    let replay = bodies.last().expect("posted again");
    assert_eq!(replay["replay"], true);
    let event = &replay["events"][0];
    assert_eq!(event["type"], "accepted");
    assert_eq!(event["message"], messages[0].as_str());
    assert_eq!(
        event["id"], refused[0]["events"][0]["id"],
        "the same event's ID"
    );

    let (_, metrics) = engine.operator("/metrics");
    assert!(
        metrics.contains("nitromta_event_batches_parked_total 1\n"),
        "{metrics}"
    );
    assert!(
        metrics.contains("nitromta_event_batches_replayed_total 1\n"),
        "{metrics}"
    );
}
