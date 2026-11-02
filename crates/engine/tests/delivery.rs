//! Delivery through the release binary: a provider's
//! connections, shared by its queues; an idle connection giving its place
//! up; a throttle cooling the site, across a restart; a refused greeting
//! cooling it; a rejection suppressing its address, and a refused sender
//! suppressing none of its recipients; and the debug lines
//! that follow a message through acceptance and its attempts.
//! Each test runs the engine against a stub DNS and a receiver that
//! records what it was told.

mod support;

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use support::receiver::Connection;
use support::{Dns, Engine, Receiver, Script, wait_for};

/// The receiver rules' providers the tests deliver to, by their exchanges.
const PROVIDERS: &str = r#"
[receivers.Hosted]
exchanges = [".hosted.test"]
connections = 2
transactions_per_connection = 3

[receivers.Idle]
exchanges = [".idle.test"]
connections = 1

[receivers.Throttled]
exchanges = [".throttled.test"]
connections = 2

[[receivers.Throttled.throttles]]
name = "slow"
pattern = "slow down"
cooldown_seconds = 600

[receivers.Greeted]
exchanges = [".greeted.test"]

[[receivers.Greeted.throttles]]
name = "slow"
pattern = "slow down"
cooldown_seconds = 900
"#;

const ROUTES: &[(&str, &str)] = &[
    ("a.test", "mx.a.hosted.test"),
    ("b.test", "mx.b.hosted.test"),
    ("x.test", "mx.x.idle.test"),
    ("y.test", "mx.y.idle.test"),
    ("t.test", "mx.t.throttled.test"),
    ("g.test", "mx.g.greeted.test"),
    ("plain.test", "mx.plain.test"),
];

/// Recipients at t.test but ok@ are told to slow down; gone@plain.test
/// does not exist.
fn rcpt(recipient: &str) -> &'static str {
    match recipient {
        "gone@plain.test" => "550 5.1.1 no such user",
        _ if recipient.ends_with("@t.test") && !recipient.starts_with("ok") => {
            "451 4.7.1 slow down please"
        }
        _ => "250 2.1.5 Ok",
    }
}

fn start(name: &str) -> (Receiver, Engine) {
    start_logging(name, "")
}

/// As [`start`], with `log`'s lines in the configuration's `[log]`.
fn start_logging(name: &str, log: &str) -> (Receiver, Engine) {
    start_scripted(
        name,
        log,
        Script {
            rcpt,
            content_delay: Duration::from_millis(100),
            slow_quit: Duration::from_secs(2),
            ..Script::default()
        },
    )
}

/// As [`start_logging`], the receiver answering as `script` says.
fn start_scripted(name: &str, log: &str, script: Script) -> (Receiver, Engine) {
    let dns = Dns::start(ROUTES);
    let receiver = Receiver::start(script);
    let engine = Engine::start(
        name,
        &dns,
        &receiver,
        "idle_seconds = 30\n# The stub DNS signs nothing.\ndane = false",
        &format!(
            "{PROVIDERS}\n[operator]\nlisten = \"127.0.0.1:0\"\n\n[log]\nformat = \"json\"\n{log}"
        ),
    );
    (receiver, engine)
}

/// The most connections open at once.
fn peak(connections: &[Connection]) -> usize {
    let mut changes: Vec<(Instant, i32)> = Vec::new();
    for connection in connections {
        changes.push((connection.opened, 1));
        changes.push((connection.closed.unwrap_or_else(Instant::now), -1));
    }
    // A close at the instant of an open comes first.
    changes.sort();
    let (mut open, mut most) = (0, 0);
    for (_, change) in changes {
        open += change;
        most = most.max(open);
    }
    usize::try_from(most).expect("never negative")
}

/// The queue report's entry for `site`.
fn site(engine: &Engine, site: &str) -> Value {
    let queues = engine.admin(&[json!({"op": "queue"})]);
    let queues = &queues[0]["ok"]["queues"];
    queues
        .as_array()
        .and_then(|queues| queues.iter().find(|queue| queue["site"] == site))
        .cloned()
        .unwrap_or_else(|| panic!("no queue at {site}: {queues}"))
}

#[test]
fn a_providers_queues_share_its_connections_and_never_mix() {
    let (receiver, mut engine) = start("shared");
    let recipients: Vec<String> = (0..6)
        .flat_map(|n| [format!("r{n}@a.test"), format!("r{n}@b.test")])
        .collect();
    engine.submit(&recipients.iter().map(String::as_str).collect::<Vec<_>>());
    wait_for("every message delivered", || {
        receiver.delivered().len() == 12
    });
    let connections = receiver.connections();
    assert_eq!(
        peak(&connections),
        2,
        "the provider's two connections, shared by both queues: {connections:#?}"
    );
    for connection in &connections {
        assert!(connection.transactions.len() <= 3, "{connection:#?}");
        assert_eq!(
            connection.domains().len(),
            1,
            "a connection carries one queue's mail: {connection:#?}"
        );
    }
}

#[test]
fn an_idle_connection_gives_its_place_to_a_queue_without_one() {
    let (receiver, mut engine) = start("idle");
    engine.submit(&["one@x.test"]);
    wait_for("x.test's message", || receiver.delivered().len() == 1);
    // x.test's connection stands idle for thirty seconds, and fills the
    // provider's one place.
    let asked = Instant::now();
    engine.submit(&["one@y.test"]);
    wait_for("y.test's message", || receiver.delivered().len() == 2);
    assert!(
        asked.elapsed() < Duration::from_secs(10),
        "y.test waited for x.test's idle connection to time out"
    );
    assert_eq!(peak(&receiver.connections()), 1);
}

#[test]
fn a_throttle_cools_the_site_across_a_restart() {
    let (receiver, mut engine) = start("throttled");
    engine.submit(&["ok@t.test"]);
    wait_for("the first message", || receiver.delivered().len() == 1);
    engine.submit(&["one@t.test"]);
    wait_for("the throttle", || receiver.asked("one@t.test") == 1);
    // While the throttled connection quits, slowly, the site has room for
    // another, which nothing may take.
    engine.submit(&["two@t.test", "three@t.test"]);
    std::thread::sleep(Duration::from_secs(3));
    let cooling = site(&engine, "Throttled");
    assert_eq!(
        receiver.answered().len(),
        2,
        "{:#?}",
        receiver.connections()
    );
    assert!(
        cooling["cooling"]["reply"]
            .as_str()
            .is_some_and(|reply| reply.contains("slow down")),
        "{cooling}"
    );
    // Counted by the provider's site.
    let (_, metrics) = engine.operator("/metrics");
    for result in ["delivered", "throttled"] {
        let line = format!(
            "nitromta_attempts_by_site_total{{site=\"Throttled\",result=\"{result}\"}} 1\n"
        );
        assert!(metrics.contains(&line), "{line} in {metrics}");
    }
    engine.restart();
    engine.submit(&["four@t.test"]);
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(
        receiver.answered().len(),
        2,
        "the cooldown outlived the restart: {:#?}",
        receiver.connections()
    );
    assert!(site(&engine, "Throttled")["cooling"].is_object());
    // The four waiting out the cooldown are the queue, counted at the
    // restart and as the fourth came.
    wait_for("the waiting queue measured", || {
        let (_, metrics) = engine.operator("/metrics");
        metrics.contains("nitromta_queue_deliveries{state=\"waiting\"} 4\n")
    });
}

#[test]
fn a_refused_greeting_cools_the_site() {
    let (receiver, mut engine) = start("greeted");
    receiver.refuse_greetings(true);
    engine.submit(&["one@g.test"]);
    wait_for("the refusal", || {
        receiver
            .connections()
            .iter()
            .any(|connection| connection.refused)
    });
    receiver.refuse_greetings(false);
    engine.submit(&["two@g.test"]);
    std::thread::sleep(Duration::from_secs(2));
    let connections = receiver.connections();
    assert!(
        connections.iter().all(|connection| connection.refused),
        "{connections:#?}"
    );
    let cooling = site(&engine, "Greeted");
    assert!(cooling["cooling"].is_object(), "{cooling}");
}

#[test]
fn a_rejection_that_rules_the_address_out_suppresses_it() {
    let (receiver, mut engine) = start("suppressed");
    engine.submit(&["gone@plain.test", "one@plain.test"]);
    wait_for("the rejection and the delivery", || {
        receiver.asked("gone@plain.test") == 1 && receiver.delivered().len() == 1
    });
    engine.submit(&["gone@plain.test", "two@plain.test"]);
    wait_for("the next delivery", || receiver.delivered().len() == 2);
    assert_eq!(receiver.asked("gone@plain.test"), 1);
    // At the default level, no line for any message, delivery or attempt.
    let log = engine.log();
    for line in [
        "a message was accepted",
        "a delivery was accepted",
        "an attempt ended",
    ] {
        assert!(!log.contains(line), "{log}");
    }
}

#[test]
fn a_refusal_of_the_sender_suppresses_none_of_its_recipients() {
    // The first sender is refused in words that would rule an address
    // out; every later one is taken.
    static REFUSED: AtomicBool = AtomicBool::new(false);
    let (receiver, mut engine) = start_scripted(
        "sender-refused",
        "",
        Script {
            mail: |_| {
                if REFUSED.swap(true, Ordering::SeqCst) {
                    "250 2.1.0 Ok"
                } else {
                    "550 5.1.1 sender address rejected"
                }
            },
            rcpt,
            ..Script::default()
        },
    );
    let messages = engine.submit(&["one@plain.test"]);
    wait_for("the refusal", || {
        engine.explain(&messages[0])[0]["completion"] == "rejected"
    });
    engine.submit(&["one@plain.test"]);
    wait_for("the next delivery", || {
        receiver.delivered() == ["one@plain.test"]
    });
}

#[test]
fn at_debug_a_message_its_deliveries_and_their_attempts_each_have_a_line() {
    let (receiver, mut engine) = start_logging("debug", "level = \"debug\"");
    let messages = engine.submit(&["gone@plain.test", "one@plain.test"]);
    wait_for("the rejection and the delivery", || {
        receiver.asked("gone@plain.test") == 1 && receiver.delivered().len() == 1
    });
    let deliveries: Vec<String> = messages
        .iter()
        .map(|message| {
            engine.explain(message)[0]["delivery"]
                .as_str()
                .expect("a delivery")
                .to_owned()
        })
        .collect();
    let mut lines = Vec::new();
    wait_for("both attempts' lines", || {
        lines = engine
            .log()
            .lines()
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .collect();
        lines
            .iter()
            .filter(|line| line["message"] == "an attempt ended")
            .count()
            == 2
    });
    let said = |text: &str| -> Vec<&Value> {
        lines
            .iter()
            .filter(|line| line["message"] == text)
            .collect()
    };
    let accepted = said("a message was accepted");
    assert_eq!(accepted.len(), 2);
    for (message, delivery) in messages.iter().zip(&deliveries) {
        let line = accepted
            .iter()
            .find(|line| line["message_id"] == message.as_str())
            .expect("the message's line");
        assert!(line["submission"].is_string() && line["account"].is_string());
        assert_eq!(line["recipients"], 1);
        let delivered = said("a delivery was accepted");
        let line = delivered
            .iter()
            .find(|line| line["delivery"] == delivery.as_str())
            .expect("the delivery's line");
        assert_eq!(line["message_id"], message.as_str());
        assert_eq!(line["domain"], "plain.test");
    }
    let attempts = said("an attempt ended");
    let ended = |delivery: &str| {
        attempts
            .iter()
            .find(|line| line["delivery"] == delivery)
            .expect("the attempt's line")
    };
    let (rejected, delivered) = (ended(&deliveries[0]), ended(&deliveries[1]));
    assert_eq!(
        (&rejected["result"], &rejected["code"]),
        (&json!("rejected"), &json!(550))
    );
    assert_eq!(rejected["rules"], "no-such-mailbox");
    assert_eq!(
        (&delivered["result"], &delivered["code"]),
        (&json!("delivered"), &json!(250))
    );
    assert!(delivered["attempt"].is_string() && delivered["site"].is_string());
    // Never an address, nor a body.
    let log = engine.log();
    for recipient in ["gone@", "one@", "app@sender.test", "hello"] {
        assert!(!log.contains(recipient), "{recipient} in {log}");
    }
    // Each counted by its site and egress, with the time to its outcome,
    // and each message's time to acceptance.
    let (_, metrics) = engine.operator("/metrics");
    for line in [
        "nitromta_attempts_by_site_total{site=\"other\",result=\"delivered\"} 1\n",
        "nitromta_attempts_by_site_total{site=\"other\",result=\"rejected\"} 1\n",
        "nitromta_attempts_by_egress_total{egress=\"host\",result=\"delivered\"} 1\n",
        "nitromta_outcome_seconds_count{result=\"delivered\"} 1\n",
        "nitromta_outcome_seconds_count{result=\"rejected\"} 1\n",
        "nitromta_acceptance_seconds_count 2\n",
    ] {
        assert!(metrics.contains(line), "{line} in {metrics}");
    }
    let value = |name: &str| {
        metrics
            .lines()
            .find_map(|line| line.strip_prefix(name)?.strip_prefix(' '))
            .and_then(|value| value.parse::<f64>().ok())
            .unwrap_or_else(|| panic!("{name} in {metrics}"))
    };
    assert!(value("nitromta_accepted_bytes_total") > 0.0);
    // The receiver holds each message's content a tenth of a second, so
    // its delivery came that long at least after its acceptance; and each
    // acceptance took some time, well under a second.
    assert!(value("nitromta_outcome_seconds_sum{result=\"delivered\"}") >= 0.1);
    let accepting = value("nitromta_acceptance_seconds_sum");
    assert!(accepting > 0.0 && accepting < 2.0, "{accepting}");
    assert_eq!(value("nitromta_acceptance_seconds_bucket{le=\"1\"}"), 2.0);
    // Both finished, the queue is empty, as the store measures it.
    wait_for("an empty queue measured", || {
        let (_, metrics) = engine.operator("/metrics");
        ["waiting", "in_flight", "held"].iter().all(|state| {
            metrics.contains(&format!(
                "nitromta_queue_deliveries{{state=\"{state}\"}} 0\n"
            ))
        }) && metrics.contains("nitromta_queue_oldest_seconds 0\n")
    });
}
