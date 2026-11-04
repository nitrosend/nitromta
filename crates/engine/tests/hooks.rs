//! Hook points through a build of the engine with hooks of its own:
//! this test's binary, which runs as the engine, with the hooks
//! below, when a test starts it with `run --config`, and runs the tests
//! otherwise. The admission hook refuses for good or for now with its
//! reason, and keeps nothing it refuses; the dispatch hook holds and
//! rejects with its reason, and what it lets go still meets suppression; a
//! hook that fails, panics or does not decide in time comes to its failure
//! policy, logged as failures begin and end, and its calls under way are
//! bounded; and the engine's own binary,
//! which carries no hooks, refuses settings for one.

mod support;

use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use engine::hook::{Answer, Reason, admission, dispatch};
use serde_json::json;
use support::{Dns, Engine, Receiver, Script, Submitting, wait_for};

/// Refuses a message that says REJECT for good and one that says DEFER for
/// now, panics over one that says PANIC, and takes two seconds over one
/// that says SLOW; lets the rest through.
struct Admission;

impl admission::Hook for Admission {
    fn admit(self: Arc<Self>, messages: Vec<admission::Message>) -> Answer<admission::Verdict> {
        Box::pin(async move {
            let mut verdicts = Vec::new();
            for message in &messages {
                let says = |word: &str| {
                    message
                        .content
                        .windows(word.len())
                        .any(|window| window == word.as_bytes())
                };
                if says("SLOW") {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
                assert!(!says("PANIC"), "the test's admission hook panics");
                verdicts.push(if says("REJECT") {
                    admission::Verdict::Reject(Reason::new("the message says REJECT"))
                } else if says("DEFER") {
                    admission::Verdict::Defer(Reason::new("the message says DEFER"))
                } else {
                    admission::Verdict::Accept
                });
            }
            Ok(verdicts)
        })
    }
}

/// Rejects recipients whose name begins `never`, holds those beginning
/// `later`, and takes two seconds over a batch with one beginning `slow`;
/// lets the rest go.
struct Dispatch;

impl dispatch::Hook for Dispatch {
    fn decide(self: Arc<Self>, recipients: Vec<dispatch::Recipient>) -> Answer<dispatch::Verdict> {
        Box::pin(async move {
            let named = |recipient: &dispatch::Recipient, start: &str| {
                recipient.address.local_part().starts_with(start)
            };
            if recipients.iter().any(|recipient| named(recipient, "slow")) {
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            let verdicts = recipients.iter().map(|recipient| {
                if named(recipient, "never") {
                    dispatch::Verdict::Reject(Reason::new("never to this one"))
                } else if named(recipient, "later") {
                    dispatch::Verdict::Hold(Reason::new("not yet"))
                } else {
                    dispatch::Verdict::Proceed
                }
            });
            Ok(verdicts.collect())
        })
    }
}

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    if arguments.first().is_some_and(|command| command == "run") {
        return engine::main(engine::Hooks {
            admission: Some(Box::new(|| Arc::new(Admission))),
            dispatch: Some(Box::new(|| Arc::new(Dispatch))),
        });
    }
    let tests: [(&str, fn()); 7] = [
        (
            "the_admission_hook_refuses_for_good_or_for_now_with_its_reason",
            the_admission_hook_refuses_for_good_or_for_now_with_its_reason,
        ),
        (
            "an_admission_hook_that_fails_comes_to_its_failure_policy",
            an_admission_hook_that_fails_comes_to_its_failure_policy,
        ),
        (
            "an_admission_hooks_calls_under_way_are_bounded",
            an_admission_hooks_calls_under_way_are_bounded,
        ),
        (
            "the_dispatch_hook_holds_and_rejects_with_its_reason",
            the_dispatch_hook_holds_and_rejects_with_its_reason,
        ),
        (
            "what_the_dispatch_hook_lets_go_still_meets_its_suppression",
            what_the_dispatch_hook_lets_go_still_meets_its_suppression,
        ),
        (
            "a_dispatch_hook_that_does_not_decide_in_time_comes_to_its_failure_policy",
            a_dispatch_hook_that_does_not_decide_in_time_comes_to_its_failure_policy,
        ),
        (
            "a_build_without_a_hook_refuses_settings_for_one",
            a_build_without_a_hook_refuses_settings_for_one,
        ),
    ];
    let options = Options::parse(&arguments);
    if options.list {
        for (name, _) in &tests {
            println!("{name}: test");
        }
        return ExitCode::SUCCESS;
    }
    let chosen: Vec<(&str, fn())> = tests
        .into_iter()
        .filter(|(name, _)| options.runs(name))
        .collect();
    println!("\nrunning {} tests", chosen.len());
    let failed: Vec<&str> = std::thread::scope(|scope| {
        let running: Vec<_> = chosen
            .iter()
            .map(|&(name, test)| (name, scope.spawn(test)))
            .collect();
        running
            .into_iter()
            .filter_map(|(name, running)| {
                let passed = running.join().is_ok();
                println!("test {name} ... {}", if passed { "ok" } else { "FAILED" });
                (!passed).then_some(name)
            })
            .collect()
    });
    if failed.is_empty() {
        println!("\ntest result: ok. {} passed", chosen.len());
        ExitCode::SUCCESS
    } else {
        println!("\ntest result: FAILED. {} failed", failed.len());
        ExitCode::FAILURE
    }
}

/// What libtest's arguments ask of this binary, which has its own main:
/// the tests to run, by the names they hold, or exactly, and those to skip,
/// or only their list. Other options are taken and ignored, their values
/// with them, so no value is taken for a name.
#[derive(Default)]
struct Options {
    filters: Vec<String>,
    skips: Vec<String>,
    exact: bool,
    list: bool,
}

impl Options {
    /// libtest's options that take a value as the next argument.
    const VALUED: [&str; 7] = [
        "--test-threads",
        "--color",
        "--format",
        "--logfile",
        "--skip",
        "--shuffle-seed",
        "-Z",
    ];

    fn parse(arguments: &[String]) -> Self {
        let mut options = Self::default();
        let mut arguments = arguments.iter();
        while let Some(argument) = arguments.next() {
            match argument.as_str() {
                "--exact" => options.exact = true,
                "--list" => options.list = true,
                option if Self::VALUED.contains(&option) => {
                    let value = arguments.next();
                    if option == "--skip" {
                        options.skips.extend(value.cloned());
                    }
                }
                option if option.starts_with('-') => {}
                name => options.filters.push(name.to_owned()),
            }
        }
        options
    }

    fn runs(&self, name: &str) -> bool {
        let named = |filter: &String| {
            if self.exact {
                name == filter
            } else {
                name.contains(filter.as_str())
            }
        };
        (self.filters.is_empty() || self.filters.iter().any(named))
            && !self.skips.iter().any(|skip| name.contains(skip.as_str()))
    }
}

/// An engine built with the hooks above, with `sections` added to its
/// configuration, delivering to a receiver that takes every recipient.
fn start(name: &str, sections: &str) -> (Receiver, Engine) {
    let dns = Dns::start(&[("plain.test", "mx.plain.test")]);
    let receiver = Receiver::start(Script::default());
    let binary = std::env::current_exe().expect("this test's binary");
    let sections = format!("[operator]\nlisten = \"127.0.0.1:0\"\n\n{sections}");
    let engine = Engine::start_as(
        &binary,
        name,
        &dns,
        &receiver,
        "dane = false",
        &sections,
        &[],
    );
    (receiver, engine)
}

/// One transaction of `body` to `recipient`, and its final reply.
fn transaction(session: &mut Submitting, recipient: &str, body: &str) -> String {
    session.send("MAIL FROM:<app@sender.test>", 250);
    session.send(&format!("RCPT TO:<{recipient}>"), 250);
    session.send("DATA", 354);
    session.ask(&format!(
        "From: app@sender.test\r\nTo: {recipient}\r\nSubject: a test\r\n\r\n{body}\r\n."
    ))
}

/// What the engine's metrics count under `metric`, or nothing.
fn metric(engine: &Engine, metric: &str) -> u64 {
    let (_, metrics) = engine.operator("/metrics");
    metrics
        .lines()
        .find_map(|line| line.strip_prefix(metric)?.strip_prefix(' ')?.parse().ok())
        .unwrap_or_default()
}

/// How many times this run logged `message`.
fn logged(engine: &Engine, message: &str) -> usize {
    engine
        .logged()
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|line| line["message"] == message)
        .count()
}

const FAILED: &str = "a hook failed; until it decides again, its failure policy does";
const DECIDES: &str = "a hook decides again";
const PANICKED: &str = "a hook panicked; a hook's panics are logged at most once a minute";

fn the_admission_hook_refuses_for_good_or_for_now_with_its_reason() {
    let (receiver, mut engine) = start("admission", "");
    let mut session = engine.session();
    let reply = transaction(&mut session, "one@plain.test", "REJECT this");
    assert!(
        reply.starts_with("550 5.7.1 the message says REJECT"),
        "{reply}"
    );
    let reply = transaction(&mut session, "two@plain.test", "DEFER this");
    assert!(
        reply.starts_with("451 4.7.1 the message says DEFER"),
        "{reply}"
    );
    let reply = transaction(&mut session, "three@plain.test", "hello");
    assert!(reply.starts_with("250"), "{reply}");
    session.send("QUIT", 221);
    wait_for("the accepted message", || !receiver.delivered().is_empty());
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(receiver.delivered(), ["three@plain.test"]);
    // Nothing it refused was kept.
    assert_eq!(metric(&engine, "nitromta_messages_accepted_total"), 1);
    for (verdict, count) in [("accept", 1), ("reject", 1), ("defer", 1)] {
        let name =
            format!("nitromta_hook_verdicts_total{{hook=\"admission\",verdict=\"{verdict}\"}}");
        assert_eq!(metric(&engine, &name), count, "{verdict}");
    }
}

fn an_admission_hook_that_fails_comes_to_its_failure_policy() {
    let (receiver, mut closed) = start("admission-closed", "[hooks.admission]\ntimeout_ms = 300");
    let mut session = closed.session();
    let refused = "451 4.7.1 the admission hook did not decide";
    let reply = transaction(&mut session, "one@plain.test", "SLOW");
    assert!(reply.starts_with(refused), "{reply}");
    for recipient in ["two@plain.test", "again@plain.test"] {
        let reply = transaction(&mut session, recipient, "PANIC");
        assert!(reply.starts_with(refused), "{reply}");
    }
    // Failures in a row are one line in the log, panics among them, and
    // the next answer another; every line is the log's own JSON.
    assert_eq!(logged(&closed, FAILED), 1, "{}", closed.logged());
    let log = closed.logged();
    assert!(
        log.lines()
            .all(|line| serde_json::from_str::<serde_json::Value>(line).is_ok()),
        "{log}"
    );
    // Two panics, one line: a hook's panics are logged at most once a minute.
    assert_eq!(logged(&closed, PANICKED), 1, "{log}");
    let reply = transaction(&mut session, "three@plain.test", "hello");
    assert!(reply.starts_with("250"), "{reply}");
    session.send("QUIT", 221);
    assert_eq!(logged(&closed, DECIDES), 1, "{}", closed.logged());
    assert_eq!(
        metric(&closed, "nitromta_hook_failures_total{hook=\"admission\"}"),
        3
    );
    wait_for("the accepted message", || !receiver.delivered().is_empty());

    let (receiver, mut open) = start(
        "admission-open",
        "[hooks.admission]\ntimeout_ms = 300\non_failure = \"open\"",
    );
    let mut session = open.session();
    let reply = transaction(&mut session, "four@plain.test", "SLOW");
    assert!(reply.starts_with("250"), "{reply}");
    session.send("QUIT", 221);
    wait_for("the message let through", || {
        receiver.delivered() == ["four@plain.test"]
    });
}

fn an_admission_hooks_calls_under_way_are_bounded() {
    let (_receiver, mut engine) = start(
        "admission-bounded",
        "[hooks.admission]\ntimeout_ms = 5000\nconcurrency = 1",
    );
    let mut slow = engine.session();
    let mut other = engine.session();
    // The slow message holds the one place for two seconds.
    let holding = std::thread::spawn(move || transaction(&mut slow, "one@plain.test", "SLOW"));
    std::thread::sleep(Duration::from_millis(300));
    let asked = Instant::now();
    let reply = transaction(&mut other, "two@plain.test", "hello");
    assert!(reply.starts_with("250"), "{reply}");
    assert!(
        asked.elapsed() >= Duration::from_millis(1200),
        "it waited for the place: {:?}",
        asked.elapsed()
    );
    let reply = holding.join().expect("the slow transaction");
    assert!(reply.starts_with("250"), "{reply}");
}

fn the_dispatch_hook_holds_and_rejects_with_its_reason() {
    let (receiver, mut engine) = start("dispatch", "");
    let messages = engine.submit(&["never@plain.test", "later@plain.test", "ok@plain.test"]);
    wait_for("the one it lets go", || {
        receiver.delivered() == ["ok@plain.test"]
    });
    let explained = |message: &str, state: &str| {
        let mut delivery = serde_json::Value::Null;
        wait_for(state, || {
            delivery = engine.explain(message)[0].clone();
            delivery["state"] == state && delivery["last_reply"].is_object()
        });
        delivery
    };
    let rejected = explained(&messages[0], "finished");
    assert_eq!(rejected["completion"], "rejected");
    let reply = rejected["last_reply"]["reply"].as_str().unwrap_or_default();
    assert!(
        reply.contains("rejected by the dispatch hook: never to this one"),
        "{rejected}"
    );
    let held = explained(&messages[1], "waiting");
    let reply = held["last_reply"]["reply"].as_str().unwrap_or_default();
    assert!(
        reply.contains("held by the dispatch hook: not yet"),
        "{held}"
    );
    assert_eq!(receiver.asked("never@plain.test"), 0);
    assert_eq!(receiver.asked("later@plain.test"), 0);
    for (verdict, count) in [("proceed", 1), ("hold", 1), ("reject", 1)] {
        let name =
            format!("nitromta_hook_verdicts_total{{hook=\"dispatch\",verdict=\"{verdict}\"}}");
        assert_eq!(metric(&engine, &name), count, "{verdict}");
    }
}

fn what_the_dispatch_hook_lets_go_still_meets_its_suppression() {
    let (receiver, mut engine) = start("dispatch-suppressed", "");
    // The sender exists once a session has logged in.
    drop(engine.session());
    let answers = engine.admin(&[json!({
        "op": "suppress",
        "account": 1,
        "addresses": ["gone@plain.test"],
        "reason": "bounce",
    })]);
    assert!(answers[0]["ok"].is_object(), "{answers:?}");
    let messages = engine.submit(&["gone@plain.test", "ok@plain.test"]);
    wait_for("the other recipient", || {
        receiver.delivered() == ["ok@plain.test"]
    });
    wait_for("the suppression", || {
        engine.explain(&messages[0])[0]["completion"] == "suppressed"
    });
    assert_eq!(receiver.asked("gone@plain.test"), 0);
    let proceeded = "nitromta_hook_verdicts_total{hook=\"dispatch\",verdict=\"proceed\"}";
    assert_eq!(metric(&engine, proceeded), 2, "the hook let both go");
}

fn a_dispatch_hook_that_does_not_decide_in_time_comes_to_its_failure_policy() {
    let (receiver, mut closed) = start("dispatch-closed", "[hooks.dispatch]\ntimeout_ms = 300");
    let messages = closed.submit(&["slow@plain.test"]);
    let mut delivery = serde_json::Value::Null;
    wait_for("the hold", || {
        delivery = closed.explain(&messages[0])[0].clone();
        delivery["last_reply"].is_object()
    });
    let reply = delivery["last_reply"]["reply"].as_str().unwrap_or_default();
    assert!(
        reply.contains("held by the dispatch hook: the dispatch hook did not decide"),
        "{delivery}"
    );
    assert_eq!(delivery["state"], "waiting");
    assert_eq!(receiver.asked("slow@plain.test"), 0);
    assert_eq!(logged(&closed, FAILED), 1, "{}", closed.logged());

    let (receiver, mut open) = start(
        "dispatch-open",
        "[hooks.dispatch]\ntimeout_ms = 300\non_failure = \"open\"",
    );
    open.submit(&["slow@plain.test"]);
    wait_for("the recipient let go", || {
        receiver.delivered() == ["slow@plain.test"]
    });
}

fn a_build_without_a_hook_refuses_settings_for_one() {
    let dns = Dns::start(&[("plain.test", "mx.plain.test")]);
    let receiver = Receiver::start(Script::default());
    let mut engine = Engine::start("unhooked", &dns, &receiver, "dane = false", "");
    engine.stop();
    let config = engine.dir.join("config.toml");
    let mut text = std::fs::read_to_string(&config).expect("its configuration");
    text.push_str("\n[hooks.dispatch]\ntimeout_ms = 100\n");
    std::fs::write(&config, text).expect("written");
    let refused = engine
        .start_again()
        .expect_err("the engine refuses to start");
    assert!(
        refused.contains("[hooks.dispatch] is configured, and this build carries no dispatch hook"),
        "{refused}"
    );
}
