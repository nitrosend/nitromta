//! SES's mailbox simulator through the release binary: each
//! of its addresses ends as SES ends it, nothing reaches a receiver,
//! nothing it does suppresses an address, and its complaints count toward
//! no reputation.

mod support;

use support::{Dns, Engine, Receiver, Script, wait_for};

#[test]
fn each_simulator_address_ends_as_ses_ends_it_and_none_is_suppressed() {
    // No records at all: the simulator's domain is never looked up.
    let dns = Dns::start(&[]);
    let receiver = Receiver::start(Script::default());
    let operator = "[operator]\nlisten = \"127.0.0.1:0\"";
    let mut engine = Engine::start("simulator", &dns, &receiver, "dane = false", operator);
    let addresses = [
        "success+order-7@simulator.amazonses.com",
        "bounce@simulator.amazonses.com",
        "complaint@simulator.amazonses.com",
        "suppressionlist@simulator.amazonses.com",
    ];
    let send = |engine: &mut Engine| engine.submit(&addresses);
    let ended = |engine: &Engine, messages: &[String]| -> Vec<String> {
        messages
            .iter()
            .map(|message| {
                let explained = engine.explain(message);
                format!(
                    "{} {}",
                    explained[0]["state"].as_str().unwrap_or_default(),
                    explained[0]["completion"].as_str().unwrap_or_default()
                )
            })
            .collect()
    };
    for round in 0..2 {
        let messages = send(&mut engine);
        wait_for("each ended", || {
            ended(&engine, &messages)
                .iter()
                .all(|state| state.starts_with("finished"))
        });
        // The second time too: nothing the first did suppressed an address.
        assert_eq!(
            ended(&engine, &messages),
            [
                "finished delivered",
                "finished rejected",
                "finished delivered",
                "finished rejected"
            ],
            "round {round}"
        );
        let reply = &engine.explain(&messages[1])[0]["last_reply"]["reply"];
        assert!(
            reply.as_str().is_some_and(|reply| reply
                == "550 5.1.1 As requested: user unknown <bounce@simulator.amazonses.com>"),
            "{reply}"
        );
    }
    // Its complaints are recorded with their deliveries, and counted as no
    // report: SES keeps its simulator's mail out of reputation metrics.
    // Nothing reached a receiver.
    let (_, metrics) = engine.operator("/metrics");
    assert!(metrics.contains("nitromta_reports_total 0\n"), "{metrics}");
    assert!(!metrics.contains("kind=\"complaint\"} 1"), "{metrics}");
    assert!(receiver.delivered().is_empty());
}
