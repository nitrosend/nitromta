//! The observer: joins what the load generator was told
//! with what the sinks received, so every result is judged from outside the
//! system under test.
//!
//! Deliveries are counted per recipient: a message with several reaches the
//! sink once for each, and each must arrive once.
//!
//! Messages to a throttled receiver may be held while it throttles, so they
//! are counted apart: held rather than missing, with their own delivery
//! times, until the throttle lifts and every one must arrive.

use std::collections::{BTreeMap, HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::records::{Ack, Arrival};

/// Percentiles of a sample, by nearest rank.
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Spread {
    pub min: f64,
    pub p50: f64,
    pub p95: f64,
    pub p99: f64,
    pub max: f64,
}

/// `None` for an empty sample.
pub fn spread(values: &mut [f64]) -> Option<Spread> {
    if values.is_empty() {
        return None;
    }
    values.sort_by(f64::total_cmp);
    let rank = |share: f64| {
        values[((share * values.len() as f64).ceil() as usize).clamp(1, values.len()) - 1]
    };
    Some(Spread {
        min: values[0],
        p50: rank(0.50),
        p95: rank(0.95),
        p99: rank(0.99),
        max: values[values.len() - 1],
    })
}

/// What one step of offered load produced, seen from outside.
#[derive(Clone, Debug, Serialize)]
pub struct Step {
    pub offered_rate: f64,
    pub seconds: f64,
    pub attempted: u64,
    pub accepted: u64,
    /// Accepted submissions per second of offered load.
    pub accepted_rate: f64,
    /// Refused submissions by reply code; 0 counts failed connections.
    pub refused: BTreeMap<u16, u64>,
    /// Recipients of accepted messages that the sink received, this step's
    /// or late ones from earlier steps.
    pub delivered: u64,
    /// Recipients of accepted messages, from this step or earlier, that have
    /// not been received, other than those held for a throttled receiver.
    pub missing: u64,
    /// Recipients at a throttled receiver that have not been received.
    pub held: u64,
    /// Recipients received though their message's submission was refused or
    /// lost its reply: committed requests whose response was lost.
    pub unacknowledged: u64,
    /// Second and later arrivals for a recipient.
    pub duplicates: u64,
    /// Arrivals without a valid signature, an intact body, TLS, or an id.
    pub unsigned: u64,
    pub altered: u64,
    pub plaintext: u64,
    pub unidentified: u64,
    /// From when a message was due to its final reply.
    pub submit_ms: Option<Spread>,
    /// From its final reply to its arrival at the sink, for every message
    /// but those to a throttled receiver.
    pub delivery_ms: Option<Spread>,
    /// The same, for messages to a throttled receiver.
    pub throttled_delivery_ms: Option<Spread>,
}

impl Step {
    /// Every arrival passed every check, and nothing accepted was lost or
    /// delivered twice: the conditions for a measurement to count at all.
    pub fn faults(&self) -> Vec<String> {
        let mut faults = Vec::new();
        for (count, what) in [
            (self.missing, "accepted messages never reached the sink"),
            (self.duplicates, "messages reached the sink more than once"),
            (
                self.unsigned,
                "messages arrived without a valid DKIM signature",
            ),
            (self.altered, "messages arrived with an altered body"),
            (self.plaintext, "messages arrived without TLS"),
            (
                self.unidentified,
                "messages arrived without the load generator's id",
            ),
        ] {
            if count > 0 {
                faults.push(format!("{count} {what}"));
            }
        }
        faults
    }
}

/// What every arrival must have passed. An ablation turns off what it takes
/// away: without signing, arrivals are unsigned; without TLS, plaintext.
#[derive(Clone, Copy)]
pub struct Expected {
    pub signed: bool,
    pub tls: bool,
}

impl Default for Expected {
    fn default() -> Self {
        Self {
            signed: true,
            tls: true,
        }
    }
}

/// What one system's run has seen so far, so a duplicate counts whichever
/// step it arrives in and a late arrival still finds its submission.
pub struct Observer {
    /// The share of ids that go to a throttled receiver.
    throttled_share: f64,
    /// Recipients per message.
    recipients: u16,
    expected: Expected,
    /// Each recipient received, by message id and recipient index.
    arrived: HashSet<(u64, u16)>,
    /// Recipients of accepted messages that have not been received, with
    /// their message's reply time.
    outstanding: HashMap<(u64, u16), i64>,
}

/// One recipient per message, none of them throttled.
impl Default for Observer {
    fn default() -> Self {
        Self::new(0.0, 1)
    }
}

impl Observer {
    pub fn new(throttled_share: f64, recipients: u16) -> Self {
        Self {
            throttled_share,
            recipients: recipients.max(1),
            expected: Expected::default(),
            arrived: HashSet::new(),
            outstanding: HashMap::new(),
        }
    }

    /// Judges arrivals by `expected` in place of every check.
    pub fn expecting(self, expected: Expected) -> Self {
        Self { expected, ..self }
    }

    fn throttled(&self, id: u64) -> bool {
        crate::load::throttled(id, self.throttled_share)
    }

    /// Accepted messages that have not arrived: those for the sink, and
    /// those for a throttled receiver.
    pub fn outstanding(&self) -> (u64, u64) {
        let held = self
            .outstanding
            .keys()
            .filter(|&&(id, _)| self.throttled(id))
            .count() as u64;
        (self.outstanding.len() as u64 - held, held)
    }

    pub fn step(
        &mut self,
        offered_rate: f64,
        seconds: f64,
        acks: &[Ack],
        arrivals: &[Arrival],
    ) -> Step {
        let accepted: Vec<&Ack> = acks.iter().filter(|ack| ack.accepted()).collect();
        for ack in &accepted {
            for recipient in 0..self.recipients {
                self.outstanding.insert((ack.id, recipient), ack.replied);
            }
        }
        let mut refused = BTreeMap::new();
        for ack in acks.iter().filter(|ack| !ack.accepted()) {
            *refused.entry(ack.code).or_default() += 1;
        }
        let mut step = Step {
            offered_rate,
            seconds,
            attempted: acks.len() as u64,
            accepted: accepted.len() as u64,
            accepted_rate: accepted.len() as f64 / seconds.max(f64::MIN_POSITIVE),
            refused,
            delivered: 0,
            missing: 0,
            held: 0,
            unacknowledged: 0,
            duplicates: 0,
            unsigned: 0,
            altered: 0,
            plaintext: 0,
            unidentified: 0,
            submit_ms: None,
            delivery_ms: None,
            throttled_delivery_ms: None,
        };
        let mut delivery = Vec::with_capacity(arrivals.len());
        let mut throttled = Vec::new();
        for arrival in arrivals {
            step.unsigned += u64::from(self.expected.signed && !arrival.passed(Arrival::DKIM));
            step.altered += u64::from(!arrival.passed(Arrival::BODY));
            step.plaintext += u64::from(self.expected.tls && !arrival.passed(Arrival::TLS));
            if !arrival.passed(Arrival::IDENTIFIED) {
                step.unidentified += 1;
                continue;
            }
            let key = (arrival.id, arrival.recipient);
            if !self.arrived.insert(key) {
                step.duplicates += 1;
                continue;
            }
            match self.outstanding.remove(&key) {
                Some(replied) => {
                    step.delivered += 1;
                    let ms = (arrival.at - replied) as f64 / 1000.0;
                    if self.throttled(arrival.id) {
                        throttled.push(ms);
                    } else {
                        delivery.push(ms);
                    }
                }
                None => step.unacknowledged += 1,
            }
        }
        (step.missing, step.held) = self.outstanding();
        let mut submit: Vec<f64> = accepted
            .iter()
            .map(|ack| (ack.replied - ack.due) as f64 / 1000.0)
            .collect();
        step.submit_ms = spread(&mut submit);
        step.delivery_ms = spread(&mut delivery);
        step.throttled_delivery_ms = spread(&mut throttled);
        step
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: u8 = Arrival::DKIM | Arrival::BODY | Arrival::TLS | Arrival::IDENTIFIED;

    fn ack(id: u64, code: u16) -> Ack {
        Ack {
            id,
            due: 1_000,
            sent: 1_500,
            replied: 3_000,
            code,
        }
    }

    fn arrival(id: u64, checks: u8) -> Arrival {
        Arrival {
            id,
            recipient: 0,
            at: 5_000,
            checks,
            source: std::net::Ipv4Addr::LOCALHOST.into(),
        }
    }

    #[test]
    fn percentiles_use_the_nearest_rank() {
        let mut values: Vec<f64> = (1..=100).map(f64::from).collect();
        values.reverse();
        let spread = spread(&mut values).unwrap();
        assert_eq!(
            (spread.min, spread.p50, spread.p95, spread.p99, spread.max),
            (1.0, 50.0, 95.0, 99.0, 100.0)
        );
        assert_eq!(super::spread(&mut [7.0]).unwrap().p50, 7.0);
        assert!(super::spread(&mut []).is_none());
    }

    #[test]
    fn steps_account_for_every_message() {
        let mut observer = Observer::default();
        let acks = [
            ack(1, 250),
            ack(2, 250),
            ack(3, 451),
            ack(4, 0),
            ack(5, 250),
        ];
        let arrivals = [
            arrival(1, ALL),
            arrival(2, ALL & !Arrival::DKIM),
            arrival(4, ALL),
            arrival(1, ALL),
            arrival(0, ALL & !Arrival::IDENTIFIED),
        ];
        let step = observer.step(5.0, 1.0, &acks, &arrivals);
        assert_eq!(
            (step.attempted, step.accepted, step.accepted_rate),
            (5, 3, 3.0)
        );
        assert_eq!(step.refused, BTreeMap::from([(0, 1), (451, 1)]));
        assert_eq!(
            (
                step.delivered,
                step.missing,
                step.unacknowledged,
                step.duplicates
            ),
            (2, 1, 1, 1)
        );
        assert_eq!(
            (
                step.unsigned,
                step.unidentified,
                step.altered,
                step.plaintext
            ),
            (1, 1, 0, 0)
        );
        assert_eq!(step.submit_ms.unwrap().p50, 2.0);
        assert_eq!(step.delivery_ms.unwrap().max, 2.0);
        assert_eq!(step.faults().len(), 4);

        // A message missing from one step that arrives in the next is
        // delivered late, and a repeat of an earlier one is a duplicate.
        let late = observer.step(
            1.0,
            1.0,
            &[ack(6, 250)],
            &[arrival(6, ALL), arrival(5, ALL), arrival(2, ALL)],
        );
        assert_eq!(
            (
                late.delivered,
                late.missing,
                late.unacknowledged,
                late.duplicates
            ),
            (2, 0, 0, 1)
        );
    }

    #[test]
    fn each_recipient_of_a_message_must_arrive_once() {
        let mut observer = Observer::new(0.0, 3);
        let to = |recipient| Arrival {
            recipient,
            ..arrival(7, ALL)
        };
        let step = observer.step(1.0, 1.0, &[ack(7, 250)], &[to(0), to(2), to(2)]);
        assert_eq!((step.delivered, step.missing, step.duplicates), (2, 1, 1));
        let late = observer.step(0.0, 1.0, &[], &[to(1)]);
        assert_eq!((late.delivered, late.missing), (1, 0));
    }

    #[test]
    fn messages_for_a_throttled_receiver_are_held_not_missing() {
        // A tenth of ids are throttled: 0 to 99 of every thousand.
        let mut observer = Observer::new(0.1, 1);
        let step = observer.step(
            3.0,
            1.0,
            &[ack(5, 250), ack(500, 250), ack(600, 250)],
            &[arrival(600, ALL)],
        );
        assert_eq!((step.missing, step.held), (1, 1));
        assert!(step.throttled_delivery_ms.is_none());
        let late = observer.step(0.0, 1.0, &[], &[arrival(5, ALL), arrival(500, ALL)]);
        assert_eq!((late.missing, late.held, late.delivered), (0, 0, 2));
        assert_eq!(late.throttled_delivery_ms.unwrap().max, 2.0);
        assert_eq!(observer.outstanding(), (0, 0));
    }
}
