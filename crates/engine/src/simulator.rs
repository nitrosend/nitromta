//! SES's mailbox simulator: mail to `simulator.amazonses.com`
//! is never sent anywhere. Each address ends as SES's own does: `success`
//! and `ooto` delivered, `bounce` refused as an unknown user, `suppressionlist`
//! refused as an address SES suppresses, `complaint` delivered and
//! complained of, and any other address refused as unknown. A label after
//! `+` is kept and ignored, as SES ignores it. Nothing it does suppresses
//! an address: SES never places its simulator's on a list.
//!
//! A complaint is recorded in its delivery's outcome's commit, after it and
//! for that delivery alone, so a stop never loses it and it never runs
//! ahead of another delivery's outcome; tried again, it is the same
//! complaint. It is kept out of the complaint counts, as SES keeps its
//! simulator's mail out of reputation metrics.
//!
//! What SES says of its simulator beyond these outcomes is not simulated:
//! `ooto`'s automatic reply is not sent, and simulator mail counts against
//! the daily quota as any mail does.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use engine_core::address::Address;
use engine_core::attempt::Evidence;
use engine_core::feedback::{Claim, Kind, Report};
use engine_core::id::{IdGenerator, ReportId};
use engine_core::suppression;
use engine_scheduler::{Attempted, Dispatch, Route, Tls};
use tokio::sync::mpsc::UnboundedSender;

use crate::clock::SystemClock;

/// The simulator's domain, which SES's own addresses are at.
pub const DOMAIN: &str = "simulator.amazonses.com";

/// The one route the simulator's domain has, which names no host.
const SIMULATED: &str = "simulator.invalid";

pub struct Simulator {
    pub scheduler: UnboundedSender<engine_scheduler::Input>,
    /// The IDs of the complaint reports it makes.
    pub ids: Mutex<IdGenerator>,
    pub clock: Arc<SystemClock>,
}

/// What the simulator does with one address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    Delivered,
    Complained,
    Unknown,
    Suppressed,
}

impl Simulator {
    /// Tells the scheduler the simulator's own route, without a lookup, if
    /// `domain` is the simulator's, and says whether it was.
    pub fn resolve(&self, domain: &str) -> bool {
        if !domain.eq_ignore_ascii_case(DOMAIN) {
            return false;
        }
        let _ = self.scheduler.send(engine_scheduler::Input::Resolved {
            domain: domain.into(),
            route: Route::Exchanges(vec![SIMULATED.to_owned()], Tls::default()),
            ttl: Duration::from_secs(86_400),
        });
        true
    }

    /// Whether `dispatch` goes to the simulator.
    pub fn takes(dispatch: &Dispatch) -> bool {
        dispatch
            .exchanges
            .first()
            .is_some_and(|exchange| exchange == SIMULATED)
    }

    /// Ends each of a transaction's deliveries as its address does at SES,
    /// those that complain with their complaint.
    pub fn dispatch(&self, dispatch: Dispatch) {
        for (permit, recipient) in dispatch.recipients {
            let outcome = outcome(&recipient);
            // As SES's simulator answers, word for word (its fixtures).
            let (result, evidence) = match outcome {
                Outcome::Delivered | Outcome::Complained => {
                    (Attempted::Delivered, Evidence::new(250, "Ok"))
                }
                Outcome::Unknown => (
                    Attempted::Rejected,
                    Evidence::new(
                        550,
                        &format!("5.1.1 As requested: user unknown <{}>", recipient.as_str()),
                    ),
                ),
                Outcome::Suppressed => (
                    Attempted::Rejected,
                    Evidence::new(
                        550,
                        &format!(
                            "5.1.1 As requested: user unknown (suppressed address: {})",
                            recipient.as_str()
                        ),
                    ),
                ),
            };
            let feedback = (outcome == Outcome::Complained)
                .then(|| Box::new(self.complaint(dispatch.message, recipient)));
            // No verdict: a simulated refusal rules nothing out.
            let _ = self.scheduler.send(engine_scheduler::Input::Finished {
                permit,
                result,
                evidence: Some(evidence),
                verdict: None,
                feedback,
                replied: None,
            });
        }
    }

    /// The complaint of abuse a recipient makes of a message, as a feedback
    /// report (RFC 5965) the store records with its event.
    fn complaint(&self, message: engine_core::id::MessageId, recipient: Address) -> Report {
        let now = self.clock.now().wall;
        let id = ReportId(
            self.ids
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .next(now),
        );
        // One complaint of a message at an address, however often it is
        // tried: each of its deliveries there takes it once, with its own
        // outcome.
        let mut identity = [0u8; 32];
        let digest = aws_lc_rs::digest::digest(
            &aws_lc_rs::digest::SHA256,
            format!(
                "simulator complaint {} {}",
                message.0.as_u64(),
                suppression::key(&recipient)
            )
            .as_bytes(),
        );
        identity.copy_from_slice(digest.as_ref());
        Report {
            id,
            message: Some(message),
            kind: Kind::Feedback("abuse".to_owned()),
            recipients: vec![Claim {
                address: recipient,
                failed: false,
                status: None,
                rules_out_address: false,
                diagnostic: None,
            }],
            identity,
            evidence: Bytes::from_static(
                b"Content-Type: message/feedback-report\r\n\r\nFeedback-Type: abuse\r\nUser-Agent: the mailbox simulator\r\nVersion: 1\r\n",
            ),
            received_at: now,
            authenticated: false,
            trusted: true,
            simulated: true,
        }
    }
}

/// What the simulator does with `recipient`: by its local part, a label
/// after `+` aside, whatever its case.
fn outcome(recipient: &Address) -> Outcome {
    let local = recipient
        .as_str()
        .rsplit_once('@')
        .map_or("", |(local, _)| local);
    let local = local.split_once('+').map_or(local, |(local, _)| local);
    match local.to_ascii_lowercase().as_str() {
        "success" | "ooto" => Outcome::Delivered,
        "complaint" => Outcome::Complained,
        "suppressionlist" => Outcome::Suppressed,
        _ => Outcome::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_address_ends_as_ses_ends_it_whatever_its_label() {
        let of = |address: &str| outcome(&Address::parse(address).unwrap());
        assert_eq!(of("success@simulator.amazonses.com"), Outcome::Delivered);
        assert_eq!(
            of("success+order-7@simulator.amazonses.com"),
            Outcome::Delivered
        );
        assert_eq!(of("OOTO@simulator.amazonses.com"), Outcome::Delivered);
        assert_eq!(of("bounce+x@simulator.amazonses.com"), Outcome::Unknown);
        assert_eq!(of("complaint@simulator.amazonses.com"), Outcome::Complained);
        assert_eq!(
            of("suppressionlist@simulator.amazonses.com"),
            Outcome::Suppressed
        );
        assert_eq!(of("anyone@simulator.amazonses.com"), Outcome::Unknown);
    }
}
