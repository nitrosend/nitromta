//! What the feedback listener takes, and what it makes of each report it
//! takes. It takes mail only for the return paths the engine
//! issued and for its operator's complaint-loop addresses; anything else
//! is relay, refused before the report is sent.

use std::sync::Arc;

use aws_lc_rs::digest;
use engine_core::address::Address;
use engine_core::feedback::{Claim, Kind, MAX_EVIDENCE_BYTES, Report, Trust};
use engine_core::id::{MessageId, ReportId};
use engine_core::time::Timestamp;
use engine_rules::Rules;

use crate::report::{self, Action};
use crate::token::{self, Key};

pub struct Intake {
    /// The key return paths are made with now, then those they were made
    /// with before a rotation, whose mail may still bounce.
    keys: Vec<Key>,
    /// The return path's domain, in lowercase.
    domain: String,
    /// Whether a return path may also be at another domain, in lowercase:
    /// an identity's own MAIL FROM domain.
    also_at: Arc<dyn Fn(&str) -> bool + Send + Sync>,
    /// The complaint-loop addresses, in lowercase.
    loops: Vec<String>,
    /// What a report's statuses say of each address.
    rules: Arc<Rules>,
    /// The least class of evidence whose reports suppress and count.
    trusting: Trust,
}

impl Intake {
    /// For return paths at `domain` made with any of `keys`, the current
    /// first, and the complaint loops that send to `loops`, judging statuses
    /// by `rules`.
    pub fn new(keys: Vec<Key>, domain: &str, loops: &[Address], rules: Arc<Rules>) -> Self {
        Self {
            keys,
            domain: domain.to_ascii_lowercase(),
            also_at: Arc::new(|_| false),
            loops: loops
                .iter()
                .map(|address| address.as_str().to_ascii_lowercase())
                .collect(),
            rules,
            trusting: Trust::default(),
        }
    }

    /// As it is, letting only reports of `trusting`'s class or above
    /// suppress and count.
    pub fn trusting(self, trusting: Trust) -> Self {
        Self { trusting, ..self }
    }

    /// The least class whose reports suppress and count.
    pub fn trusts(&self) -> Trust {
        self.trusting
    }

    /// As it is, taking return paths at the other domains `also_at` says it
    /// may, as well as its own.
    pub fn also_at(self, also_at: impl Fn(&str) -> bool + Send + Sync + 'static) -> Self {
        Self {
            also_at: Arc::new(also_at),
            ..self
        }
    }

    /// Whether it takes mail for `recipient`.
    pub fn takes(&self, recipient: &Address) -> bool {
        self.message_of(recipient.as_str()).is_some()
            || self
                .loops
                .contains(&recipient.as_str().to_ascii_lowercase())
    }

    /// The report `content`, received for `recipients`, as the store records
    /// it; `authenticated` if a reporter the operator enrolled with signed
    /// it, as the shell verified. A delivery status notification names its
    /// message by the return path it was sent to; a feedback report, sent to
    /// a complaint loop, by the return path of the message it carries.
    pub fn report(
        &self,
        id: ReportId,
        recipients: &[Address],
        content: &[u8],
        received_at: Timestamp,
        authenticated: bool,
    ) -> Report {
        let read = report::read(content);
        let message = recipients
            .iter()
            .find_map(|recipient| self.message_of(recipient.as_str()))
            .or_else(|| {
                read.return_path
                    .as_deref()
                    .and_then(|path| self.message_of(path))
            });
        let kind = match read.kind {
            report::Kind::DeliveryStatus => Kind::DeliveryStatus,
            report::Kind::Feedback { feedback_type } => Kind::Feedback(feedback_type),
            report::Kind::Unrecognised => Kind::Unrecognised,
        };
        let claims: Vec<Claim> = read
            .recipients
            .iter()
            .filter_map(|reported| {
                let failed = reported.action == Action::Failed;
                Some(Claim {
                    address: Address::parse(&reported.address).ok()?,
                    failed,
                    status: reported.status,
                    rules_out_address: failed
                        && reported
                            .status
                            .is_some_and(|status| self.rules.rules_out_address(status)),
                    diagnostic: reported.diagnostic.clone(),
                })
            })
            .collect();
        let identity = identity(read.id.as_deref(), message, &kind);
        let kept = content.len().min(MAX_EVIDENCE_BYTES);
        Report {
            id,
            message,
            kind,
            recipients: claims,
            identity,
            evidence: bytes::Bytes::copy_from_slice(&content[..kept]),
            received_at,
            authenticated,
            trusted: match self.trusting {
                Trust::Correlated => true,
                Trust::Authenticated => authenticated,
            },
            simulated: false,
        }
    }

    /// The message a return path's token names, if the path is at the
    /// return path's domain, or another it may be at, and its token is one
    /// the engine issued.
    fn message_of(&self, path: &str) -> Option<MessageId> {
        let (local, domain) = path.rsplit_once('@')?;
        let domain = domain.to_ascii_lowercase();
        if domain != self.domain && !(self.also_at)(&domain) {
            return None;
        }
        self.keys.iter().find_map(|key| token::message(key, local))
    }
}

/// What makes a report the same as one received before, whenever it
/// arrives: its reporter's ID, the message it names and its
/// kind. What it says of a recipient is not part of it, so the same report
/// sent again with a status revised changes nothing it has done.
fn identity(reporter_id: Option<&str>, message: Option<MessageId>, kind: &Kind) -> [u8; 32] {
    let mut context = digest::Context::new(&digest::SHA256);
    let mut field = |bytes: &[u8]| {
        context.update(&(bytes.len() as u64).to_be_bytes());
        context.update(bytes);
    };
    field(reporter_id.unwrap_or_default().as_bytes());
    field(
        &message
            .map_or(0, |message| message.0.as_u64())
            .to_be_bytes(),
    );
    match kind {
        Kind::DeliveryStatus => field(b"delivery-status"),
        Kind::Feedback(feedback_type) => field(format!("feedback {feedback_type}").as_bytes()),
        Kind::Unrecognised => field(b"unrecognised"),
    }
    let mut identity = [0; 32];
    identity.copy_from_slice(context.finish().as_ref());
    identity
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine_core::id::Id;

    fn intake() -> Intake {
        Intake::new(
            vec![Key::new(b"the installation's secret")],
            "Bounces.Example.Test",
            &[Address::parse("fbl@example.test").unwrap()],
            Arc::new(Rules::new(&std::collections::BTreeMap::new()).unwrap()),
        )
    }

    fn message(value: u64) -> MessageId {
        MessageId(Id::from_u64(value).unwrap())
    }

    fn return_path(intake: &Intake, message: MessageId) -> Address {
        let local = token::local_part(&intake.keys[0], message);
        Address::parse(&format!("{local}@bounces.example.test")).unwrap()
    }

    fn report_id(value: u64) -> ReportId {
        ReportId(Id::from_u64(value).unwrap())
    }

    const BOUNCE: &str = "Message-ID: <r1@mx.example.net>\r\n\
Content-Type: multipart/report; report-type=delivery-status; boundary=b\r\n\
\r\n\
--b\r\n\
Content-Type: message/delivery-status\r\n\
\r\n\
Reporting-MTA: dns; mx.example.net\r\n\
\r\n\
Final-Recipient: rfc822; gone@example.net\r\n\
Action: failed\r\n\
Status: 5.1.1\r\n\
\r\n\
--b--\r\n";

    #[test]
    fn a_return_path_made_before_a_rotation_is_taken_while_its_key_is_kept() {
        let before = Key::new(b"the secret before the rotation");
        let made = token::local_part(&before, message(1 << 40));
        let path = Address::parse(&format!("{made}@bounces.example.test")).unwrap();
        let rules = || Arc::new(Rules::new(&std::collections::BTreeMap::new()).unwrap());
        let rotated = |keys| Intake::new(keys, "bounces.example.test", &[], rules());
        let current = || Key::new(b"the installation's secret");
        assert!(rotated(vec![current(), before]).takes(&path));
        assert!(!rotated(vec![current()]).takes(&path));
    }

    #[test]
    fn it_takes_only_its_return_paths_and_loops() {
        let intake = intake();
        assert!(intake.takes(&return_path(&intake, message(1 << 40))));
        assert!(intake.takes(&Address::parse("FBL@example.test").unwrap()));
        for refused in [
            "someone@example.test",
            "postmaster@bounces.example.test",
            "b0000010000000000-00112233445566778899@bounces.example.test",
        ] {
            assert!(
                !intake.takes(&Address::parse(refused).unwrap()),
                "{refused}"
            );
        }
        // A token the engine issued, at another domain, is not a return path,
        // unless it is a domain the intake may also take, as an identity's
        // MAIL FROM domain is.
        let local = token::local_part(&intake.keys[0], message(1 << 40));
        let at = |domain: &str| Address::parse(&format!("{local}@{domain}")).unwrap();
        assert!(!intake.takes(&at("example.org")));
        let also = intake.also_at(|domain| domain == "bounces.customer.test");
        assert!(also.takes(&at("Bounces.Customer.test")));
        assert!(!also.takes(&at("example.org")));
    }

    #[test]
    fn a_bounce_names_its_message_by_the_return_path_it_came_to() {
        let intake = intake();
        let to = return_path(&intake, message(1 << 40));
        let report = intake.report(
            report_id(9),
            &[to],
            BOUNCE.as_bytes(),
            Timestamp::from_micros(5),
            false,
        );
        assert_eq!(report.message, Some(message(1 << 40)));
        assert_eq!(report.kind, Kind::DeliveryStatus);
        assert_eq!(report.recipients.len(), 1);
        assert!(report.recipients[0].failed);
        assert!(
            report.recipients[0].rules_out_address,
            "a failure with 5.1.1, by the receiver rules"
        );
        let full = intake.report(
            report_id(13),
            &[return_path(&intake, message(1 << 40))],
            BOUNCE.replace("5.1.1", "5.2.2").as_bytes(),
            Timestamp::from_micros(5),
            false,
        );
        assert!(!full.recipients[0].rules_out_address, "a full mailbox");
        assert_eq!(report.evidence.as_ref(), BOUNCE.as_bytes());
        // The same report again, at another time and under another ID, is
        // the same report; about another message, it is not.
        let to = return_path(&intake, message(1 << 40));
        let again = intake.report(
            report_id(10),
            &[to],
            BOUNCE.as_bytes(),
            Timestamp::from_micros(7),
            false,
        );
        assert_eq!(again.identity, report.identity);
        let other = return_path(&intake, message(2 << 40));
        let elsewhere = intake.report(
            report_id(11),
            &[other],
            BOUNCE.as_bytes(),
            Timestamp::from_micros(7),
            false,
        );
        assert_ne!(elsewhere.identity, report.identity);
    }

    #[test]
    fn a_complaint_names_its_message_by_the_return_path_it_carries() {
        let intake = intake();
        let path = return_path(&intake, message(3 << 40));
        let complaint = format!(
            "Content-Type: multipart/report; report-type=feedback-report; boundary=b\r\n\
\r\n\
--b\r\n\
Content-Type: message/feedback-report\r\n\
\r\n\
Feedback-Type: abuse\r\n\
Original-Mail-From: <{}>\r\n\
\r\n\
--b--\r\n",
            path.as_str()
        );
        let to = Address::parse("fbl@example.test").unwrap();
        let report = intake.report(
            report_id(12),
            &[to],
            complaint.as_bytes(),
            Timestamp::from_micros(5),
            false,
        );
        assert_eq!(report.message, Some(message(3 << 40)));
        assert_eq!(report.kind, Kind::Feedback("abuse".to_owned()));
        assert!(report.recipients.is_empty(), "the recipient was redacted");
        assert!(
            report.trusted && !report.authenticated,
            "correlated, trusted by default"
        );
        // Trusting only authenticated reports, an unsigned one changes
        // nothing; a signed one does.
        let strict = intake.trusting(Trust::Authenticated);
        let to = || Address::parse("fbl@example.test").unwrap();
        let at = Timestamp::from_micros(5);
        let unsigned = strict.report(report_id(14), &[to()], complaint.as_bytes(), at, false);
        assert!(!unsigned.trusted);
        let signed = strict.report(report_id(15), &[to()], complaint.as_bytes(), at, true);
        assert!(signed.trusted && signed.authenticated);
    }

    #[test]
    fn evidence_is_kept_to_its_limit() {
        let intake = intake();
        let large = vec![b'x'; MAX_EVIDENCE_BYTES + 100];
        let report = intake.report(report_id(13), &[], &large, Timestamp::from_micros(5), false);
        assert_eq!(report.evidence.len(), MAX_EVIDENCE_BYTES);
        assert_eq!(report.message, None);
        assert_eq!(report.kind, Kind::Unrecognised);
    }
}
