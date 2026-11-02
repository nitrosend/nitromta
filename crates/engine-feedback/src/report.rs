//! What a bounce or complaint report says: delivery status
//! notifications (RFC 3464, and RFC 6533's for SMTPUTF8) and feedback
//! reports (RFC 5965). A report in neither form is unrecognised, though
//! the address it was sent to may still name the message it is about.
//!
//! Reading a report proves nothing about who sent it: correlation and
//! trust are decided apart from it.

use engine_core::status::Status;

use crate::mime::{Entity, parts};

/// The most recipients read from one report: as many as one message may
/// have, so a report about any message the engine sent names them all.
const MAX_RECIPIENTS: usize = engine_core::command::MAX_RECIPIENTS;

/// The most bytes of a diagnostic kept, as an attempt's evidence keeps.
const MAX_DIAGNOSTIC_BYTES: usize = 512;

/// What a report says, as far as its form lets it be read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    pub kind: Kind,
    /// The recipients it reports on, and what it says of each.
    pub recipients: Vec<Reported>,
    /// The envelope sender of the message it is about, from its own copy
    /// of that message, or a feedback report's `Original-Mail-From`.
    pub return_path: Option<String>,
    /// Its `Message-ID`, which a reporter that sends it again repeats.
    pub id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A delivery status notification.
    DeliveryStatus,
    /// A feedback report: a complaint, or another kind its feedback type
    /// names (`abuse`, `fraud`, `not-spam` and the rest), in lowercase.
    Feedback { feedback_type: String },
    /// Neither form.
    Unrecognised,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reported {
    /// As the report gives it.
    pub address: String,
    pub action: Action,
    pub status: Option<Status>,
    /// The receiver's own words, at most [`MAX_DIAGNOSTIC_BYTES`].
    pub diagnostic: Option<String>,
}

/// What became of a recipient, by a delivery status notification's
/// `Action` (RFC 3464, 2.3.3). A feedback report's recipients have none.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Failed,
    Delayed,
    Delivered,
    Relayed,
    Expanded,
    None,
}

/// Reads `content`, a report as it arrived.
pub fn read(content: &[u8]) -> Report {
    let top = Entity::read(content);
    let id = top.field("message-id").map(angle_free);
    let content_type = top.content_type();
    let unrecognised = Report {
        kind: Kind::Unrecognised,
        recipients: Vec::new(),
        return_path: None,
        id: id.clone(),
    };
    let Some(boundary) = content_type.parameter("boundary") else {
        return unrecognised;
    };
    if content_type.kind != "multipart/report" {
        return unrecognised;
    }
    let mut report = Report { id, ..unrecognised };
    let mut kind = None;
    for part in parts(top.body, boundary) {
        let entity = Entity::read(part);
        let decoded = entity.decoded();
        match entity.content_type().kind.as_str() {
            "message/delivery-status" | "message/global-delivery-status" => {
                kind.get_or_insert(Kind::DeliveryStatus);
                report.recipients = delivery_status(&decoded);
            }
            "message/feedback-report" => {
                let feedback = Entity::read(&decoded);
                kind.get_or_insert(Kind::Feedback {
                    feedback_type: feedback_type(feedback.field("feedback-type")).to_owned(),
                });
                report.recipients = feedback
                    .every("original-rcpt-to")
                    .take(MAX_RECIPIENTS)
                    .map(|address| Reported {
                        address: angle_free(address),
                        action: Action::None,
                        status: None,
                        diagnostic: None,
                    })
                    .collect();
                if let Some(sender) = feedback.field("original-mail-from") {
                    report.return_path = Some(angle_free(sender));
                }
            }
            "message/rfc822"
            | "message/global"
            | "text/rfc822-headers"
            | "message/global-headers" => {
                let original = Entity::read(&decoded);
                if report.return_path.is_none()
                    && let Some(path) = original.field("return-path")
                {
                    report.return_path = Some(angle_free(path));
                }
            }
            _ => {}
        }
    }
    report.kind = kind.unwrap_or(Kind::Unrecognised);
    report
}

/// The recipients of a `message/delivery-status` body: the field groups
/// after the first, which is about the message (RFC 3464, 2.1).
fn delivery_status(body: &[u8]) -> Vec<Reported> {
    let mut groups = Vec::new();
    let mut group = Vec::new();
    for line in body.split_inclusive(|&byte| byte == b'\n') {
        let blank = line.iter().all(u8::is_ascii_whitespace);
        if blank && !group.is_empty() {
            groups.push(std::mem::take(&mut group));
        } else if !blank {
            group.extend_from_slice(line);
        }
    }
    if !group.is_empty() {
        groups.push(group);
    }
    groups
        .iter()
        .skip(1)
        .filter_map(|group| {
            let fields = Entity::read(group);
            let address = fields
                .field("final-recipient")
                .or_else(|| fields.field("original-recipient"))?;
            Some(Reported {
                address: typed_value(address),
                action: match fields
                    .field("action")
                    .map(str::to_ascii_lowercase)
                    .as_deref()
                {
                    Some(action) if action.starts_with("failed") => Action::Failed,
                    Some(action) if action.starts_with("delayed") => Action::Delayed,
                    Some(action) if action.starts_with("delivered") => Action::Delivered,
                    Some(action) if action.starts_with("relayed") => Action::Relayed,
                    Some(action) if action.starts_with("expanded") => Action::Expanded,
                    _ => Action::None,
                },
                status: fields.field("status").and_then(Status::parse),
                diagnostic: fields
                    .field("diagnostic-code")
                    .map(|code| truncated(&typed_value(code))),
            })
        })
        .take(MAX_RECIPIENTS)
        .collect()
}

/// A typed field's value without its type: `rfc822; a@b` is `a@b`.
fn typed_value(value: &str) -> String {
    let value = value.split_once(';').map_or(value, |(_, value)| value);
    angle_free(value)
}

/// An address without its angle brackets or surrounding space.
fn angle_free(value: &str) -> String {
    let value = value.trim();
    value
        .strip_prefix('<')
        .and_then(|value| value.strip_suffix('>'))
        .unwrap_or(value)
        .trim()
        .to_owned()
}

fn truncated(text: &str) -> String {
    if text.len() <= MAX_DIAGNOSTIC_BYTES {
        return text.to_owned();
    }
    let mut end = MAX_DIAGNOSTIC_BYTES;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

/// A feedback report's type as one of those registered (RFC 5965, 6430,
/// 6591), `other` where it names none, or `unknown`: the field is the
/// reporter's own text, which kept as it came could hold anything, an
/// address included.
fn feedback_type(field: Option<&str>) -> &'static str {
    let Some(field) = field else {
        return "other";
    };
    let field = field.trim();
    [
        "abuse",
        "fraud",
        "virus",
        "other",
        "not-spam",
        "auth-failure",
    ]
    .into_iter()
    .find(|registered| field.eq_ignore_ascii_case(registered))
    .unwrap_or("unknown")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A bounce as Postfix sends one.
    const BOUNCE: &[u8] = b"Return-Path: <>\r\n\
Message-ID: <20261028101500.ABC123@mx.example.net>\r\n\
From: MAILER-DAEMON@mx.example.net (Mail Delivery System)\r\n\
Subject: Undelivered Mail Returned to Sender\r\n\
MIME-Version: 1.0\r\n\
Content-Type: multipart/report; report-type=delivery-status;\r\n\
\tboundary=\"ABC123.1761646500/mx.example.net\"\r\n\
\r\n\
This is a MIME-encapsulated message.\r\n\
\r\n\
--ABC123.1761646500/mx.example.net\r\n\
Content-Description: Notification\r\n\
Content-Type: text/plain; charset=us-ascii\r\n\
\r\n\
I'm sorry to have to inform you that your message could not\r\n\
be delivered to one or more recipients.\r\n\
\r\n\
--ABC123.1761646500/mx.example.net\r\n\
Content-Description: Delivery report\r\n\
Content-Type: message/delivery-status\r\n\
\r\n\
Reporting-MTA: dns; mx.example.net\r\n\
X-Postfix-Queue-ID: ABC123\r\n\
Arrival-Date: Tue, 28 Oct 2026 10:14:58 +0000 (UTC)\r\n\
\r\n\
Final-Recipient: rfc822; gone@example.net\r\n\
Original-Recipient: rfc822;gone@example.net\r\n\
Action: failed\r\n\
Status: 5.1.1\r\n\
Remote-MTA: dns; mailstore.example.net\r\n\
Diagnostic-Code: smtp; 550 5.1.1 <gone@example.net>: Recipient address\r\n\
\trejected: User unknown in local recipient table\r\n\
\r\n\
Final-Recipient: rfc822; full@example.net\r\n\
Action: failed\r\n\
Status: 5.2.2\r\n\
\r\n\
--ABC123.1761646500/mx.example.net\r\n\
Content-Description: Undelivered Message Headers\r\n\
Content-Type: text/rfc822-headers\r\n\
\r\n\
Return-Path: <b0000000000001000-00112233445566778899@bounces.example.test>\r\n\
From: Sender <hello@sender.test>\r\n\
Subject: Hello\r\n\
\r\n\
--ABC123.1761646500/mx.example.net--\r\n";

    /// A complaint as a feedback loop sends one (RFC 5965, B.1).
    const COMPLAINT: &[u8] = b"From: <abusedesk@example.com>\r\n\
Date: Thu, 8 Mar 2005 17:40:36 EDT\r\n\
Subject: FW: Earn money\r\n\
To: <abuse@example.net>\r\n\
MIME-Version: 1.0\r\n\
Content-Type: multipart/report; report-type=feedback-report;\r\n\
\tboundary=\"part1_13d.2e68ed54_boundary\"\r\n\
\r\n\
--part1_13d.2e68ed54_boundary\r\n\
Content-Type: text/plain; charset=\"US-ASCII\"\r\n\
Content-Transfer-Encoding: 7bit\r\n\
\r\n\
This is an email abuse report for an email message received from IP\r\n\
192.0.2.1 on Thu, 8 Mar 2005 14:00:00 EDT.\r\n\
\r\n\
--part1_13d.2e68ed54_boundary\r\n\
Content-Type: message/feedback-report\r\n\
\r\n\
Feedback-Type: abuse\r\n\
User-Agent: SomeGenerator/1.0\r\n\
Version: 1\r\n\
Original-Mail-From: <b0000000000002000-aabbccddeeff00112233@bounces.example.test>\r\n\
Original-Rcpt-To: <user@example.com>\r\n\
Arrival-Date: Thu, 8 Mar 2005 14:00:00 EDT\r\n\
Source-IP: 192.0.2.1\r\n\
\r\n\
--part1_13d.2e68ed54_boundary\r\n\
Content-Type: message/rfc822\r\n\
Content-Disposition: inline\r\n\
\r\n\
From: <somespammer@example.net>\r\n\
Received: from mailserver.example.net (mailserver.example.net\r\n\
\t[192.0.2.1]) by example.com with ESMTP id M63d4137594e46;\r\n\
\tThu, 08 Mar 2005 14:00:00 -0400\r\n\
To: <Undisclosed Recipients>\r\n\
Subject: Earn money\r\n\
MIME-Version: 1.0\r\n\
Content-type: text/plain\r\n\
Message-ID: 8787KJKJ3K4J3K4J3K4J3.mail@example.net\r\n\
Date: Thu, 02 Sep 2004 12:31:03 -0500\r\n\
\r\n\
Spam Spam Spam\r\n\
\r\n\
--part1_13d.2e68ed54_boundary--\r\n";

    #[test]
    fn a_bounce_names_each_recipient_and_its_status() {
        let report = read(BOUNCE);
        assert_eq!(report.kind, Kind::DeliveryStatus);
        assert_eq!(
            report.id.as_deref(),
            Some("20261028101500.ABC123@mx.example.net")
        );
        assert_eq!(
            report.return_path.as_deref(),
            Some("b0000000000001000-00112233445566778899@bounces.example.test")
        );
        let [gone, full] = report.recipients.as_slice() else {
            panic!("two recipients: {:?}", report.recipients);
        };
        assert_eq!(gone.address, "gone@example.net");
        assert_eq!(gone.action, Action::Failed);
        assert_eq!(
            gone.status.map(|status| status.to_string()).as_deref(),
            Some("5.1.1")
        );
        assert_eq!(
            gone.diagnostic.as_deref(),
            Some(
                "550 5.1.1 <gone@example.net>: Recipient address rejected: User unknown in local recipient table"
            )
        );
        assert_eq!(full.address, "full@example.net");
        assert_eq!(full.diagnostic, None);
    }

    #[test]
    fn a_bounce_names_every_recipient_a_message_may_have() {
        // A hundred failed recipients in one report, each read, none cut.
        let text = String::from_utf8_lossy(BOUNCE).into_owned();
        let one =
            "Final-Recipient: rfc822; full@example.net\r\nAction: failed\r\nStatus: 5.2.2\r\n\r\n";
        let many: String = (0..100)
            .map(|n| one.replace("full@", &format!("full{n}@")))
            .collect();
        let report = read(text.replace(one, &many).as_bytes());
        assert_eq!(report.recipients.len(), 101);
        assert_eq!(report.recipients[100].address, "full99@example.net");
    }

    #[test]
    fn a_complaint_names_every_recipient_a_message_may_have() {
        let text = String::from_utf8_lossy(COMPLAINT).into_owned();
        let one = "Original-Rcpt-To: <user@example.com>\r\n";
        let many: String = (0..engine_core::command::MAX_RECIPIENTS)
            .map(|n| one.replace("user@", &format!("user{n}@")))
            .collect();
        let report = read(text.replace(one, &many).as_bytes());
        assert_eq!(
            report.recipients.len(),
            engine_core::command::MAX_RECIPIENTS
        );
        assert_eq!(report.recipients[9_999].address, "user9999@example.com");
    }

    #[test]
    fn a_complaint_names_its_type_recipient_and_return_path() {
        let report = read(COMPLAINT);
        assert_eq!(
            report.kind,
            Kind::Feedback {
                feedback_type: "abuse".to_owned()
            }
        );
        assert_eq!(report.recipients.len(), 1);
        assert_eq!(report.recipients[0].address, "user@example.com");
        assert_eq!(report.recipients[0].action, Action::None);
        assert_eq!(
            report.return_path.as_deref(),
            Some("b0000000000002000-aabbccddeeff00112233@bounces.example.test")
        );
        // Its type is one of those registered, whatever the field says: the
        // field's own text is never kept.
        let typed = |field: &str| {
            let complaint = String::from_utf8_lossy(COMPLAINT).replace("abuse\r\n", field);
            match read(complaint.as_bytes()).kind {
                Kind::Feedback { feedback_type } => feedback_type,
                other => panic!("a complaint read as {other:?}"),
            }
        };
        assert_eq!(typed(" Not-Spam \r\n"), "not-spam");
        assert_eq!(typed("ann@example.com\r\n"), "unknown");
        assert_eq!(typed("abusive\r\n"), "unknown");
    }

    #[test]
    fn anything_else_is_unrecognised() {
        for content in [
            &b"Subject: out of office\r\n\r\nI am away.\r\n"[..],
            b"Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n\r\nx\r\n--b--\r\n",
            b"Content-Type: multipart/report; report-type=delivery-status\r\n\r\nno boundary\r\n",
            b"",
        ] {
            let report = read(content);
            assert_eq!(report.kind, Kind::Unrecognised);
            assert!(report.recipients.is_empty());
        }
    }

    #[test]
    fn a_long_diagnostic_is_cut_at_a_character() {
        let long = format!("smtp; 550 {}", "é".repeat(400));
        let kept = truncated(&typed_value(&long));
        assert!(kept.len() <= MAX_DIAGNOSTIC_BYTES);
        assert!(kept.starts_with("550 é"));
    }
}
