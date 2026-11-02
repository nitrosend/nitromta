//! SES's shape: a journal entry as SES publishes the event
//! to an SNS destination, with the `mail` object its message's kept copy
//! gives. Accepted is `Send`; an attempt delivered, or captured, is
//! `Delivery`; deferred, `DeliveryDelay`, its type by what said so (a full
//! mailbox, the receiver's reply, the engine's own hold, its own account of
//! a connection that went no further); refused for good, or a report that it bounced,
//! `Bounce`, `Permanent` for a 5.x.x status and `Transient` for a 4.x.x one,
//! with the status the reply or report gave, and `Undetermined` twice over
//! for neither; expired, `Bounce`, `Transient`; suppressed, `Bounce`,
//! `Permanent`, `OnAccountSuppressionList`; a complaint, `Complaint`. An
//! uncertain attempt and a cancelled delivery have no SES name, and are not
//! rendered.

use std::collections::BTreeMap;

use engine_core::address;
use engine_core::attempt::Evidence;
use engine_core::command::{Mailed, Owed};
use engine_core::id::{AccountId, MessageId};
use engine_core::journal::Entry;
use engine_core::status::Status;
use engine_core::time::Timestamp;
use serde_json::{Map, Value, json};

use crate::render::{hex, rfc3339};

/// The event `entry`, at `position`, as SES publishes it for `account`: its
/// JSON, and its type. None for an entry SES has no event for, or whose
/// recipient is no longer known.
pub fn event(
    position: u64,
    entry: &Entry,
    owed: &Owed,
    account: AccountId,
) -> Option<(String, &'static str)> {
    let feedback_id = format!("{position:016x}");
    let recipient = |delivery| owed.deliveries.get(delivery);
    let (kind, message, at, detail): (&'static str, MessageId, Timestamp, Value) = match entry {
        Entry::Accepted { message, at, .. } => ("Send", *message, *at, json!({})),
        Entry::Attempted {
            attempt, evidence, ..
        } => {
            let ended = attempt.ended?;
            let (message, address) = recipient(&attempt.delivery)?;
            let evidence = evidence.as_ref();
            let detail = match ended.result {
                engine_core::attempt::AttemptResult::Delivered
                | engine_core::attempt::AttemptResult::Captured => {
                    let accepted_at = owed
                        .mailed
                        .get(message)
                        .map_or(ended.at, |mailed| mailed.accepted_at);
                    let processing = ended.at.saturating_duration_since(accepted_at);
                    (
                        "Delivery",
                        json!({
                            "timestamp": rfc3339(ended.at),
                            "processingTimeMillis": u64::try_from(processing.as_millis()).unwrap_or(u64::MAX),
                            "recipients": [address.as_str()],
                            "smtpResponse": evidence.map(reply).unwrap_or_default(),
                        }),
                    )
                }
                engine_core::attempt::AttemptResult::Deferred => (
                    "DeliveryDelay",
                    json!({
                        "timestamp": rfc3339(ended.at),
                        "delayType": delay_type(evidence),
                        "delayedRecipients": [recipient_json(address.as_str(), evidence)],
                    }),
                ),
                engine_core::attempt::AttemptResult::Rejected => {
                    // The reply's status says how permanent, else its code.
                    let class = evidence.and_then(|evidence| {
                        Status::parse(&evidence.text)
                            .map(|status| u16::from(status.class))
                            .or((!evidence.is_local()).then_some(evidence.code / 100))
                    });
                    let detail = bounce(
                        bounce_type(class),
                        "General",
                        recipient_json(address.as_str(), evidence),
                        ended.at,
                        &feedback_id,
                    );
                    ("Bounce", detail)
                }
                engine_core::attempt::AttemptResult::Uncertain
                | engine_core::attempt::AttemptResult::Abandoned => return None,
            };
            let (kind, detail) = detail;
            (kind, *message, ended.at, detail)
        }
        Entry::Expired { delivery, at, .. } => {
            let (message, address) = recipient(delivery)?;
            let detail = bounce(
                "Transient",
                "General",
                recipient_json(address.as_str(), None),
                *at,
                &feedback_id,
            );
            ("Bounce", *message, *at, detail)
        }
        Entry::Suppressed { delivery, at, .. } => {
            let (message, address) = recipient(delivery)?;
            let detail = bounce(
                "Permanent",
                "OnAccountSuppressionList",
                json!({
                    "emailAddress": address.as_str(),
                    "action": "failed",
                    "diagnosticCode": "Amazon SES did not send the message to this address because it is on the suppression list for your account.",
                }),
                *at,
                &feedback_id,
            );
            ("Bounce", *message, *at, detail)
        }
        Entry::Bounced {
            delivery,
            status,
            at,
            ..
        } => {
            let (message, address) = recipient(delivery)?;
            let mut recipient = recipient_json(address.as_str(), None);
            if let Some(status) = status {
                recipient["status"] = json!(status.to_string());
                if status.class == 5 {
                    recipient["action"] = json!("failed");
                }
            }
            let detail = bounce(
                bounce_type(status.map(|status| u16::from(status.class))),
                "General",
                recipient,
                *at,
                &feedback_id,
            );
            ("Bounce", *message, *at, detail)
        }
        Entry::Complained {
            delivery,
            feedback_type,
            at,
            ..
        } => {
            let (message, address) = recipient(delivery)?;
            let detail = json!({
                "feedbackId": feedback_id,
                "complaintSubType": null,
                "complainedRecipients": [{"emailAddress": address.as_str()}],
                "timestamp": rfc3339(*at),
                "complaintFeedbackType": feedback_type,
            });
            ("Complaint", *message, *at, detail)
        }
        Entry::Cancelled { .. } => return None,
    };
    let mut event = Map::new();
    event.insert("eventType".to_owned(), json!(kind));
    event.insert(
        "mail".to_owned(),
        mail(message, owed.mailed.get(&message), account, at),
    );
    let key = match kind {
        "Send" => "send",
        "Delivery" => "delivery",
        "DeliveryDelay" => "deliveryDelay",
        "Bounce" => "bounce",
        _ => "complaint",
    };
    event.insert(key.to_owned(), detail);
    Some((Value::Object(event).to_string(), kind))
}

/// SES's bounce type for a status's or reply's class.
fn bounce_type(class: Option<u16>) -> &'static str {
    match class {
        Some(5) => "Permanent",
        Some(4) => "Transient",
        _ => "Undetermined",
    }
}

/// SES's bounce object, for one recipient. A bounce of an undetermined
/// type has an undetermined subtype, as SES pairs them.
fn bounce(kind: &str, subtype: &str, recipient: Value, at: Timestamp, feedback_id: &str) -> Value {
    let subtype = if kind == "Undetermined" {
        "Undetermined"
    } else {
        subtype
    };
    json!({
        "feedbackId": feedback_id,
        "bounceType": kind,
        "bounceSubType": subtype,
        "bouncedRecipients": [recipient],
        "timestamp": rfc3339(at),
    })
}

/// SES's delay type for a deferral, by what said so: a full mailbox, the
/// receiver's reply of any other kind, the engine's own hold, its own
/// account of a connection that went no further, or nothing at all.
fn delay_type(evidence: Option<&Evidence>) -> &'static str {
    match evidence {
        None => "Undetermined",
        Some(evidence) if evidence.code == Evidence::HELD => "SendingDeferral",
        Some(evidence) if evidence.is_local() => "TransientCommunicationFailure",
        Some(evidence)
            if Status::parse(&evidence.text)
                .is_some_and(|status| (status.subject, status.detail) == (2, 2)) =>
        {
            "MailboxFull"
        }
        Some(_) => "RecipientServerError",
    }
}

/// What a receiver said, as SES gives it: its code and its text; the
/// engine's own account, its text alone.
fn reply(evidence: &Evidence) -> String {
    if evidence.is_local() {
        evidence.text.clone()
    } else {
        format!("{} {}", evidence.code, evidence.text)
    }
}

/// A recipient as a bounce or delay names it, with what its receiver
/// said, if anything: its enhanced status, and whether it failed for good.
fn recipient_json(address: &str, evidence: Option<&Evidence>) -> Value {
    let mut recipient = Map::new();
    recipient.insert("emailAddress".to_owned(), json!(address));
    if let Some(evidence) = evidence {
        let status = Status::parse(&evidence.text);
        let permanent = status.map_or(!evidence.is_local() && evidence.code >= 500, |status| {
            status.class == 5
        });
        if permanent {
            recipient.insert("action".to_owned(), json!("failed"));
        }
        if let Some(status) = status {
            recipient.insert("status".to_owned(), json!(status.to_string()));
        }
        recipient.insert(
            "diagnosticCode".to_owned(),
            json!(format!("smtp; {}", reply(evidence))),
        );
    }
    Value::Object(recipient)
}

/// SES's `mail` object: what was kept of the message, or, if nothing was,
/// its ID and when the event happened.
fn mail(message: MessageId, mailed: Option<&Mailed>, account: AccountId, at: Timestamp) -> Value {
    let mut object = Map::new();
    let accepted_at = mailed.map_or(at, |mailed| mailed.accepted_at);
    object.insert("timestamp".to_owned(), json!(rfc3339(accepted_at)));
    object.insert("messageId".to_owned(), json!(hex(message.0)));
    object.insert(
        "sendingAccountId".to_owned(),
        json!(format!("{:012}", account.0.as_u64())),
    );
    if let Some(mail) = mailed.and_then(|mailed| mailed.mail.as_ref()) {
        object.insert("source".to_owned(), json!(mail.source));
        object.insert("destination".to_owned(), json!(mail.destination));
        object.insert("headersTruncated".to_owned(), json!(mail.truncated));
        let headers = fields(&mail.headers);
        object.insert(
            "headers".to_owned(),
            Value::Array(
                headers
                    .iter()
                    .map(|(name, value)| json!({"name": name, "value": value}))
                    .collect(),
            ),
        );
        object.insert("commonHeaders".to_owned(), common(&headers, message));
        let mut tags: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for (name, value) in &mail.tags {
            tags.entry(name).or_default().push(value);
        }
        object.insert("tags".to_owned(), json!(tags));
    }
    Value::Object(object)
}

/// A header block's fields, each its name and its value unfolded.
fn fields(block: &[u8]) -> Vec<(String, String)> {
    let text = String::from_utf8_lossy(block);
    let mut fields: Vec<(String, String)> = Vec::new();
    for line in text.split("\r\n").filter(|line| !line.is_empty()) {
        if line.starts_with([' ', '\t']) {
            if let Some((_, value)) = fields.last_mut() {
                value.push(' ');
                value.push_str(line.trim());
            }
        } else if let Some((name, value)) = line.split_once(':') {
            fields.push((name.to_owned(), value.trim().to_owned()));
        }
    }
    fields
}

/// SES's `commonHeaders`: From, To, Cc, Reply-To, Date and Subject, as the
/// header block gives them, each mailbox of a list whole; and the message's
/// ID, the one its send was answered with, as SES gives its own.
fn common(headers: &[(String, String)], message: MessageId) -> Value {
    let named = |name: &str| {
        headers
            .iter()
            .find(|(field, _)| field.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    };
    let list = |name: &str| {
        named(name).map(|value| {
            address::list_members(value.as_bytes())
                .unwrap_or_default()
                .into_iter()
                .filter_map(|member| std::str::from_utf8(member).ok())
                .map(str::trim)
                .collect::<Vec<_>>()
        })
    };
    let mut common = Map::new();
    for (key, name) in [
        ("from", "From"),
        ("to", "To"),
        ("cc", "Cc"),
        ("replyTo", "Reply-To"),
    ] {
        if let Some(items) = list(name) {
            common.insert(key.to_owned(), json!(items));
        }
    }
    for (key, name) in [("date", "Date"), ("subject", "Subject")] {
        if let Some(value) = named(name) {
            common.insert(key.to_owned(), json!(value));
        }
    }
    common.insert("messageId".to_owned(), json!(hex(message.0)));
    Value::Object(common)
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use engine_core::address::Address;
    use engine_core::id::{DeliveryId, Id, ReportId};
    use engine_core::message::Mail;

    use super::*;

    fn id(value: u64) -> Id {
        Id::from_u64(value).unwrap()
    }

    #[test]
    fn a_bounce_suppression_and_complaint_read_as_nitrosends_adapter_reads_them() {
        let message = MessageId(id(1 << 40));
        let delivery = DeliveryId(id((1 << 40) + 2));
        let account = AccountId(id(1));
        let at = Timestamp::from_micros(1_800_000_000_000_000);
        let mail = Mail {
            source: "news@brand.test".to_owned(),
            destination: vec!["ann@example.com".to_owned()],
            headers: Bytes::from_static(
                b"From: news@brand.test\r\nTo: \"Last, First\" <ann@example.com>, Team: bo@example.com (Bo);\r\nSubject: Autumn\r\n\tsale\r\nX-Nitro-Message: m-7\r\nMessage-ID: <theirs@brand.test>\r\n",
            ),
            truncated: false,
            tags: vec![
                ("message_id".to_owned(), "m-7".to_owned()),
                ("ses:configuration-set".to_owned(), "cohort-a".to_owned()),
            ],
        };
        let owed = Owed {
            entries: Vec::new(),
            deliveries: BTreeMap::from([(
                delivery,
                (message, Address::parse("ann@example.com").unwrap()),
            )]),
            mailed: BTreeMap::from([(
                message,
                Mailed {
                    accepted_at: at,
                    mail: Some(mail),
                },
            )]),
            through: 0,
            failing_since: None,
        };
        let render = |entry: &Entry| -> Value {
            serde_json::from_str(&event(9, entry, &owed, account).unwrap().0).unwrap()
        };
        let complaint = render(&Entry::Complained {
            delivery,
            account,
            configuration: None,
            report: ReportId(id(5)),
            feedback_type: "abuse".to_owned(),
            authenticated: false,
            at,
        });
        assert_eq!(complaint["eventType"], "Complaint");
        assert_eq!(
            complaint["complaint"]["complainedRecipients"][0]["emailAddress"],
            "ann@example.com"
        );
        assert_eq!(complaint["complaint"]["complaintFeedbackType"], "abuse");
        assert_eq!(complaint["mail"]["messageId"], "0000010000000000");
        assert_eq!(complaint["mail"]["sendingAccountId"], "000000000001");
        assert_eq!(complaint["mail"]["tags"]["message_id"], json!(["m-7"]));
        assert_eq!(
            complaint["mail"]["headers"][3],
            json!({"name": "X-Nitro-Message", "value": "m-7"})
        );
        assert_eq!(complaint["mail"]["commonHeaders"]["subject"], "Autumn sale");
        // Each mailbox whole, a group's members its own; the message's ID
        // the engine's, as the send was answered, its own header kept.
        assert_eq!(
            complaint["mail"]["commonHeaders"]["to"],
            json!(["\"Last, First\" <ann@example.com>", "bo@example.com (Bo)"])
        );
        assert_eq!(
            complaint["mail"]["commonHeaders"]["messageId"],
            "0000010000000000"
        );
        assert_eq!(
            complaint["mail"]["headers"][4],
            json!({"name": "Message-ID", "value": "<theirs@brand.test>"})
        );
        let suppressed = render(&Entry::Suppressed {
            delivery,
            account,
            configuration: None,
            at,
        });
        assert_eq!(suppressed["bounce"]["bounceType"], "Permanent");
        assert_eq!(
            suppressed["bounce"]["bounceSubType"],
            "OnAccountSuppressionList"
        );
        let reported = render(&Entry::Bounced {
            delivery,
            account,
            configuration: None,
            report: ReportId(id(6)),
            status: engine_core::status::Status::parse("5.1.1"),
            authenticated: false,
            at,
        });
        assert_eq!(reported["bounce"]["bounceType"], "Permanent");
        assert_eq!(
            reported["bounce"]["bouncedRecipients"][0]["status"],
            "5.1.1"
        );
        // A report without a status: undetermined, both.
        let undetermined = render(&Entry::Bounced {
            delivery,
            account,
            configuration: None,
            report: ReportId(id(7)),
            status: None,
            authenticated: false,
            at,
        });
        assert_eq!(undetermined["bounce"]["bounceType"], "Undetermined");
        assert_eq!(undetermined["bounce"]["bounceSubType"], "Undetermined");
        // A refusal's enhanced status; a deferral's kind, by what said so.
        let attempt = |result, evidence: Option<Evidence>| Entry::Attempted {
            attempt: engine_core::attempt::Attempt {
                id: engine_core::id::AttemptId(id(8)),
                delivery,
                account,
                reserved_at: at,
                ended: Some(engine_core::attempt::AttemptEnd { result, at }),
            },
            configuration: None,
            evidence,
        };
        let refused = render(&attempt(
            engine_core::attempt::AttemptResult::Rejected,
            Some(Evidence::new(550, "5.1.1 user unknown")),
        ));
        let bounced = &refused["bounce"]["bouncedRecipients"][0];
        assert_eq!(refused["bounce"]["bounceType"], "Permanent");
        assert_eq!(bounced["status"], "5.1.1");
        assert_eq!(bounced["action"], "failed");
        assert_eq!(bounced["diagnosticCode"], "smtp; 550 5.1.1 user unknown");
        let delayed = |evidence| {
            render(&attempt(
                engine_core::attempt::AttemptResult::Deferred,
                evidence,
            ))["deliveryDelay"]["delayType"]
                .clone()
        };
        assert_eq!(
            delayed(Some(Evidence::new(452, "4.2.2 mailbox full"))),
            "MailboxFull"
        );
        assert_eq!(
            delayed(Some(Evidence::new(451, "4.3.0 try later"))),
            "RecipientServerError"
        );
        assert_eq!(
            delayed(Some(Evidence::local("the exchange refused the connection"))),
            "TransientCommunicationFailure"
        );
        assert_eq!(
            delayed(Some(Evidence::held("held by the dispatch hook: later"))),
            "SendingDeferral"
        );
        assert_eq!(delayed(None), "Undetermined");
        // A message with no copy still says when it was accepted, and how
        // long its delivery took.
        let bare = Owed {
            entries: Vec::new(),
            deliveries: owed.deliveries.clone(),
            mailed: BTreeMap::from([(
                message,
                Mailed {
                    accepted_at: at,
                    mail: None,
                },
            )]),
            through: 0,
            failing_since: None,
        };
        let later = Timestamp::from_micros(1_800_000_002_000_000);
        let delivered = Entry::Attempted {
            attempt: engine_core::attempt::Attempt {
                id: engine_core::id::AttemptId(id(8)),
                delivery,
                account,
                reserved_at: at,
                ended: Some(engine_core::attempt::AttemptEnd {
                    result: engine_core::attempt::AttemptResult::Delivered,
                    at: later,
                }),
            },
            configuration: None,
            evidence: Some(Evidence::new(250, "2.0.0 Ok")),
        };
        let delivered: Value =
            serde_json::from_str(&event(9, &delivered, &bare, account).unwrap().0).unwrap();
        assert_eq!(delivered["delivery"]["processingTimeMillis"], 2_000);
        assert_eq!(delivered["mail"]["timestamp"], rfc3339(at));
        assert!(delivered["mail"].get("headers").is_none());
        // A cancelled delivery has no SES event.
        let cancelled = Entry::Cancelled {
            delivery,
            account,
            configuration: None,
            at,
        };
        assert!(event(9, &cancelled, &owed, account).is_none());

        // Every member SES gives each event, as its fixtures recorded it
        // from real SES (fixtures/ses), the engine gives too, but for those
        // it does not keep yet, named here; and none SES does not. A tag's,
        // a header's and a common header's own members are the message's.
        const NOT_YET: [&str; 10] = [
            "mail.sourceArn",
            "mail.tenant",
            "mail.tenant.tenantName",
            "mail.tenant.tenantId",
            "delivery.remoteMtaIp",
            "delivery.reportingMTA",
            "bounce.remoteMtaIp",
            "bounce.reportingMTA",
            "complaint.userAgent",
            "complaint.arrivalDate",
        ];
        fn paths(value: &Value, at: &str, out: &mut std::collections::BTreeSet<String>) {
            if ["mail.tags", "mail.headers", "mail.commonHeaders"].contains(&at) {
                return;
            }
            match value {
                Value::Object(members) => {
                    for (name, member) in members {
                        let path = if at.is_empty() {
                            name.clone()
                        } else {
                            format!("{at}.{name}")
                        };
                        out.insert(path.clone());
                        paths(member, &path, out);
                    }
                }
                Value::Array(items) => {
                    if let Some(first) = items.first() {
                        paths(first, &format!("{at}[]"), out);
                    }
                }
                _ => {}
            }
        }
        let of = |value: &Value| {
            let mut out = std::collections::BTreeSet::new();
            paths(value, "", &mut out);
            out
        };
        let fixtures: Value =
            serde_json::from_str(include_str!("../../../fixtures/ses/events.json")).unwrap();
        let send = render(&Entry::Accepted {
            message,
            account,
            configuration: None,
            deliveries: vec![delivery],
            at,
        });
        let delivered = render(&attempt(
            engine_core::attempt::AttemptResult::Delivered,
            Some(Evidence::new(250, "Ok")),
        ));
        let bounced = render(&attempt(
            engine_core::attempt::AttemptResult::Rejected,
            Some(Evidence::new(
                550,
                "5.1.1 As requested: user unknown <ann@example.com>",
            )),
        ));
        for (name, ours) in [
            ("send-tenant", send.clone()),
            ("send-success", send),
            ("delivery-success", delivered),
            ("bounce-bounce", bounced),
            ("complaint-complaint", complaint),
        ] {
            let (theirs, ours) = (of(&fixtures[name]), of(&ours));
            let missing: Vec<&String> = theirs
                .difference(&ours)
                .filter(|path| !NOT_YET.contains(&path.as_str()))
                .collect();
            assert!(missing.is_empty(), "{name}: SES gives {missing:?}");
            let extra: Vec<&String> = ours.difference(&theirs).collect();
            assert!(extra.is_empty(), "{name}: SES gives no {extra:?}");
        }
    }
}
