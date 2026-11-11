//! How each native record is stored. These layouts are persisted formats,
//! and only grow: a field keeps its number and its meaning for good, a new
//! one is optional, so a row an earlier release wrote reads as it did, and
//! a retired number is never reused. A record's own ID is its row key, not
//! a field. The golden fixtures (`fixtures/formats`) are rows written by the
//! release that added each case, which every later release's tests read.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::Arc;

use engine_core::address::Address;
use engine_core::attempt::{Attempt, AttemptEnd, AttemptResult, Evidence};
use engine_core::budget::{BUCKETS, Counts, Signal, Tally, Window};
use engine_core::command::SiteCooldown;
use engine_core::delivery::{Completion, Delivery, DeliveryRecord, Generation, QueueState};
use engine_core::event::EventKind;
use engine_core::feedback::{Claim, Kind, Report};
use engine_core::id::{
    AccountId, AttemptId, BodyId, ConfigurationId, CredentialId, DeliveryId, DestinationId,
    EgressId, HoldId, Id, IdentityId, MessageId, PoolId, ReportId, SubmissionId, SubscriptionId,
    TemplateId, TenantId, TopicId,
};
use engine_core::journal::Entry;
use engine_core::message::{Mail, Message, PolicyRevision};
use engine_core::policy::{
    Account, Caps, Check, Configuration, Credential, Destination, Egress, Hold, Identity, Judgment,
    Limits, MailFrom, OnMxFailure, Origin, Paused, Permissions, Pool, Record, Scope, Secret,
    Signing, Subscriber, Subscription, Tag, Template, TemplateContent, Tenant, Topic, Verdict,
    Verification, Warmed,
};
use engine_core::status::Status;
use engine_core::sts;
use engine_core::suppression::{Reason, Suppressed};
use engine_core::time::Timestamp;

use crate::codec::{CodecError, Reader, Sealing, Value, Writer};
use crate::keys::{self, Keyring, Keys, Kind as Sealed, Unopened};

const MESSAGE_VERSION: u8 = 1;
mod message_field {
    pub const SUBMISSION: u32 = 1;
    pub const ACCOUNT: u32 = 2;
    pub const TENANT: u32 = 3;
    pub const IDENTITY: u32 = 4;
    pub const BODY: u32 = 5;
    pub const ACCEPTED_AT: u32 = 6;
    pub const POLICY_REVISION: u32 = 7;
    pub const CONFIGURATION: u32 = 8;
    pub const RECIPIENTS: u32 = 9;
}

const MAIL_VERSION: u8 = 1;
mod mail_field {
    pub const SOURCE: u32 = 1;
    /// Each recipient, its length in 4 bytes, big-endian, before it.
    pub const DESTINATION: u32 = 2;
    pub const HEADERS: u32 = 3;
    /// 1 if the header block was longer than what is kept.
    pub const TRUNCATED: u32 = 4;
    /// Each tag's name and value, as policy's tags are packed.
    pub const TAGS: u32 = 5;
}

const DELIVERY_VERSION: u8 = 1;
mod delivery_field {
    pub const MESSAGE: u32 = 1;
    pub const ACCOUNT: u32 = 2;
    pub const RECIPIENT: u32 = 3;
    pub const EXPIRES_AT: u32 = 4;
    pub const GENERATION: u32 = 5;
    pub const ATTEMPTS: u32 = 6;
    pub const UNCERTAIN_ATTEMPTS: u32 = 7;
    /// 0 waiting, 1 in flight, 2 finished, 3 held.
    pub const STATE: u32 = 8;
    pub const DUE_AT: u32 = 9;
    /// The attempt in flight, or the one that finished it.
    pub const ATTEMPT: u32 = 10;
    /// When the attempt in flight was reserved, or the hold parked it.
    pub const SINCE: u32 = 11;
    /// 0 remote accepted, 1 rejected, 2 expired, 3 suppressed, 4 cancelled.
    pub const COMPLETION: u32 = 12;
    pub const FINISHED_AT: u32 = 13;
    /// Its message's origin.
    pub const IDENTITY: u32 = 14;
    pub const TENANT: u32 = 15;
    pub const CONFIGURATION: u32 = 16;
    /// The egress its last reservation chose, absent for the host's own
    /// address.
    pub const EGRESS: u32 = 17;
    /// The journal position of the entry holding what the receiver said
    /// when its last attempt ended without delivering it.
    pub const REPLY_ENTRY: u32 = 18;
}

const COOLDOWN_VERSION: u8 = 1;
mod cooldown_field {
    pub const THROTTLES: u32 = 1;
    /// What the receiver said when it began: its code and text, and the
    /// receiver rules it matched, separated by spaces, when any did.
    pub const REPLY_CODE: u32 = 2;
    pub const REPLY_TEXT: u32 = 3;
    pub const REPLY_RULES: u32 = 4;
}

const STS_VERSION: u8 = 1;
mod sts_field {
    /// The ID its domain's record named when it was fetched.
    pub const ID: u32 = 1;
    /// 0 enforce, 1 testing, 2 none.
    pub const MODE: u32 = 2;
    /// Its exchange patterns, each ended by a newline, which no name holds.
    pub const MX: u32 = 3;
    /// In seconds.
    pub const MAX_AGE: u32 = 4;
}

const WINDOW_VERSION: u8 = 1;
mod window_field {
    /// The period of its newest bucket, and every bucket's count, each in
    /// 4 bytes, big-endian, by period from the oldest.
    pub const NEWEST: u32 = 1;
    pub const COUNTS: u32 = 2;
    /// Warmup's evidence beside it: the UTC day it counts, in
    /// days since the Unix epoch, and that day's and the day before's
    /// counts, as `pack_counts` packs them. Absent when it has counted
    /// nothing.
    pub const DAY: u32 = 3;
    pub const TODAY: u32 = 4;
    pub const YESTERDAY: u32 = 5;
}

const SUPPRESSION_VERSION: u8 = 1;
mod suppression_field {
    /// 0 bounce, 1 complaint, 2 operator.
    pub const REASON: u32 = 1;
    pub const AT: u32 = 2;
    /// The address as it was given, so the list reads back whatever its
    /// key.
    pub const ADDRESS: u32 = 3;
}

const POLICY_VERSION: u8 = 1;
mod policy_field {
    /// 0 identity, 1 tenant, 2 configuration, 3 credential, 4 account,
    /// 5 subscription, 6 pool, 7 egress, 8 hold, 9 topic, 10 topic
    /// subscriber, 11 destination, 12 template.
    pub const KIND: u32 = 1;
    pub const ACCOUNT: u32 = 2;
    /// An identity's, tenant's, configuration's, subscription's or pool's
    /// name.
    pub const NAME: u32 = 3;
    /// An identity's DKIM selector, key and signed header fields, the
    /// fields separated by colons.
    pub const SELECTOR: u32 = 4;
    pub const KEY: u32 = 5;
    pub const HEADERS: u32 = 6;
    /// An identity's default configuration, or a subscription's.
    pub const CONFIGURATION: u32 = 7;
    /// A tenant's identities and configurations, and a credential's scopes,
    /// each ID in 8 bytes, big-endian. A credential's scope is any when
    /// absent.
    pub const IDENTITIES: u32 = 8;
    pub const CONFIGURATIONS: u32 = 9;
    pub const TENANTS: u32 = 10;
    /// A credential's: 0 login, 1 access key.
    pub const SECRET_KIND: u32 = 11;
    /// Its login user or access key ID.
    pub const HANDLE: u32 = 12;
    /// Its password's SHA-256, or its access key's secret; or a
    /// subscription's signing key.
    pub const SECRET: u32 = 13;
    /// An account's or tenant's admission rates, each absent when
    /// unlimited, and an account's daily quota.
    pub const RECIPIENTS_PER_SECOND: u32 = 14;
    pub const BYTES_PER_SECOND: u32 = 15;
    pub const DAILY_QUOTA: u32 = 16;
    /// A subscription's URL, and the kinds of event it owes, bit `i` for
    /// `EventKind::ALL[i]`.
    pub const URL: u32 = 17;
    pub const EVENTS: u32 = 18;
    /// An egress's address, in its 4 or 16 bytes, and its HELO name.
    pub const ADDRESS: u32 = 19;
    pub const HELO: u32 = 20;
    /// A configuration's or egress's pool.
    pub const POOL: u32 = 21;
    /// An egress's daily cap for each site.
    pub const DAILY_CAP: u32 = 22;
    /// What a hold pauses: 0 its account, 1 a tenant, 2 a configuration,
    /// 3 an identity, 4 an egress; and that record's ID.
    pub const PAUSED_KIND: u32 = 23;
    pub const PAUSED: u32 = 24;
    /// Whether a hold still accepts new mail, 1 if it does, and its reason.
    pub const ACCEPTING: u32 = 25;
    pub const REASON: u32 = 26;
    /// 1 for an identity whose mail is not signed with its key: absent, it
    /// is.
    pub const UNSIGNED: u32 = 27;
    /// Where the check of an identity's DKIM record stands, 0 pending, 1
    /// success, 2 a temporary failure, 3 failed, and since when, in
    /// microseconds: absent for an identity never checked.
    pub const VERIFICATION: u32 = 28;
    pub const VERIFIED_SINCE: u32 = 29;
    /// A credential's permissions, 1 to send and 2 to manage: absent, it
    /// sends.
    pub const PERMISSIONS: u32 = 30;
    /// An identity's own MAIL FROM domain, 1 if its mail is refused until
    /// that is found (absent, it goes with the installation's return path),
    /// and where its check stands and since when, as `VERIFICATION`'s.
    pub const MAIL_FROM: u32 = 31;
    pub const MAIL_FROM_REJECTS: u32 = 32;
    pub const MAIL_FROM_STATUS: u32 = 33;
    pub const MAIL_FROM_SINCE: u32 = 34;
    /// An identity's, tenant's or configuration's tags, each its key and
    /// value with their lengths in 4 bytes, big-endian, before them: absent
    /// when it has none.
    pub const TAGS: u32 = 35;
    /// When a tenant or template was created through SES's API, in
    /// microseconds.
    pub const CREATED: u32 = 36;
    /// 1 for a configuration with `ReputationMetricsEnabled`.
    pub const REPUTATION_METRICS: u32 = 37;
    /// A topic subscriber's or destination's topic.
    pub const TOPIC: u32 = 38;
    /// 1 for a topic subscriber that has confirmed.
    pub const CONFIRMED: u32 = 39;
    /// 1 for a destination that is not enabled.
    pub const DISABLED: u32 = 40;
    /// An egress's sites' own caps, as `pack_site_caps` packs them, and
    /// warmup's last judgment of it, as `pack_warmed` packs it:
    /// absent when it has none.
    pub const SITE_CAPS: u32 = 41;
    pub const WARMED: u32 = 42;
    /// The policy revision that last changed an egress's caps: absent for
    /// none since they were first kept.
    pub const CAPS_CHANGED: u32 = 43;
    /// A template's subject, and its text and HTML parts, each absent when
    /// it has none.
    pub const SUBJECT: u32 = 44;
    pub const TEXT: u32 = 45;
    pub const HTML: u32 = 46;
    /// The templates a tenant may send with, each ID in 8 bytes,
    /// big-endian: absent when it has none.
    pub const TEMPLATES: u32 = 47;
}

const ENTRY_VERSION: u8 = 1;
mod entry_field {
    /// 0 accepted, 1 attempted, 2 expired, 3 suppressed, 4 cancelled,
    /// 5 bounced, 6 complained.
    pub const KIND: u32 = 1;
    pub const MESSAGE: u32 = 2;
    pub const ACCOUNT: u32 = 3;
    /// The delivery an attempt was for, or that expired.
    pub const DELIVERY: u32 = 4;
    /// When it was accepted, its attempt ended, or it expired.
    pub const AT: u32 = 5;
    pub const ATTEMPT: u32 = 6;
    pub const RESERVED_AT: u32 = 7;
    /// 0 delivered, 1 rejected, 2 deferred, 3 uncertain, 4 abandoned.
    pub const RESULT: u32 = 8;
    /// The deliveries an acceptance made, each ID in 8 bytes, big-endian.
    pub const DELIVERIES: u32 = 9;
    /// The configuration its mail was sent under, if any.
    pub const CONFIGURATION: u32 = 10;
    /// What the receiver last said in an attempt: its reply's code and
    /// text.
    pub const EVIDENCE_CODE: u32 = 11;
    pub const EVIDENCE_TEXT: u32 = 12;
    /// The report a bounce or complaint came from.
    pub const REPORT: u32 = 13;
    /// A bounce's status, packed (`pack_status`).
    pub const STATUS: u32 = 14;
    /// A complaint's feedback type.
    pub const FEEDBACK_TYPE: u32 = 15;
    /// The receiver rules an attempt's evidence matched, by name, separated
    /// by spaces, when any did.
    pub const EVIDENCE_RULES: u32 = 16;
    /// 1 for a bounce or complaint whose report a reporter the operator
    /// enrolled with signed.
    pub const AUTHENTICATED: u32 = 17;
}

const REPORT_VERSION: u8 = 1;

mod report_field {
    /// The message its return path's token named, if one did.
    pub const MESSAGE: u32 = 1;
    /// 0 a delivery status notification, 1 a feedback report, 2 neither.
    pub const KIND: u32 = 2;
    /// A feedback report's feedback type.
    pub const FEEDBACK_TYPE: u32 = 3;
    /// The recipients it names, in order: each a record of its own
    /// (`claim_field`), after its length in 4 bytes, big-endian.
    pub const CLAIMS: u32 = 4;
    pub const RECEIVED_AT: u32 = 5;
    /// The report as it arrived.
    pub const EVIDENCE: u32 = 6;
    /// 1 if a reporter the operator enrolled with signed it, and 1 if its
    /// class is below the one the operator trusts: absent, it
    /// was neither.
    pub const AUTHENTICATED: u32 = 7;
    pub const UNTRUSTED: u32 = 8;
}

const CLAIM_VERSION: u8 = 1;

mod claim_field {
    pub const ADDRESS: u32 = 1;
    /// 1 if delivery to it failed.
    pub const FAILED: u32 = 2;
    pub const STATUS: u32 = 3;
    pub const DIAGNOSTIC: u32 = 4;
    /// 1 if its status rules the address out, by the receiver rules.
    pub const RULES_OUT_ADDRESS: u32 = 5;
}

pub fn encode_message(message: &Message) -> Vec<u8> {
    use message_field::*;
    let mut writer = Writer::new(MESSAGE_VERSION);
    writer.uint(SUBMISSION, message.submission.0.as_u64());
    writer.uint(ACCOUNT, message.account.0.as_u64());
    if let Some(tenant) = message.origin.tenant {
        writer.uint(TENANT, tenant.0.as_u64());
    }
    writer.uint(IDENTITY, message.origin.identity.0.as_u64());
    writer.uint(BODY, message.body.0.as_u64());
    writer.uint(ACCEPTED_AT, message.accepted_at.as_micros());
    writer.uint(POLICY_REVISION, message.policy_revision.0);
    if let Some(configuration) = message.origin.configuration {
        writer.uint(CONFIGURATION, configuration.0.as_u64());
    }
    writer.uint(RECIPIENTS, u64::from(message.recipients));
    writer.finish()
}

/// What SES-shaped events say of message `message`, as the store keeps it:
/// its addresses, header copy and tags sealed under `keys` while
/// encryption is on.
pub fn encode_mail(
    mail: &Mail,
    message: MessageId,
    tenant: Option<TenantId>,
    keys: Option<&Keys>,
) -> Vec<u8> {
    use mail_field::*;
    let sealing = Sealing::of(keys, tenant_of(tenant), Sealed::Message, message.0.as_u64());
    let mut writer = Writer::new(MAIL_VERSION);
    writer.sealed(SOURCE, mail.source.as_bytes(), sealing);
    let mut destination = Vec::new();
    for address in &mail.destination {
        pack_text(&mut destination, address);
    }
    writer.sealed(DESTINATION, &destination, sealing);
    writer.sealed(HEADERS, &mail.headers, sealing);
    if mail.truncated {
        writer.uint(TRUNCATED, 1);
    }
    let tags: Vec<Tag> = mail
        .tags
        .iter()
        .map(|(key, value)| Tag {
            key: key.clone(),
            value: value.clone(),
        })
        .collect();
    writer.sealed(TAGS, &pack_tags(&tags), sealing);
    writer.finish()
}

pub fn decode_mail(
    record: &[u8],
    message: MessageId,
    keys: Option<&Keys>,
) -> Result<Mail, CodecError> {
    use mail_field::*;
    let sealing = Sealing::of(keys, None, Sealed::Message, message.0.as_u64());
    let mut reader = Reader::new(record, MAIL_VERSION)?;
    let (mut source, mut destination, mut headers) = (None, Vec::new(), None);
    let (mut truncated, mut tags) = (false, Vec::new());
    while let Some((field, value)) = reader.next()? {
        match field {
            SOURCE => {
                source = Some(text_of(
                    &opened(value, field, sealing, ERASED_ADDRESS)?,
                    "source",
                )?);
            }
            DESTINATION => {
                let opened = opened(value, field, sealing, b"")?;
                let mut packed = &opened[..];
                while !packed.is_empty() {
                    destination.push(unpack_text(&mut packed)?);
                }
            }
            HEADERS => {
                headers = Some(bytes::Bytes::from(
                    opened(value, field, sealing, b"")?.into_owned(),
                ));
            }
            TRUNCATED => truncated = value.uint(field)? == 1,
            TAGS => tags = unpack_tags(&opened(value, field, sealing, b"")?)?,
            other => return Err(CodecError::UnknownField(other)),
        }
    }
    Ok(Mail {
        source: source.ok_or(CodecError::Missing("source"))?,
        destination,
        headers: headers.ok_or(CodecError::Missing("headers"))?,
        truncated,
        tags: tags.into_iter().map(|tag| (tag.key, tag.value)).collect(),
    })
}

pub fn decode_message(id: MessageId, record: &[u8]) -> Result<Message, CodecError> {
    use message_field::*;
    let mut reader = Reader::new(record, MESSAGE_VERSION)?;
    let (mut submission, mut account, mut tenant, mut identity) = (None, None, None, None);
    let (mut body, mut accepted_at, mut policy_revision) = (None, None, None);
    let (mut configuration, mut recipients) = (None, None);
    while let Some((field, value)) = reader.next()? {
        match field {
            RECIPIENTS => {
                recipients = Some(
                    u32::try_from(value.uint(field)?)
                        .map_err(|_| CodecError::Invalid("recipients"))?,
                );
            }
            SUBMISSION => submission = Some(SubmissionId(id_of(value.uint(field)?)?)),
            ACCOUNT => account = Some(AccountId(id_of(value.uint(field)?)?)),
            TENANT => tenant = Some(TenantId(id_of(value.uint(field)?)?)),
            IDENTITY => identity = Some(IdentityId(id_of(value.uint(field)?)?)),
            BODY => body = Some(BodyId(id_of(value.uint(field)?)?)),
            ACCEPTED_AT => accepted_at = Some(Timestamp::from_micros(value.uint(field)?)),
            POLICY_REVISION => policy_revision = Some(PolicyRevision(value.uint(field)?)),
            CONFIGURATION => configuration = Some(ConfigurationId(id_of(value.uint(field)?)?)),
            other => return Err(CodecError::UnknownField(other)),
        }
    }
    Ok(Message {
        id,
        submission: submission.ok_or(CodecError::Missing("submission"))?,
        account: account.ok_or(CodecError::Missing("account"))?,
        origin: Origin {
            identity: identity.ok_or(CodecError::Missing("identity"))?,
            tenant,
            configuration,
        },
        body: body.ok_or(CodecError::Missing("body"))?,
        accepted_at: accepted_at.ok_or(CodecError::Missing("acceptance time"))?,
        policy_revision: policy_revision.ok_or(CodecError::Missing("policy revision"))?,
        recipients: recipients.ok_or(CodecError::Missing("recipients"))?,
    })
}

/// A delivery's record, its recipient sealed under `keys` while encryption
/// is on, as `tenant`'s, if it is sealed as a tenant's.
pub fn encode_delivery(
    delivery: &Delivery,
    tenant: Option<TenantId>,
    keys: Option<&Keys>,
) -> Vec<u8> {
    use delivery_field::*;
    let sealing = Sealing::of(
        keys,
        tenant_of(tenant),
        Sealed::Delivery,
        delivery.id().0.as_u64(),
    );
    let mut writer = Writer::new(DELIVERY_VERSION);
    writer.uint(MESSAGE, delivery.message().0.as_u64());
    writer.uint(ACCOUNT, delivery.account().0.as_u64());
    writer.sealed(RECIPIENT, delivery.recipient().as_str().as_bytes(), sealing);
    writer.uint(EXPIRES_AT, delivery.expires_at().as_micros());
    writer.uint(GENERATION, u64::from(delivery.generation().as_u32()));
    writer.uint(ATTEMPTS, u64::from(delivery.attempts()));
    writer.uint(UNCERTAIN_ATTEMPTS, u64::from(delivery.uncertain_attempts()));
    match delivery.state() {
        QueueState::Ready { due_at } => {
            writer.uint(STATE, 0);
            writer.uint(DUE_AT, due_at.as_micros());
        }
        QueueState::InFlight { attempt, since } => {
            writer.uint(STATE, 1);
            writer.uint(ATTEMPT, attempt.0.as_u64());
            writer.uint(SINCE, since.as_micros());
        }
        QueueState::Held { due_at, since } => {
            writer.uint(STATE, 3);
            writer.uint(DUE_AT, due_at.as_micros());
            writer.uint(SINCE, since.as_micros());
        }
        QueueState::Finished { completion, at } => {
            writer.uint(STATE, 2);
            let kind = match completion {
                Completion::RemoteAccepted { attempt } => {
                    writer.uint(ATTEMPT, attempt.0.as_u64());
                    0
                }
                Completion::Rejected { attempt } => {
                    writer.uint(ATTEMPT, attempt.0.as_u64());
                    1
                }
                Completion::Expired => 2,
                Completion::Suppressed => 3,
                Completion::Cancelled => 4,
                Completion::Captured { attempt } => {
                    writer.uint(ATTEMPT, attempt.0.as_u64());
                    5
                }
            };
            writer.uint(COMPLETION, kind);
            writer.uint(FINISHED_AT, at.as_micros());
        }
    }
    let origin = delivery.origin();
    writer.uint(IDENTITY, origin.identity.0.as_u64());
    if let Some(tenant) = origin.tenant {
        writer.uint(TENANT, tenant.0.as_u64());
    }
    if let Some(configuration) = origin.configuration {
        writer.uint(CONFIGURATION, configuration.0.as_u64());
    }
    if let Some(egress) = delivery.egress() {
        writer.uint(EGRESS, egress.0.as_u64());
    }
    if let Some(entry) = delivery.reply_entry() {
        writer.uint(REPLY_ENTRY, entry);
    }
    writer.finish()
}

pub fn decode_delivery(
    id: DeliveryId,
    record: &[u8],
    keys: Option<&Keys>,
) -> Result<Delivery, CodecError> {
    use delivery_field::*;
    let sealing = Sealing::of(keys, None, Sealed::Delivery, id.0.as_u64());
    let mut reader = Reader::new(record, DELIVERY_VERSION)?;
    let (mut message, mut account, mut recipient, mut expires_at) = (None, None, None, None);
    let (mut generation, mut attempts, mut uncertain_attempts) = (None, None, None);
    let (mut state, mut due_at, mut attempt, mut since) = (None, None, None, None);
    let (mut completion, mut finished_at) = (None, None);
    let (mut identity, mut tenant, mut configuration, mut egress) = (None, None, None, None);
    let mut reply_entry = None;
    while let Some((field, value)) = reader.next()? {
        match field {
            MESSAGE => message = Some(MessageId(id_of(value.uint(field)?)?)),
            ACCOUNT => account = Some(AccountId(id_of(value.uint(field)?)?)),
            RECIPIENT => {
                let sealed = opened(value, field, sealing, ERASED_ADDRESS)?;
                let text =
                    std::str::from_utf8(&sealed).map_err(|_| CodecError::Invalid("recipient"))?;
                recipient =
                    Some(Address::parse(text).map_err(|_| CodecError::Invalid("recipient"))?);
            }
            EXPIRES_AT => expires_at = Some(Timestamp::from_micros(value.uint(field)?)),
            GENERATION => generation = Some(Generation::from_u32(u32_of(value.uint(field)?)?)),
            ATTEMPTS => attempts = Some(u32_of(value.uint(field)?)?),
            UNCERTAIN_ATTEMPTS => uncertain_attempts = Some(u32_of(value.uint(field)?)?),
            STATE => state = Some(value.uint(field)?),
            DUE_AT => due_at = Some(Timestamp::from_micros(value.uint(field)?)),
            ATTEMPT => attempt = Some(AttemptId(id_of(value.uint(field)?)?)),
            SINCE => since = Some(Timestamp::from_micros(value.uint(field)?)),
            COMPLETION => completion = Some(value.uint(field)?),
            FINISHED_AT => finished_at = Some(Timestamp::from_micros(value.uint(field)?)),
            IDENTITY => identity = Some(IdentityId(id_of(value.uint(field)?)?)),
            TENANT => tenant = Some(TenantId(id_of(value.uint(field)?)?)),
            CONFIGURATION => configuration = Some(ConfigurationId(id_of(value.uint(field)?)?)),
            EGRESS => egress = Some(EgressId(id_of(value.uint(field)?)?)),
            REPLY_ENTRY => reply_entry = Some(value.uint(field)?),
            other => return Err(CodecError::UnknownField(other)),
        }
    }
    let attempt_of = || attempt.ok_or(CodecError::Missing("attempt"));
    let state = match state.ok_or(CodecError::Missing("state"))? {
        0 => QueueState::Ready {
            due_at: due_at.ok_or(CodecError::Missing("due time"))?,
        },
        1 => QueueState::InFlight {
            attempt: attempt_of()?,
            since: since.ok_or(CodecError::Missing("reservation time"))?,
        },
        2 => QueueState::Finished {
            completion: match completion.ok_or(CodecError::Missing("completion"))? {
                0 => Completion::RemoteAccepted {
                    attempt: attempt_of()?,
                },
                1 => Completion::Rejected {
                    attempt: attempt_of()?,
                },
                2 => Completion::Expired,
                3 => Completion::Suppressed,
                4 => Completion::Cancelled,
                5 => Completion::Captured {
                    attempt: attempt_of()?,
                },
                _ => return Err(CodecError::Invalid("completion")),
            },
            at: finished_at.ok_or(CodecError::Missing("finishing time"))?,
        },
        3 => QueueState::Held {
            due_at: due_at.ok_or(CodecError::Missing("due time"))?,
            since: since.ok_or(CodecError::Missing("hold time"))?,
        },
        _ => return Err(CodecError::Invalid("state")),
    };
    Delivery::from_record(DeliveryRecord {
        id,
        message: message.ok_or(CodecError::Missing("message"))?,
        account: account.ok_or(CodecError::Missing("account"))?,
        origin: Origin {
            identity: identity.ok_or(CodecError::Missing("identity"))?,
            tenant,
            configuration,
        },
        recipient: recipient.ok_or(CodecError::Missing("recipient"))?,
        expires_at: expires_at.ok_or(CodecError::Missing("expiry"))?,
        generation: generation.ok_or(CodecError::Missing("generation"))?,
        state,
        attempts: attempts.ok_or(CodecError::Missing("attempt count"))?,
        uncertain_attempts: uncertain_attempts
            .ok_or(CodecError::Missing("uncertain attempt count"))?,
        egress,
        reply_entry,
    })
    .map_err(|_| CodecError::Invalid("delivery state"))
}

/// The record a cooldown's reply is sealed in: its source's, the host's
/// own address 0, its site bound to it as well.
fn cooldown_place(egress: Option<EgressId>) -> u64 {
    egress.map_or(0, |egress| egress.0.as_u64())
}

/// What an address reads as once its tenant's key is gone.
pub const ERASED_ADDRESS: &[u8] = b"erased@erased.invalid";
/// What a reply or diagnostic reads as once its tenant's key is gone.
pub const ERASED_TEXT: &[u8] = b"[erased]";

/// A sealed field's value, or `erased` once its tenant's key is gone.
fn opened<'a>(
    value: Value<'a>,
    field: u32,
    sealing: Option<Sealing<'_>>,
    erased: &'static [u8],
) -> Result<std::borrow::Cow<'a, [u8]>, CodecError> {
    match value.sealed(field, sealing) {
        Err(CodecError::Erased) => Ok(std::borrow::Cow::Borrowed(erased)),
        other => other,
    }
}

fn tenant_of(tenant: Option<TenantId>) -> Option<u64> {
    tenant.map(|tenant| tenant.0.as_u64())
}

/// A site's cooldown, but for its source, site and end, which are its
/// row's columns.
pub fn encode_cooldown(cooldown: &SiteCooldown, keys: Option<&Keys>) -> Vec<u8> {
    use cooldown_field::*;
    let mut writer = Writer::new(COOLDOWN_VERSION);
    writer.uint(THROTTLES, u64::from(cooldown.throttles));
    if let Some(reply) = &cooldown.reply {
        writer.uint(REPLY_CODE, u64::from(reply.code));
        // A reply may name a recipient, so it is sealed as one is.
        let sealing = Sealing::of(
            keys,
            None,
            Sealed::Cooldown,
            cooldown_place(cooldown.egress),
        )
        .map(|sealing| sealing.bound(cooldown.site.as_bytes()));
        writer.sealed(REPLY_TEXT, reply.text.as_bytes(), sealing);
        if !reply.rules.is_empty() {
            writer.bytes(REPLY_RULES, reply.rules.as_bytes());
        }
    }
    writer.finish()
}

pub fn decode_cooldown(
    egress: Option<EgressId>,
    site: Arc<str>,
    until: Timestamp,
    record: &[u8],
    keys: Option<&Keys>,
) -> Result<SiteCooldown, CodecError> {
    use cooldown_field::*;
    let sealing = Sealing::of(keys, None, Sealed::Cooldown, cooldown_place(egress))
        .map(|sealing| sealing.bound(site.as_bytes()));
    let mut reader = Reader::new(record, COOLDOWN_VERSION)?;
    let (mut throttles, mut code, mut text, mut rules) = (None, None, None, None);
    while let Some((field, value)) = reader.next()? {
        match field {
            THROTTLES => throttles = Some(u32_of(value.uint(field)?)?),
            REPLY_CODE => {
                code = Some(
                    u16::try_from(value.uint(field)?)
                        .map_err(|_| CodecError::Invalid("reply code"))?,
                );
            }
            REPLY_TEXT => text = Some(text_of(&value.sealed(field, sealing)?, "reply text")?),
            REPLY_RULES => rules = Some(text_of(value.bytes(field)?, "reply rules")?),
            other => return Err(CodecError::UnknownField(other)),
        }
    }
    let reply = match (code, text, rules) {
        (Some(code), Some(text), rules) => Some(Evidence {
            code,
            text,
            rules: rules.unwrap_or_default(),
        }),
        (None, None, None) => None,
        _ => return Err(CodecError::Invalid("reply")),
    };
    Ok(SiteCooldown {
        egress,
        site,
        until,
        throttles: throttles.ok_or(CodecError::Missing("throttles"))?,
        reply,
    })
}

/// An (egress, site)'s window of the dispatch ledger. Its egress and site
/// are its row's key.
/// A domain's MTA-STS policy, but its domain and when it was fetched,
/// which are its row's key and column.
pub fn encode_sts(policy: &sts::Policy) -> Vec<u8> {
    use sts_field::*;
    let mut writer = Writer::new(STS_VERSION);
    writer.bytes(ID, policy.id.as_bytes());
    writer.uint(
        MODE,
        match policy.mode {
            sts::Mode::Enforce => 0,
            sts::Mode::Testing => 1,
            sts::Mode::None => 2,
        },
    );
    let mut mx = String::new();
    for pattern in &policy.mx {
        mx.push_str(pattern);
        mx.push('\n');
    }
    writer.bytes(MX, mx.as_bytes());
    writer.uint(MAX_AGE, policy.max_age.as_secs());
    writer.finish()
}

pub fn decode_sts(
    domain: &str,
    fetched_at: Timestamp,
    record: &[u8],
) -> Result<sts::Policy, CodecError> {
    use sts_field::*;
    let mut reader = Reader::new(record, STS_VERSION)?;
    let (mut id, mut mode, mut mx, mut max_age) = (None, None, None, None);
    while let Some((field, value)) = reader.next()? {
        match field {
            ID => id = Some(text_of(value.bytes(field)?, "policy ID")?),
            MODE => {
                mode = Some(match value.uint(field)? {
                    0 => sts::Mode::Enforce,
                    1 => sts::Mode::Testing,
                    2 => sts::Mode::None,
                    _ => return Err(CodecError::Invalid("mode")),
                });
            }
            MX => mx = Some(text_of(value.bytes(field)?, "exchange patterns")?),
            MAX_AGE => max_age = Some(std::time::Duration::from_secs(value.uint(field)?)),
            other => return Err(CodecError::UnknownField(other)),
        }
    }
    Ok(sts::Policy {
        domain: domain.into(),
        id: id.ok_or(CodecError::Missing("policy ID"))?.into(),
        mode: mode.ok_or(CodecError::Missing("mode"))?,
        mx: mx
            .ok_or(CodecError::Missing("exchange patterns"))?
            .lines()
            .map(Into::into)
            .collect(),
        max_age: max_age.ok_or(CodecError::Missing("max age"))?,
        fetched_at,
    })
}

/// An (egress, site)'s row of the dispatch ledger: its window, and the
/// tally beside it.
pub fn encode_dispatched(window: &Window, tally: &Tally) -> Vec<u8> {
    use window_field::*;
    let mut writer = Writer::new(WINDOW_VERSION);
    let (newest, counts) = window.parts();
    writer.uint(NEWEST, newest);
    let bytes: Vec<u8> = counts
        .iter()
        .flat_map(|count| count.to_be_bytes())
        .collect();
    writer.bytes(COUNTS, &bytes);
    if *tally != Tally::default() {
        let (day, today, yesterday) = tally.parts();
        writer.uint(DAY, day);
        writer.bytes(TODAY, &pack_counts(&today));
        writer.bytes(YESTERDAY, &pack_counts(&yesterday));
    }
    writer.finish()
}

pub fn decode_dispatched(record: &[u8]) -> Result<(Window, Tally), CodecError> {
    use window_field::*;
    let mut reader = Reader::new(record, WINDOW_VERSION)?;
    let (mut newest, mut counts) = (None, None);
    let (mut day, mut today, mut yesterday) = (None, None, None);
    while let Some((field, value)) = reader.next()? {
        match field {
            NEWEST => newest = Some(value.uint(field)?),
            COUNTS => {
                let bytes = value.bytes(field)?;
                if bytes.len() != BUCKETS * 4 {
                    return Err(CodecError::Invalid("window"));
                }
                let mut buckets = [0; BUCKETS];
                for (bucket, chunk) in buckets.iter_mut().zip(bytes.as_chunks::<4>().0) {
                    *bucket = u32::from_be_bytes(*chunk);
                }
                counts = Some(buckets);
            }
            DAY => day = Some(value.uint(field)?),
            TODAY => today = Some(unpack_counts(value.bytes(field)?)?),
            YESTERDAY => yesterday = Some(unpack_counts(value.bytes(field)?)?),
            other => return Err(CodecError::UnknownField(other)),
        }
    }
    let window = Window::from_parts(
        newest.ok_or(CodecError::Missing("newest period"))?,
        counts.ok_or(CodecError::Missing("buckets"))?,
    );
    // All three, or none, for a row written before it kept a tally.
    let tally = match (day, today, yesterday) {
        (Some(day), Some(today), Some(yesterday)) => Tally::from_parts(day, today, yesterday),
        (None, None, None) => Tally::default(),
        _ => return Err(CodecError::Invalid("a tally in part")),
    };
    Ok((window, tally))
}

/// Counts as five 4-byte big-endian numbers: deliveries, deferrals,
/// throttles, failures and complaints.
fn pack_counts(counts: &Counts) -> [u8; 20] {
    let mut packed = [0; 20];
    let each = [
        counts.delivered,
        counts.deferred,
        counts.throttled,
        counts.failed,
        counts.complained,
    ];
    for (chunk, count) in packed.as_chunks_mut::<4>().0.iter_mut().zip(each) {
        *chunk = count.to_be_bytes();
    }
    packed
}

fn unpack_counts(packed: &[u8]) -> Result<Counts, CodecError> {
    let (chunks, []) = packed.as_chunks::<4>() else {
        return Err(CodecError::Invalid("counts"));
    };
    let [delivered, deferred, throttled, failed, complained] = chunks else {
        return Err(CodecError::Invalid("counts"));
    };
    let count = |chunk: &[u8; 4]| u32::from_be_bytes(*chunk);
    Ok(Counts {
        delivered: count(delivered),
        deferred: count(deferred),
        throttled: count(throttled),
        failed: count(failed),
        complained: count(complained),
    })
}

/// A judgment as its counts, then its verdict, 0 raised, 1 untested, 2
/// held, 3 lowered, 4 set by an operator since, 5 promotion held, and the signal that held or
/// lowered it, 0 deliveries, 1 deferrals, 2 throttles, 3 failures, 4
/// complaints, in a byte each.
fn pack_judgment(packed: &mut Vec<u8>, judgment: &Judgment) {
    packed.extend_from_slice(&pack_counts(&judgment.counts));
    let signal = |signal| match signal {
        Signal::Delivered => 0,
        Signal::Deferred => 1,
        Signal::Throttled => 2,
        Signal::Failed => 3,
        Signal::Complained => 4,
    };
    let (verdict, by) = match judgment.verdict {
        Verdict::Raised => (0, 0),
        Verdict::Untested => (1, 0),
        Verdict::Held(by) => (2, signal(by)),
        Verdict::Lowered(by) => (3, signal(by)),
        Verdict::Set => (4, 0),
        Verdict::PromotionHeld => (5, 0),
    };
    packed.extend_from_slice(&[verdict, by]);
}

fn unpack_judgment(packed: &mut &[u8]) -> Result<Judgment, CodecError> {
    let invalid = || CodecError::Invalid("judgment");
    let (counts, rest) = packed.split_at_checked(20).ok_or_else(invalid)?;
    let (&[verdict, by], rest) = rest.split_first_chunk::<2>().ok_or_else(invalid)?;
    *packed = rest;
    let signal = match by {
        0 => Signal::Delivered,
        1 => Signal::Deferred,
        2 => Signal::Throttled,
        3 => Signal::Failed,
        4 => Signal::Complained,
        _ => return Err(invalid()),
    };
    let verdict = match verdict {
        0 => Verdict::Raised,
        1 => Verdict::Untested,
        2 => Verdict::Held(signal),
        3 => Verdict::Lowered(signal),
        4 => Verdict::Set,
        5 => Verdict::PromotionHeld,
        _ => return Err(invalid()),
    };
    Ok(Judgment {
        counts: unpack_counts(counts)?,
        verdict,
    })
}

/// Sites' caps, each its name as `pack_text` packs it, then 1 and the cap
/// in 8 bytes, big-endian, or 0 for none.
fn pack_site_caps(sites: &BTreeMap<Arc<str>, Option<u64>>) -> Vec<u8> {
    let mut packed = Vec::new();
    for (site, cap) in sites {
        pack_text(&mut packed, site);
        match cap {
            Some(cap) => {
                packed.push(1);
                packed.extend_from_slice(&cap.to_be_bytes());
            }
            None => packed.push(0),
        }
    }
    packed
}

fn unpack_site_caps(mut packed: &[u8]) -> Result<BTreeMap<Arc<str>, Option<u64>>, CodecError> {
    let invalid = || CodecError::Invalid("site caps");
    let mut sites = BTreeMap::new();
    while !packed.is_empty() {
        let site = unpack_text(&mut packed)?;
        // In order, each once, as they are written.
        if sites
            .last_key_value()
            .is_some_and(|(last, _): (&Arc<str>, _)| **last >= *site)
        {
            return Err(invalid());
        }
        let (&flag, rest) = packed.split_first().ok_or_else(invalid)?;
        packed = rest;
        let cap = match flag {
            0 => None,
            1 => {
                let (cap, rest) = packed.split_first_chunk::<8>().ok_or_else(invalid)?;
                packed = rest;
                Some(u64::from_be_bytes(*cap))
            }
            _ => return Err(invalid()),
        };
        sites.insert(Arc::from(site), cap);
    }
    Ok(sites)
}

/// Warmup's judgment of an egress: its day in 8 bytes, big-endian, the
/// pool's judgment, then each site judged on its own, its name as
/// `pack_text` packs it, then its judgment.
fn pack_warmed(warmed: &Warmed) -> Vec<u8> {
    let mut packed = warmed.day.to_be_bytes().to_vec();
    pack_judgment(&mut packed, &warmed.pool);
    for (site, judgment) in &warmed.sites {
        pack_text(&mut packed, site);
        pack_judgment(&mut packed, judgment);
    }
    packed
}

fn unpack_warmed(packed: &[u8]) -> Result<Warmed, CodecError> {
    let (day, mut packed) = packed
        .split_first_chunk::<8>()
        .ok_or(CodecError::Invalid("warmup's judgment"))?;
    let pool = unpack_judgment(&mut packed)?;
    let mut sites = BTreeMap::new();
    while !packed.is_empty() {
        let site = unpack_text(&mut packed)?;
        // In order, each once, as they are written.
        if sites
            .last_key_value()
            .is_some_and(|(last, _): (&Arc<str>, _)| **last >= *site)
        {
            return Err(CodecError::Invalid("warmup's judgment"));
        }
        sites.insert(Arc::from(site), unpack_judgment(&mut packed)?);
    }
    Ok(Warmed {
        day: u64::from_be_bytes(*day),
        pool,
        sites,
    })
}

/// A suppression's record: why, since when, and its address as given,
/// sealed under `keys` while encryption is on, in its account's
/// place and bound to `key`, its row's key there, so it opens in its own
/// row alone.
pub fn encode_suppression(
    account: AccountId,
    key: &str,
    address: &Address,
    reason: Reason,
    at: Timestamp,
    keys: Option<&Keys>,
) -> Vec<u8> {
    use suppression_field::*;
    let sealing = Sealing::of(keys, None, Sealed::Suppression, account.0.as_u64())
        .map(|sealing| sealing.bound(key.as_bytes()));
    let mut writer = Writer::new(SUPPRESSION_VERSION);
    let reason = match reason {
        Reason::Bounce => 0,
        Reason::Complaint => 1,
        Reason::Operator => 2,
    };
    writer.uint(REASON, reason);
    writer.uint(AT, at.as_micros());
    writer.sealed(ADDRESS, address.as_str().as_bytes(), sealing);
    writer.finish()
}

pub fn decode_suppression(
    record: &[u8],
    account: AccountId,
    key: &[u8],
    keys: Option<&Keys>,
) -> Result<Suppressed, CodecError> {
    use suppression_field::*;
    let sealing = Sealing::of(keys, None, Sealed::Suppression, account.0.as_u64())
        .map(|sealing| sealing.bound(key));
    let mut reader = Reader::new(record, SUPPRESSION_VERSION)?;
    let (mut reason, mut at, mut address) = (None, None, None);
    while let Some((field, value)) = reader.next()? {
        match field {
            REASON => reason = Some(value.uint(field)?),
            AT => at = Some(Timestamp::from_micros(value.uint(field)?)),
            ADDRESS => {
                let text = text_of(&value.sealed(field, sealing)?, "address")?;
                address = Some(Address::parse(&text).map_err(|_| CodecError::Invalid("address"))?);
            }
            other => return Err(CodecError::UnknownField(other)),
        }
    }
    Ok(Suppressed {
        address: address.ok_or(CodecError::Missing("address"))?,
        reason: match reason.ok_or(CodecError::Missing("reason"))? {
            0 => Reason::Bounce,
            1 => Reason::Complaint,
            2 => Reason::Operator,
            _ => return Err(CodecError::Invalid("reason")),
        },
        at: at.ok_or(CodecError::Missing("at"))?,
    })
}

/// The topics an event is published to, each its ID's eight bytes, big
/// endian: none is no column at all, null.
pub fn encode_topics(topics: &[TopicId]) -> Option<Vec<u8>> {
    (!topics.is_empty()).then(|| {
        topics
            .iter()
            .flat_map(|topic| topic.0.as_u64().to_be_bytes())
            .collect()
    })
}

/// The topics an entry was published to as it was written.
pub fn decode_topics(bytes: Option<&[u8]>) -> Result<Vec<TopicId>, CodecError> {
    let Some(bytes) = bytes else {
        return Ok(Vec::new());
    };
    let (topics, rest) = bytes.as_chunks::<8>();
    if bytes.is_empty() || !rest.is_empty() {
        return Err(CodecError::Invalid("topics"));
    }
    topics
        .iter()
        .map(|topic| id_of(u64::from_be_bytes(*topic)).map(TopicId))
        .collect()
}

/// A journal entry, what a receiver said in an attempt sealed in its
/// attempt's place under `keys` while encryption is on.
pub fn encode_entry(entry: &Entry, tenant: Option<TenantId>, keys: Option<&Keys>) -> Vec<u8> {
    use entry_field::*;
    let mut writer = Writer::new(ENTRY_VERSION);
    let finished = |writer: &mut Writer, kind, delivery: &DeliveryId, account: &AccountId, at| {
        writer.uint(KIND, kind);
        writer.uint(ACCOUNT, account.0.as_u64());
        writer.uint(DELIVERY, delivery.0.as_u64());
        writer.uint(AT, Timestamp::as_micros(at));
    };
    match entry {
        Entry::Accepted {
            message,
            account,
            configuration: _,
            deliveries,
            at,
        } => {
            writer.uint(KIND, 0);
            writer.uint(MESSAGE, message.0.as_u64());
            writer.uint(ACCOUNT, account.0.as_u64());
            writer.uint(AT, at.as_micros());
            writer.bytes(
                DELIVERIES,
                &pack(deliveries.iter().map(|delivery| delivery.0)),
            );
        }
        Entry::Attempted { attempt, .. } => {
            let ended = attempt
                .ended
                .expect("the journal records attempts that have ended");
            writer.uint(KIND, 1);
            writer.uint(ACCOUNT, attempt.account.0.as_u64());
            writer.uint(DELIVERY, attempt.delivery.0.as_u64());
            writer.uint(AT, ended.at.as_micros());
            writer.uint(ATTEMPT, attempt.id.0.as_u64());
            writer.uint(RESERVED_AT, attempt.reserved_at.as_micros());
            let result = match ended.result {
                AttemptResult::Delivered => 0,
                AttemptResult::Rejected => 1,
                AttemptResult::Deferred => 2,
                AttemptResult::Uncertain => 3,
                AttemptResult::Abandoned => 4,
                AttemptResult::Captured => 5,
            };
            writer.uint(RESULT, result);
        }
        Entry::Expired {
            delivery,
            account,
            at,
            ..
        } => finished(&mut writer, 2, delivery, account, *at),
        Entry::Suppressed {
            delivery,
            account,
            at,
            ..
        } => finished(&mut writer, 3, delivery, account, *at),
        Entry::Cancelled {
            delivery,
            account,
            at,
            ..
        } => finished(&mut writer, 4, delivery, account, *at),
        Entry::Bounced {
            delivery,
            account,
            at,
            ..
        } => finished(&mut writer, 5, delivery, account, *at),
        Entry::Complained {
            delivery,
            account,
            at,
            ..
        } => finished(&mut writer, 6, delivery, account, *at),
    }
    if let Some(configuration) = entry.configuration() {
        writer.uint(CONFIGURATION, configuration.0.as_u64());
    }
    if let Entry::Attempted {
        attempt,
        evidence: Some(evidence),
        ..
    } = entry
    {
        // A reply may name a recipient, so it is sealed as one is.
        let sealing = Sealing::of(
            keys,
            tenant_of(tenant),
            Sealed::Entry,
            attempt.id.0.as_u64(),
        );
        writer.uint(EVIDENCE_CODE, u64::from(evidence.code));
        writer.sealed(EVIDENCE_TEXT, evidence.text.as_bytes(), sealing);
    }
    match entry {
        Entry::Bounced { report, status, .. } => {
            writer.uint(REPORT, report.0.as_u64());
            if let Some(status) = status {
                writer.uint(STATUS, pack_status(*status));
            }
        }
        Entry::Complained {
            report,
            feedback_type,
            ..
        } => {
            writer.uint(REPORT, report.0.as_u64());
            writer.bytes(FEEDBACK_TYPE, feedback_type.as_bytes());
        }
        Entry::Attempted {
            evidence: Some(evidence),
            ..
        } if !evidence.rules.is_empty() => {
            writer.bytes(EVIDENCE_RULES, evidence.rules.as_bytes());
        }
        _ => {}
    }
    if let Entry::Bounced {
        authenticated: true,
        ..
    }
    | Entry::Complained {
        authenticated: true,
        ..
    } = entry
    {
        writer.uint(AUTHENTICATED, 1);
    }
    writer.finish()
}

pub fn decode_entry(record: &[u8], keys: Option<&Keys>) -> Result<Entry, CodecError> {
    use entry_field::*;
    let mut reader = Reader::new(record, ENTRY_VERSION)?;
    let (mut kind, mut message, mut account, mut delivery, mut at) = (None, None, None, None, None);
    let (mut attempt, mut reserved_at, mut result, mut deliveries) = (None, None, None, None);
    let (mut configuration, mut code, mut text, mut rules) = (None, None, None, None);
    let (mut report, mut status, mut feedback_type) = (None, None, None);
    let mut authenticated = false;
    while let Some((field, value)) = reader.next()? {
        match field {
            KIND => kind = Some(value.uint(field)?),
            REPORT => report = Some(ReportId(id_of(value.uint(field)?)?)),
            STATUS => status = Some(unpack_status(value.uint(field)?)?),
            FEEDBACK_TYPE => feedback_type = Some(text_of(value.bytes(field)?, "feedback type")?),
            MESSAGE => message = Some(MessageId(id_of(value.uint(field)?)?)),
            ACCOUNT => account = Some(AccountId(id_of(value.uint(field)?)?)),
            DELIVERY => delivery = Some(DeliveryId(id_of(value.uint(field)?)?)),
            AT => at = Some(Timestamp::from_micros(value.uint(field)?)),
            ATTEMPT => attempt = Some(AttemptId(id_of(value.uint(field)?)?)),
            RESERVED_AT => reserved_at = Some(Timestamp::from_micros(value.uint(field)?)),
            RESULT => {
                result = Some(match value.uint(field)? {
                    0 => AttemptResult::Delivered,
                    1 => AttemptResult::Rejected,
                    2 => AttemptResult::Deferred,
                    3 => AttemptResult::Uncertain,
                    4 => AttemptResult::Abandoned,
                    5 => AttemptResult::Captured,
                    _ => return Err(CodecError::Invalid("attempt result")),
                });
            }
            DELIVERIES => {
                deliveries = Some(unpack(value.bytes(field)?, DeliveryId)?);
            }
            CONFIGURATION => {
                configuration = Some(ConfigurationId(id_of(value.uint(field)?)?));
            }
            EVIDENCE_CODE => {
                code = Some(
                    u16::try_from(value.uint(field)?)
                        .map_err(|_| CodecError::Invalid("evidence code"))?,
                );
            }
            EVIDENCE_TEXT => {
                // Its attempt, whose place it is sealed in, comes before it.
                let attempt = attempt.ok_or(CodecError::Missing("attempt"))?;
                let sealing = Sealing::of(keys, None, Sealed::Entry, attempt.0.as_u64());
                text = Some(
                    String::from_utf8(opened(value, field, sealing, ERASED_TEXT)?.into_owned())
                        .map_err(|_| CodecError::Invalid("evidence text"))?,
                );
            }
            EVIDENCE_RULES => rules = Some(text_of(value.bytes(field)?, "evidence rules")?),
            AUTHENTICATED => authenticated = value.uint(field)? == 1,
            other => return Err(CodecError::UnknownField(other)),
        }
    }
    let account = account.ok_or(CodecError::Missing("account"))?;
    let at = at.ok_or(CodecError::Missing("time"))?;
    let delivery = || delivery.ok_or(CodecError::Missing("delivery"));
    match kind.ok_or(CodecError::Missing("kind"))? {
        0 => Ok(Entry::Accepted {
            message: message.ok_or(CodecError::Missing("message"))?,
            account,
            configuration,
            deliveries: deliveries.ok_or(CodecError::Missing("deliveries"))?,
            at,
        }),
        1 => Ok(Entry::Attempted {
            attempt: Attempt {
                id: attempt.ok_or(CodecError::Missing("attempt"))?,
                delivery: delivery()?,
                account,
                reserved_at: reserved_at.ok_or(CodecError::Missing("reservation time"))?,
                ended: Some(AttemptEnd {
                    result: result.ok_or(CodecError::Missing("attempt result"))?,
                    at,
                }),
            },
            configuration,
            evidence: match (code, text, rules) {
                (Some(code), Some(text), rules) => Some(Evidence {
                    code,
                    text,
                    rules: rules.unwrap_or_default(),
                }),
                (None, None, None) => None,
                _ => return Err(CodecError::Invalid("evidence")),
            },
        }),
        2 => Ok(Entry::Expired {
            delivery: delivery()?,
            account,
            configuration,
            at,
        }),
        3 => Ok(Entry::Suppressed {
            delivery: delivery()?,
            account,
            configuration,
            at,
        }),
        4 => Ok(Entry::Cancelled {
            delivery: delivery()?,
            account,
            configuration,
            at,
        }),
        5 => Ok(Entry::Bounced {
            delivery: delivery()?,
            account,
            configuration,
            report: report.ok_or(CodecError::Missing("report"))?,
            status,
            authenticated,
            at,
        }),
        6 => Ok(Entry::Complained {
            delivery: delivery()?,
            account,
            configuration,
            report: report.ok_or(CodecError::Missing("report"))?,
            feedback_type: feedback_type.ok_or(CodecError::Missing("feedback type"))?,
            authenticated,
            at,
        }),
        _ => Err(CodecError::Invalid("entry kind")),
    }
}

/// `record` as the store keeps it, its secrets sealed under `keys`.
pub fn encode_policy(record: &Record, keys: &Keyring) -> Vec<u8> {
    use policy_field::*;
    let mut writer = Writer::new(POLICY_VERSION);
    let id = record.id().as_u64();
    let seal = |field, secret: &[u8]| keys.seal(keys::place(id, field), secret);
    let limits = |writer: &mut Writer, limits: &Limits| {
        if let Some(rate) = limits.recipients_per_second {
            writer.uint(RECIPIENTS_PER_SECOND, u64::from(rate));
        }
        if let Some(rate) = limits.bytes_per_second {
            writer.uint(BYTES_PER_SECOND, rate);
        }
    };
    match record {
        Record::Account(account) => {
            writer.uint(KIND, 4);
            limits(&mut writer, &account.limits);
            if let Some(quota) = account.daily_quota {
                writer.uint(DAILY_QUOTA, quota);
            }
        }
        Record::Identity(identity) => {
            writer.uint(KIND, 0);
            writer.uint(ACCOUNT, identity.account.0.as_u64());
            writer.bytes(NAME, identity.name.as_bytes());
            if let Some(signing) = &identity.signing {
                writer.bytes(SELECTOR, signing.selector.as_bytes());
                writer.bytes(KEY, &seal(KEY, signing.key.as_bytes()));
                writer.bytes(HEADERS, signing.headers.join(":").as_bytes());
            }
            if let Some(configuration) = identity.configuration {
                writer.uint(CONFIGURATION, configuration.0.as_u64());
            }
            if !identity.signs {
                writer.uint(UNSIGNED, 1);
            }
            if let Some(check) = identity.verification {
                writer.uint(VERIFICATION, status_code(check.status));
                writer.uint(VERIFIED_SINCE, check.since.as_micros());
            }
            if let Some(mail_from) = &identity.mail_from {
                writer.bytes(MAIL_FROM, mail_from.domain.as_bytes());
                if mail_from.behavior == OnMxFailure::Reject {
                    writer.uint(MAIL_FROM_REJECTS, 1);
                }
                writer.uint(MAIL_FROM_STATUS, status_code(mail_from.check.status));
                writer.uint(MAIL_FROM_SINCE, mail_from.check.since.as_micros());
            }
            if !identity.tags.is_empty() {
                writer.bytes(TAGS, &pack_tags(&identity.tags));
            }
        }
        Record::Tenant(tenant) => {
            writer.uint(KIND, 1);
            writer.uint(ACCOUNT, tenant.account.0.as_u64());
            writer.bytes(NAME, tenant.name.as_bytes());
            writer.bytes(IDENTITIES, &pack(tenant.identities.iter().map(|id| id.0)));
            writer.bytes(
                CONFIGURATIONS,
                &pack(tenant.configurations.iter().map(|id| id.0)),
            );
            limits(&mut writer, &tenant.limits);
            if !tenant.tags.is_empty() {
                writer.bytes(TAGS, &pack_tags(&tenant.tags));
            }
            if let Some(created) = tenant.created {
                writer.uint(CREATED, created.as_micros());
            }
            if !tenant.templates.is_empty() {
                writer.bytes(TEMPLATES, &pack(tenant.templates.iter().map(|id| id.0)));
            }
        }
        Record::Configuration(configuration) => {
            writer.uint(KIND, 2);
            writer.uint(ACCOUNT, configuration.account.0.as_u64());
            writer.bytes(NAME, configuration.name.as_bytes());
            if let Some(pool) = configuration.pool {
                writer.uint(POOL, pool.0.as_u64());
            }
            if !configuration.tags.is_empty() {
                writer.bytes(TAGS, &pack_tags(&configuration.tags));
            }
            if configuration.reputation_metrics {
                writer.uint(REPUTATION_METRICS, 1);
            }
        }
        Record::Pool(pool) => {
            writer.uint(KIND, 6);
            writer.uint(ACCOUNT, pool.account.0.as_u64());
            writer.bytes(NAME, pool.name.as_bytes());
        }
        Record::Egress(egress) => {
            writer.uint(KIND, 7);
            writer.uint(ACCOUNT, egress.account.0.as_u64());
            let address = match egress.address {
                IpAddr::V4(v4) => v4.octets().to_vec(),
                IpAddr::V6(v6) => v6.octets().to_vec(),
            };
            writer.bytes(ADDRESS, &address);
            writer.bytes(HELO, egress.helo.as_bytes());
            if let Some(pool) = egress.pool {
                writer.uint(POOL, pool.0.as_u64());
            }
            if let Some(cap) = egress.caps.daily {
                writer.uint(DAILY_CAP, cap);
            }
            if !egress.caps.sites.is_empty() {
                writer.bytes(SITE_CAPS, &pack_site_caps(&egress.caps.sites));
            }
            if let Some(warmed) = &egress.caps.warmed {
                writer.bytes(WARMED, &pack_warmed(warmed));
            }
            if egress.caps.changed.0 > 0 {
                writer.uint(CAPS_CHANGED, egress.caps.changed.0);
            }
        }
        Record::Credential(credential) => {
            writer.uint(KIND, 3);
            writer.uint(ACCOUNT, credential.account.0.as_u64());
            if let Scope::Only(identities) = &credential.identities {
                writer.bytes(IDENTITIES, &pack(identities.iter().map(|id| id.0)));
            }
            if let Scope::Only(tenants) = &credential.tenants {
                writer.bytes(TENANTS, &pack(tenants.iter().map(|id| id.0)));
            }
            let (kind, handle, secret) = match &credential.secret {
                Secret::Login {
                    user,
                    password_sha256,
                } => (0, user, &password_sha256[..]),
                Secret::AccessKey { id, secret } => (1, id, secret.as_bytes()),
            };
            writer.uint(SECRET_KIND, kind);
            writer.bytes(HANDLE, handle.as_bytes());
            writer.bytes(SECRET, &seal(SECRET, secret));
            if credential.permissions != Permissions::SENDS {
                let Permissions { sends, manages } = credential.permissions;
                writer.uint(PERMISSIONS, u64::from(sends) | u64::from(manages) << 1);
            }
        }
        Record::Subscription(subscription) => {
            writer.uint(KIND, 5);
            writer.uint(ACCOUNT, subscription.account.0.as_u64());
            writer.bytes(NAME, subscription.name.as_bytes());
            writer.uint(CONFIGURATION, subscription.configuration.0.as_u64());
            writer.bytes(SECRET, &seal(SECRET, &subscription.secret));
            writer.bytes(URL, subscription.url.as_bytes());
            writer.uint(EVENTS, event_bits(&subscription.events));
        }
        Record::Hold(hold) => {
            writer.uint(KIND, 8);
            writer.uint(ACCOUNT, hold.account.0.as_u64());
            let (kind, paused) = match hold.paused {
                Paused::Account => (0, None),
                Paused::Tenant(id) => (1, Some(id.0)),
                Paused::Configuration(id) => (2, Some(id.0)),
                Paused::Identity(id) => (3, Some(id.0)),
                Paused::Egress(id) => (4, Some(id.0)),
            };
            writer.uint(PAUSED_KIND, kind);
            if let Some(paused) = paused {
                writer.uint(PAUSED, paused.as_u64());
            }
            writer.uint(ACCEPTING, u64::from(hold.accepting));
            writer.bytes(REASON, hold.reason.as_bytes());
        }
        Record::Topic(topic) => {
            writer.uint(KIND, 9);
            writer.uint(ACCOUNT, topic.account.0.as_u64());
            writer.bytes(NAME, topic.name.as_bytes());
        }
        Record::Subscriber(subscriber) => {
            writer.uint(KIND, 10);
            writer.uint(ACCOUNT, subscriber.account.0.as_u64());
            writer.bytes(SECRET, &seal(SECRET, &subscriber.token));
            writer.bytes(URL, subscriber.endpoint.as_bytes());
            writer.uint(TOPIC, subscriber.topic.0.as_u64());
            if subscriber.confirmed {
                writer.uint(CONFIRMED, 1);
            }
        }
        Record::Destination(destination) => {
            writer.uint(KIND, 11);
            writer.uint(ACCOUNT, destination.account.0.as_u64());
            writer.bytes(NAME, destination.name.as_bytes());
            writer.uint(CONFIGURATION, destination.configuration.0.as_u64());
            writer.uint(EVENTS, event_bits(&destination.events));
            writer.uint(TOPIC, destination.topic.0.as_u64());
            if !destination.enabled {
                writer.uint(DISABLED, 1);
            }
        }
        Record::Template(template) => {
            writer.uint(KIND, 12);
            writer.uint(ACCOUNT, template.account.0.as_u64());
            writer.bytes(NAME, template.name.as_bytes());
            writer.uint(CREATED, template.created.as_micros());
            writer.bytes(SUBJECT, template.content.subject.as_bytes());
            if let Some(text) = &template.content.text {
                writer.bytes(TEXT, text.as_bytes());
            }
            if let Some(html) = &template.content.html {
                writer.bytes(HTML, html.as_bytes());
            }
        }
    }
    writer.finish()
}

/// The kinds of event in `events`, bit `i` for `EventKind::ALL[i]`.
fn event_bits(events: &BTreeSet<EventKind>) -> u64 {
    EventKind::ALL
        .iter()
        .enumerate()
        .filter(|(_, kind)| events.contains(kind))
        .fold(0, |bits, (bit, _)| bits | 1 << bit)
}

fn events_of(bits: u64) -> BTreeSet<EventKind> {
    EventKind::ALL
        .iter()
        .enumerate()
        .filter(|(bit, _)| bits & (1 << bit) != 0)
        .map(|(_, kind)| *kind)
        .collect()
}

/// Where a check of an identity's DNS stands, as the store keeps it.
fn status_code(status: Verification) -> u64 {
    match status {
        Verification::Pending => 0,
        Verification::Success => 1,
        Verification::TemporaryFailure => 2,
        Verification::Failed => 3,
    }
}

fn status_of(code: u64) -> Result<Verification, CodecError> {
    Ok(match code {
        0 => Verification::Pending,
        1 => Verification::Success,
        2 => Verification::TemporaryFailure,
        3 => Verification::Failed,
        _ => return Err(CodecError::Invalid("verification")),
    })
}

/// The record `id` the store keeps as `record`, its secrets opened with
/// `keys`.
pub fn decode_policy(id: Id, record: &[u8], keys: &Keyring) -> Result<Record, CodecError> {
    use policy_field::*;
    let mut reader = Reader::new(record, POLICY_VERSION)?;
    let open = |field, value: Value<'_>| {
        keys.open(keys::place(id.as_u64(), field), value.bytes(field)?)
            .map(|(secret, _)| secret)
            .map_err(|unopened| match unopened {
                Unopened::NoKey(key) => CodecError::NoKey(key),
                // A secret is never a tenant's.
                Unopened::Erased | Unopened::Damaged => CodecError::Invalid("sealed secret"),
            })
    };
    let (mut kind, mut account, mut name, mut selector, mut key) = (None, None, None, None, None);
    let (mut headers, mut configuration, mut identities) = (None, None, None);
    let (mut configurations, mut tenants, mut secret_kind) = (None, None, None);
    let (mut handle, mut secret, mut url, mut events) = (None, None, None, None);
    let (mut address, mut helo, mut pool, mut daily_cap) = (None, None, None, None);
    let (mut recipients_per_second, mut bytes_per_second, mut daily_quota) = (None, None, None);
    let (mut paused_kind, mut paused, mut accepting, mut reason) = (None, None, None, None);
    let (mut unsigned, mut verification, mut verified_since, mut permissions) =
        (None, None, None, None);
    let (mut mail_from, mut mail_from_rejects, mut mail_from_status, mut mail_from_since) =
        (None, None, None, None);
    let (mut tags, mut created, mut reputation_metrics) = (Vec::new(), None, None);
    let (mut topic, mut confirmed, mut disabled) = (None, None, None);
    let (mut site_caps, mut warmed, mut caps_changed) = (BTreeMap::new(), None, None);
    let (mut subject, mut text_part, mut html, mut templates) = (None, None, None, None);
    let text = |bytes: &[u8], what| {
        std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| CodecError::Invalid(what))
    };
    while let Some((field, value)) = reader.next()? {
        match field {
            KIND => kind = Some(value.uint(field)?),
            ACCOUNT => account = Some(AccountId(id_of(value.uint(field)?)?)),
            NAME => name = Some(text(value.bytes(field)?, "name")?),
            SELECTOR => selector = Some(text(value.bytes(field)?, "selector")?),
            KEY => key = Some(text(&open(field, value)?, "key")?),
            HEADERS => headers = Some(text(value.bytes(field)?, "headers")?),
            CONFIGURATION => configuration = Some(ConfigurationId(id_of(value.uint(field)?)?)),
            IDENTITIES => identities = Some(unpack(value.bytes(field)?, IdentityId)?),
            CONFIGURATIONS => configurations = Some(unpack(value.bytes(field)?, ConfigurationId)?),
            TENANTS => tenants = Some(unpack(value.bytes(field)?, TenantId)?),
            SECRET_KIND => secret_kind = Some(value.uint(field)?),
            HANDLE => handle = Some(text(value.bytes(field)?, "handle")?),
            SECRET => secret = Some(open(field, value)?),
            RECIPIENTS_PER_SECOND => {
                recipients_per_second = Some(
                    u32::try_from(value.uint(field)?).map_err(|_| CodecError::Invalid("rate"))?,
                );
            }
            BYTES_PER_SECOND => bytes_per_second = Some(value.uint(field)?),
            DAILY_QUOTA => daily_quota = Some(value.uint(field)?),
            URL => url = Some(text(value.bytes(field)?, "url")?),
            EVENTS => events = Some(value.uint(field)?),
            ADDRESS => {
                let bytes = value.bytes(field)?;
                address = Some(match bytes.len() {
                    4 => IpAddr::from(<[u8; 4]>::try_from(bytes).expect("four bytes")),
                    16 => IpAddr::from(<[u8; 16]>::try_from(bytes).expect("sixteen bytes")),
                    _ => return Err(CodecError::Invalid("address")),
                });
            }
            HELO => helo = Some(text(value.bytes(field)?, "helo")?),
            POOL => pool = Some(PoolId(id_of(value.uint(field)?)?)),
            DAILY_CAP => daily_cap = Some(value.uint(field)?),
            PAUSED_KIND => paused_kind = Some(value.uint(field)?),
            PAUSED => paused = Some(id_of(value.uint(field)?)?),
            ACCEPTING => accepting = Some(value.uint(field)?),
            REASON => reason = Some(text(value.bytes(field)?, "reason")?),
            UNSIGNED => unsigned = Some(value.uint(field)?),
            VERIFICATION => verification = Some(value.uint(field)?),
            VERIFIED_SINCE => verified_since = Some(value.uint(field)?),
            PERMISSIONS => permissions = Some(value.uint(field)?),
            MAIL_FROM => mail_from = Some(text(value.bytes(field)?, "mail from")?),
            MAIL_FROM_REJECTS => mail_from_rejects = Some(value.uint(field)?),
            MAIL_FROM_STATUS => mail_from_status = Some(value.uint(field)?),
            MAIL_FROM_SINCE => mail_from_since = Some(value.uint(field)?),
            TAGS => tags = unpack_tags(value.bytes(field)?)?,
            CREATED => created = Some(Timestamp::from_micros(value.uint(field)?)),
            SUBJECT => subject = Some(text(value.bytes(field)?, "subject")?),
            TEXT => text_part = Some(text(value.bytes(field)?, "text")?),
            HTML => html = Some(text(value.bytes(field)?, "html")?),
            TEMPLATES => templates = Some(unpack(value.bytes(field)?, TemplateId)?),
            REPUTATION_METRICS => reputation_metrics = Some(value.uint(field)?),
            TOPIC => topic = Some(TopicId(id_of(value.uint(field)?)?)),
            CONFIRMED => confirmed = Some(value.uint(field)?),
            DISABLED => disabled = Some(value.uint(field)?),
            SITE_CAPS => site_caps = unpack_site_caps(value.bytes(field)?)?,
            WARMED => warmed = Some(unpack_warmed(value.bytes(field)?)?),
            CAPS_CHANGED => caps_changed = Some(PolicyRevision(value.uint(field)?)),
            other => return Err(CodecError::UnknownField(other)),
        }
    }
    let limits = Limits {
        recipients_per_second,
        bytes_per_second,
    };
    if kind == Some(4) {
        return Ok(Record::Account(Account {
            id: AccountId(id),
            limits,
            daily_quota,
        }));
    }
    let account = account.ok_or(CodecError::Missing("account"))?;
    fn set<T: Ord>(ids: Option<Vec<T>>) -> Option<BTreeSet<T>> {
        ids.map(|ids| ids.into_iter().collect())
    }
    Ok(match kind.ok_or(CodecError::Missing("kind"))? {
        0 => Record::Identity(Identity {
            id: IdentityId(id),
            account,
            name: name.ok_or(CodecError::Missing("name"))?,
            signing: match (selector, key, headers) {
                (Some(selector), Some(key), Some(headers)) => Some(Signing {
                    selector,
                    key,
                    headers: headers.split(':').map(str::to_owned).collect(),
                }),
                (None, None, None) => None,
                _ => return Err(CodecError::Missing("signing")),
            },
            signs: match unsigned {
                None => true,
                Some(1) => false,
                Some(_) => return Err(CodecError::Invalid("unsigned")),
            },
            configuration,
            tags,
            verification: match (verification, verified_since) {
                (None, None) => None,
                (Some(status), Some(since)) => Some(Check {
                    status: status_of(status)?,
                    since: Timestamp::from_micros(since),
                }),
                _ => return Err(CodecError::Missing("verification")),
            },
            mail_from: match (mail_from, mail_from_status, mail_from_since) {
                (None, None, None) if mail_from_rejects.is_none() => None,
                (Some(domain), Some(status), Some(since)) => Some(MailFrom {
                    domain: domain.into(),
                    behavior: match mail_from_rejects {
                        None => OnMxFailure::UseDefault,
                        Some(1) => OnMxFailure::Reject,
                        Some(_) => return Err(CodecError::Invalid("mail from behavior")),
                    },
                    check: Check {
                        status: status_of(status)?,
                        since: Timestamp::from_micros(since),
                    },
                }),
                _ => return Err(CodecError::Missing("mail from")),
            },
        }),
        1 => Record::Tenant(Tenant {
            id: TenantId(id),
            account,
            name: name.ok_or(CodecError::Missing("name"))?,
            identities: set(identities).ok_or(CodecError::Missing("identities"))?,
            templates: set(templates).unwrap_or_default(),
            configurations: set(configurations).ok_or(CodecError::Missing("configurations"))?,
            limits,
            tags,
            created,
        }),
        2 => Record::Configuration(Configuration {
            id: ConfigurationId(id),
            account,
            name: name.ok_or(CodecError::Missing("name"))?,
            pool,
            tags,
            reputation_metrics: match reputation_metrics {
                None => false,
                Some(1) => true,
                Some(_) => return Err(CodecError::Invalid("reputation metrics")),
            },
        }),
        6 => Record::Pool(Pool {
            id: PoolId(id),
            account,
            name: name.ok_or(CodecError::Missing("name"))?,
        }),
        7 => Record::Egress(Egress {
            id: EgressId(id),
            account,
            address: address.ok_or(CodecError::Missing("address"))?,
            helo: helo.ok_or(CodecError::Missing("helo"))?,
            pool,
            caps: Caps {
                daily: daily_cap,
                sites: site_caps,
                warmed,
                changed: caps_changed.unwrap_or_default(),
            },
        }),
        8 => {
            let paused_id = || paused.ok_or(CodecError::Missing("paused"));
            Record::Hold(Hold {
                id: HoldId(id),
                account,
                paused: match paused_kind.ok_or(CodecError::Missing("paused kind"))? {
                    0 => Paused::Account,
                    1 => Paused::Tenant(TenantId(paused_id()?)),
                    2 => Paused::Configuration(ConfigurationId(paused_id()?)),
                    3 => Paused::Identity(IdentityId(paused_id()?)),
                    4 => Paused::Egress(EgressId(paused_id()?)),
                    _ => return Err(CodecError::Invalid("paused kind")),
                },
                accepting: match accepting.ok_or(CodecError::Missing("accepting"))? {
                    0 => false,
                    1 => true,
                    _ => return Err(CodecError::Invalid("accepting")),
                },
                reason: reason.ok_or(CodecError::Missing("reason"))?,
            })
        }
        3 => {
            let handle = handle.ok_or(CodecError::Missing("handle"))?;
            let secret = secret.ok_or(CodecError::Missing("secret"))?;
            Record::Credential(Credential {
                id: CredentialId(id),
                account,
                secret: match secret_kind.ok_or(CodecError::Missing("secret kind"))? {
                    0 => Secret::Login {
                        user: handle,
                        password_sha256: <[u8; 32]>::try_from(secret.as_slice())
                            .map_err(|_| CodecError::Invalid("password digest"))?,
                    },
                    1 => Secret::AccessKey {
                        id: handle,
                        secret: text(&secret, "secret")?,
                    },
                    _ => return Err(CodecError::Invalid("secret kind")),
                },
                identities: set(identities).map_or(Scope::Any, Scope::Only),
                tenants: set(tenants).map_or(Scope::Any, Scope::Only),
                permissions: match permissions {
                    None => Permissions::SENDS,
                    // Stored only when it is not that, and never as nothing.
                    Some(bits @ (2 | 3)) => Permissions {
                        sends: bits & 1 == 1,
                        manages: true,
                    },
                    Some(_) => return Err(CodecError::Invalid("permissions")),
                },
            })
        }
        5 => {
            let events = events.ok_or(CodecError::Missing("events"))?;
            if events >> EventKind::ALL.len() != 0 {
                return Err(CodecError::Invalid("events"));
            }
            Record::Subscription(Subscription {
                id: SubscriptionId(id),
                account,
                name: name.ok_or(CodecError::Missing("name"))?,
                configuration: configuration.ok_or(CodecError::Missing("configuration"))?,
                url: url.ok_or(CodecError::Missing("url"))?,
                events: events_of(events),
                secret: <[u8; 32]>::try_from(
                    secret.ok_or(CodecError::Missing("secret"))?.as_slice(),
                )
                .map_err(|_| CodecError::Invalid("signing key"))?,
            })
        }
        9 => Record::Topic(Topic {
            id: TopicId(id),
            account,
            name: name.ok_or(CodecError::Missing("name"))?,
        }),
        10 => Record::Subscriber(Subscriber {
            id: SubscriptionId(id),
            account,
            topic: topic.ok_or(CodecError::Missing("topic"))?,
            endpoint: url.ok_or(CodecError::Missing("url"))?,
            token: <[u8; 32]>::try_from(secret.ok_or(CodecError::Missing("secret"))?.as_slice())
                .map_err(|_| CodecError::Invalid("token"))?,
            confirmed: match confirmed {
                None => false,
                Some(1) => true,
                Some(_) => return Err(CodecError::Invalid("confirmed")),
            },
        }),
        11 => {
            let events = events.ok_or(CodecError::Missing("events"))?;
            if events >> EventKind::ALL.len() != 0 {
                return Err(CodecError::Invalid("events"));
            }
            Record::Destination(Destination {
                id: DestinationId(id),
                account,
                configuration: configuration.ok_or(CodecError::Missing("configuration"))?,
                name: name.ok_or(CodecError::Missing("name"))?,
                topic: topic.ok_or(CodecError::Missing("topic"))?,
                events: events_of(events),
                enabled: match disabled {
                    None => true,
                    Some(1) => false,
                    Some(_) => return Err(CodecError::Invalid("disabled")),
                },
            })
        }
        12 => Record::Template(Template {
            id: TemplateId(id),
            account,
            name: name.ok_or(CodecError::Missing("name"))?,
            created: created.ok_or(CodecError::Missing("created"))?,
            content: TemplateContent {
                subject: subject.ok_or(CodecError::Missing("subject"))?,
                text: text_part,
                html,
            },
        }),
        _ => return Err(CodecError::Invalid("policy kind")),
    })
}

/// IDs packed in 8 bytes each, big-endian.
pub fn encode_report(report: &Report, tenant: Option<TenantId>, keys: Option<&Keys>) -> Vec<u8> {
    use report_field::*;
    let sealing = Sealing::of(
        keys,
        tenant_of(tenant),
        Sealed::Report,
        report.id.0.as_u64(),
    );
    let mut writer = Writer::new(REPORT_VERSION);
    if let Some(message) = report.message {
        writer.uint(MESSAGE, message.0.as_u64());
    }
    match &report.kind {
        Kind::DeliveryStatus => writer.uint(KIND, 0),
        Kind::Feedback(feedback_type) => {
            writer.uint(KIND, 1);
            writer.bytes(FEEDBACK_TYPE, feedback_type.as_bytes());
        }
        Kind::Unrecognised => writer.uint(KIND, 2),
    }
    let mut claims = Vec::new();
    for (index, claim) in report.recipients.iter().enumerate() {
        // Each claim's fields are sealed in places of its own.
        let within = sealing.map(|sealing| sealing.nested(index));
        let mut nested = Writer::new(CLAIM_VERSION);
        nested.sealed(
            claim_field::ADDRESS,
            claim.address.as_str().as_bytes(),
            within,
        );
        nested.uint(claim_field::FAILED, u64::from(claim.failed));
        if let Some(status) = claim.status {
            nested.uint(claim_field::STATUS, pack_status(status));
        }
        if let Some(diagnostic) = &claim.diagnostic {
            nested.sealed(claim_field::DIAGNOSTIC, diagnostic.as_bytes(), within);
        }
        if claim.rules_out_address {
            nested.uint(claim_field::RULES_OUT_ADDRESS, 1);
        }
        let nested = nested.finish();
        let length = u32::try_from(nested.len()).expect("a claim is small");
        claims.extend_from_slice(&length.to_be_bytes());
        claims.extend_from_slice(&nested);
    }
    writer.bytes(CLAIMS, &claims);
    writer.uint(RECEIVED_AT, report.received_at.as_micros());
    writer.sealed(EVIDENCE, &report.evidence, sealing);
    if report.authenticated {
        writer.uint(AUTHENTICATED, 1);
    }
    if !report.trusted {
        writer.uint(UNTRUSTED, 1);
    }
    writer.finish()
}

pub fn decode_report(
    id: ReportId,
    identity: [u8; 32],
    record: &[u8],
    keys: Option<&Keys>,
) -> Result<Report, CodecError> {
    use report_field::*;
    let sealing = Sealing::of(keys, None, Sealed::Report, id.0.as_u64());
    let mut reader = Reader::new(record, REPORT_VERSION)?;
    let (mut message, mut kind, mut feedback_type, mut received_at, mut evidence) =
        (None, None, None, None, None);
    let (mut authenticated, mut trusted) = (false, true);
    let mut recipients = Vec::new();
    while let Some((field, value)) = reader.next()? {
        match field {
            MESSAGE => message = Some(MessageId(id_of(value.uint(field)?)?)),
            KIND => kind = Some(value.uint(field)?),
            FEEDBACK_TYPE => feedback_type = Some(text_of(value.bytes(field)?, "feedback type")?),
            CLAIMS => {
                let mut rest = value.bytes(field)?;
                while let Some((length, after)) = rest.split_first_chunk::<4>() {
                    let length = u32::from_be_bytes(*length) as usize;
                    let nested = after.get(..length).ok_or(CodecError::Truncated)?;
                    let within = sealing.map(|sealing| sealing.nested(recipients.len()));
                    recipients.push(decode_claim(nested, within)?);
                    rest = &after[length..];
                }
                if !rest.is_empty() {
                    return Err(CodecError::Truncated);
                }
            }
            RECEIVED_AT => received_at = Some(Timestamp::from_micros(value.uint(field)?)),
            EVIDENCE => {
                evidence = Some(bytes::Bytes::from(
                    opened(value, field, sealing, b"")?.into_owned(),
                ));
            }
            AUTHENTICATED => authenticated = value.uint(field)? == 1,
            UNTRUSTED => trusted = value.uint(field)? != 1,
            other => return Err(CodecError::UnknownField(other)),
        }
    }
    let kind = match kind.ok_or(CodecError::Missing("kind"))? {
        0 => Kind::DeliveryStatus,
        1 => Kind::Feedback(feedback_type.ok_or(CodecError::Missing("feedback type"))?),
        2 => Kind::Unrecognised,
        _ => return Err(CodecError::Invalid("report kind")),
    };
    Ok(Report {
        id,
        message,
        kind,
        recipients,
        identity,
        evidence: evidence.ok_or(CodecError::Missing("evidence"))?,
        received_at: received_at.ok_or(CodecError::Missing("received time"))?,
        authenticated,
        trusted,
        simulated: false,
    })
}

fn decode_claim(record: &[u8], sealing: Option<Sealing<'_>>) -> Result<Claim, CodecError> {
    use claim_field::*;
    let mut reader = Reader::new(record, CLAIM_VERSION)?;
    let (mut address, mut failed, mut status, mut diagnostic) = (None, None, None, None);
    let mut rules_out_address = false;
    while let Some((field, value)) = reader.next()? {
        match field {
            ADDRESS => {
                let text = text_of(&opened(value, field, sealing, ERASED_ADDRESS)?, "address")?;
                address = Some(Address::parse(&text).map_err(|_| CodecError::Invalid("address"))?);
            }
            FAILED => failed = Some(value.uint(field)? == 1),
            STATUS => status = Some(unpack_status(value.uint(field)?)?),
            DIAGNOSTIC => {
                diagnostic = Some(text_of(
                    &opened(value, field, sealing, ERASED_TEXT)?,
                    "diagnostic",
                )?);
            }
            RULES_OUT_ADDRESS => rules_out_address = value.uint(field)? == 1,
            other => return Err(CodecError::UnknownField(other)),
        }
    }
    Ok(Claim {
        address: address.ok_or(CodecError::Missing("address"))?,
        failed: failed.ok_or(CodecError::Missing("failed"))?,
        status,
        rules_out_address,
        diagnostic,
    })
}

/// A status in one number: its class, subject and detail.
fn pack_status(status: Status) -> u64 {
    (u64::from(status.class) << 32) | (u64::from(status.subject) << 16) | u64::from(status.detail)
}

fn unpack_status(packed: u64) -> Result<Status, CodecError> {
    let invalid = || CodecError::Invalid("status");
    let status = Status {
        class: u8::try_from(packed >> 32).map_err(|_| invalid())?,
        subject: u16::try_from((packed >> 16) & 0xffff).map_err(|_| invalid())?,
        detail: u16::try_from(packed & 0xffff).map_err(|_| invalid())?,
    };
    Status::parse(&status.to_string()).ok_or_else(invalid)
}

fn text_of(bytes: &[u8], what: &'static str) -> Result<String, CodecError> {
    String::from_utf8(bytes.to_vec()).map_err(|_| CodecError::Invalid(what))
}

/// `text` after its length, in 4 bytes, big-endian.
fn pack_text(packed: &mut Vec<u8>, text: &str) {
    let length = u32::try_from(text.len()).expect("a packed text is short");
    packed.extend_from_slice(&length.to_be_bytes());
    packed.extend_from_slice(text.as_bytes());
}

/// The text at the front of `packed`, which then holds what follows.
fn unpack_text(packed: &mut &[u8]) -> Result<String, CodecError> {
    let invalid = || CodecError::Invalid("packed text");
    let (length, rest) = packed.split_first_chunk::<4>().ok_or_else(invalid)?;
    let length = usize::try_from(u32::from_be_bytes(*length)).map_err(|_| invalid())?;
    let (text, rest) = rest.split_at_checked(length).ok_or_else(invalid)?;
    *packed = rest;
    text_of(text, "packed text")
}

fn pack_tags(tags: &[Tag]) -> Vec<u8> {
    let mut packed = Vec::new();
    for tag in tags {
        pack_text(&mut packed, &tag.key);
        pack_text(&mut packed, &tag.value);
    }
    packed
}

fn unpack_tags(mut packed: &[u8]) -> Result<Vec<Tag>, CodecError> {
    let mut tags = Vec::new();
    while !packed.is_empty() {
        let key = unpack_text(&mut packed)?;
        let value = unpack_text(&mut packed)?;
        tags.push(Tag { key, value });
    }
    Ok(tags)
}

fn pack(ids: impl Iterator<Item = Id>) -> Vec<u8> {
    ids.flat_map(|id| id.as_u64().to_be_bytes()).collect()
}

fn unpack<T>(packed: &[u8], typed: fn(Id) -> T) -> Result<Vec<T>, CodecError> {
    if !packed.len().is_multiple_of(8) {
        return Err(CodecError::Invalid("packed IDs"));
    }
    packed
        .as_chunks::<8>()
        .0
        .iter()
        .map(|id| id_of(u64::from_be_bytes(*id)).map(typed))
        .collect()
}

fn id_of(value: u64) -> Result<Id, CodecError> {
    Id::from_u64(value).ok_or(CodecError::Invalid("ID"))
}

fn u32_of(value: u64) -> Result<u32, CodecError> {
    u32::try_from(value).map_err(|_| CodecError::Invalid("count"))
}

#[cfg(test)]
mod tests {
    use engine_core::delivery::Disposition;
    use engine_core::id::{IdGenerator, Lane, Shard};

    use super::*;
    use crate::golden;

    const NOW: Timestamp = Timestamp::from_micros(1_800_000_000_000_000);

    fn later(seconds: u64) -> Timestamp {
        NOW.saturating_add(std::time::Duration::from_secs(seconds))
    }

    fn ids() -> IdGenerator {
        IdGenerator::new(Shard::new(2), Lane::new(1).expect("a lane"), None)
    }

    #[test]
    fn a_tally_in_part_and_a_site_named_twice_are_refused() {
        use window_field::*;
        // The ledger's row with today's counts but not their day.
        let window = Window::default();
        let (newest, counts) = window.parts();
        let mut writer = Writer::new(WINDOW_VERSION);
        writer.uint(NEWEST, newest);
        let bytes: Vec<u8> = counts
            .iter()
            .flat_map(|count| count.to_be_bytes())
            .collect();
        writer.bytes(COUNTS, &bytes);
        writer.bytes(TODAY, &pack_counts(&Counts::default()));
        assert_eq!(
            decode_dispatched(&writer.finish()),
            Err(CodecError::Invalid("a tally in part"))
        );
        // A site's cap given twice, or its judgment, opens as neither.
        let mut caps = Vec::new();
        for cap in [Some(50_u64), None] {
            pack_text(&mut caps, "Google");
            match cap {
                Some(cap) => {
                    caps.push(1);
                    caps.extend_from_slice(&cap.to_be_bytes());
                }
                None => caps.push(0),
            }
        }
        assert!(unpack_site_caps(&caps).is_err());
        let judgment = Judgment {
            counts: Counts::default(),
            verdict: Verdict::Untested,
        };
        let mut warmed = 20_390_u64.to_be_bytes().to_vec();
        pack_judgment(&mut warmed, &judgment);
        for _ in 0..2 {
            pack_text(&mut warmed, "Google");
            pack_judgment(&mut warmed, &judgment);
        }
        assert!(unpack_warmed(&warmed).is_err());
    }

    #[test]
    fn messages_round_trip() {
        let mut ids = ids();
        let named = (TenantId(ids.next(NOW)), ConfigurationId(ids.next(NOW)));
        for (case, tenant, configuration) in [
            ("plain", None, None),
            ("named", Some(named.0), Some(named.1)),
        ] {
            let message = Message {
                id: MessageId(ids.next(NOW)),
                submission: SubmissionId(ids.next(NOW)),
                account: AccountId(ids.next(NOW)),
                origin: Origin {
                    identity: IdentityId(ids.next(NOW)),
                    tenant,
                    configuration,
                },
                body: BodyId(ids.next(NOW)),
                accepted_at: NOW,
                policy_revision: PolicyRevision(7),
                recipients: 2,
            };
            let kept = golden::record("message", MESSAGE_VERSION, case, &encode_message(&message));
            assert_eq!(decode_message(message.id, &kept), Ok(message));
        }
    }

    #[test]
    fn deliveries_round_trip_in_every_state() {
        let mut ids = ids();
        let mut delivery = Delivery::new(
            DeliveryId(ids.next(NOW)),
            MessageId(ids.next(NOW)),
            AccountId(ids.next(NOW)),
            Origin {
                identity: IdentityId(ids.next(NOW)),
                tenant: Some(TenantId(ids.next(NOW))),
                configuration: None,
            },
            Address::parse("\"Quoted Name\"@Example.com").expect("a valid address"),
            NOW,
            later(3_600),
        )
        .expect("due before it expires");
        // Plain, and sealed under the installation's keys.
        let keys = Keys::new(Arc::new(Keyring::new(&[(1, [5; 32])]).unwrap()));
        let round_trip = |case: &str, delivery: &Delivery| {
            let sealed = golden::record(
                "delivery",
                DELIVERY_VERSION,
                &format!("{case}-sealed"),
                &encode_delivery(delivery, None, Some(&keys)),
            );
            assert!(
                !sealed.windows(6).any(|window| window == b"Quoted"),
                "its recipient is sealed"
            );
            assert_eq!(
                decode_delivery(delivery.id(), &sealed, Some(&keys)).as_ref(),
                Ok(delivery)
            );
            let plain = golden::record(
                "delivery",
                DELIVERY_VERSION,
                case,
                &encode_delivery(delivery, None, None),
            );
            decode_delivery(delivery.id(), &plain, None)
        };
        assert_eq!(round_trip("waiting", &delivery).as_ref(), Ok(&delivery));

        let permit = delivery
            .reserve(
                delivery.generation(),
                AttemptId(ids.next(NOW)),
                Some(EgressId(ids.next(NOW))),
                later(1),
            )
            .expect("due");
        assert_eq!(round_trip("in-flight", &delivery).as_ref(), Ok(&delivery));
        let retry = Disposition::Uncertain {
            not_before: later(60),
        };
        delivery
            .record_outcome(permit, retry, later(2))
            .expect("in flight");
        assert_eq!(round_trip("uncertain", &delivery).as_ref(), Ok(&delivery));

        let egress = Some(EgressId(ids.next(NOW)));
        delivery
            .park(delivery.generation(), egress, later(3))
            .expect("waiting");
        assert_eq!(round_trip("held", &delivery).as_ref(), Ok(&delivery));
        delivery.release(delivery.generation()).expect("held");

        let permit = delivery
            .reserve(
                delivery.generation(),
                AttemptId(ids.next(NOW)),
                None,
                later(60),
            )
            .expect("due");
        delivery
            .record_outcome(permit, Disposition::Rejected, later(61))
            .expect("in flight");
        let reply = Evidence::new(550, "5.1.1 <a@example.com>: no such user");
        delivery.heard(Some(&reply), 1 << 40);
        assert_eq!(round_trip("rejected", &delivery).as_ref(), Ok(&delivery));
        assert_eq!(delivery.reply_entry(), Some(1 << 40));
    }

    #[test]
    fn entries_round_trip() {
        let mut ids = ids();
        let account = AccountId(ids.next(NOW));
        let configuration = Some(ConfigurationId(ids.next(NOW)));
        let attempt = |ids: &mut IdGenerator, result| Attempt {
            id: AttemptId(ids.next(NOW)),
            delivery: DeliveryId(ids.next(NOW)),
            account,
            reserved_at: NOW,
            ended: Some(AttemptEnd {
                result,
                at: later(5),
            }),
        };
        let entries = [
            (
                "accepted",
                Entry::Accepted {
                    message: MessageId(ids.next(NOW)),
                    account,
                    configuration,
                    deliveries: vec![DeliveryId(ids.next(NOW)), DeliveryId(ids.next(NOW))],
                    at: NOW,
                },
            ),
            (
                "rejected",
                Entry::Attempted {
                    attempt: attempt(&mut ids, AttemptResult::Rejected),
                    configuration,
                    evidence: Some(Evidence::new(550, "5.1.1 No such user")),
                },
            ),
            (
                "abandoned",
                Entry::Attempted {
                    attempt: attempt(&mut ids, AttemptResult::Abandoned),
                    configuration: None,
                    evidence: None,
                },
            ),
            (
                "expired",
                Entry::Expired {
                    delivery: DeliveryId(ids.next(NOW)),
                    account,
                    configuration,
                    at: later(9),
                },
            ),
            (
                "suppressed",
                Entry::Suppressed {
                    delivery: DeliveryId(ids.next(NOW)),
                    account,
                    configuration: None,
                    at: later(10),
                },
            ),
            (
                "cancelled",
                Entry::Cancelled {
                    delivery: DeliveryId(ids.next(NOW)),
                    account,
                    configuration,
                    at: later(11),
                },
            ),
            (
                "bounced",
                Entry::Bounced {
                    delivery: DeliveryId(ids.next(NOW)),
                    account,
                    configuration,
                    report: ReportId(ids.next(NOW)),
                    status: Status::parse("5.1.1"),
                    authenticated: true,
                    at: later(12),
                },
            ),
            (
                "complained",
                Entry::Complained {
                    delivery: DeliveryId(ids.next(NOW)),
                    account,
                    configuration: None,
                    report: ReportId(ids.next(NOW)),
                    feedback_type: "abuse".to_owned(),
                    authenticated: false,
                    at: later(13),
                },
            ),
        ];
        let keys = Keys::new(Arc::new(Keyring::new(&[(1, [5; 32])]).unwrap()));
        for (case, entry) in entries {
            let sealed = golden::record(
                "entry",
                ENTRY_VERSION,
                &format!("{case}-sealed"),
                &encode_entry(&entry, None, Some(&keys)),
            );
            assert_eq!(decode_entry(&sealed, Some(&keys)), Ok(entry.clone()));
            let plain = golden::record(
                "entry",
                ENTRY_VERSION,
                case,
                &encode_entry(&entry, None, None),
            );
            assert_eq!(decode_entry(&plain, None), Ok(entry));
        }
    }

    #[test]
    fn what_holds_personal_data_reads_back_sealed_and_shows_none_of_it() {
        let mut ids = ids();
        let keys = Keys::new(Arc::new(Keyring::new(&[(2, [6; 32])]).unwrap()));
        let secret = |record: &[u8]| record.windows(5).any(|window| window == b"alice");
        let report = Report {
            id: ReportId(ids.next(NOW)),
            message: Some(MessageId(ids.next(NOW))),
            kind: Kind::DeliveryStatus,
            recipients: vec![
                Claim {
                    address: Address::parse("alice@example.com").unwrap(),
                    failed: true,
                    status: Status::parse("5.1.1"),
                    rules_out_address: true,
                    diagnostic: Some("550 alice unknown".to_owned()),
                },
                Claim {
                    address: Address::parse("bob@example.com").unwrap(),
                    failed: false,
                    status: None,
                    rules_out_address: false,
                    diagnostic: Some("550 alice unknown".to_owned()),
                },
            ],
            identity: [3; 32],
            evidence: bytes::Bytes::from_static(b"To: alice@example.com\r\n"),
            received_at: NOW,
            authenticated: false,
            trusted: true,
            simulated: false,
        };
        let sealed = golden::record(
            "report",
            REPORT_VERSION,
            "sealed",
            &encode_report(&report, None, Some(&keys)),
        );
        assert!(!secret(&sealed));
        let plain = golden::record(
            "report",
            REPORT_VERSION,
            "plain",
            &encode_report(&report, None, None),
        );
        assert_eq!(
            decode_report(report.id, report.identity, &plain, None),
            Ok(report.clone())
        );
        assert_eq!(
            decode_report(report.id, report.identity, &sealed, Some(&keys)),
            Ok(report.clone())
        );
        assert_eq!(
            decode_report(report.id, report.identity, &sealed, None),
            Err(CodecError::Encrypted)
        );
        let message = MessageId(ids.next(NOW));
        let mail = Mail {
            source: "news@brand.test".to_owned(),
            destination: vec!["alice@example.com".to_owned()],
            headers: bytes::Bytes::from_static(b"To: alice@example.com\r\n"),
            truncated: false,
            tags: vec![("list".to_owned(), "alice".to_owned())],
        };
        let sealed = golden::record(
            "mail",
            MAIL_VERSION,
            "sealed",
            &encode_mail(&mail, message, None, Some(&keys)),
        );
        assert!(!secret(&sealed));
        assert_eq!(decode_mail(&sealed, message, Some(&keys)), Ok(mail.clone()));
        let plain = golden::record(
            "mail",
            MAIL_VERSION,
            "plain",
            &encode_mail(&mail, message, None, None),
        );
        assert_eq!(decode_mail(&plain, message, None), Ok(mail));
        let account = AccountId(ids.next(NOW));
        let alice = Address::parse("alice@example.com").unwrap();
        let sealed = golden::record(
            "suppression",
            SUPPRESSION_VERSION,
            "sealed",
            &encode_suppression(account, "row a", &alice, Reason::Bounce, NOW, Some(&keys)),
        );
        assert!(!secret(&sealed));
        let plain = golden::record(
            "suppression",
            SUPPRESSION_VERSION,
            "plain",
            &encode_suppression(account, "row a", &alice, Reason::Bounce, NOW, None),
        );
        assert_eq!(
            decode_suppression(&plain, account, b"row a", None).map(|found| found.address),
            Ok(alice.clone())
        );
        assert_eq!(
            decode_suppression(&sealed, account, b"row a", Some(&keys)).map(|found| found.address),
            Ok(alice)
        );
        assert_eq!(
            decode_suppression(&sealed, account, b"row b", Some(&keys)).map(|found| found.address),
            Err(CodecError::Invalid("sealed data")),
            "a suppression's address opens in its own row alone"
        );
        let cooldown = SiteCooldown {
            egress: None,
            site: Arc::from("mx.example.com"),
            until: later(60),
            throttles: 1,
            reply: Some(Evidence::new(421, "4.7.0 alice is busy")),
        };
        let sealed = golden::record(
            "cooldown",
            COOLDOWN_VERSION,
            "sealed",
            &encode_cooldown(&cooldown, Some(&keys)),
        );
        assert!(!secret(&sealed));
        let plain = golden::record(
            "cooldown",
            COOLDOWN_VERSION,
            "plain",
            &encode_cooldown(&cooldown, None),
        );
        assert_eq!(
            decode_cooldown(None, Arc::from("mx.example.com"), later(60), &plain, None),
            Ok(cooldown.clone())
        );
        assert_eq!(
            decode_cooldown(
                None,
                Arc::from("mx.example.com"),
                later(60),
                &sealed,
                Some(&keys)
            ),
            Ok(cooldown)
        );
    }

    #[test]
    fn policy_records_round_trip() {
        let mut ids = ids();
        let account = AccountId(ids.next(NOW));
        let identity = IdentityId(ids.next(NOW));
        let tenant = TenantId(ids.next(NOW));
        let configuration = ConfigurationId(ids.next(NOW));
        let pool = PoolId(ids.next(NOW));
        let records = [
            Record::Identity(Identity {
                id: identity,
                account,
                name: "example.test".to_owned(),
                signing: Some(Signing {
                    selector: "s1".to_owned(),
                    key: "-----BEGIN PRIVATE KEY-----\n...\n".to_owned(),
                    headers: vec!["From".to_owned(), "Subject".to_owned()],
                }),
                signs: false,
                configuration: Some(configuration),
                tags: vec![Tag {
                    key: "Application".to_owned(),
                    value: "nitrosend".to_owned(),
                }],
                verification: Some(Check {
                    status: Verification::TemporaryFailure,
                    since: NOW,
                }),
                mail_from: Some(MailFrom {
                    domain: "bounces.example.test".into(),
                    behavior: OnMxFailure::Reject,
                    check: Check {
                        status: Verification::Success,
                        since: NOW,
                    },
                }),
            }),
            Record::Identity(Identity {
                id: IdentityId(ids.next(NOW)),
                account,
                name: "ceo@example.test".to_owned(),
                signing: None,
                signs: true,
                configuration: None,
                tags: Vec::new(),
                verification: None,
                mail_from: None,
            }),
            Record::Tenant(Tenant {
                id: tenant,
                account,
                name: "acme".to_owned(),
                identities: BTreeSet::from([identity]),
                templates: BTreeSet::new(),
                configurations: BTreeSet::new(),
                limits: Limits {
                    recipients_per_second: Some(5),
                    bytes_per_second: Some(1 << 20),
                },
                tags: vec![
                    Tag {
                        key: "DeliverabilityCohort".to_owned(),
                        value: "a".to_owned(),
                    },
                    Tag {
                        key: "empty".to_owned(),
                        value: String::new(),
                    },
                ],
                created: Some(NOW),
            }),
            Record::Account(Account {
                id: account,
                limits: Limits {
                    recipients_per_second: Some(14),
                    bytes_per_second: None,
                },
                daily_quota: Some(50_000),
            }),
            Record::Configuration(Configuration {
                id: configuration,
                account,
                name: "receipts".to_owned(),
                pool: Some(pool),
                tags: Vec::new(),
                reputation_metrics: true,
            }),
            Record::Pool(Pool {
                id: pool,
                account,
                name: "transactional".to_owned(),
            }),
            Record::Egress(Egress {
                id: EgressId(ids.next(NOW)),
                account,
                address: "203.0.113.7".parse().unwrap(),
                helo: "mta1.example.test".to_owned(),
                pool: Some(pool),
                caps: Caps {
                    daily: Some(5_000),
                    sites: BTreeMap::from([
                        (Arc::from("Google"), Some(10_000)),
                        (Arc::from("Yahoo"), None),
                    ]),
                    warmed: Some(Warmed {
                        day: 20_390,
                        pool: Judgment {
                            counts: Counts {
                                delivered: 40,
                                ..Counts::default()
                            },
                            verdict: Verdict::Untested,
                        },
                        sites: BTreeMap::from([
                            (
                                Arc::from("Google"),
                                Judgment {
                                    counts: Counts {
                                        delivered: 4_990,
                                        deferred: 3,
                                        throttled: 0,
                                        failed: 7,
                                        complained: 1,
                                    },
                                    verdict: Verdict::Raised,
                                },
                            ),
                            (
                                Arc::from("Microsoft"),
                                Judgment {
                                    counts: Counts {
                                        delivered: 900,
                                        throttled: 12,
                                        ..Counts::default()
                                    },
                                    verdict: Verdict::Lowered(Signal::Throttled),
                                },
                            ),
                            (
                                Arc::from("Yahoo"),
                                Judgment {
                                    counts: Counts::default(),
                                    verdict: Verdict::Set,
                                },
                            ),
                        ]),
                    }),
                    changed: PolicyRevision(12),
                },
            }),
            Record::Egress(Egress {
                id: EgressId(ids.next(NOW)),
                account,
                address: "2001:db8::7".parse().unwrap(),
                helo: "mta2.example.test".to_owned(),
                pool: None,
                caps: Caps::default(),
            }),
            Record::Hold(Hold {
                id: HoldId(ids.next(NOW)),
                account,
                paused: Paused::Configuration(configuration),
                accepting: false,
                reason: "complaints from one tenant's list".to_owned(),
            }),
            Record::Hold(Hold {
                id: HoldId(ids.next(NOW)),
                account,
                paused: Paused::Account,
                accepting: true,
                reason: "billing".to_owned(),
            }),
            Record::Credential(Credential {
                id: CredentialId(ids.next(NOW)),
                account,
                secret: Secret::Login {
                    user: "app".to_owned(),
                    password_sha256: [7; 32],
                },
                identities: Scope::Any,
                tenants: Scope::Only(BTreeSet::from([tenant])),
                permissions: Permissions::SENDS,
            }),
            Record::Credential(Credential {
                id: CredentialId(ids.next(NOW)),
                account,
                secret: Secret::AccessKey {
                    id: "AKIDEXAMPLE".to_owned(),
                    secret: "secret".to_owned(),
                },
                identities: Scope::Only(BTreeSet::new()),
                tenants: Scope::Any,
                permissions: Permissions {
                    sends: false,
                    manages: true,
                },
            }),
            Record::Subscription(Subscription {
                id: SubscriptionId(ids.next(NOW)),
                account,
                name: "hooks".to_owned(),
                configuration,
                url: "https://hooks.example.test/in".to_owned(),
                events: BTreeSet::from([EventKind::Delivered, EventKind::Cancelled]),
                secret: [9; 32],
            }),
            Record::Topic(Topic {
                id: TopicId(ids.next(NOW)),
                account,
                name: "feedback".to_owned(),
            }),
            Record::Subscriber(Subscriber {
                id: SubscriptionId(ids.next(NOW)),
                account,
                topic: TopicId(ids.next(NOW)),
                endpoint: "https://hooks.example.test/ses".to_owned(),
                token: [11; 32],
                confirmed: true,
            }),
            Record::Destination(Destination {
                id: DestinationId(ids.next(NOW)),
                account,
                configuration,
                name: "receipts-feedback".to_owned(),
                topic: TopicId(ids.next(NOW)),
                events: BTreeSet::from([EventKind::Bounced, EventKind::Complained]),
                enabled: false,
            }),
            Record::Template(Template {
                id: TemplateId(ids.next(NOW)),
                account,
                name: "welcome".to_owned(),
                content: TemplateContent {
                    subject: "Welcome, {{name}}".to_owned(),
                    text: Some("Hello {{name}}".to_owned()),
                    html: None,
                },
                created: NOW,
            }),
            // A tenant with the templates it may send with.
            Record::Tenant(Tenant {
                id: TenantId(ids.next(NOW)),
                account,
                name: "beta".to_owned(),
                identities: BTreeSet::from([identity]),
                templates: BTreeSet::from([TemplateId(ids.next(NOW))]),
                configurations: BTreeSet::new(),
                limits: Limits::default(),
                tags: Vec::new(),
                created: Some(NOW),
            }),
            Record::Egress(Egress {
                id: EgressId(ids.next(NOW)),
                account,
                address: "203.0.113.9".parse().unwrap(),
                helo: "held.example.test".to_owned(),
                pool: None,
                caps: Caps {
                    daily: Some(500),
                    warmed: Some(Warmed {
                        day: 20_391,
                        pool: Judgment {
                            counts: Counts::default(),
                            verdict: Verdict::PromotionHeld,
                        },
                        sites: BTreeMap::new(),
                    }),
                    ..Caps::default()
                },
            }),
        ];
        let keys = Keyring::new(&[(1, [7; 32])]).unwrap();
        for (n, record) in records.into_iter().enumerate() {
            let kind = format!("{record:?}");
            let kind = kind.split('(').next().unwrap_or_default().to_lowercase();
            let encoded = golden::record(
                "policy",
                POLICY_VERSION,
                &format!("{n:02}-{kind}"),
                &encode_policy(&record, &keys),
            );
            assert_eq!(
                decode_policy(record.id(), &encoded, &keys),
                Ok(record.clone())
            );
            // A secret is never kept as it is.
            let secret: &[u8] = match &record {
                Record::Identity(Identity {
                    signing: Some(signing),
                    ..
                }) => signing.key.as_bytes(),
                Record::Credential(Credential {
                    secret: Secret::AccessKey { secret, .. },
                    ..
                }) => secret.as_bytes(),
                Record::Subscription(subscription) => &subscription.secret,
                Record::Subscriber(subscriber) => &subscriber.token,
                _ => continue,
            };
            assert!(
                !encoded.windows(secret.len()).any(|window| window == secret),
                "{record:?}"
            );
            // Nor opened without its key.
            let other = Keyring::new(&[(2, [8; 32])]).unwrap();
            assert_eq!(
                decode_policy(record.id(), &encoded, &other),
                Err(CodecError::NoKey(1))
            );
        }
    }

    #[test]
    fn sts_policies_and_the_dispatch_ledger_round_trip() {
        let policy = sts::Policy {
            domain: "example.com".into(),
            id: "20261030T000000".into(),
            mode: sts::Mode::Enforce,
            mx: vec!["mx1.example.com".into(), "example.net".into()],
            max_age: std::time::Duration::from_secs(604_800),
            fetched_at: NOW,
        };
        let kept = golden::record("sts", STS_VERSION, "enforce", &encode_sts(&policy));
        assert_eq!(decode_sts("example.com", NOW, &kept), Ok(policy));
        let mut counts = [0; BUCKETS];
        counts[0] = 40;
        counts[3] = 7;
        counts[BUCKETS - 1] = 1;
        let window = Window::from_parts(2_937_600, counts);
        let today = Counts {
            delivered: 47,
            deferred: 2,
            throttled: 1,
            failed: 3,
            complained: 0,
        };
        let tally = Tally::from_parts(20_391, today, Counts::default());
        let kept = golden::record(
            "dispatched",
            WINDOW_VERSION,
            "counted",
            &encode_dispatched(&window, &tally),
        );
        assert_eq!(decode_dispatched(&kept), Ok((window, tally)));
    }

    #[test]
    fn a_record_missing_a_field_or_in_an_impossible_state_is_refused() {
        let mut ids = ids();
        let delivery_id = DeliveryId(ids.next(NOW));
        let mut writer = Writer::new(DELIVERY_VERSION);
        writer.uint(delivery_field::MESSAGE, ids.next(NOW).as_u64());
        assert!(matches!(
            decode_delivery(delivery_id, &writer.finish(), None),
            Err(CodecError::Missing(_))
        ));

        // In flight, with no attempt ever reserved.
        let mut writer = Writer::new(DELIVERY_VERSION);
        writer.uint(delivery_field::MESSAGE, ids.next(NOW).as_u64());
        writer.uint(delivery_field::ACCOUNT, ids.next(NOW).as_u64());
        writer.sealed(delivery_field::RECIPIENT, b"rcpt@example.com", None);
        writer.uint(delivery_field::EXPIRES_AT, later(60).as_micros());
        writer.uint(delivery_field::GENERATION, 1);
        writer.uint(delivery_field::ATTEMPTS, 0);
        writer.uint(delivery_field::UNCERTAIN_ATTEMPTS, 0);
        writer.uint(delivery_field::STATE, 1);
        writer.uint(delivery_field::ATTEMPT, ids.next(NOW).as_u64());
        writer.uint(delivery_field::SINCE, NOW.as_micros());
        writer.uint(delivery_field::IDENTITY, ids.next(NOW).as_u64());
        assert_eq!(
            decode_delivery(delivery_id, &writer.finish(), None),
            Err(CodecError::Invalid("delivery state"))
        );
    }
}
