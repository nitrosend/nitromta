//! SMTP submission: who may log in, and the reply each outcome
//! of preparation and acceptance earns.

use aws_lc_rs::constant_time::verify_slices_are_equal;
use aws_lc_rs::digest::{SHA256, digest};
use engine_core::command::{AcceptRefusal, Commit};
use engine_core::hook::admission::Refused;
use engine_core::id::MessageId;
use engine_core::policy::{Credential, Denial, Policy, Secret};
use engine_message::prepare::Rejection;
use engine_smtp::reply::Reply;

use crate::snapshot::Unprepared;

/// The credential an SMTP AUTH login names, if the password is its own.
/// The password is compared in constant time. The engine issues every
/// password from 256 bits of randomness, so a fast hash is enough: a slow
/// one only guards secrets weak enough to guess, and none is ever chosen by
/// hand.
pub fn authenticate<'a>(policy: &'a Policy, user: &str, password: &str) -> Option<&'a Credential> {
    let credential = policy.login(user)?;
    let Secret::Login {
        password_sha256, ..
    } = &credential.secret
    else {
        return None;
    };
    let offered = digest(&SHA256, password.as_bytes());
    verify_slices_are_equal(offered.as_ref(), password_sha256)
        .ok()
        .map(|()| credential)
}

/// The reply to a transaction that would pass its account's rate.
pub fn too_fast() -> Reply {
    Reply::new(
        454,
        "4.7.0 Throttling failure: Maximum sending rate exceeded.",
    )
}

/// The reply to a transaction while the engine stops: a
/// temporary failure, which the client tries again.
pub fn shutting_down() -> Reply {
    Reply::new(451, "4.3.2 Service shutting down, try again later")
}

/// The reply to a transaction that could not be prepared.
pub fn unprepared(unprepared: &Unprepared) -> Reply {
    match unprepared {
        Unprepared::Rejected(rejection) => refused(rejection),
        Unprepared::Denied(denial) => denied(*denial),
        Unprepared::Tags(refusal) => Reply::new(554, format!("5.6.0 {refusal}")),
        Unprepared::TooFast => too_fast(),
    }
}

/// The reply to a transaction policy does not allow.
pub fn denied(denial: Denial) -> Reply {
    match denial {
        Denial::UnknownCredential => Reply::new(535, "5.7.8 The login is no longer valid"),
        Denial::NotSending => Reply::new(550, "5.7.1 The login may not send"),
        Denial::UnknownIdentity | Denial::IdentityNotPermitted | Denial::DifferentFrom => {
            Reply::new(550, "5.7.1 Not authorised to send as that From address")
        }
        Denial::Unverified => Reply::new(550, "5.7.1 That From address is not yet verified"),
        Denial::MailFromUnverified => Reply::new(
            550,
            "5.7.1 That From address's MAIL FROM domain is not yet verified",
        ),
        Denial::UnknownTenant
        | Denial::TenantNotPermitted
        | Denial::NotAssociated
        | Denial::UnknownConfiguration => Reply::new(
            550,
            "5.7.1 Not authorised to send for that tenant or configuration",
        ),
        // For now: a client keeps the message until the hold is lifted.
        Denial::Paused => Reply::new(451, "4.7.1 Sending is paused; try again later"),
    }
}

/// The reply to a transaction that preparation refused.
pub fn refused(rejection: &Rejection) -> Reply {
    match rejection {
        Rejection::TooLarge => Reply::new(552, "5.3.4 Message too big"),
        Rejection::NulStart => Reply::new(554, "5.6.0 The message must begin with a header field"),
        Rejection::BareLineFeed | Rejection::LineTooLong => Reply::new(
            554,
            "5.6.0 Every line must end in CRLF and fit in 998 characters",
        ),
        Rejection::From | Rejection::FromUnreadable => Reply::new(
            554,
            "5.6.0 The message needs exactly one readable From address",
        ),
        Rejection::FromNotAllowed => {
            Reply::new(550, "5.7.1 Not authorised to send as that From address")
        }
        Rejection::Signing(_) => Reply::new(451, "4.3.0 The message could not be signed"),
    }
}

/// The refusal of a recipient while the store's disk is below its reserve.
pub fn storage_full() -> Reply {
    Reply::new(452, "4.3.1 Insufficient system storage; try again later")
}

/// The refusal of a recipient while more mail waits for its commit than
/// may.
pub fn storage_busy() -> Reply {
    Reply::new(
        451,
        "4.3.2 Too much mail waits to be stored; try again later",
    )
}

/// The refusal of a recipient while the engine drains: it
/// takes no new mail while its queue is delivered.
pub fn draining() -> Reply {
    Reply::new(451, "4.3.2 Not taking new mail for now; try again later")
}

/// The reply to a transaction the admission hook refused, for
/// good or for now, with its reason.
pub fn admission_refused(refused: &Refused) -> Reply {
    if refused.permanent {
        Reply::new(550, format!("5.7.1 {}", refused.reason))
    } else {
        Reply::new(451, format!("4.7.1 {}", refused.reason))
    }
}

/// The reply once an acceptance's commit is known, naming the message as
/// SES's own SMTP interface does, which `explain` and the events name too.
/// Success is sent only for a committed acceptance.
pub fn answered(commit: &Commit<(), AcceptRefusal>, message: MessageId) -> Reply {
    match commit {
        Commit::Committed(()) => Reply::new(
            250,
            format!("2.0.0 Ok: queued as {:016x}", message.0.as_u64()),
        ),
        // Generated IDs collided: a new attempt draws new ones.
        Commit::Refused(AcceptRefusal::Conflict) => Reply::new(451, "4.3.0 Try again"),
        Commit::Refused(AcceptRefusal::Unauthorised(denial)) => denied(*denial),
        Commit::Refused(AcceptRefusal::QuotaExceeded) => Reply::new(
            454,
            "4.7.0 Throttling failure: Daily message quota exceeded.",
        ),
        Commit::Refused(_) => Reply::new(554, "5.6.0 Not accepted"),
        Commit::Unknown => Reply::new(
            451,
            "4.3.0 Storage failed as it was accepted; sending it again may deliver it twice",
        ),
        Commit::Unavailable => Reply::new(451, "4.3.0 Storage is unavailable"),
    }
}

#[cfg(test)]
mod tests {
    use engine_core::hook::Reason;
    use engine_core::id::{AccountId, CredentialId, Id};
    use engine_core::message::PolicyRevision;
    use engine_core::policy::{Permissions, Record, Scope};

    use super::*;

    #[test]
    fn only_the_right_password_authenticates() {
        let mut password_sha256 = [0; 32];
        password_sha256.copy_from_slice(digest(&SHA256, b"secret").as_ref());
        let login = Record::Credential(Credential {
            id: CredentialId(Id::from_u64(3).unwrap()),
            account: AccountId(Id::from_u64(1).unwrap()),
            secret: Secret::Login {
                user: "bench".to_owned(),
                password_sha256,
            },
            identities: Scope::Any,
            tenants: Scope::Any,
            permissions: Permissions::SENDS,
        });
        let policy = Policy::from_records(PolicyRevision(1), vec![login]).unwrap();
        assert!(authenticate(&policy, "bench", "secret").is_some());
        assert!(authenticate(&policy, "bench", "Secret").is_none());
        assert!(authenticate(&policy, "other", "secret").is_none());
    }

    #[test]
    fn success_is_answered_only_for_a_committed_acceptance() {
        let message = MessageId(Id::from_u64(0x2a).unwrap());
        assert_eq!(
            answered(&Commit::Committed(()), message),
            Reply::new(250, "2.0.0 Ok: queued as 000000000000002a")
        );
        for commit in [
            Commit::Refused(AcceptRefusal::Conflict),
            Commit::Refused(AcceptRefusal::NoRecipients),
            Commit::Refused(AcceptRefusal::Unauthorised(Denial::UnknownIdentity)),
            Commit::Unknown,
            Commit::Unavailable,
        ] {
            assert!(!answered(&commit, message).is_positive());
        }
        assert_eq!(refused(&Rejection::FromNotAllowed).code, 550);
        assert_eq!(denied(Denial::UnknownIdentity).code, 550);
    }

    #[test]
    fn the_admission_hooks_refusal_is_answered_with_its_reason() {
        let refusal = |permanent| Refused {
            permanent,
            reason: Reason::new("a virus"),
        };
        assert_eq!(
            admission_refused(&refusal(true)),
            Reply::new(550, "5.7.1 a virus")
        );
        assert_eq!(
            admission_refused(&refusal(false)),
            Reply::new(451, "4.7.1 a virus")
        );
    }
}
