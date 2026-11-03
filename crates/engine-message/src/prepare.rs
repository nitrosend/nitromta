//! Preparation of a submitted message: the checks that come before
//! acceptance, which find the mailbox its From names, then the Date and
//! Message-ID it lacks, and its DKIM signature when the identity that
//! mailbox sends as signs. A message is prepared once; the bytes it returns
//! are kept and sent exactly as they are.

use std::borrow::Cow;

use bytes::Bytes;
use engine_core::address::{self, Address};
use engine_core::time::Timestamp;

use crate::dkim::{Signer, SigningFailed, fields, name_of};

/// RFC 5322's limit on a line, without its CRLF (2.1.1).
const MAX_LINE: usize = 998;

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// The largest message accepted, as it was given: before preparation
    /// adds the Date and Message-ID it lacks, and its signature.
    pub max_bytes: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Rejection {
    TooLarge,
    /// The message begins with a NUL byte, which no header field does, and
    /// which the store keeps for a sealed body's mark.
    NulStart,
    /// A line ends in LF without CR.
    BareLineFeed,
    LineTooLong,
    /// The message has no From field, or more than one.
    From,
    /// From does not name a single mailbox the engine can read.
    FromUnreadable,
    /// From names a domain the sender may not sign for.
    FromNotAllowed,
    Signing(SigningFailed),
}

/// What a message is sent as: the identity's domain, which every message's
/// From must name, and its signing key when it signs. An identity may send
/// unsigned, as one whose application signs its own mail does.
pub struct Sender {
    domain: String,
    signer: Option<Signer>,
}

impl Sender {
    /// Sends as `signer`'s domain, signed with its key.
    pub fn signing(signer: Signer) -> Self {
        Self {
            domain: signer.domain().to_owned(),
            signer: Some(signer),
        }
    }

    pub fn unsigned(domain: &str) -> Self {
        Self {
            domain: domain.to_owned(),
            signer: None,
        }
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }
}

/// What a message is given where it has no field of its own, as SES and a
/// submission server give it: a Date, when it was accepted, and a
/// Message-ID, its ID at the domain it is sent as. Receivers may refuse
/// mail without them; Gmail refuses mail with no Message-ID.
#[derive(Clone, Copy)]
pub struct Stamp<'a> {
    pub date: Timestamp,
    /// The Message-ID's part before its `@`.
    pub id: &'a str,
}

/// A message that passed the checks, and the one mailbox its From names,
/// which decides the identity it is sent as.
pub struct Checked<'a> {
    raw: &'a [u8],
    header: &'a [u8],
    body: &'a [u8],
    from: Address,
    /// Whether it has a Date field of its own, and a Message-ID field.
    dated: bool,
    identified: bool,
}

impl Checked<'_> {
    pub fn from(&self) -> &Address {
        &self.from
    }

    /// The content exactly as it will be sent as `sender`, whose domain its
    /// From must name: given `stamp`'s fields where it has none of its own,
    /// ahead of its header, and signed with them when the sender signs.
    pub fn sent_as(&self, sender: &Sender, stamp: Stamp<'_>) -> Result<Bytes, Rejection> {
        if !self.from.domain().eq_ignore_ascii_case(sender.domain()) {
            return Err(Rejection::FromNotAllowed);
        }
        let mut stamped = String::new();
        if !self.dated {
            stamped.push_str(&format!("Date: {}\r\n", rfc5322(stamp.date)));
        }
        if !self.identified {
            stamped.push_str(&format!(
                "Message-ID: <{}@{}>\r\n",
                stamp.id,
                sender.domain()
            ));
        }
        let signature = match &sender.signer {
            Some(signer) => {
                let header = if stamped.is_empty() {
                    Cow::Borrowed(self.header)
                } else {
                    Cow::Owned([stamped.as_bytes(), self.header].concat())
                };
                signer
                    .sign(&header, self.body)
                    .map_err(Rejection::Signing)?
            }
            None => Vec::new(),
        };
        let mut content = Vec::with_capacity(signature.len() + stamped.len() + self.raw.len());
        for part in [&signature, stamped.as_bytes(), self.raw] {
            content.extend_from_slice(part);
        }
        Ok(Bytes::from(content))
    }
}

/// Checks a submitted message's size, start, lines and From.
pub fn check(raw: &[u8], limits: Limits) -> Result<Checked<'_>, Rejection> {
    if raw.len() > limits.max_bytes {
        return Err(Rejection::TooLarge);
    }
    if raw.first() == Some(&0) {
        return Err(Rejection::NulStart);
    }
    check_lines(raw)?;
    let (header, body) = match raw.windows(4).position(|window| window == b"\r\n\r\n") {
        Some(end) => (&raw[..end + 2], &raw[end + 4..]),
        None => (raw, &[][..]),
    };
    let fields = fields(header);
    let mut from = fields
        .iter()
        .filter(|field| name_of(field).eq_ignore_ascii_case(b"from"));
    let (Some(field), None) = (from.next(), from.next()) else {
        return Err(Rejection::From);
    };
    let value = field
        .iter()
        .position(|&byte| byte == b':')
        .map(|colon| &field[colon + 1..]);
    let from = value.and_then(mailbox).ok_or(Rejection::FromUnreadable)?;
    // A line with no colon is no field, whatever it begins with.
    let has = |name: &[u8]| {
        fields
            .iter()
            .any(|field| field.contains(&b':') && name_of(field).eq_ignore_ascii_case(name))
    };
    Ok(Checked {
        raw,
        header,
        body,
        from,
        dated: has(b"date"),
        identified: has(b"message-id"),
    })
}

/// `Tue, 27 Oct 2026 15:30:00 +0000` (RFC 5322, 3.3).
fn rfc5322(at: Timestamp) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let at = at.utc();
    format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} +0000",
        DAYS[at.weekday as usize],
        at.day,
        MONTHS[(at.month - 1) as usize],
        at.year,
        at.hour,
        at.minute,
        at.second,
    )
}

/// Every line ends in CRLF and fits RFC 5322's limit.
fn check_lines(raw: &[u8]) -> Result<(), Rejection> {
    let mut start = 0;
    for (at, &byte) in raw.iter().enumerate() {
        if byte != b'\n' {
            continue;
        }
        if at == 0 || raw[at - 1] != b'\r' {
            return Err(Rejection::BareLineFeed);
        }
        if at - 1 - start > MAX_LINE {
            return Err(Rejection::LineTooLong);
        }
        start = at + 1;
    }
    if raw.len() - start > MAX_LINE {
        return Err(Rejection::LineTooLong);
    }
    Ok(())
}

/// The one mailbox an address field's value names (RFC 5322, 3.4): its
/// angle address, or its bare address. Comments are skipped, and so is a
/// display name, quoted or not, so a comma inside one is not taken for a
/// second mailbox; a quoted local part is the address's own, kept as it is.
pub fn mailbox(value: &[u8]) -> Option<Address> {
    let mut plain = Vec::with_capacity(value.len());
    let mut angle: Option<Vec<u8>> = None;
    let mut closed = false;
    let (mut quoted, mut comment, mut escaped) = (false, 0usize, false);
    for &byte in value {
        // Whether the byte is the address's: a comment's never is, and a
        // quoted string's always is, where the address is read from.
        let kept = if escaped {
            escaped = false;
            quoted
        } else if comment > 0 {
            match byte {
                b'\\' => escaped = true,
                b'(' => comment += 1,
                b')' => comment -= 1,
                _ => {}
            }
            false
        } else if quoted {
            match byte {
                b'\\' => escaped = true,
                b'"' => quoted = false,
                // Folding inside a quoted string unfolds to its white
                // space (RFC 5322, 3.2.4).
                b'\r' | b'\n' => continue,
                _ => {}
            }
            true
        } else {
            match byte {
                b'"' => {
                    quoted = true;
                    true
                }
                b'(' => {
                    comment += 1;
                    false
                }
                // A comment closed that never opened.
                b',' | b';' | b')' => return None,
                b'\r' | b'\n' | b' ' | b'\t' => false,
                b'<' if angle.is_none() && !closed => {
                    angle = Some(Vec::new());
                    false
                }
                b'>' if angle.is_some() && !closed => {
                    closed = true;
                    false
                }
                _ => true,
            }
        };
        if kept {
            // Nothing follows the angle address but white space and
            // comments.
            if closed {
                return None;
            }
            angle.as_mut().unwrap_or(&mut plain).push(byte);
        }
    }
    // An angle address must close.
    if quoted || comment > 0 || (angle.is_some() && !closed) {
        return None;
    }
    // A display name beside an angle address, quoted or not, is not the
    // address; a bare address has none.
    let text = angle.unwrap_or(plain);
    Address::parse(std::str::from_utf8(&text).ok()?).ok()
}

/// The mailboxes an address list names (RFC 5322, 3.4): each address and
/// each member of each group, in order; none for an empty group. `None` if
/// any of them cannot be read, as a list with one bad address is refused
/// whole.
pub fn mailboxes(value: &[u8]) -> Option<Vec<Address>> {
    address::list_members(value)?
        .into_iter()
        .map(mailbox)
        .collect()
}

#[cfg(test)]
mod tests {
    use aws_lc_rs::encoding::AsDer;
    use aws_lc_rs::rsa::{KeyPair, KeySize};
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;

    use super::*;

    #[test]
    fn an_address_list_gives_each_mailbox_and_each_groups_members() {
        let listed = |value: &str| {
            mailboxes(value.as_bytes()).map(|found| {
                found
                    .iter()
                    .map(|address| address.as_str().to_owned())
                    .collect::<Vec<_>>()
            })
        };
        assert_eq!(
            listed("\"Last, First\" <a@example.test>, b@example.test (a comment, here)"),
            Some(vec![
                "a@example.test".to_owned(),
                "b@example.test".to_owned()
            ])
        );
        assert_eq!(
            listed("Team: c@example.test, <d@example.test>;, e@example.test"),
            Some(vec![
                "c@example.test".to_owned(),
                "d@example.test".to_owned(),
                "e@example.test".to_owned()
            ])
        );
        assert_eq!(listed("undisclosed-recipients:;"), Some(Vec::new()));
        assert_eq!(
            listed("a@example.test,\r\n b@example.test").map(|found| found.len()),
            Some(2)
        );
        assert_eq!(listed("a@example.test, not an address"), None);
        assert_eq!(listed("\"unclosed <a@example.test>"), None);
        // A group with a comment and no member is empty.
        assert_eq!(listed("undisclosed: (none);"), Some(Vec::new()));
        assert_eq!(
            listed("Team: (none);, c@example.test"),
            Some(vec!["c@example.test".to_owned()])
        );
        // A quoted local part is the address's own, comma and all.
        assert_eq!(
            listed("\"a,b\"@example.test, \"Ann, A\" <\"a b\\\"c\"@example.test>"),
            Some(vec![
                "\"a,b\"@example.test".to_owned(),
                "\"a b\\\"c\"@example.test".to_owned()
            ])
        );
        // Nothing but a comment follows an angle address.
        assert_eq!(
            listed("<a@example.test> (a comment)"),
            Some(vec!["a@example.test".to_owned()])
        );
        assert_eq!(listed("<a@example.test> b"), None);
        // An angle address that never closes, or a comment closed that
        // never opened, is no address; folding in a quoted local part is
        // its white space.
        for malformed in ["<a@example.test", "Bad) <a@example.test>"] {
            assert_eq!(mailbox(malformed.as_bytes()), None, "{malformed}");
        }
        assert_eq!(
            mailbox(b"\"a\r\n b\"@example.test").map(|address| address.as_str().to_owned()),
            Some("\"a b\"@example.test".to_owned())
        );
    }

    fn signer() -> Sender {
        let pair = KeyPair::generate(KeySize::Rsa2048).unwrap();
        let der = STANDARD.encode(pair.as_der().unwrap().as_ref());
        let pem = format!("-----BEGIN PRIVATE KEY-----\n{der}\n-----END PRIVATE KEY-----\n");
        let headers = ["From", "Subject", "Date", "Message-ID"];
        Sender::signing(Signer::from_pem(&pem, "bench.test", "s1", &headers).unwrap())
    }

    const LIMITS: Limits = Limits { max_bytes: 1024 };

    const STAMP: Stamp<'static> = Stamp {
        date: Timestamp::from_micros(1_700_000_000_000_000),
        id: "000000000000002a",
    };

    /// A message with a Date and a Message-ID of its own.
    const DATED: &[u8] = b"From: load@bench.test\r\nDate: Mon, 2 Nov 2026 09:00:00 +0000\r\nMessage-ID: <theirs@bench.test>\r\nSubject: hi\r\n\r\nbody\r\n";

    fn prepare(raw: &[u8], sender: &Sender, limits: Limits) -> Result<Bytes, Rejection> {
        check(raw, limits)?.sent_as(sender, STAMP)
    }

    #[test]
    fn a_message_is_signed_and_otherwise_kept() {
        let signer = signer();
        let raw = b"From: Load <load@Bench.Test>\r\nSubject: hi\r\n\r\nbody\r\n";
        assert_eq!(
            check(raw, LIMITS).unwrap().from().as_str(),
            "load@Bench.Test"
        );
        let content = prepare(raw, &signer, LIMITS).unwrap();
        assert!(content.starts_with(b"DKIM-Signature: v=1; a=rsa-sha256;"));
        assert!(content.ends_with(raw));
    }

    #[test]
    fn a_message_without_a_date_or_message_id_is_given_them_and_signed_with_them() {
        let raw = b"From: load@bench.test\r\nSubject: hi\r\n\r\nbody\r\n";
        let stamped = b"Date: Tue, 14 Nov 2023 22:13:20 +0000\r\nMessage-ID: <000000000000002a@bench.test>\r\n";
        let unsigned = prepare(raw, &Sender::unsigned("bench.test"), LIMITS).unwrap();
        assert_eq!(&unsigned[..], [stamped.as_slice(), raw].concat());
        let signed = String::from_utf8(prepare(raw, &signer(), LIMITS).unwrap().to_vec()).unwrap();
        assert!(
            signed.contains("h=from:subject:date:message-id;"),
            "{signed}"
        );
        assert!(signed.ends_with(std::str::from_utf8(&unsigned).unwrap()));
        // Each is given only where the message has none: a Message-ID of
        // its own, in any case, is kept and no other added.
        let own = b"From: load@bench.test\r\nmessage-id: <theirs@bench.test>\r\n\r\nbody\r\n";
        assert_eq!(
            &prepare(own, &Sender::unsigned("bench.test"), LIMITS).unwrap()[..],
            [b"Date: Tue, 14 Nov 2023 22:13:20 +0000\r\n".as_slice(), own].concat()
        );
        // A line that names one but has no colon is no field of it.
        let colonless = b"From: load@bench.test\r\nDate\r\nMessage-ID";
        assert_eq!(
            &prepare(colonless, &Sender::unsigned("bench.test"), LIMITS).unwrap()[..],
            [stamped.as_slice(), colonless].concat()
        );
    }

    #[test]
    fn an_identity_that_does_not_sign_sends_its_message_as_it_came() {
        let sender = Sender::unsigned("bench.test");
        assert_eq!(&prepare(DATED, &sender, LIMITS).unwrap()[..], DATED);
        assert_eq!(
            prepare(b"From: a@other.test\r\n\r\n", &sender, LIMITS).err(),
            Some(Rejection::FromNotAllowed)
        );
        // One beginning with a NUL byte would be read back as a sealed body.
        assert_eq!(
            prepare(
                b"\0X: y\r\nFrom: a@bench.test\r\n\r\nbody\r\n",
                &sender,
                LIMITS
            )
            .err(),
            Some(Rejection::NulStart)
        );
    }

    #[test]
    fn checks_come_before_signing() {
        let signer = signer();
        let check = |raw: &[u8]| prepare(raw, &signer, LIMITS).err();
        assert_eq!(check(&[b'x'; 1025]), Some(Rejection::TooLarge));
        assert_eq!(
            check(b"From: a@bench.test\n\r\nbody\r\n"),
            Some(Rejection::BareLineFeed)
        );
        let long = [b"From: a@bench.test\r\n\r\n".as_slice(), &[b'x'; 999]].concat();
        assert_eq!(check(&long), Some(Rejection::LineTooLong));
        assert_eq!(check(b"Subject: x\r\n\r\nbody\r\n"), Some(Rejection::From));
        assert_eq!(
            check(b"From: a@bench.test\r\nFrom: b@bench.test\r\n\r\n"),
            Some(Rejection::From)
        );
        assert_eq!(
            check(b"From: a@bench.test, b@bench.test\r\n\r\n"),
            Some(Rejection::FromUnreadable)
        );
        assert_eq!(
            check(b"From: a@other.test\r\n\r\n"),
            Some(Rejection::FromNotAllowed)
        );
    }

    #[test]
    fn a_mailbox_is_read_past_display_names_and_comments() {
        let read = |value: &str| mailbox(value.as_bytes()).map(|a| a.as_str().to_owned());
        assert_eq!(read(" a@bench.test").as_deref(), Some("a@bench.test"));
        assert_eq!(
            read(" \"Doe, Jane\" <jane@bench.test>").as_deref(),
            Some("jane@bench.test")
        );
        assert_eq!(
            read(" Jane (work, mostly) <jane@bench.test>").as_deref(),
            Some("jane@bench.test")
        );
        assert_eq!(
            read(" Jane\r\n <jane@bench.test>").as_deref(),
            Some("jane@bench.test")
        );
        assert_eq!(read(" Undisclosed:;").as_deref(), None);
        assert_eq!(read(" <a@bench.test> extra").as_deref(), None);
        assert_eq!(read(" \"unterminated <a@bench.test>").as_deref(), None);
    }
}
