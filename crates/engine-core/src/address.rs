//! Envelope addresses: RFC 5321 mailboxes.
//!
//! An [`Address`] is checked once, when it is accepted, so it can later be
//! written into an SMTP command without further checks. It has no
//! whitespace, control characters or angle brackets outside a quoted local
//! part, and it fits the protocol's length limits. Its local part keeps its
//! case.
//!
//! Only ASCII addresses are accepted for now. Internationalised addresses
//! (RFC 6531) would be stored the same way, so supporting them widens this
//! check and changes no stored format. Address literals such as
//! `user@[192.0.2.1]` are refused.

use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Address {
    text: Box<str>,
    /// The index of the `@` between the local part and the domain.
    at: u16,
}

impl Address {
    /// The longest mailbox that fits SMTP's 256-octet path with its angle
    /// brackets (RFC 5321, section 4.5.3.1.3). It also keeps every domain
    /// within the 255-octet limit.
    pub const MAX_LEN: usize = 254;
    /// RFC 5321, section 4.5.3.1.1.
    pub const MAX_LOCAL_PART: usize = 64;
    /// RFC 1035, section 2.3.4.
    pub const MAX_LABEL: usize = 63;

    pub fn parse(text: &str) -> Result<Self, AddressError> {
        if text.is_empty() {
            return Err(AddressError::Empty);
        }
        if !text.is_ascii() {
            return Err(AddressError::NonAscii);
        }
        if text.len() > Self::MAX_LEN {
            return Err(AddressError::TooLong);
        }
        let bytes = text.as_bytes();
        let at = if bytes[0] == b'"' {
            quoted_string_end(bytes)?
        } else {
            dot_string_end(bytes)?
        };
        if at > Self::MAX_LOCAL_PART {
            return Err(AddressError::LocalPartTooLong);
        }
        let domain = &text[at + 1..];
        if domain.starts_with('[') {
            return Err(AddressError::AddressLiteral);
        }
        check_domain(domain)?;
        Ok(Self {
            text: text.into(),
            at: u16::try_from(at).expect("a local part is at most 64 octets"),
        })
    }

    pub fn as_str(&self) -> &str {
        &self.text
    }

    pub fn local_part(&self) -> &str {
        &self.text[..usize::from(self.at)]
    }

    pub fn domain(&self) -> &str {
        &self.text[usize::from(self.at) + 1..]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressError {
    Empty,
    NonAscii,
    TooLong,
    MissingAt,
    BadLocalPart,
    LocalPartTooLong,
    AddressLiteral,
    BadDomain,
    LabelTooLong,
}

impl fmt::Display for AddressError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Empty => "the address is empty",
            Self::NonAscii => "internationalised addresses are not supported yet",
            Self::TooLong => "the address is longer than 254 octets",
            Self::MissingAt => "the address has no @ before its domain",
            Self::BadLocalPart => "the local part is not a valid dot-string or quoted string",
            Self::LocalPartTooLong => "the local part is longer than 64 octets",
            Self::AddressLiteral => "address literals are not supported",
            Self::BadDomain => "the domain is not a valid host name",
            Self::LabelTooLong => "a domain label is longer than 63 octets",
        })
    }
}

impl std::error::Error for AddressError {}

/// The index of the `@` that ends a dot-string local part.
/// The members an address list names (RFC 5322, 3.4), each its text as
/// the list holds it: each mailbox, and each member of each group, the
/// group's name left out. None for an empty group, nor for a part that is
/// only white space and comments, as `undisclosed: (none);` is. `None` if a
/// quoted string, comment, angle address or literal is left open.
pub fn list_members(value: &[u8]) -> Option<Vec<&[u8]>> {
    fn take<'a>(members: &mut Vec<&'a [u8]>, part: &'a [u8]) {
        if !blank(part) {
            members.push(part);
        }
    }
    let mut members: Vec<&[u8]> = Vec::new();
    let mut start = 0;
    let (mut quoted, mut comment, mut escaped) = (false, 0usize, false);
    let (mut angle, mut literal) = (false, false);
    for (at, &byte) in value.iter().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        match byte {
            b'\\' if quoted || comment > 0 => escaped = true,
            b'"' if comment == 0 => quoted = !quoted,
            b'(' if !quoted => comment += 1,
            b')' if !quoted && comment > 0 => comment -= 1,
            _ if quoted || comment > 0 => {}
            b'<' => angle = true,
            b'>' => angle = false,
            b'[' => literal = true,
            b']' => literal = false,
            _ if angle || literal => {}
            // A group's name ends: its members follow.
            b':' => start = at + 1,
            b',' | b';' => {
                take(&mut members, &value[start..at]);
                start = at + 1;
            }
            _ => {}
        }
    }
    if quoted || comment > 0 || angle || literal {
        return None;
    }
    take(&mut members, &value[start..]);
    Some(members)
}

/// Whether `part` of an address list is only folding white space and
/// comments.
fn blank(part: &[u8]) -> bool {
    let (mut comment, mut escaped) = (0usize, false);
    part.iter().all(|&byte| {
        if escaped {
            escaped = false;
            return true;
        }
        match byte {
            b'\\' if comment > 0 => escaped = true,
            b'(' => comment += 1,
            b')' if comment > 0 => comment -= 1,
            _ if comment > 0 => {}
            byte => return byte.is_ascii_whitespace(),
        }
        true
    })
}

fn dot_string_end(bytes: &[u8]) -> Result<usize, AddressError> {
    // A dot-string is atoms joined by single dots, so it cannot be empty,
    // start or end with a dot, or contain two in a row.
    let mut after_dot = true;
    for (index, &byte) in bytes.iter().enumerate() {
        match byte {
            b'@' if !after_dot => return Ok(index),
            b'.' if !after_dot => after_dot = true,
            _ if is_atext(byte) => after_dot = false,
            _ => return Err(AddressError::BadLocalPart),
        }
    }
    Err(AddressError::MissingAt)
}

/// The index of the `@` after a quoted-string local part.
fn quoted_string_end(bytes: &[u8]) -> Result<usize, AddressError> {
    let mut index = 1;
    while let Some(&byte) = bytes.get(index) {
        match byte {
            b'"' => {
                return match bytes.get(index + 1).copied() {
                    Some(b'@') => Ok(index + 1),
                    Some(_) => Err(AddressError::BadLocalPart),
                    None => Err(AddressError::MissingAt),
                };
            }
            // A quoted pair escapes any printable character.
            b'\\' => match bytes.get(index + 1).copied() {
                Some(32..=126) => index += 2,
                _ => return Err(AddressError::BadLocalPart),
            },
            // Printable characters and space; the quote and backslash are
            // handled above.
            32..=126 => index += 1,
            _ => return Err(AddressError::BadLocalPart),
        }
    }
    Err(AddressError::BadLocalPart)
}

/// Checks a domain on its own, as an identity names it: a host name of
/// dot-separated labels of letters, digits and inner hyphens, within DNS's
/// 253-octet limit.
pub fn domain(domain: &str) -> Result<(), AddressError> {
    if domain.len() > 253 {
        return Err(AddressError::TooLong);
    }
    check_domain(domain)
}

/// Host names: dot-separated labels of letters, digits and inner hyphens.
fn check_domain(domain: &str) -> Result<(), AddressError> {
    for label in domain.split('.') {
        let bytes = label.as_bytes();
        let (Some(first), Some(last)) = (bytes.first(), bytes.last()) else {
            return Err(AddressError::BadDomain);
        };
        if bytes.len() > Address::MAX_LABEL {
            return Err(AddressError::LabelTooLong);
        }
        let inner_ok = bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-');
        if !first.is_ascii_alphanumeric() || !last.is_ascii_alphanumeric() || !inner_ok {
            return Err(AddressError::BadDomain);
        }
    }
    Ok(())
}

/// RFC 5322 `atext`.
fn is_atext(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-/=?^_`{|}~".contains(&byte)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_addresses_keep_their_parts() {
        let cases = [
            ("user@example.com", "user", "example.com"),
            (
                "First.Last@Sub.Example.CO.uk",
                "First.Last",
                "Sub.Example.CO.uk",
            ),
            ("user+tag@example.com", "user+tag", "example.com"),
            (
                "!#$%&'*+-/=?^_`{|}~@example.com",
                "!#$%&'*+-/=?^_`{|}~",
                "example.com",
            ),
            ("\"john doe\"@example.com", "\"john doe\"", "example.com"),
            ("\"a@b\"@example.com", "\"a@b\"", "example.com"),
            (
                "\"say \\\"hi\\\"\"@example.com",
                "\"say \\\"hi\\\"\"",
                "example.com",
            ),
            ("\"\"@example.com", "\"\"", "example.com"),
            ("x@a", "x", "a"),
            ("x@1-2.example", "x", "1-2.example"),
        ];
        for (text, local_part, domain) in cases {
            let address = Address::parse(text).unwrap_or_else(|error| panic!("{text}: {error}"));
            assert_eq!(address.as_str(), text);
            assert_eq!(address.local_part(), local_part, "{text}");
            assert_eq!(address.domain(), domain, "{text}");
        }
    }

    #[test]
    fn invalid_addresses_are_refused_for_their_reason() {
        let long_local = format!("{}@example.com", "a".repeat(65));
        let long_label = format!("user@{}.com", "a".repeat(64));
        let long_address = format!("user@{}.com", vec!["a".repeat(60); 5].join("."));
        let cases = [
            ("", AddressError::Empty),
            ("plain", AddressError::MissingAt),
            ("@example.com", AddressError::BadLocalPart),
            (".user@example.com", AddressError::BadLocalPart),
            ("user.@example.com", AddressError::BadLocalPart),
            ("us..er@example.com", AddressError::BadLocalPart),
            ("us er@example.com", AddressError::BadLocalPart),
            ("user\r\n@example.com", AddressError::BadLocalPart),
            ("<user>@example.com", AddressError::BadLocalPart),
            ("\"unterminated@example.com", AddressError::BadLocalPart),
            ("\"quoted\"x@example.com", AddressError::BadLocalPart),
            ("\"tab\there\"@example.com", AddressError::BadLocalPart),
            ("\"quoted\"", AddressError::MissingAt),
            ("user@", AddressError::BadDomain),
            ("user@-example.com", AddressError::BadDomain),
            ("user@example-.com", AddressError::BadDomain),
            ("user@exa_mple.com", AddressError::BadDomain),
            ("user@example..com", AddressError::BadDomain),
            ("user@example.com.", AddressError::BadDomain),
            ("user@example.com\r\nRCPT TO:<x@y>", AddressError::BadDomain),
            ("user@example.com>", AddressError::BadDomain),
            ("user@[192.0.2.1]", AddressError::AddressLiteral),
            ("user@exämple.com", AddressError::NonAscii),
            (long_local.as_str(), AddressError::LocalPartTooLong),
            (long_label.as_str(), AddressError::LabelTooLong),
            (long_address.as_str(), AddressError::TooLong),
        ];
        for (text, error) in cases {
            assert_eq!(Address::parse(text), Err(error), "{text:?}");
        }
    }

    #[test]
    fn the_length_limits_are_inclusive() {
        let local = "a".repeat(Address::MAX_LOCAL_PART);
        let at_limit = format!("{local}@example.com");
        assert!(Address::parse(&at_limit).is_ok());

        let domain = format!("{}.com", vec!["a".repeat(61); 3].join("."));
        let longest = format!("{local}@{domain}");
        assert_eq!(longest.len(), 254);
        assert!(Address::parse(&longest).is_ok());
    }
}
