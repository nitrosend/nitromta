//! The return path's correlation token: one per message, a keyed
//! MAC over its ID in the envelope sender's local part. It is computed as
//! the envelope is written and checked by computing it again, so nothing is
//! stored for it. Being one per message, it lets a message's recipients
//! share a transaction; a report's recipient fields say which
//! delivery it is about.
//!
//! The local part is lowercase hex, so a receiver that changes its case
//! changes nothing: `b`, the message ID in 16 digits, `-`, and the MAC's
//! first 10 bytes.

use aws_lc_rs::hmac;
use engine_core::id::{Id, MessageId};

const PREFIX: &str = "b";
const MAC_BYTES: usize = 10;

/// The secret the tokens are made with.
pub struct Key(hmac::Key);

impl Key {
    pub fn new(secret: &[u8]) -> Self {
        Self(hmac::Key::new(hmac::HMAC_SHA256, secret))
    }

    fn mac(&self, message: MessageId) -> [u8; MAC_BYTES] {
        let tag = hmac::sign(&self.0, &message.0.as_u64().to_be_bytes());
        let mut mac = [0; MAC_BYTES];
        mac.copy_from_slice(&tag.as_ref()[..MAC_BYTES]);
        mac
    }
}

/// The local part of `message`'s return path.
pub fn local_part(key: &Key, message: MessageId) -> String {
    let mut local = format!("{PREFIX}{:016x}-", message.0.as_u64());
    for byte in key.mac(message) {
        local.push_str(&format!("{byte:02x}"));
    }
    local
}

/// The message a return path's local part names, if its token is one the
/// engine issued.
pub fn message(key: &Key, local_part: &str) -> Option<MessageId> {
    let local = local_part.to_ascii_lowercase();
    let (id, mac) = local.strip_prefix(PREFIX)?.split_once('-')?;
    if id.len() != 16 || mac.len() != 2 * MAC_BYTES {
        return None;
    }
    let message = MessageId(Id::from_u64(u64::from_str_radix(id, 16).ok()?)?);
    let mut given = [0; MAC_BYTES];
    for (index, byte) in given.iter_mut().enumerate() {
        *byte = u8::from_str_radix(mac.get(2 * index..2 * index + 2)?, 16).ok()?;
    }
    let expected = key.mac(message);
    aws_lc_rs::constant_time::verify_slices_are_equal(&given, &expected)
        .ok()
        .map(|()| message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message_id(value: u64) -> MessageId {
        MessageId(Id::from_u64(value).unwrap())
    }

    #[test]
    fn a_token_names_its_message_whatever_the_case() {
        let key = Key::new(b"a secret of the installation");
        let local = local_part(&key, message_id(1 << 40));
        assert_eq!(local.len(), 1 + 16 + 1 + 2 * MAC_BYTES);
        assert_eq!(message(&key, &local), Some(message_id(1 << 40)));
        assert_eq!(
            message(&key, &local.to_ascii_uppercase()),
            Some(message_id(1 << 40))
        );
    }

    #[test]
    fn a_token_the_engine_did_not_issue_names_nothing() {
        let key = Key::new(b"a secret of the installation");
        let local = local_part(&key, message_id(7));
        // Another key, another message under this MAC, or a damaged token.
        assert_eq!(message(&Key::new(b"another secret"), &local), None);
        let other = local.replacen(&format!("{:016x}", 7), &format!("{:016x}", 8), 1);
        assert_eq!(message(&key, &other), None);
        assert_eq!(message(&key, &local[..local.len() - 1]), None);
        assert_eq!(message(&key, "bounces"), None);
    }
}
