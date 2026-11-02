//! A message's header fields, read by name and taken out (RFC 5322, 2.2):
//! a field is its first line and the folded lines after it, and the header
//! block ends at the message's first blank line.

use std::borrow::Cow;

use crate::dkim::{fields, name_of};

/// The message's header block, each field with its CRLF, and the rest: the
/// blank line and the body. With no blank line, it is all header.
fn split(raw: &[u8]) -> (&[u8], &[u8]) {
    if raw.starts_with(b"\r\n") {
        return (&[], raw);
    }
    match raw.windows(4).position(|window| window == b"\r\n\r\n") {
        Some(at) => raw.split_at(at + 2),
        None => (raw, &[]),
    }
}

/// The values of the fields named `name`, whatever its case, in order:
/// each after its colon, with its folding.
pub fn values<'a>(raw: &'a [u8], name: &str) -> Vec<&'a [u8]> {
    let (header, _) = split(raw);
    fields(header)
        .into_iter()
        .filter(|field| name_of(field).eq_ignore_ascii_case(name.as_bytes()))
        .map(|field| {
            let colon = field
                .iter()
                .position(|&byte| byte == b':')
                .map_or(field.len(), |at| at + 1);
            &field[colon..]
        })
        .collect()
}

/// The message without its fields named any of `names`, whatever their
/// case: itself, uncopied, when it has none.
pub fn without<'a>(raw: &'a [u8], names: &[&str]) -> Cow<'a, [u8]> {
    let (header, rest) = split(raw);
    let fields = fields(header);
    let named = |field: &[u8]| {
        let name = name_of(field);
        names
            .iter()
            .any(|wanted| name.eq_ignore_ascii_case(wanted.as_bytes()))
    };
    if !fields.iter().any(|field| named(field)) {
        return Cow::Borrowed(raw);
    }
    let mut kept = Vec::with_capacity(raw.len());
    for field in fields.into_iter().filter(|field| !named(field)) {
        kept.extend_from_slice(field);
    }
    kept.extend_from_slice(rest);
    Cow::Owned(kept)
}

/// The message's header block, each field with its CRLF, at most `most`
/// bytes: cut after the last whole field that fits, and whether any was
/// left out.
pub fn block(raw: &[u8], most: usize) -> (&[u8], bool) {
    let (header, _) = split(raw);
    if header.len() <= most {
        return (header, false);
    }
    let mut kept = 0;
    for field in fields(header) {
        if kept + field.len() > most {
            break;
        }
        kept += field.len();
    }
    (&header[..kept], true)
}

/// Whether the header block holds a field whose name starts with
/// `prefix`, whatever its case: one pass over the header block's lines,
/// stopping at the blank line that ends it, for a test that is mostly no.
pub fn has_prefixed(raw: &[u8], prefix: &str) -> bool {
    let prefix = prefix.as_bytes();
    for line in raw.split(|&byte| byte == b'\n') {
        if line.is_empty() || line == b"\r" {
            return false;
        }
        if line.len() >= prefix.len() && line[..prefix.len()].eq_ignore_ascii_case(prefix) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    const MESSAGE: &[u8] = b"From: a@example.test\r\nX-Kept: one\r\nX-Gone: two\r\n\tfolded\r\nTo: b@example.test,\r\n c@example.test\r\n\r\nX-Gone: in the body\r\n";

    #[test]
    fn fields_are_read_and_taken_out_by_name_and_never_from_the_body() {
        assert_eq!(
            values(MESSAGE, "to"),
            [&b" b@example.test,\r\n c@example.test\r\n"[..]]
        );
        assert_eq!(values(MESSAGE, "X-GONE"), [&b" two\r\n\tfolded\r\n"[..]]);
        assert_eq!(
            &*without(MESSAGE, &["x-gone"]),
            b"From: a@example.test\r\nX-Kept: one\r\nTo: b@example.test,\r\n c@example.test\r\n\r\nX-Gone: in the body\r\n"
        );
        assert!(matches!(without(MESSAGE, &["X-Absent"]), Cow::Borrowed(_)));
        assert!(has_prefixed(MESSAGE, "x-g"));
        // A block cut at the end of a field, never in one.
        let whole = MESSAGE.len() - "\r\nX-Gone: in the body\r\n".len();
        assert_eq!(block(MESSAGE, usize::MAX), (&MESSAGE[..whole], false));
        assert_eq!(
            block(MESSAGE, 40),
            (&b"From: a@example.test\r\nX-Kept: one\r\n"[..], true)
        );
        assert!(!has_prefixed(MESSAGE, "x-ses-"));
        // The body is never read, nor a message with no header block.
        assert!(!has_prefixed(MESSAGE, "X-Gone: in"));
        assert!(!has_prefixed(b"\r\nX-SES-A: 1\r\n", "x-ses-"));
        assert!(has_prefixed(b"X-SES-A: 1", "x-ses-"));
        // A message with no body is all header.
        assert_eq!(
            values(b"To: x@example.test\r\n", "To"),
            [&b" x@example.test\r\n"[..]]
        );
    }
}
