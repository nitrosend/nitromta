//! Just enough MIME (RFC 2045, 2046) to read a report: an entity's header
//! fields and body, a multipart body's parts, and the transfer encodings a
//! part may use. Every limit is a count or a length, so no input makes it
//! work harder than its size.

use std::borrow::Cow;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

/// The most header fields read from one entity: a field for every
/// recipient a message may have, as a complaint names them, and room for
/// the rest. The report's own size bounds what they hold.
const MAX_FIELDS: usize = engine_core::command::MAX_RECIPIENTS + 256;

/// The most parts read from one multipart body.
pub const MAX_PARTS: usize = 16;

/// One entity: its header fields, unfolded, with names in lowercase, and
/// its body.
pub struct Entity<'a> {
    pub fields: Vec<(String, String)>,
    pub body: &'a [u8],
}

impl<'a> Entity<'a> {
    /// Splits `bytes` at the first empty line into header and body. An
    /// entity with no empty line is all header.
    pub fn read(bytes: &'a [u8]) -> Self {
        let (header, body) = split_header(bytes);
        Self {
            fields: fields(header),
            body,
        }
    }

    /// The first field named `name`, which is in lowercase.
    pub fn field(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(field, _)| field == name)
            .map(|(_, value)| value.as_str())
    }

    /// Every field named `name`, in order.
    pub fn every<'s>(&'s self, name: &'s str) -> impl Iterator<Item = &'s str> + 's {
        self.fields
            .iter()
            .filter(move |(field, _)| field == name)
            .map(|(_, value)| value.as_str())
    }

    /// Its content type, `text/plain` if it states none (RFC 2045, 5.2).
    pub fn content_type(&self) -> ContentType {
        ContentType::parse(self.field("content-type").unwrap_or("text/plain"))
    }

    /// Its body with its transfer encoding undone. A body in an encoding
    /// this does not know is returned as it is.
    pub fn decoded(&self) -> Cow<'a, [u8]> {
        let encoding = self
            .field("content-transfer-encoding")
            .map(|value| value.trim().to_ascii_lowercase());
        match encoding.as_deref() {
            Some("base64") => {
                let compact: Vec<u8> = self
                    .body
                    .iter()
                    .copied()
                    .filter(|byte| !byte.is_ascii_whitespace())
                    .collect();
                STANDARD
                    .decode(compact)
                    .map_or(Cow::Borrowed(self.body), Cow::Owned)
            }
            Some("quoted-printable") => Cow::Owned(quoted_printable(self.body)),
            _ => Cow::Borrowed(self.body),
        }
    }
}

/// A content type: `type/subtype` in lowercase, and its parameters, with
/// names in lowercase and quoted values unquoted.
pub struct ContentType {
    pub kind: String,
    parameters: Vec<(String, String)>,
}

impl ContentType {
    fn parse(value: &str) -> Self {
        let mut pieces = split_parameters(value);
        let kind = pieces
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        let parameters = pieces
            .filter_map(|piece| {
                let (name, value) = piece.split_once('=')?;
                let value = value.trim();
                let value = value
                    .strip_prefix('"')
                    .and_then(|value| value.strip_suffix('"'))
                    .unwrap_or(value);
                Some((name.trim().to_ascii_lowercase(), value.to_owned()))
            })
            .collect();
        Self { kind, parameters }
    }

    pub fn parameter(&self, name: &str) -> Option<&str> {
        self.parameters
            .iter()
            .find(|(parameter, _)| parameter == name)
            .map(|(_, value)| value.as_str())
    }
}

/// The parts of a multipart body, at most [`MAX_PARTS`]: what lies between
/// its boundary lines, up to the closing one (RFC 2046, 5.1.1).
pub fn parts<'a>(body: &'a [u8], boundary: &str) -> Vec<&'a [u8]> {
    let delimiter = format!("--{boundary}");
    let mut parts = Vec::new();
    let mut start = None;
    let mut offset = 0;
    for line in body.split_inclusive(|&byte| byte == b'\n') {
        let text = trim_line(line);
        if let Some(rest) = text.strip_prefix(delimiter.as_bytes()) {
            let closing = rest.starts_with(b"--");
            if rest.iter().all(u8::is_ascii_whitespace) || closing {
                if let Some(start) = start {
                    // The line break before a boundary belongs to it.
                    parts.push(trim_end_break(&body[start..offset]));
                    if parts.len() == MAX_PARTS {
                        break;
                    }
                }
                if closing {
                    break;
                }
                start = Some(offset + line.len());
            }
        }
        offset += line.len();
    }
    parts
}

/// Header fields, unfolded, with names in lowercase; at most
/// [`MAX_FIELDS`].
fn fields(header: &[u8]) -> Vec<(String, String)> {
    let mut fields: Vec<(String, String)> = Vec::new();
    for line in header.split_inclusive(|&byte| byte == b'\n') {
        let line = String::from_utf8_lossy(trim_line(line));
        if line.starts_with([' ', '\t']) {
            // A folded line continues the field before it.
            if let Some((_, value)) = fields.last_mut() {
                value.push(' ');
                value.push_str(line.trim());
            }
        } else if let Some((name, value)) = line.split_once(':') {
            if fields.len() == MAX_FIELDS {
                break;
            }
            fields.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
        }
    }
    fields
}

/// Splits an entity at its first empty line.
fn split_header(bytes: &[u8]) -> (&[u8], &[u8]) {
    let mut offset = 0;
    for line in bytes.split_inclusive(|&byte| byte == b'\n') {
        if trim_line(line).is_empty() {
            return (&bytes[..offset], &bytes[offset + line.len()..]);
        }
        offset += line.len();
    }
    (bytes, &[])
}

/// A line without its line break.
fn trim_line(line: &[u8]) -> &[u8] {
    let line = line.strip_suffix(b"\n").unwrap_or(line);
    line.strip_suffix(b"\r").unwrap_or(line)
}

fn trim_end_break(part: &[u8]) -> &[u8] {
    let part = part.strip_suffix(b"\n").unwrap_or(part);
    part.strip_suffix(b"\r").unwrap_or(part)
}

/// A field value's `;`-separated pieces, where a `;` inside quotes is part
/// of its piece.
fn split_parameters(value: &str) -> impl Iterator<Item = &str> {
    let mut pieces = Vec::new();
    let (mut start, mut quoted) = (0, false);
    for (index, character) in value.char_indices() {
        match character {
            '"' => quoted = !quoted,
            ';' if !quoted => {
                pieces.push(&value[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    pieces.push(&value[start..]);
    pieces.into_iter()
}

/// Undoes quoted-printable encoding (RFC 2045, 6.7): `=XX` escapes and soft
/// line breaks. A malformed escape is kept as it is.
fn quoted_printable(body: &[u8]) -> Vec<u8> {
    let hex = |byte: u8| (byte as char).to_digit(16);
    let mut out = Vec::with_capacity(body.len());
    let mut index = 0;
    while index < body.len() {
        let byte = body[index];
        if byte != b'=' {
            out.push(byte);
            index += 1;
            continue;
        }
        let rest = &body[index + 1..];
        if rest.starts_with(b"\r\n") {
            index += 3;
        } else if rest.starts_with(b"\n") {
            index += 2;
        } else if let (Some(high), Some(low)) = (
            rest.first().copied().and_then(hex),
            rest.get(1).copied().and_then(hex),
        ) {
            out.push(u8::try_from(high * 16 + low).unwrap_or(b'='));
            index += 3;
        } else {
            out.push(byte);
            index += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_are_unfolded_and_named_in_lowercase() {
        let entity = Entity::read(
            b"Content-Type: multipart/report;\r\n\treport-type=delivery-status;\r\n boundary=\"a;b\"\r\nX-Two: 1\r\nX-Two: 2\r\n\r\nbody\r\n",
        );
        let content_type = entity.content_type();
        assert_eq!(content_type.kind, "multipart/report");
        assert_eq!(
            content_type.parameter("report-type"),
            Some("delivery-status")
        );
        assert_eq!(content_type.parameter("boundary"), Some("a;b"));
        assert_eq!(entity.every("x-two").collect::<Vec<_>>(), ["1", "2"]);
        assert_eq!(entity.body, b"body\r\n");
        assert_eq!(
            Entity::read(b"Subject: x").content_type().kind,
            "text/plain"
        );
    }

    #[test]
    fn a_multipart_body_splits_at_its_boundaries() {
        let body = b"preamble\r\n--b\r\nContent-Type: text/plain\r\n\r\none\r\n--b \r\n\r\ntwo\r\n--b--\r\nepilogue\r\n--b\r\n\r\nnever\r\n";
        let parts = parts(body, "b");
        assert_eq!(parts.len(), 2);
        assert_eq!(Entity::read(parts[0]).body, b"one");
        assert_eq!(Entity::read(parts[1]).body, b"two");
        // A line that only starts with the boundary is not one.
        assert_eq!(
            super::parts(b"--b\r\n\r\nx\r\n--bb\r\n--b--\r\n", "b").len(),
            1
        );
    }

    #[test]
    fn transfer_encodings_are_undone() {
        let base64 = Entity::read(b"Content-Transfer-Encoding: base64\r\n\r\naGVs\r\nbG8=\r\n");
        assert_eq!(&*base64.decoded(), b"hello");
        let quoted =
            Entity::read(b"Content-Transfer-Encoding: Quoted-Printable\r\n\r\na=3Db=\r\nc =ZZ\r\n");
        assert_eq!(&*quoted.decoded(), b"a=bc =ZZ\r\n");
    }

    #[test]
    fn limits_hold_whatever_the_input() {
        let many: String = (0..MAX_FIELDS + 100)
            .map(|n| format!("X-{n}: v\r\n"))
            .collect();
        assert_eq!(Entity::read(many.as_bytes()).fields.len(), MAX_FIELDS);
        let parts: String = (0..100).map(|_| "--b\r\n\r\nx\r\n").collect();
        assert_eq!(super::parts(parts.as_bytes(), "b").len(), MAX_PARTS);
    }
}
