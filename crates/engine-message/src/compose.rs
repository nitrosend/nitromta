//! MIME construction for a message given as parts: headers, a subject, and a
//! text body, an HTML body or both. Every line of the result is 7-bit and
//! fits RFC 5322's limit, so it is prepared and signed like any submitted
//! message.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use engine_core::time::Timestamp;

/// RFC 2045's limit on an encoded line, without its CRLF.
const ENCODED_LINE: usize = 76;
/// UTF-8 bytes per encoded word, so each fits RFC 2047's 75 characters.
const WORD_BYTES: usize = 45;

pub struct Parts<'a> {
    /// The From field's value, as given: an address or `Name <address>`.
    pub from: &'a str,
    pub to: &'a [String],
    pub cc: &'a [String],
    pub reply_to: &'a [String],
    pub subject: &'a str,
    pub text: Option<&'a str>,
    pub html: Option<&'a str>,
    /// Further header fields, by name and value.
    pub headers: &'a [(String, String)],
    pub date: Timestamp,
    /// The Message-ID, without its angle brackets.
    pub message_id: &'a str,
    /// The most bytes the message may come to: past it, it is refused
    /// before more of it is built.
    pub most: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ComposeError {
    /// Neither a text nor an HTML body.
    NoBody,
    /// A header name or value that would break the header block.
    Header(String),
    /// It would come to more than its parts allow.
    TooLarge,
}

/// Builds the message. Its multipart boundary derives from the Message-ID,
/// so the same parts always make the same bytes.
pub fn compose(parts: &Parts<'_>) -> Result<Vec<u8>, ComposeError> {
    let mut out = Vec::with_capacity(
        (1024 + parts.text.map_or(0, str::len) + parts.html.map_or(0, str::len)).min(parts.most),
    );
    field(&mut out, "From", &display(checked("From", parts.from)?))?;
    for (name, list) in [
        ("To", parts.to),
        ("Cc", parts.cc),
        ("Reply-To", parts.reply_to),
    ] {
        if !list.is_empty() {
            let mut joined = Vec::with_capacity(list.len());
            for address in list {
                joined.push(display(checked(name, address)?));
            }
            field(&mut out, name, &joined.join(", "))?;
        }
    }
    field(
        &mut out,
        "Subject",
        &words(checked("Subject", parts.subject)?),
    )?;
    field(&mut out, "Date", &rfc5322(parts.date))?;
    field(&mut out, "Message-ID", &format!("<{}>", parts.message_id))?;
    for (name, value) in parts.headers {
        let reserved = [
            "from",
            "to",
            "cc",
            "bcc",
            "reply-to",
            "subject",
            "date",
            "message-id",
            "mime-version",
            "content-type",
            "content-transfer-encoding",
        ];
        if reserved
            .iter()
            .any(|reserved| name.eq_ignore_ascii_case(reserved))
        {
            return Err(ComposeError::Header(format!(
                "{name} is set by the message itself"
            )));
        }
        field(&mut out, name, &words(checked(name, value)?))?;
    }
    field(&mut out, "MIME-Version", "1.0")?;
    let most = parts.most;
    match (parts.text, parts.html) {
        (None, None) => return Err(ComposeError::NoBody),
        (Some(body), None) => single(&mut out, "text/plain", body, most)?,
        (None, Some(body)) => single(&mut out, "text/html", body, most)?,
        (Some(text), Some(html)) => {
            let boundary = boundary(parts.message_id, &[text, html]);
            out.extend_from_slice(
                format!("Content-Type: multipart/alternative; boundary=\"{boundary}\"\r\n\r\n")
                    .as_bytes(),
            );
            for (kind, body) in [("text/plain", text), ("text/html", html)] {
                out.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
                single(&mut out, kind, body, most)?;
            }
            out.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
        }
    }
    if out.len() > most {
        return Err(ComposeError::TooLarge);
    }
    Ok(out)
}

/// Raw header text, which must not hold a line break: one would end the
/// field early and start another.
fn checked<'a>(name: &str, raw: &'a str) -> Result<&'a str, ComposeError> {
    if raw.contains(['\r', '\n']) {
        return Err(ComposeError::Header(format!(
            "the value of {name} has a line break"
        )));
    }
    Ok(raw)
}

/// A header field whose value is already encoded, and checked as raw text.
fn field(out: &mut Vec<u8>, name: &str, value: &str) -> Result<(), ComposeError> {
    let printable = |c: char| c.is_ascii_graphic() && c != ':';
    if name.is_empty() || !name.chars().all(printable) {
        return Err(ComposeError::Header(format!(
            "{name:?} is not a header name"
        )));
    }
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(b": ");
    out.extend_from_slice(value.as_bytes());
    out.extend_from_slice(b"\r\n");
    Ok(())
}

/// One body part: its type and encoding, a blank line, and the body.
/// ASCII that already fits stays 7bit; anything else is quoted-printable.
/// Refused once the message would pass `most` bytes.
fn single(out: &mut Vec<u8>, kind: &str, body: &str, most: usize) -> Result<(), ComposeError> {
    let body = crlf(body);
    let plain = body.is_ascii()
        && body
            .split(|&byte| byte == b'\n')
            .all(|line| line.len() <= 999);
    let encoding = if plain { "7bit" } else { "quoted-printable" };
    out.extend_from_slice(
        format!(
            "Content-Type: {kind}; charset=UTF-8\r\nContent-Transfer-Encoding: {encoding}\r\n\r\n"
        )
        .as_bytes(),
    );
    if plain {
        if out.len() + body.len() > most {
            return Err(ComposeError::TooLarge);
        }
        out.extend_from_slice(&body);
    } else {
        quoted_printable(&body, out, most)?;
    }
    if !out.ends_with(b"\r\n") {
        out.extend_from_slice(b"\r\n");
    }
    Ok(())
}

/// Line endings as CRLF, whatever they were, in one pass.
fn crlf(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() + bytes.len() / 32);
    let mut at = 0;
    while at < bytes.len() {
        match bytes[at] {
            b'\r' => {
                out.extend_from_slice(b"\r\n");
                if bytes.get(at + 1) == Some(&b'\n') {
                    at += 1;
                }
            }
            b'\n' => out.extend_from_slice(b"\r\n"),
            byte => out.push(byte),
        }
        at += 1;
    }
    out
}

/// Quoted-printable (RFC 2045, 6.7) of text whose lines end in CRLF,
/// refused once `out` would pass `most` bytes.
fn quoted_printable(text: &[u8], out: &mut Vec<u8>, most: usize) -> Result<(), ComposeError> {
    for (index, line) in text.split(|&byte| byte == b'\n').enumerate() {
        if index > 0 {
            out.extend_from_slice(b"\r\n");
        }
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let mut length = 0;
        for (at, &byte) in line.iter().enumerate() {
            let last = at + 1 == line.len();
            let literal = (byte == b' ' || byte == b'\t') && !last
                || (33..=126).contains(&byte) && byte != b'=';
            let width = if literal { 1 } else { 3 };
            // A soft break keeps every line within the limit, the `=` included.
            if length + width > ENCODED_LINE - 1 {
                if out.len() > most {
                    return Err(ComposeError::TooLarge);
                }
                out.extend_from_slice(b"=\r\n");
                length = 0;
            }
            if literal {
                out.push(byte);
            } else {
                out.extend_from_slice(format!("={byte:02X}").as_bytes());
            }
            length += width;
        }
        if out.len() > most {
            return Err(ComposeError::TooLarge);
        }
    }
    Ok(())
}

/// Text as it may appear in a header: unchanged if it is printable ASCII,
/// otherwise as UTF-8 encoded words (RFC 2047), folded between words.
fn words(text: &str) -> String {
    if text.chars().all(|c| c == ' ' || c.is_ascii_graphic()) && text.len() <= 900 {
        return text.to_owned();
    }
    let mut encoded = Vec::new();
    let mut start = 0;
    while start < text.len() {
        let mut end = (start + WORD_BYTES).min(text.len());
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        encoded.push(format!(
            "=?UTF-8?B?{}?=",
            STANDARD.encode(&text.as_bytes()[start..end])
        ));
        start = end;
    }
    encoded.join("\r\n ")
}

/// An address field's value, with a non-ASCII display name encoded.
fn display(address: &str) -> String {
    match address.rsplit_once('<') {
        Some((name, rest)) if !name.is_ascii() => format!("{} <{rest}", words(name.trim())),
        _ => address.to_owned(),
    }
}

/// A boundary no part contains: one derived from the Message-ID, lengthened
/// until it is unique.
fn boundary(message_id: &str, parts: &[&str]) -> String {
    let base: String = message_id
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .collect();
    let mut boundary = format!("=_part_{base}");
    while parts.iter().any(|part| part.contains(&boundary)) {
        boundary.push('_');
    }
    boundary
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

#[cfg(test)]
mod tests {
    use super::*;

    fn parts<'a>(text: Option<&'a str>, html: Option<&'a str>) -> Parts<'a> {
        Parts {
            from: "Load <load@bench.test>",
            to: &[],
            cc: &[],
            reply_to: &[],
            subject: "Hello",
            text,
            html,
            headers: &[],
            date: Timestamp::from_micros(1_700_000_000_000_000),
            message_id: "0123abcd@bench.test",
            most: usize::MAX,
        }
    }

    fn text(parts: &Parts<'_>) -> String {
        String::from_utf8(compose(parts).unwrap()).unwrap()
    }

    #[test]
    fn a_text_message_has_its_headers_and_stays_seven_bit() {
        let to = ["a@sink.test".to_owned(), "b@sink.test".to_owned()];
        let message = text(&Parts {
            to: &to,
            ..parts(Some("Line one\nLine two"), None)
        });
        assert_eq!(
            message,
            "From: Load <load@bench.test>\r\nTo: a@sink.test, b@sink.test\r\nSubject: Hello\r\n\
             Date: Tue, 14 Nov 2023 22:13:20 +0000\r\nMessage-ID: <0123abcd@bench.test>\r\n\
             MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\
             Content-Transfer-Encoding: 7bit\r\n\r\nLine one\r\nLine two\r\n"
        );
    }

    #[test]
    fn text_and_html_make_an_alternative_and_utf8_is_encoded() {
        let message = text(&Parts {
            subject: "Grüße aus Köln, ein längerer Betreff mit Umlauten",
            ..parts(Some("Grüße"), Some("<p>Grüße</p>"))
        });
        assert!(message.contains(
            "Content-Type: multipart/alternative; boundary=\"=_part_0123abcdbenchtest\""
        ));
        assert!(
            message
                .contains("Content-Transfer-Encoding: quoted-printable\r\n\r\nGr=C3=BC=C3=9Fe\r\n")
        );
        assert!(message.ends_with("--=_part_0123abcdbenchtest--\r\n"));
        let subject = message
            .lines()
            .find(|line| line.starts_with("Subject: "))
            .unwrap();
        assert!(subject.starts_with("Subject: =?UTF-8?B?"));
        for line in message.split("\r\n") {
            assert!(line.is_ascii() && line.len() <= 998, "{line}");
        }
    }

    #[test]
    fn quoted_printable_lines_stay_within_the_limit() {
        let long = "é".repeat(200) + " trailing ";
        let mut out = Vec::new();
        quoted_printable(long.as_bytes(), &mut out, usize::MAX).unwrap();
        let encoded = String::from_utf8(out).unwrap();
        assert!(encoded.split("\r\n").all(|line| line.len() <= ENCODED_LINE));
        assert!(
            encoded.ends_with("=20"),
            "a trailing space is encoded: {encoded}"
        );
    }

    #[test]
    fn headers_cannot_be_injected_or_duplicated() {
        let injected = [("X-Campaign".to_owned(), "a\r\nBcc: evil@x.test".to_owned())];
        assert!(matches!(
            compose(&Parts {
                headers: &injected,
                ..parts(Some("x"), None)
            }),
            Err(ComposeError::Header(_))
        ));
        let duplicate = [("subject".to_owned(), "again".to_owned())];
        assert!(matches!(
            compose(&Parts {
                headers: &duplicate,
                ..parts(Some("x"), None)
            }),
            Err(ComposeError::Header(_))
        ));
        assert_eq!(compose(&parts(None, None)), Err(ComposeError::NoBody));
    }

    #[test]
    fn a_message_past_its_bytes_is_refused_before_it_is_built_whole() {
        // Each `=` quoted-printable writes as three bytes.
        let body = "=".repeat(10_000);
        let whole = compose(&parts(Some(&body), None)).unwrap();
        assert!(whole.len() > 30_000);
        for most in [100, 20_000, whole.len() - 1] {
            assert_eq!(
                compose(&Parts {
                    most,
                    ..parts(Some(&body), None)
                }),
                Err(ComposeError::TooLarge),
                "{most}"
            );
        }
        let plain = "x".repeat(500);
        assert_eq!(
            compose(&Parts {
                most: 400,
                ..parts(Some(&plain), None)
            }),
            Err(ComposeError::TooLarge)
        );
        assert_eq!(
            compose(&Parts {
                most: whole.len(),
                ..parts(Some(&body), None)
            }),
            Ok(whole)
        );
    }

    #[test]
    fn line_endings_become_crlf_whatever_they_were() {
        assert_eq!(crlf("a\nb\rc\r\nd\r"), b"a\r\nb\r\nc\r\nd\r\n");
    }

    #[test]
    fn the_boundary_avoids_the_parts() {
        let boundary = boundary("id", &["contains =_part_id here"]);
        assert_eq!(boundary, "=_part_id_");
    }
}
