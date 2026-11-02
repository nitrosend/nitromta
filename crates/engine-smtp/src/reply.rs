//! SMTP replies (RFC 5321, 4.2): what a server writes and a client reads.

/// The longest reply line either side accepts, CRLF included. RFC 5321
/// allows 512 octets; extensions make some replies longer.
const MAX_LINE: usize = 4096;
/// The most lines one reply may have.
const MAX_LINES: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reply {
    pub code: u16,
    /// Each line's text, without its code.
    pub lines: Vec<String>,
}

impl Reply {
    pub fn new(code: u16, text: impl Into<String>) -> Self {
        Self {
            code,
            lines: vec![text.into()],
        }
    }

    pub fn is_positive(&self) -> bool {
        matches!(self.code / 100, 2 | 3)
    }

    pub fn is_transient(&self) -> bool {
        self.code / 100 == 4
    }

    pub fn text(&self) -> String {
        self.lines.join(" ")
    }

    /// Appends the reply as it goes on the wire.
    pub fn write(&self, out: &mut Vec<u8>) {
        let code = self.code.to_string();
        for (index, line) in self.lines.iter().enumerate() {
            out.extend_from_slice(code.as_bytes());
            out.push(if index + 1 == self.lines.len() {
                b' '
            } else {
                b'-'
            });
            out.extend_from_slice(line.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        if self.lines.is_empty() {
            out.extend_from_slice(code.as_bytes());
            out.extend_from_slice(b" \r\n");
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplyError {
    /// A line that is not `ddd` followed by a space, a hyphen or its end.
    Malformed,
    TooLong,
    /// A continuation line changed the reply's code.
    CodeChanged,
}

/// Reads replies from bytes as they arrive, however they are split.
#[derive(Debug, Default)]
pub struct ReplyReader {
    line: Vec<u8>,
    code: Option<u16>,
    lines: Vec<String>,
}

impl ReplyReader {
    /// Takes bytes from the front of `input` until a whole reply has been
    /// read, and returns it. Bytes after it stay in `input`.
    pub fn read(&mut self, input: &mut &[u8]) -> Result<Option<Reply>, ReplyError> {
        loop {
            let Some(end) = input.iter().position(|&byte| byte == b'\n') else {
                if self.line.len() + input.len() > MAX_LINE {
                    return Err(ReplyError::TooLong);
                }
                self.line.extend_from_slice(input);
                *input = &[];
                return Ok(None);
            };
            if self.line.len() + end + 1 > MAX_LINE {
                return Err(ReplyError::TooLong);
            }
            self.line.extend_from_slice(&input[..=end]);
            *input = &input[end + 1..];

            let line = self.line.trim_ascii_end();
            let code = line
                .get(..3)
                .filter(|digits| digits.iter().all(u8::is_ascii_digit))
                .and_then(|digits| std::str::from_utf8(digits).ok())
                .and_then(|digits| digits.parse::<u16>().ok())
                .filter(|code| (200..600).contains(code))
                .ok_or(ReplyError::Malformed)?;
            let last = match line.get(3) {
                None | Some(b' ') => true,
                Some(b'-') => false,
                Some(_) => return Err(ReplyError::Malformed),
            };
            if self.code.is_some_and(|first| first != code) {
                return Err(ReplyError::CodeChanged);
            }
            if self.lines.len() == MAX_LINES {
                return Err(ReplyError::TooLong);
            }
            self.code = Some(code);
            self.lines
                .push(String::from_utf8_lossy(line.get(4..).unwrap_or_default()).into_owned());
            self.line.clear();
            if last {
                self.code = None;
                return Ok(Some(Reply {
                    code,
                    lines: std::mem::take(&mut self.lines),
                }));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replies_are_read_however_they_are_split() {
        let wire = b"250-mx.test\r\n250-PIPELINING\r\n250 STARTTLS\r\n354 go ahead\r\n";
        for split in 0..wire.len() {
            let mut reader = ReplyReader::default();
            let mut replies = Vec::new();
            for part in [&wire[..split], &wire[split..]] {
                let mut input = part;
                while let Some(reply) = reader.read(&mut input).unwrap() {
                    replies.push(reply);
                }
                assert!(input.is_empty());
            }
            assert_eq!(replies.len(), 2, "split at {split}");
            assert_eq!(replies[0].lines, ["mx.test", "PIPELINING", "STARTTLS"]);
            assert_eq!(
                (replies[1].code, replies[1].text()),
                (354, "go ahead".to_owned())
            );
        }
    }

    #[test]
    fn bad_replies_are_errors() {
        let read = |wire: &[u8]| ReplyReader::default().read(&mut &wire[..]);
        assert_eq!(read(b"hello\r\n"), Err(ReplyError::Malformed));
        assert_eq!(read(b"25x ok\r\n"), Err(ReplyError::Malformed));
        assert_eq!(read(b"250+ok\r\n"), Err(ReplyError::Malformed));
        assert_eq!(read(b"250-a\r\n251 b\r\n"), Err(ReplyError::CodeChanged));
        assert_eq!(read(&[b'2'; MAX_LINE + 1]), Err(ReplyError::TooLong));
        assert_eq!(read(b"220\r\n").unwrap().unwrap().lines, [""]);
    }

    #[test]
    fn replies_write_their_continuation_lines() {
        let reply = Reply {
            code: 250,
            lines: vec!["host".to_owned(), "PIPELINING".to_owned()],
        };
        let mut out = Vec::new();
        reply.write(&mut out);
        assert_eq!(out, b"250-host\r\n250 PIPELINING\r\n");
        let mut input = &out[..];
        assert_eq!(
            ReplyReader::default().read(&mut input).unwrap(),
            Some(reply)
        );
    }
}
