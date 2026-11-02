//! Message content after DATA (RFC 5321, 4.1.1.4 and 4.5.2): read up to the
//! terminating line, with dot-stuffing removed.
//!
//! A line begins only after CRLF, and only CRLF `.` CRLF ends the content,
//! so a bare LF can never end a message early (the SMTP smuggling family of
//! attacks). The DATA command's own CRLF counts as the line end before the
//! first line, so an empty message and a stuffed first line are read
//! correctly.

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum State {
    /// After CRLF.
    #[default]
    LineStart,
    /// Within a line; `cr` if its last byte was CR.
    Line { cr: bool },
    /// A dot at the start of a line.
    Dot,
    /// A dot and CR at the start of a line.
    DotCr,
}

#[derive(Debug, Default)]
pub struct ContentReader {
    state: State,
}

impl ContentReader {
    /// Appends content from the front of `input` to `out`, and returns true
    /// once the terminating line has been read. Bytes after it stay in
    /// `input`.
    pub fn read(&mut self, input: &mut &[u8], out: &mut Vec<u8>) -> bool {
        let mut rest = *input;
        let ended = loop {
            let Some(&first) = rest.first() else {
                break false;
            };
            match self.state {
                State::LineStart if first == b'.' => {
                    rest = &rest[1..];
                    self.state = State::Dot;
                }
                State::LineStart => self.state = State::Line { cr: false },
                State::Dot if first == b'\r' => {
                    rest = &rest[1..];
                    self.state = State::DotCr;
                }
                // The dot was stuffing, and is dropped.
                State::Dot => self.state = State::Line { cr: false },
                State::DotCr if first == b'\n' => {
                    rest = &rest[1..];
                    break true;
                }
                State::DotCr => {
                    out.push(b'\r');
                    self.state = State::Line { cr: true };
                }
                State::Line { cr } => match rest.iter().position(|&byte| byte == b'\n') {
                    Some(at) => {
                        let crlf = if at == 0 { cr } else { rest[at - 1] == b'\r' };
                        out.extend_from_slice(&rest[..=at]);
                        rest = &rest[at + 1..];
                        self.state = if crlf {
                            State::LineStart
                        } else {
                            State::Line { cr: false }
                        };
                    }
                    None => {
                        out.extend_from_slice(rest);
                        self.state = State::Line {
                            cr: rest.last() == Some(&b'\r'),
                        };
                        rest = &[];
                    }
                },
            }
        };
        *input = rest;
        if ended {
            self.state = State::LineStart;
        }
        ended
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reads `wire` split at every point, and returns the content and what
    /// followed it, once they agree for every split.
    fn read(wire: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
        let mut agreed = None;
        for split in 0..=wire.len() {
            let mut reader = ContentReader::default();
            let mut out = Vec::new();
            let mut first = &wire[..split];
            let mut second = &wire[split..];
            let result = if reader.read(&mut first, &mut out) {
                Some((out, [first, second].concat()))
            } else if reader.read(&mut second, &mut out) {
                Some((out, second.to_vec()))
            } else {
                None
            };
            match &agreed {
                None if split == 0 => agreed = Some(result),
                Some(previous) => assert_eq!(previous, &result, "split at {split}"),
                None => unreachable!(),
            }
        }
        agreed.flatten()
    }

    #[test]
    fn content_ends_at_the_dot_line_and_is_unstuffed() {
        assert_eq!(
            read(b"a\r\n..b\r\n.\r\nQUIT\r\n"),
            Some((b"a\r\n.b\r\n".to_vec(), b"QUIT\r\n".to_vec()))
        );
        assert_eq!(read(b".\r\n"), Some((Vec::new(), Vec::new())));
        assert_eq!(
            read(b"..first\r\n.\r\n"),
            Some((b".first\r\n".to_vec(), Vec::new()))
        );
        assert_eq!(read(b".x\r\n.\r\n"), Some((b"x\r\n".to_vec(), Vec::new())));
        assert_eq!(
            read(b".\rx\r\n.\r\n"),
            Some((b"\rx\r\n".to_vec(), Vec::new()))
        );
        assert_eq!(read(b"no end\r\n"), None);
    }

    #[test]
    fn a_bare_line_feed_never_ends_the_content() {
        assert_eq!(
            read(b"a\n.\r\nb\r\n.\r\n"),
            Some((b"a\n.\r\nb\r\n".to_vec(), Vec::new()))
        );
        assert_eq!(
            read(b"a\r\n.\nb\r\n.\r\n"),
            Some((b"a\r\n\nb\r\n".to_vec(), Vec::new()))
        );
        assert_eq!(
            read(b"a\r\r\n.\r\n"),
            Some((b"a\r\r\n".to_vec(), Vec::new()))
        );
    }
}
