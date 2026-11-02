//! The SMTP line handling the load generator and the sink share.

use std::io;

use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

/// The longest command or reply line either side accepts, CRLF included.
/// RFC 5321 allows 512 octets; extensions make some replies longer.
const LINE_LIMIT: usize = 4096;

/// Reads one line, CRLF included, into `line`. Returns false at the end of
/// the stream.
pub async fn read_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    line: &mut Vec<u8>,
) -> io::Result<bool> {
    line.clear();
    if reader.read_until(b'\n', line).await? == 0 {
        return Ok(false);
    }
    if line.len() > LINE_LIMIT || !line.ends_with(b"\n") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "an SMTP line was too long or unterminated",
        ));
    }
    Ok(true)
}

/// A reply: its code, and the text of each of its lines.
pub struct Reply {
    pub code: u16,
    pub lines: Vec<String>,
}

impl Reply {
    pub fn text(&self) -> String {
        self.lines.join(" / ")
    }
}

pub async fn read_reply<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    line: &mut Vec<u8>,
) -> io::Result<Reply> {
    let mut lines = Vec::new();
    loop {
        if !read_line(reader, line).await? {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the connection closed before a reply",
            ));
        }
        let text = line.trim_ascii_end();
        let code = text
            .get(..3)
            .and_then(|digits| std::str::from_utf8(digits).ok())
            .and_then(|digits| digits.parse().ok())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("not an SMTP reply: {}", String::from_utf8_lossy(text)),
                )
            })?;
        let last = text.get(3) != Some(&b'-');
        lines.push(String::from_utf8_lossy(text.get(4..).unwrap_or_default()).into_owned());
        if last {
            return Ok(Reply { code, lines });
        }
    }
}

/// Writes `bytes` to the stream under `reader` and flushes them.
pub async fn send<S: AsyncRead + AsyncWrite + Unpin>(
    reader: &mut BufReader<S>,
    bytes: &[u8],
) -> io::Result<()> {
    let stream = reader.get_mut();
    stream.write_all(bytes).await?;
    stream.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn replies_join_their_lines() {
        let mut input: &[u8] = b"250-sink.test\r\n250-PIPELINING\r\n250 STARTTLS\r\n354 go\r\n";
        let mut line = Vec::new();
        let reply = read_reply(&mut input, &mut line).await.unwrap();
        assert_eq!(reply.code, 250);
        assert_eq!(reply.lines, ["sink.test", "PIPELINING", "STARTTLS"]);
        assert_eq!(read_reply(&mut input, &mut line).await.unwrap().code, 354);
        assert!(read_reply(&mut input, &mut line).await.is_err());
        let mut garbage: &[u8] = b"hello\r\n";
        assert!(read_reply(&mut garbage, &mut line).await.is_err());
    }
}
