//! Running a protocol session over a stream: reading with the session's
//! deadline, and writing what it asks in order. Both the submission server
//! and the delivery client run their plain phase and their TLS phase through
//! this, one stream type each.

use std::io::{self, IoSlice};
use std::time::Duration;

use bytes::{Buf, Bytes};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::clock::SystemClock;

/// The most read at once.
const READ: usize = 64 * 1024;

pub enum Read {
    Bytes(Bytes),
    /// The session's deadline passed first.
    Deadline,
    /// The peer closed the connection.
    Closed,
}

/// Reads what arrives, or waits until `deadline`.
pub async fn read<S: AsyncRead + Unpin>(
    stream: &mut S,
    buffer: &mut Vec<u8>,
    deadline: Option<engine_core::time::Monotonic>,
    clock: &SystemClock,
) -> io::Result<Read> {
    buffer.resize(READ, 0);
    let read = match deadline {
        Some(at) => match tokio::time::timeout_at(clock.instant(at), stream.read(buffer)).await {
            Ok(read) => read,
            Err(_) => return Ok(Read::Deadline),
        },
        None => stream.read(buffer).await,
    }?;
    if read == 0 {
        return Ok(Read::Closed);
    }
    Ok(Read::Bytes(Bytes::copy_from_slice(&buffer[..read])))
}

/// How long a write may wait for the peer to take it: RFC 5321's three
/// minutes for a block of data (4.5.3.2.5), so a peer that stops reading
/// loses its connection rather than holding it, and what it holds, for
/// good.
const WRITE: Duration = Duration::from_secs(180);

/// Writes `pending` in one go and flushes it, within [`WRITE`].
pub async fn write<S: AsyncWrite + Unpin>(
    stream: &mut S,
    pending: &mut Vec<Bytes>,
) -> io::Result<()> {
    within(stream, pending, WRITE).await
}

async fn within<S: AsyncWrite + Unpin>(
    stream: &mut S,
    pending: &mut Vec<Bytes>,
    limit: Duration,
) -> io::Result<()> {
    pending.retain(|bytes| !bytes.is_empty());
    if pending.is_empty() {
        return Ok(());
    }
    tokio::time::timeout(limit, written(stream, pending))
        .await
        .unwrap_or_else(|_| Err(io::ErrorKind::TimedOut.into()))
}

async fn written<S: AsyncWrite + Unpin>(
    stream: &mut S,
    pending: &mut Vec<Bytes>,
) -> io::Result<()> {
    // As many buffers as the stream takes at once, in one vectored write:
    // a session's replies, or a transaction's commands and its content,
    // cost one write, not one each.
    while !pending.is_empty() {
        let mut slices = [IoSlice::new(&[]); VECTORED];
        for (slice, bytes) in slices.iter_mut().zip(pending.iter()) {
            *slice = IoSlice::new(bytes);
        }
        let filled = pending.len().min(VECTORED);
        let mut written = stream.write_vectored(&slices[..filled]).await?;
        if written == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        let done = pending
            .iter()
            .take_while(|bytes| {
                let whole = written >= bytes.len();
                if whole {
                    written -= bytes.len();
                }
                whole
            })
            .count();
        pending.drain(..done);
        if let Some(partial) = pending.first_mut() {
            partial.advance(written);
        }
    }
    stream.flush().await
}

/// The most buffers one vectored write takes.
const VECTORED: usize = 16;

/// How long a session's close may wait: TLS's own close sends what it
/// holds, and its `close_notify`, which a peer that stops reading never
/// takes.
const CLOSE: Duration = Duration::from_secs(10);

/// Closes `stream` as its protocol asks, within [`CLOSE`]; past it, the
/// connection goes as the stream is dropped.
pub async fn close<S: AsyncWrite + Unpin>(stream: &mut S) {
    close_within(stream, CLOSE).await;
}

async fn close_within<S: AsyncWrite + Unpin>(stream: &mut S, limit: Duration) {
    let _ = tokio::time::timeout(limit, stream.shutdown()).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn pending_buffers_are_written_whole_and_in_order() {
        let mut pending: Vec<Bytes> = vec![Bytes::new(); 17];
        pending.extend((0..40).map(|n| Bytes::from(format!("{n},"))));
        pending.push(Bytes::new());
        let expected: String = (0..40).map(|n| format!("{n},")).collect();
        let mut written = Vec::new();
        write(&mut written, &mut pending).await.unwrap();
        assert_eq!(String::from_utf8(written).unwrap(), expected);
        assert!(pending.is_empty());
    }

    /// A stream whose close never finishes, as a TLS stream's to a peer
    /// that has stopped reading.
    struct Stuck;

    impl AsyncWrite for Stuck {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            written: &[u8],
        ) -> std::task::Poll<io::Result<usize>> {
            std::task::Poll::Ready(Ok(written.len()))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Pending
        }
    }

    #[tokio::test]
    async fn a_close_the_peer_never_lets_finish_ends_at_its_bound() {
        let closed = tokio::time::timeout(
            Duration::from_secs(5),
            close_within(&mut Stuck, Duration::from_millis(50)),
        )
        .await;
        assert!(closed.is_ok(), "the close waited past its bound");
    }

    #[tokio::test]
    async fn a_peer_that_stops_reading_times_the_write_out() {
        // Its buffer full, the peer reads nothing more.
        let (mut ours, _theirs) = tokio::io::duplex(1024);
        let mut pending = vec![Bytes::from(vec![b'x'; 64 * 1024])];
        let written = within(&mut ours, &mut pending, Duration::from_millis(50)).await;
        assert_eq!(written.unwrap_err().kind(), io::ErrorKind::TimedOut);
    }
}
