//! A listener's connections: at most so many open at once,
//! a new one past them closed as it comes, before anything is read from it
//! or written to it, and counted.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

use crate::operator::{Listener, Operations};

/// Connections a listener keeps open at once at most.
pub const MOST_OPEN: usize = 1024;

/// Accepts `listener`'s connections, at most `most` open at once, each
/// served by `serve` in a task of its own, which holds its place until it
/// ends. Those past the most are closed as they come, and counted as
/// `which`'s.
pub async fn accept<S>(
    listener: TcpListener,
    which: Listener,
    most: usize,
    operations: &Operations,
    serve: impl Fn(TcpStream) -> S,
) -> Result<(), String>
where
    S: Future<Output = ()> + Send + 'static,
{
    let open = Arc::new(Semaphore::new(most));
    loop {
        match listener.accept().await {
            Ok((tcp, _)) => {
                let Ok(place) = Arc::clone(&open).try_acquire_owned() else {
                    operations.refused_connection(which);
                    continue;
                };
                let _ = tcp.set_nodelay(true);
                let connection = serve(tcp);
                tokio::spawn(async move {
                    connection.await;
                    drop(place);
                });
            }
            // Out of descriptors, for one: the next connection may fare
            // better.
            Err(error) => {
                tracing::warn!(%error, listener = which.name(), "accepting a connection");
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use tokio::io::AsyncReadExt as _;

    use super::*;

    #[tokio::test]
    async fn past_its_most_a_connection_is_closed_as_it_comes_and_counted() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let operations = Arc::new(Operations::default());
        let counting = Arc::clone(&operations);
        // Each connection served stays open until it is told to end.
        let (end, ending) = tokio::sync::watch::channel(0);
        tokio::spawn(async move {
            let _ = accept(listener, Listener::Ses, 2, &counting, move |tcp| {
                let mut ending = ending.clone();
                ending.borrow_and_update();
                async move {
                    let _ = ending.changed().await;
                    drop(tcp);
                }
            })
            .await;
        });
        let mut open = Vec::new();
        for _ in 0..2 {
            open.push(TcpStream::connect(address).await.unwrap());
        }
        let mut byte = [0; 1];
        let mut past = TcpStream::connect(address).await.unwrap();
        assert_eq!(past.read(&mut byte).await.unwrap(), 0, "closed as it came");
        let refused =
            || operations.connections_refused[Listener::Ses as usize].load(Ordering::Relaxed);
        assert_eq!(refused(), 1);
        // Once those open end, there are places again.
        end.send(1).unwrap();
        for mut ended in open {
            assert_eq!(ended.read(&mut byte).await.unwrap(), 0);
        }
        let mut again = TcpStream::connect(address).await.unwrap();
        let read = tokio::time::timeout(Duration::from_millis(200), again.read(&mut byte)).await;
        assert!(read.is_err(), "served, and open");
        assert_eq!(refused(), 1);
    }
}
