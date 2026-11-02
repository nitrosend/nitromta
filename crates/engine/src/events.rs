//! Event delivery's driver: runs engine-events' component on a
//! task of its own, tells it the policy as it changes and the operator's
//! replays, carries its requests to the store, and posts its batches to
//! subscribers over HTTP/1.1, each subscription keeping its connection open
//! between batches. A subscriber's host is resolved and connected to as the
//! outbound network policy allows, at an address the policy was
//! checked against.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use engine_core::command::{Answer, Command, Commit, Request, Response, Unavailable};
use engine_core::component::{Component, Ticket};
use engine_core::id::{AccountId, SubscriptionId};
use engine_core::outbound::Outbound;
use engine_core::retry::RetrySchedule;
use engine_core::rng::Rng;
use engine_events::{Config, Events, Input, Output, Post};
use http_body_util::Full;
use hyper::client::conn::http1::SendRequest;
use hyper_util::rt::TokioIo;
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio_rustls::TlsConnector;

use crate::clock::SystemClock;
use crate::config;
use crate::operator::Operations;
use crate::policy::Current;
use crate::store::Store;

/// How soon a feed that has caught up reads again.
const IDLE: Duration = Duration::from_millis(200);
/// How long a subscriber has to take a batch.
const TIMEOUT: Duration = Duration::from_secs(10);
/// How often the policy is looked at for subscriptions added or removed.
const POLICY_CHECK: Duration = Duration::from_secs(1);

/// Connections kept open, one to each subscription's receiver.
type Connections = Arc<Mutex<BTreeMap<SubscriptionId, SendRequest<Full<Bytes>>>>>;

/// The operator's replays of parked batches, waiting for event delivery to
/// say how many it will post again.
pub struct Replays {
    inbox: mpsc::UnboundedSender<Input>,
    next: AtomicU64,
    waiting: Mutex<BTreeMap<u64, oneshot::Sender<Result<usize, String>>>>,
}

impl Replays {
    /// Asks for `subscription`'s parked batches in `account` to be posted
    /// again, or the one whose first event is at `first`.
    pub fn ask(
        &self,
        account: AccountId,
        subscription: String,
        first: Option<u64>,
    ) -> oneshot::Receiver<Result<usize, String>> {
        let ticket = self.next.fetch_add(1, Ordering::Relaxed);
        let (reply, replaying) = oneshot::channel();
        self.waiting().insert(ticket, reply);
        let _ = self.inbox.send(Input::Replay {
            ticket: Ticket(ticket),
            account,
            subscription,
            first,
        });
        replaying
    }

    fn answer(&self, ticket: Ticket, outcome: Result<usize, String>) {
        if let Some(reply) = self.waiting().remove(&ticket.0) {
            let _ = reply.send(outcome);
        }
    }

    fn waiting(
        &self,
    ) -> std::sync::MutexGuard<'_, BTreeMap<u64, oneshot::Sender<Result<usize, String>>>> {
        self.waiting
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// What event delivery is started with, beside the store and the policy.
pub struct Delivery {
    pub clock: Arc<SystemClock>,
    pub outbound: Outbound,
    /// Checks `https` subscribers' certificates; without it, they cannot be
    /// reached.
    pub tls: Option<Arc<ClientConfig>>,
    pub rng: Rng,
    pub operations: Arc<Operations>,
}

/// Starts event delivery, each subscription within `budget`, and returns
/// where the operator's replays go.
pub fn spawn(
    store: Store,
    policy: Arc<Current>,
    budget: &config::Events,
    delivery: Delivery,
    sns: Option<(Arc<crate::sns::Sns>, String)>,
) -> Arc<Replays> {
    let config = Config {
        batch: budget.batch_events.max(1),
        batch_bytes: budget.batch_bytes,
        idle: IDLE,
        retry: RetrySchedule::new(Duration::from_secs(1), Duration::from_secs(300))
            .expect("a valid schedule"),
        park_after: Duration::from_secs(budget.park_after_seconds),
    };
    let (inbox, inputs) = mpsc::unbounded_channel();
    let replays = Arc::new(Replays {
        inbox: inbox.clone(),
        next: AtomicU64::new(0),
        waiting: Mutex::default(),
    });
    let Delivery {
        clock,
        outbound,
        tls,
        rng,
        operations,
    } = delivery;
    let network = Network { outbound, tls };
    tokio::spawn(run(
        Events::new(config, rng),
        Wiring {
            store,
            policy,
            clock,
            network,
            operations,
            replays: Arc::clone(&replays),
            sns,
        },
        (inbox, inputs),
    ));
    replays
}

/// What event delivery's task carries its outputs to.
struct Wiring {
    store: Store,
    policy: Arc<Current>,
    clock: Arc<SystemClock>,
    network: Network,
    operations: Arc<Operations>,
    replays: Arc<Replays>,
    /// The SNS subset's key, and the region its topics are in.
    sns: Option<(Arc<crate::sns::Sns>, String)>,
}

/// How subscribers are reached: where the policy allows, over TLS checked
/// against the authorities when `https`.
#[derive(Clone)]
pub struct Network {
    outbound: Outbound,
    tls: Option<Arc<ClientConfig>>,
}

impl Network {
    pub fn new(outbound: Outbound, tls: Option<Arc<ClientConfig>>) -> Self {
        Self { outbound, tls }
    }
}

/// Posts `body` to `url` once, on a connection of its own, as SNS posts a
/// subscriber its confirmation: taken, or why not.
pub async fn post_once(
    network: &Network,
    url: &str,
    content_type: &'static str,
    headers: &[(&'static str, String)],
    body: Bytes,
) -> Result<(), String> {
    let attempt = async {
        let mut sender = connect(url, network).await?;
        let malformed = || MALFORMED.to_owned();
        let uri: http::Uri = url.parse().map_err(|_| malformed())?;
        let mut request =
            http::Request::post(uri.path_and_query().map_or("/", |path| path.as_str()))
                .header(
                    http::header::HOST,
                    uri.authority().ok_or_else(malformed)?.as_str(),
                )
                .header(http::header::CONTENT_TYPE, content_type);
        for (name, value) in headers {
            request = request.header(*name, value);
        }
        let request = request.body(Full::new(body)).map_err(|_| malformed())?;
        let response = sender
            .send_request(request)
            .await
            .map_err(|error| format!("posting: {error}"))?;
        Ok::<_, String>(response.status())
    };
    let status = tokio::time::timeout(TIMEOUT, attempt)
        .await
        .map_err(|_| format!("no answer within {} s", TIMEOUT.as_secs()))??;
    if status.is_success() {
        Ok(())
    } else {
        Err(format!("answered {}", status.as_u16()))
    }
}

async fn run(
    mut events: Events,
    wiring: Wiring,
    (inbox, mut inputs): (mpsc::UnboundedSender<Input>, mpsc::UnboundedReceiver<Input>),
) {
    let Wiring {
        store,
        policy,
        clock,
        network,
        operations,
        replays,
        sns,
    } = wiring;
    let connections = Connections::default();
    let mut seen = None;
    let mut signing = None;
    let mut out = Vec::new();
    loop {
        let snapshot = policy.load();
        let revision = snapshot.policy().revision();
        if seen != Some(revision) {
            seen = Some(revision);
            let policy = Arc::clone(snapshot.policy());
            events.handle(clock.now(), Input::Policy(policy));
        }
        // Topic subscribers are posted under the SNS key as it is now: at
        // the start, and after each reload.
        if let Some((sns, region)) = &sns {
            let current = sns.signing();
            if signing
                .as_ref()
                .is_none_or(|signing| !Arc::ptr_eq(signing, &current))
            {
                let publishing = engine_events::sns::Publishing {
                    signer: Arc::clone(&current.signer),
                    url: sns.url.clone(),
                    region: region.clone(),
                };
                events.handle(clock.now(), Input::Publishing(Arc::new(publishing)));
                signing = Some(current);
            }
        }
        let now = clock.now();
        let next = events.poll(now, &mut out);
        for output in out.drain(..) {
            match output {
                Output::Request(request) => ask(&store, request, &inbox, &operations),
                Output::Replaying { ticket, outcome } => replays.answer(ticket, outcome),
                Output::Post(post) => {
                    let inbox = inbox.clone();
                    let (network, connections) = (network.clone(), Arc::clone(&connections));
                    let operations = Arc::clone(&operations);
                    tokio::spawn(async move {
                        let (id, subscription) = (post.id, post.subscription);
                        let failure = deliver(post, &network, &connections).await.err();
                        let counted = if failure.is_none() {
                            &operations.batches_taken
                        } else {
                            &operations.batches_refused
                        };
                        counted.fetch_add(1, Ordering::Relaxed);
                        if let Some(failure) = &failure {
                            tracing::warn!(
                                subscription = %format_args!("{:016x}", subscription.0.as_u64()),
                                batch = id,
                                %failure,
                                "a subscriber did not take a batch; it is posted again until its budget is spent"
                            );
                        }
                        let _ = inbox.send(Input::Posted { post: id, failure });
                    });
                }
            }
        }
        let wait = next
            .map_or(POLICY_CHECK, |at| {
                at.saturating_duration_since(now.monotonic)
            })
            .min(POLICY_CHECK);
        tokio::select! {
            input = inputs.recv() => {
                let Some(input) = input else { return };
                events.handle(clock.now(), input);
                while let Ok(input) = inputs.try_recv() {
                    events.handle(clock.now(), input);
                }
            }
            () = tokio::time::sleep(wait) => {}
        }
    }
}

/// Sends `request` to the store, its answer to come back as an input, and
/// counts the batches parked and replayed.
fn ask(
    store: &Store,
    request: Request,
    inbox: &mpsc::UnboundedSender<Input>,
    operations: &Arc<Operations>,
) {
    let Request { ticket, command } = request;
    let unanswered = match &command {
        Command::Acknowledge { .. } => Answer::Acknowledged(Commit::Unavailable),
        Command::ParkEvents(_) => Answer::EventsParked(Commit::Unavailable),
        Command::UnparkEvents { .. } => Answer::EventsUnparked(Commit::Unavailable),
        Command::ParkedEvents { .. } => Answer::ParkedEvents(Err(Unavailable)),
        Command::EventsFailing { .. } => Answer::EventsFailing(Commit::Unavailable),
        _ => Answer::Events(Err(Unavailable)),
    };
    let answer = store.submit(command);
    let (inbox, operations) = (inbox.clone(), Arc::clone(operations));
    tokio::spawn(async move {
        let answer = match answer {
            Some(answer) => answer.await.unwrap_or(unanswered),
            None => unanswered,
        };
        match &answer {
            Answer::EventsParked(Commit::Committed(())) => {
                operations.events_parked.fetch_add(1, Ordering::Relaxed);
                tracing::warn!("a batch of events past its budget is parked, for replay");
            }
            Answer::EventsUnparked(Commit::Committed(())) => {
                operations.events_replayed.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
        let _ = inbox.send(Input::Answer(Response { ticket, answer }));
    });
}

/// Posts a batch: taken, or why its subscriber did not take it.
async fn deliver(post: Post, network: &Network, connections: &Connections) -> Result<(), String> {
    let subscription = post.subscription;
    let kept = connections
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remove(&subscription);
    let attempt = async {
        // A kept connection the receiver has since closed is opened again.
        let reusable = match kept {
            Some(mut sender) => sender.ready().await.is_ok().then_some(sender),
            None => None,
        };
        let mut sender = match reusable {
            Some(sender) => sender,
            None => connect(&post.url, network).await?,
        };
        let response = sender
            .send_request(request(&post)?)
            .await
            .map_err(|error| format!("posting: {error}"))?;
        Ok::<_, String>((sender, response.status()))
    };
    let (sender, status) = tokio::time::timeout(TIMEOUT, attempt)
        .await
        .map_err(|_| format!("no answer within {} s", TIMEOUT.as_secs()))??;
    connections
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(subscription, sender);
    if status.is_success() {
        Ok(())
    } else {
        Err(format!("answered {}", status.as_u16()))
    }
}

/// Why a subscription's URL was not posted to.
const MALFORMED: &str = "its URL is not one to post to";

fn request(post: &Post) -> Result<http::Request<Full<Bytes>>, String> {
    // The URL itself is never in a reason: its path or query may hold a
    // secret of the receiver's.
    let malformed = || MALFORMED.to_owned();
    let uri: http::Uri = post.url.parse().map_err(|_| malformed())?;
    let mut request = http::Request::post(uri.path_and_query().map_or("/", |path| path.as_str()))
        .header(
            http::header::HOST,
            uri.authority().ok_or_else(malformed)?.as_str(),
        )
        .header(http::header::CONTENT_TYPE, post.content_type);
    for (name, value) in &post.headers {
        request = request.header(*name, value);
    }
    request
        .body(Full::new(post.body.clone()))
        .map_err(|_| malformed())
}

/// Opens a connection to `url`'s receiver, at the first of its addresses
/// the outbound policy allows, over TLS for `https`.
async fn connect(url: &str, network: &Network) -> Result<SendRequest<Full<Bytes>>, String> {
    let malformed = || MALFORMED.to_owned();
    let uri: http::Uri = url.parse().map_err(|_| malformed())?;
    let host = uri
        .host()
        .ok_or_else(malformed)?
        .trim_start_matches('[')
        .trim_end_matches(']');
    let https = uri.scheme_str() == Some("https");
    let port = uri.port_u16().unwrap_or(if https { 443 } else { 80 });
    let address = tokio::net::lookup_host((host, port))
        .await
        .map_err(|error| format!("looking {host} up: {error}"))?
        .find(|address| network.outbound.permits(address.ip()))
        .ok_or_else(|| format!("{host} has no address the outbound policy allows"))?;
    let stream = TcpStream::connect(address)
        .await
        .map_err(|error| format!("connecting to {address}: {error}"))?;
    let _ = stream.set_nodelay(true);
    if https {
        let name = ServerName::try_from(host.to_owned()).map_err(|_| malformed())?;
        let tls = network
            .tls
            .as_ref()
            .ok_or("no certificate authorities to check https with")?;
        let stream = TlsConnector::from(Arc::clone(tls))
            .connect(name, stream)
            .await
            .map_err(|error| format!("TLS with {host}: {error}"))?;
        handshake(TokioIo::new(stream)).await
    } else {
        handshake(TokioIo::new(stream)).await
    }
}

async fn handshake<T>(io: TokioIo<T>) -> Result<SendRequest<Full<Bytes>>, String>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (sender, connection) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|error| format!("HTTP: {error}"))?;
    tokio::spawn(connection);
    Ok(sender)
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use http_body_util::BodyExt;
    use hyper::service::service_fn;
    use tokio::net::TcpListener;

    use super::*;

    /// What a receiver on loopback was sent, and how many connections it
    /// took. It answers 200, or 503 to a body of `refuse`.
    struct Receiver {
        url: String,
        posts: Arc<Mutex<Vec<(http::HeaderMap, Bytes)>>>,
        connections: Arc<AtomicUsize>,
    }

    async fn receiver() -> Receiver {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/hooks", listener.local_addr().unwrap());
        let posts = Arc::new(Mutex::new(Vec::new()));
        let connections = Arc::new(AtomicUsize::new(0));
        let (taken, counted) = (Arc::clone(&posts), Arc::clone(&connections));
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                counted.fetch_add(1, Ordering::SeqCst);
                let taken = Arc::clone(&taken);
                let service = service_fn(move |request: http::Request<hyper::body::Incoming>| {
                    let taken = Arc::clone(&taken);
                    async move {
                        let headers = request.headers().clone();
                        let body = request.into_body().collect().await.unwrap().to_bytes();
                        let status = if body == "refuse" { 503 } else { 200 };
                        taken.lock().unwrap().push((headers, body));
                        let mut response = http::Response::new(Full::new(Bytes::new()));
                        *response.status_mut() = http::StatusCode::from_u16(status).unwrap();
                        Ok::<_, Infallible>(response)
                    }
                });
                tokio::spawn(
                    hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service),
                );
            }
        });
        Receiver {
            url,
            posts,
            connections,
        }
    }

    fn post(id: u64, url: &str, body: &'static str) -> Post {
        Post {
            id,
            subscription: SubscriptionId(engine_core::id::Id::from_u64(9).unwrap()),
            url: url.to_owned(),
            content_type: "application/json",
            headers: engine_events::sign::headers(
                &[3; 32],
                "batch-1",
                1_800_000_000,
                body.as_bytes(),
            ),
            body: Bytes::from_static(body.as_bytes()),
        }
    }

    #[tokio::test]
    async fn a_batch_is_posted_signed_on_a_kept_connection_and_a_refusal_fails_it() {
        let receiver = receiver().await;
        let (network, connections) = (local(), Connections::default());
        assert_eq!(
            deliver(post(1, &receiver.url, "{\"a\":1}"), &network, &connections).await,
            Ok(())
        );
        assert_eq!(
            deliver(post(2, &receiver.url, "{\"b\":2}"), &network, &connections).await,
            Ok(())
        );
        assert_eq!(
            deliver(post(3, &receiver.url, "refuse"), &network, &connections).await,
            Err("answered 503".to_owned())
        );
        assert_eq!(
            receiver.connections.load(Ordering::SeqCst),
            1,
            "one connection kept"
        );
        {
            let posts = receiver.posts.lock().unwrap();
            let (headers, body) = &posts[0];
            assert_eq!(body, "{\"a\":1}");
            assert_eq!(headers["content-type"], "application/json");
            assert_eq!(headers["webhook-id"], "batch-1");
            assert_eq!(headers["webhook-timestamp"], "1800000000");
            let signed =
                engine_events::sign::headers(&[3; 32], "batch-1", 1_800_000_000, b"{\"a\":1}");
            assert_eq!(headers["webhook-signature"], signed[2].1.as_str());
        }

        let nobody = post(4, "http://127.0.0.1:9/hooks", "{}");
        assert!(
            deliver(nobody, &network, &Connections::default())
                .await
                .is_err_and(|why| why.starts_with("connecting to")),
            "no receiver"
        );
        let unverified = post(5, &receiver.url.replace("http:", "https:"), "{}");
        assert_eq!(
            deliver(unverified, &network, &Connections::default()).await,
            Err("no certificate authorities to check https with".to_owned()),
            "no authorities"
        );
        let production = Network {
            outbound: Outbound::default(),
            tls: None,
        };
        let refused = post(6, &receiver.url, "{}");
        assert!(
            deliver(refused, &production, &Connections::default())
                .await
                .is_err_and(|why| why.ends_with("no address the outbound policy allows")),
            "a private receiver"
        );
        assert_eq!(receiver.posts.lock().unwrap().len(), 3, "never reached");
    }

    /// A test's network: local receivers allowed, no authorities.
    fn local() -> Network {
        Network {
            outbound: Outbound {
                private_allowed: true,
            },
            tls: None,
        }
    }
}
