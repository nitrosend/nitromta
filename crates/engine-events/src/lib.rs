//! Event delivery: each subscription's events, read from the
//! journal past its cursor, rendered ([`render`]), signed ([`sign`]) and
//! posted in batches, one batch at a time and in order, then acknowledged,
//! which moves the cursor on. A batch that fails is posted again on a
//! schedule, under the same ID and signed afresh, for as long as its
//! subscription's budget allows: then it is parked, its span recorded in
//! the commit that moves the cursor past it, so the subscription's later
//! events go on. A parked batch is posted again when an operator asks,
//! marked as a replay, and its record goes once a replay is taken. Nothing
//! is written for an event: one acknowledgement covers a batch.
//!
//! [`Events`] is a component. Its driver hands it the current policy, the
//! store's answers, each post's outcome and the operator's replays, and
//! carries its requests to the store and its posts to subscribers. Webhooks
//! never gate sending: a subscriber that fails holds back only its own
//! events.

pub mod render;
pub mod ses;
pub mod sign;
pub mod sns;

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use engine_core::command::{Answer, Command, Commit, Owed, ParkedEvents, Request, Response};
use engine_core::component::{Component, Ticket};
use engine_core::id::{AccountId, SubscriptionId};
use engine_core::policy::{Feed as Fed, Policy, Subscriber, Subscription};
use engine_core::retry::RetrySchedule;
use engine_core::rng::Rng;
use engine_core::time::{Monotonic, Now, Timestamp};

#[derive(Clone, Copy, Debug)]
pub struct Config {
    /// Journal entries read at a time, and so the most events in a batch.
    pub batch: usize,
    /// The most bytes a batch's body holds, unless its one event holds more.
    pub batch_bytes: usize,
    /// How soon a feed that has caught up reads again.
    pub idle: Duration,
    /// When a batch that failed is posted again.
    pub retry: RetrySchedule,
    /// How long a batch is posted again from its first failure before it is
    /// parked.
    pub park_after: Duration,
}

#[derive(Debug)]
pub enum Input {
    /// Policy at a new revision: a subscription it adds starts a feed, and
    /// one it removes stops its own.
    Policy(Arc<Policy>),
    /// What topic subscribers are posted under, as it is at the start and
    /// after each reload: none, and they are posted nothing.
    Publishing(Arc<sns::Publishing>),
    /// The store's answer to a request.
    Answer(Response),
    /// What became of a post: taken (answered 2xx), or why not.
    Posted { post: u64, failure: Option<String> },
    /// The operator asks for a subscription's parked batches to be posted
    /// again, or the one whose first event is at `first`: answered with
    /// `Output::Replaying` under the ticket.
    Replay {
        ticket: Ticket,
        account: AccountId,
        subscription: String,
        first: Option<u64>,
    },
}

#[derive(Debug)]
pub enum Output {
    /// A request to the store.
    Request(Request),
    Post(Post),
    /// The answer to `Input::Replay`: how many parked batches will be posted
    /// again, or why none.
    Replaying {
        ticket: Ticket,
        outcome: Result<usize, String>,
    },
}

/// What to post: a subscription's batch, signed as Standard Webhooks signs
/// one, or one notification to a topic's subscriber, signed as SNS signs
/// one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Post {
    /// Its number, by which its outcome comes back.
    pub id: u64,
    pub subscription: SubscriptionId,
    pub url: String,
    pub content_type: &'static str,
    pub headers: Vec<(&'static str, String)>,
    pub body: Bytes,
}

pub struct Events {
    config: Config,
    rng: Rng,
    feeds: BTreeMap<SubscriptionId, Feed>,
    /// What each request to the store is for.
    asked: BTreeMap<Ticket, Asked>,
    next_ticket: u64,
    next_post: u64,
    /// What topic subscribers are posted under, once given.
    publishing: Option<Arc<sns::Publishing>>,
    /// The policy last adopted, which a new publishing adopts again.
    adopted: Option<Arc<Policy>>,
    /// Inputs taken and not yet acted on.
    policy: Option<Arc<Policy>>,
    answers: Vec<Response>,
    posted: Vec<(u64, Option<String>)>,
    replays: Vec<(Ticket, AccountId, String, Option<u64>)>,
}

/// Parked batches a subscription may have waiting to be posted again.
const REPLAYS_QUEUED: usize = 100;

/// Why a batch was parked with no failure of its own: its budget ran out
/// before a restart, whose failures this run never saw.
const PAST_BUDGET: &str = "its budget ran out before the engine started again";

/// What a request to the store is for.
#[derive(Clone, Copy)]
enum Asked {
    /// A feed's read, acknowledgement or parking.
    Feed(SubscriptionId),
    /// A feed's replay: the check that its batch is still parked, the read
    /// of its events, or its record's removal.
    Replay(SubscriptionId),
    /// The parked batches an operator's replay asks for, under its ticket.
    /// A replay's parked batches: all of them, or the one it names.
    Parked(Ticket, Option<u64>),
    /// A note the store keeps, whose answer changes nothing here.
    Noted,
}

/// Who a feed posts to, and in which shape.
#[derive(Clone)]
enum Target {
    /// A subscription's webhook, posted batches of native events.
    Webhook(Subscription),
    /// A topic's confirmed subscriber, posted each event in SES's shape, one
    /// a request, as SNS posts a `Notification`.
    Topic {
        subscriber: Subscriber,
        topic_arn: String,
        unsubscribe_url: String,
    },
}

impl Target {
    fn url(&self) -> &str {
        match self {
            Self::Webhook(subscription) => &subscription.url,
            Self::Topic { subscriber, .. } => &subscriber.endpoint,
        }
    }
}

/// One subscription's delivery.
struct Feed {
    target: Target,
    /// How far its events are delivered, as far as it knows: its cursor,
    /// once the first read has told it.
    after: Option<u64>,
    state: State,
    /// Parked batches to post again, one at a time, beside the feed and in
    /// turn with it, and the first positions of those queued or under way.
    replays: VecDeque<ParkedEvents>,
    replaying: BTreeSet<u64>,
    replay: Replay,
}

impl Feed {
    /// Whether one of its batches is with its subscriber: a subscription
    /// has one in flight at most, its feed's or a replay's.
    fn posting(&self) -> bool {
        matches!(self.state, State::Posting { .. }) || matches!(self.replay, Replay::Posting(..))
    }
}

enum State {
    /// Ready to read once `due`.
    Idle {
        due: Monotonic,
    },
    Reading,
    /// A batch to post once `due`.
    Ready {
        batch: Batch,
        tries: Tries,
        due: Monotonic,
    },
    Posting {
        batch: Batch,
        tries: Tries,
        post: u64,
    },
    Acknowledging {
        through: u64,
    },
    /// A batch past its budget being parked, which moves the cursor past
    /// `through`.
    Parking {
        through: u64,
    },
}

/// A batch's posts so far, since when they have failed, and why the last
/// did.
#[derive(Clone)]
struct Tries {
    attempts: u32,
    failing_since: Option<Timestamp>,
    failure: Option<String>,
}

enum Replay {
    Idle,
    /// Asking whether it is still parked: a listing may be older than a
    /// replay that has since taken it.
    Checking(ParkedEvents),
    Reading(ParkedEvents),
    /// Read again, waiting for its subscription's one place in flight.
    Ready(ParkedEvents, Batch),
    /// With its subscriber: a topic's posted one notification at a time.
    Posting(ParkedEvents, Batch, u64),
    Unparking(u64),
}

struct Batch {
    /// The same however often it is posted, so a receiver that took it
    /// before can tell.
    id: String,
    /// A subscription's: the batch, posted whole.
    body: Bytes,
    /// A topic subscriber's: each event's notification, its ID and its
    /// body, posted one at a time, and how many are taken.
    notifications: Vec<(String, Bytes)>,
    taken: usize,
    /// The positions of its first event and of the last entry it covers.
    first: u64,
    through: u64,
    /// Posted again by the operator's replay, and marked so.
    replay: bool,
}

impl Events {
    pub fn new(config: Config, rng: Rng) -> Self {
        Self {
            config,
            rng,
            feeds: BTreeMap::new(),
            asked: BTreeMap::new(),
            next_ticket: 0,
            next_post: 0,
            publishing: None,
            adopted: None,
            policy: None,
            answers: Vec::new(),
            posted: Vec::new(),
            replays: Vec::new(),
        }
    }

    fn adopt(&mut self, policy: &Policy, now: Monotonic) {
        let publishing = self.publishing.as_deref();
        // A topic's subscriber is fed once it has confirmed, and while
        // there is a key to sign what it is posted.
        let fed = |id: &SubscriptionId| match policy.feed(*id) {
            Some(Fed::Webhook(_)) => true,
            Some(Fed::Topic(subscriber)) => subscriber.confirmed && publishing.is_some(),
            None => false,
        };
        self.feeds.retain(|id, _| fed(id));
        let topics = policy
            .subscribers()
            .filter(|subscriber| subscriber.confirmed)
            .filter_map(|subscriber| {
                let publishing = publishing?;
                let topic = policy.topic_of(subscriber.topic)?;
                let topic_arn = publishing.topic_arn(subscriber.account, &topic.name);
                let unsubscribe_url = format!(
                    "{}/?Action=Unsubscribe&SubscriptionArn={}&Token={}",
                    publishing.url,
                    encoded(&format!("{topic_arn}:{:016x}", subscriber.id.0.as_u64())),
                    subscriber
                        .token
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<String>()
                );
                Some((
                    subscriber.id,
                    Target::Topic {
                        subscriber: subscriber.clone(),
                        topic_arn,
                        unsubscribe_url,
                    },
                ))
            });
        let webhooks = policy
            .subscriptions()
            .map(|subscription| (subscription.id, Target::Webhook(subscription.clone())));
        for (id, target) in webhooks.chain(topics) {
            self.feeds.entry(id).or_insert_with(|| Feed {
                target,
                after: None,
                state: State::Idle { due: now },
                replays: VecDeque::new(),
                replaying: BTreeSet::new(),
                replay: Replay::Idle,
            });
        }
    }

    fn ask(&mut self, asked: Asked, command: Command, out: &mut Vec<Output>) {
        let ticket = Ticket(self.next_ticket);
        self.next_ticket += 1;
        self.asked.insert(ticket, asked);
        out.push(Output::Request(Request { ticket, command }));
    }

    fn answer(&mut self, now: Now, response: Response, out: &mut Vec<Output>) {
        match self.asked.remove(&response.ticket) {
            Some(Asked::Feed(id)) => self.fed(now, id, response.answer, out),
            Some(Asked::Replay(id)) => self.replayed(id, response.answer, out),
            Some(Asked::Parked(ticket, named)) => {
                let outcome = match response.answer {
                    Answer::ParkedEvents(Ok(Some((id, parked)))) => match self.feeds.get_mut(&id) {
                        // Those not already queued or under way, as many as
                        // its queue has room for.
                        Some(feed) => {
                            let room = REPLAYS_QUEUED.saturating_sub(feed.replays.len());
                            let mut added = 0;
                            let named = |parked: &ParkedEvents| {
                                named.is_none_or(|first| parked.first == first)
                            };
                            for parked in parked.into_iter().filter(named) {
                                if added < room && feed.replaying.insert(parked.first) {
                                    feed.replays.push_back(parked);
                                    added += 1;
                                }
                            }
                            Ok(added)
                        }
                        None => Err("the subscription is not delivered to".to_owned()),
                    },
                    Answer::ParkedEvents(Ok(None)) => Err("no such subscription".to_owned()),
                    _ => Err("the store did not answer".to_owned()),
                };
                out.push(Output::Replaying { ticket, outcome });
            }
            Some(Asked::Noted) | None => {}
        }
    }

    /// A feed's answer from the store.
    fn fed(&mut self, now: Now, id: SubscriptionId, answer: Answer, out: &mut Vec<Output>) {
        let config = self.config;
        let Some(feed) = self.feeds.get_mut(&id) else {
            return;
        };
        let idle = State::Idle {
            due: now.monotonic.saturating_add(config.idle),
        };
        match (&feed.state, answer) {
            (State::Reading, Answer::Events(Ok(Some(owed)))) => {
                if owed.entries.is_empty() {
                    // Nothing it owes: past what it read, if anything.
                    if feed.after.is_some_and(|after| owed.through > after) {
                        feed.state = State::Acknowledging {
                            through: owed.through,
                        };
                        let through = owed.through;
                        self.ask(Asked::Feed(id), acknowledge(id, through), out);
                    } else {
                        feed.after = Some(owed.through);
                        feed.state = idle;
                    }
                } else {
                    // A batch that was failing before a restart keeps its
                    // budget's start.
                    let batch = batch(
                        &feed.target,
                        &owed,
                        config.batch_bytes,
                        None,
                        self.publishing.as_deref(),
                    );
                    // Nothing in SES's shape to post: delivered as it is.
                    if matches!(feed.target, Target::Topic { .. }) && batch.notifications.is_empty()
                    {
                        feed.state = State::Acknowledging {
                            through: batch.through,
                        };
                        let through = batch.through;
                        self.ask(Asked::Feed(id), acknowledge(id, through), out);
                        return;
                    }
                    feed.state = State::Ready {
                        batch,
                        tries: Tries {
                            attempts: 0,
                            failing_since: owed.failing_since,
                            failure: None,
                        },
                        due: now.monotonic,
                    };
                }
            }
            // Removed since: the next policy stops its feed.
            (State::Reading, Answer::Events(Ok(None))) => {
                self.feeds.remove(&id);
            }
            (
                State::Acknowledging { through } | State::Parking { through },
                Answer::Acknowledged(commit) | Answer::EventsParked(commit),
            ) => match commit {
                Commit::Refused(_) => {
                    self.feeds.remove(&id);
                }
                // Delivered or parked, so it reads on at once. A change that
                // did not commit leaves its cursor behind, and a restart
                // delivers those events again, under the same IDs.
                commit => {
                    feed.after = Some(*through);
                    feed.state = if matches!(commit, Commit::Committed(())) {
                        State::Idle { due: now.monotonic }
                    } else {
                        idle
                    };
                }
            },
            // The store could not answer: it is asked again later.
            _ => feed.state = idle,
        }
    }

    /// A replay's answer from the store: its batch still parked, whose
    /// events are then read again whole; those events, which wait for the
    /// subscription's place in flight; or its record's removal, once taken.
    fn replayed(&mut self, id: SubscriptionId, answer: Answer, out: &mut Vec<Output>) {
        let Some(feed) = self.feeds.get_mut(&id) else {
            return;
        };
        match (std::mem::replace(&mut feed.replay, Replay::Idle), answer) {
            (Replay::Checking(asked), Answer::ParkedEvents(Ok(Some((found, parked)))))
                if found == id
                    && parked
                        .first()
                        .is_some_and(|parked| parked.first == asked.first) =>
            {
                let parked = parked.into_iter().next().expect("the one checked");
                let span = parked.through.saturating_sub(parked.first) + 1;
                let read = Command::Events {
                    subscription: id,
                    after: Some(parked.first.saturating_sub(1)),
                    until: Some(parked.through),
                    limit: usize::try_from(span).unwrap_or(usize::MAX),
                };
                feed.replay = Replay::Reading(parked);
                self.ask(Asked::Replay(id), read, out);
            }
            // No longer parked, or the store could not say: not posted.
            (Replay::Checking(asked), _) => {
                feed.replaying.remove(&asked.first);
            }
            (Replay::Reading(parked), Answer::Events(Ok(Some(owed))))
                if !owed.entries.is_empty() =>
            {
                let post = self.next_post;
                let batch = batch(
                    &feed.target,
                    &owed,
                    usize::MAX,
                    Some(post),
                    self.publishing.as_deref(),
                );
                // Nothing in SES's shape to post: taken as it is.
                if matches!(feed.target, Target::Topic { .. }) && batch.notifications.is_empty() {
                    let first = parked.first;
                    feed.replay = Replay::Unparking(first);
                    let command = Command::UnparkEvents {
                        subscription: id,
                        first,
                    };
                    self.ask(Asked::Replay(id), command, out);
                    return;
                }
                feed.replay = Replay::Ready(parked, batch);
            }
            // Its events are gone, trimmed since, or the store could not
            // answer: it stays parked, and the operator may ask again.
            (Replay::Reading(parked), _) => {
                feed.replaying.remove(&parked.first);
            }
            (Replay::Unparking(first), _) => {
                feed.replaying.remove(&first);
            }
            (state, _) => feed.replay = state,
        }
    }

    fn posted(&mut self, now: Now, post: u64, failure: Option<String>, out: &mut Vec<Output>) {
        let config = self.config;
        let found = self.feeds.iter_mut().find(|(_, feed)| {
            matches!(feed.state, State::Posting { post: current, .. } if current == post)
                || matches!(feed.replay, Replay::Posting(_, _, current) if current == post)
        });
        let Some((&id, feed)) = found else {
            return;
        };
        if matches!(&feed.replay, Replay::Posting(_, _, current) if *current == post)
            && let Replay::Posting(parked, mut batch, _) =
                std::mem::replace(&mut feed.replay, Replay::Idle)
        {
            let first = parked.first;
            // Taken: a topic's next notification, or its record goes.
            // Refused: it stays parked.
            if failure.is_some() {
                feed.replaying.remove(&first);
                return;
            }
            batch.taken += 1;
            if batch.taken < batch.notifications.len() {
                feed.replay = Replay::Ready(parked, batch);
                return;
            }
            feed.replay = Replay::Unparking(first);
            let command = Command::UnparkEvents {
                subscription: id,
                first,
            };
            self.ask(Asked::Replay(id), command, out);
            return;
        }
        let State::Posting { batch, tries, .. } =
            std::mem::replace(&mut feed.state, State::Reading)
        else {
            return;
        };
        let Some(failure) = failure else {
            // A topic subscriber's next notification, at once, or the
            // batch delivered.
            let mut batch = batch;
            batch.taken += 1;
            if batch.taken < batch.notifications.len() {
                // The batch's budget runs from its first failure, however
                // many of its notifications are taken since.
                feed.state = State::Ready {
                    batch,
                    tries: Tries {
                        attempts: 0,
                        failing_since: tries.failing_since,
                        failure: None,
                    },
                    due: now.monotonic,
                };
                return;
            }
            feed.state = State::Acknowledging {
                through: batch.through,
            };
            self.ask(Asked::Feed(id), acknowledge(id, batch.through), out);
            return;
        };
        let first_failure = tries.failing_since.is_none();
        let tries = Tries {
            attempts: tries.attempts + 1,
            failing_since: tries.failing_since.or(Some(now.wall)),
            failure: Some(failure),
        };
        let since = tries.failing_since.unwrap_or(now.wall);
        let deadline = since.saturating_add(config.park_after);
        // Past its budget: parked, and the feed goes on.
        if now.wall >= deadline {
            let (state, command) = park(id, &batch, tries, now);
            feed.state = state;
            self.ask(Asked::Feed(id), command, out);
            return;
        }
        // Posted again on the schedule, and parked at its deadline at the
        // latest.
        let again = config
            .retry
            .not_before(now.wall, tries.attempts, &mut self.rng)
            .min(deadline);
        let first = batch.first;
        feed.state = State::Ready {
            batch,
            tries,
            due: now
                .monotonic
                .saturating_add(again.saturating_duration_since(now.wall)),
        };
        // Its budget runs from its first failure, across restarts.
        if first_failure {
            let command = Command::EventsFailing {
                subscription: id,
                first,
                since: now.wall,
            };
            self.ask(Asked::Noted, command, out);
        }
    }
}

/// `batch` parked past its budget: the state that waits for the parking,
/// and the command that parks it.
fn park(id: SubscriptionId, batch: &Batch, tries: Tries, now: Now) -> (State, Command) {
    let parked = ParkedEvents {
        subscription: id,
        first: batch.first,
        through: batch.through,
        at: now.wall,
        attempts: tries.attempts,
        failure: tries.failure.unwrap_or_else(|| PAST_BUDGET.to_owned()),
    };
    let state = State::Parking {
        through: batch.through,
    };
    (state, Command::ParkEvents(parked))
}

fn acknowledge(subscription: SubscriptionId, through: u64) -> Command {
    Command::Acknowledge {
        subscription,
        through,
    }
}

/// The batch of what `owed` holds, of at most `bytes` unless its one event
/// holds more: it covers up to its last event if it holds fewer than
/// `owed` does. A replay, under post `replay`, is marked so, with an ID of
/// its own.
fn batch(
    target: &Target,
    owed: &Owed,
    bytes: usize,
    replay: Option<u64>,
    publishing: Option<&sns::Publishing>,
) -> Batch {
    let first = owed
        .entries
        .first()
        .map_or(owed.through, |(position, _)| *position);
    let (body, notifications, through, subscription) = match target {
        Target::Webhook(subscription) => {
            let (body, through) = render::bounded(subscription, owed, bytes, replay.is_some());
            (Bytes::from(body), Vec::new(), through, subscription.id)
        }
        Target::Topic {
            subscriber,
            topic_arn,
            unsubscribe_url,
        } => {
            let (notifications, through) = publishing.map_or_else(
                || (Vec::new(), owed.through),
                |publishing| {
                    notifications(
                        owed,
                        subscriber,
                        topic_arn,
                        unsubscribe_url,
                        publishing,
                        bytes,
                    )
                },
            );
            (Bytes::new(), notifications, through, subscriber.id)
        }
    };
    let id = format!(
        "{:016x}-{first:016x}-{through:016x}",
        subscription.0.as_u64()
    );
    Batch {
        id: match replay {
            Some(post) => format!("{id}-replay-{post}"),
            None => id,
        },
        body,
        notifications,
        taken: 0,
        first,
        through,
        replay: replay.is_some(),
    }
}

/// Each event `owed` holds in SES's shape, as a signed `Notification` of
/// `topic_arn`: its ID the same however often it is posted, as is its body,
/// whose time is its event's. At most `bytes` of them, and always one: those
/// that fit, and the last position they cover.
fn notifications(
    owed: &Owed,
    subscriber: &Subscriber,
    topic_arn: &str,
    unsubscribe_url: &str,
    publishing: &sns::Publishing,
    bytes: usize,
) -> (Vec<(String, Bytes)>, u64) {
    let mut notifications = Vec::new();
    let mut taken = 0;
    for (index, (position, entry)) in owed.entries.iter().enumerate() {
        let Some((message, kind)) = ses::event(*position, entry, owed, subscriber.account) else {
            continue;
        };
        let message_id = format!("{position:016x}-{kind}");
        let body = sns::notification(
            &publishing.signer,
            &sns::Notification {
                message_id: &message_id,
                topic_arn,
                message: &message,
                timestamp: &render::rfc3339(entry.at()),
                unsubscribe_url,
            },
        );
        if !notifications.is_empty() && taken + body.len() > bytes {
            return (notifications, owed.entries[index - 1].0);
        }
        taken += body.len();
        notifications.push((message_id, Bytes::from(body)));
    }
    (notifications, owed.through)
}

/// Text as a URL's query holds it.
fn encoded(text: &str) -> String {
    text.bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                char::from(byte).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

/// `batch` as post `post`: a subscription's signed now, a topic
/// subscriber's its next notification, signed as it was rendered.
fn signed(target: &Target, batch: &Batch, post: u64, now: Now) -> Post {
    match target {
        Target::Webhook(subscription) => {
            let timestamp = now.wall.as_micros() / 1_000_000;
            Post {
                id: post,
                subscription: subscription.id,
                url: subscription.url.clone(),
                content_type: "application/json",
                headers: sign::headers(&subscription.secret, &batch.id, timestamp, &batch.body),
                body: batch.body.clone(),
            }
        }
        Target::Topic {
            subscriber,
            topic_arn,
            ..
        } => {
            let (message_id, body) = &batch.notifications[batch.taken];
            let mut headers = vec![
                (sns::MESSAGE_TYPE, "Notification".to_owned()),
                (sns::MESSAGE_ID, message_id.clone()),
                (sns::TOPIC_ARN, topic_arn.clone()),
            ];
            if batch.replay {
                headers.push((sns::REPLAY, "true".to_owned()));
            }
            Post {
                id: post,
                subscription: subscriber.id,
                url: target.url().to_owned(),
                content_type: sns::CONTENT_TYPE,
                headers,
                body: body.clone(),
            }
        }
    }
}

impl Component for Events {
    type Input = Input;
    type Output = Output;

    fn handle(&mut self, _now: Now, input: Input) {
        match input {
            Input::Policy(policy) => self.policy = Some(policy),
            Input::Publishing(publishing) => {
                self.publishing = Some(publishing);
                // Its subscribers are fed under policy as it stands.
                if self.policy.is_none() {
                    self.policy = self.adopted.clone();
                }
            }
            Input::Answer(response) => self.answers.push(response),
            Input::Posted { post, failure } => self.posted.push((post, failure)),
            Input::Replay {
                ticket,
                account,
                subscription,
                first,
            } => self.replays.push((ticket, account, subscription, first)),
        }
    }

    fn poll(&mut self, now: Now, out: &mut Vec<Output>) -> Option<Monotonic> {
        if let Some(policy) = self.policy.take() {
            self.adopt(&policy, now.monotonic);
            self.adopted = Some(policy);
        }
        for response in std::mem::take(&mut self.answers) {
            self.answer(now, response, out);
        }
        for (post, failure) in std::mem::take(&mut self.posted) {
            self.posted(now, post, failure, out);
        }
        for (ticket, account, subscription, first) in std::mem::take(&mut self.replays) {
            // At most a queue's worth, or the one it names.
            let command = Command::ParkedEvents {
                account,
                subscription,
                from: first,
                limit: if first.is_some() { 1 } else { REPLAYS_QUEUED },
            };
            self.ask(Asked::Parked(ticket, first), command, out);
        }
        let mut next: Option<Monotonic> = None;
        let ids: Vec<SubscriptionId> = self.feeds.keys().copied().collect();
        for id in ids {
            let Some(feed) = self.feeds.get_mut(&id) else {
                continue;
            };
            // A replay, beside the feed, one parked batch at a time: once
            // it is known to be parked still, read again whole.
            if matches!(feed.replay, Replay::Idle)
                && let Some(parked) = feed.replays.pop_front()
            {
                let (account, name) = match &feed.target {
                    Target::Webhook(subscription) => {
                        (subscription.account, subscription.name.clone())
                    }
                    // By its ARN, which no subscription's name can be.
                    Target::Topic {
                        subscriber,
                        topic_arn,
                        ..
                    } => (
                        subscriber.account,
                        format!("{topic_arn}:{:016x}", subscriber.id.0.as_u64()),
                    ),
                };
                let check = Command::ParkedEvents {
                    account,
                    subscription: name,
                    from: Some(parked.first),
                    limit: 1,
                };
                feed.replay = Replay::Checking(parked);
                self.ask(Asked::Replay(id), check, out);
            }
            let Some(feed) = self.feeds.get_mut(&id) else {
                continue;
            };
            // Its one place in flight goes to a replay ready, or to its feed.
            if !feed.posting()
                && matches!(feed.replay, Replay::Ready(..))
                && let Replay::Ready(parked, batch) =
                    std::mem::replace(&mut feed.replay, Replay::Idle)
            {
                let post = self.next_post;
                self.next_post += 1;
                out.push(Output::Post(signed(&feed.target, &batch, post, now)));
                feed.replay = Replay::Posting(parked, batch, post);
            }
            let park_after = self.config.park_after;
            let expired = |tries: &Tries| {
                tries
                    .failing_since
                    .is_some_and(|since| now.wall >= since.saturating_add(park_after))
            };
            match &feed.state {
                // Past its budget, as a restart or a replay's turn may leave
                // it: parked, never posted again.
                State::Ready { tries, .. } if expired(tries) => {
                    let State::Ready { batch, tries, .. } =
                        std::mem::replace(&mut feed.state, State::Reading)
                    else {
                        continue;
                    };
                    let (state, command) = park(id, &batch, tries, now);
                    feed.state = state;
                    self.ask(Asked::Feed(id), command, out);
                }
                State::Idle { due } if *due <= now.monotonic => {
                    let read = Command::Events {
                        subscription: id,
                        after: feed.after,
                        until: None,
                        limit: self.config.batch,
                    };
                    feed.state = State::Reading;
                    self.ask(Asked::Feed(id), read, out);
                }
                State::Ready { due, .. } if *due <= now.monotonic && !feed.posting() => {
                    let State::Ready { batch, tries, .. } =
                        std::mem::replace(&mut feed.state, State::Reading)
                    else {
                        continue;
                    };
                    let post = self.next_post;
                    self.next_post += 1;
                    out.push(Output::Post(signed(&feed.target, &batch, post, now)));
                    feed.state = State::Posting { batch, tries, post };
                }
                // Waiting for its replay's post: the post's outcome wakes it.
                State::Ready { due, .. } if *due <= now.monotonic => {}
                State::Idle { due } | State::Ready { due, .. } => {
                    next = Some(next.map_or(*due, |next| next.min(*due)));
                }
                State::Reading
                | State::Posting { .. }
                | State::Acknowledging { .. }
                | State::Parking { .. } => {}
            }
        }
        next
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use engine_core::address::Address;
    use engine_core::attempt::{Attempt, AttemptEnd, AttemptResult, Evidence};
    use engine_core::event::EventKind;
    use engine_core::id::{AccountId, AttemptId, ConfigurationId, DeliveryId, Id, MessageId};
    use engine_core::journal::Entry;
    use engine_core::policy::Change;
    use engine_core::time::Timestamp;

    use super::*;

    const ACCOUNT: AccountId = AccountId(Id::from_u64(1).unwrap());
    const CONFIGURATION: ConfigurationId = ConfigurationId(Id::from_u64(2).unwrap());
    const SUBSCRIPTION: SubscriptionId = SubscriptionId(Id::from_u64(3).unwrap());

    fn id(value: u64) -> Id {
        Id::from_u64(value).unwrap()
    }

    fn at(millis: u64) -> Now {
        Now {
            wall: Timestamp::from_micros(1_800_000_000_000_000 + millis * 1_000),
            monotonic: Monotonic::from_micros(millis * 1_000),
        }
    }

    fn policy(subscribed: bool) -> Arc<Policy> {
        let mut policy = Policy::default();
        policy
            .apply(Change::Configuration {
                id: CONFIGURATION,
                account: ACCOUNT,
                name: "receipts".to_owned(),
                pool: None,
            })
            .unwrap();
        if subscribed {
            policy
                .apply(Change::Subscription {
                    id: SUBSCRIPTION,
                    account: ACCOUNT,
                    name: "hooks".to_owned(),
                    configuration: "receipts".to_owned(),
                    url: "https://hooks.example.test/in".to_owned(),
                    events: BTreeSet::from([EventKind::Accepted, EventKind::Bounced]),
                    secret: [5; 32],
                })
                .unwrap();
        }
        Arc::new(policy)
    }

    fn events() -> Events {
        let config = Config {
            batch: 100,
            batch_bytes: 1 << 20,
            idle: Duration::from_millis(200),
            retry: RetrySchedule::new(Duration::from_secs(1), Duration::from_secs(60)).unwrap(),
            park_after: Duration::from_secs(3_600),
        };
        Events::new(config, Rng::from_seed(1))
    }

    fn poll(events: &mut Events, now: Now) -> Vec<Output> {
        let mut out = Vec::new();
        events.poll(now, &mut out);
        out
    }

    fn request(out: &[Output]) -> &Request {
        match out {
            [Output::Request(request)] => request,
            other => panic!("expected one request, got {other:?}"),
        }
    }

    fn answer(events: &mut Events, request: &Request, answer: Answer, now: Now) -> Vec<Output> {
        let ticket = request.ticket;
        events.handle(now, Input::Answer(Response { ticket, answer }));
        poll(events, now)
    }

    fn owed() -> Owed {
        let message = MessageId(id(40));
        let delivery = DeliveryId(id(41));
        let rejected = Attempt {
            id: AttemptId(id(42)),
            delivery,
            account: ACCOUNT,
            reserved_at: at(0).wall,
            ended: Some(AttemptEnd {
                result: AttemptResult::Rejected,
                at: at(250).wall,
            }),
        };
        Owed {
            entries: vec![
                (
                    7,
                    Entry::Accepted {
                        message,
                        account: ACCOUNT,
                        configuration: Some(CONFIGURATION),
                        deliveries: vec![delivery],
                        at: at(0).wall,
                    },
                ),
                (
                    9,
                    Entry::Attempted {
                        attempt: rejected,
                        configuration: Some(CONFIGURATION),
                        evidence: Some(Evidence {
                            rules: "no-such-mailbox".to_owned(),
                            ..Evidence::new(550, "5.1.1 No such user")
                        }),
                    },
                ),
            ],
            deliveries: BTreeMap::from([(
                delivery,
                (message, Address::parse("ann@example.com").unwrap()),
            )]),
            mailed: BTreeMap::new(),
            through: 12,
            failing_since: None,
        }
    }

    #[test]
    fn a_feed_reads_posts_a_signed_batch_and_acknowledges_it() {
        let mut events = events();
        events.handle(at(0), Input::Policy(policy(true)));
        let out = poll(&mut events, at(0));
        let read = request(&out);
        assert!(matches!(
            read.command,
            Command::Events {
                subscription: SUBSCRIPTION,
                after: None,
                until: None,
                limit: 100
            }
        ));
        let out = answer(&mut events, read, Answer::Events(Ok(Some(owed()))), at(1));
        let [Output::Post(post)] = &out[..] else {
            panic!("expected a post, got {out:?}");
        };
        assert_eq!(post.url, "https://hooks.example.test/in");
        let body: serde_json::Value = serde_json::from_slice(&post.body).unwrap();
        assert_eq!(body["subscription"], "hooks");
        assert_eq!(body["events"][0]["type"], "accepted");
        assert_eq!(body["events"][0]["recipients"][0], "ann@example.com");
        assert_eq!(body["events"][1]["type"], "bounced");
        assert_eq!(body["events"][1]["id"], "0000000000000009-bounced");
        assert_eq!(body["events"][1]["recipient"], "ann@example.com");
        assert_eq!(body["events"][1]["reply"]["code"], 550);
        assert_eq!(body["events"][1]["reply"]["rules"][0], "no-such-mailbox");
        assert_eq!(body["events"][1]["at"], "2027-01-15T08:00:00.250Z");
        let signed = sign::headers(&[5; 32], &post.headers[0].1, 1_800_000_000, &post.body);
        assert_eq!(post.headers, signed);

        events.handle(
            at(2),
            Input::Posted {
                post: post.id,
                failure: None,
            },
        );
        let out = poll(&mut events, at(2));
        let acknowledge = request(&out);
        assert!(matches!(
            acknowledge.command,
            Command::Acknowledge {
                subscription: SUBSCRIPTION,
                through: 12
            }
        ));
        let out = answer(
            &mut events,
            acknowledge,
            Answer::Acknowledged(Commit::Committed(())),
            at(3),
        );
        assert!(
            matches!(
                request(&out).command,
                Command::Events {
                    after: Some(12),
                    ..
                }
            ),
            "it reads on at once from what it delivered"
        );
    }

    #[test]
    fn a_failed_batch_is_posted_again_later_under_its_id() {
        let mut events = events();
        events.handle(at(0), Input::Policy(policy(true)));
        let out = poll(&mut events, at(0));
        let out = answer(
            &mut events,
            request(&out),
            Answer::Events(Ok(Some(owed()))),
            at(0),
        );
        let [Output::Post(first)] = &out[..] else {
            panic!("expected a post");
        };
        events.handle(
            at(10),
            Input::Posted {
                post: first.id,
                failure: Some("answered 503".to_owned()),
            },
        );
        let mut out = Vec::new();
        let due = events.poll(at(10), &mut out).expect("a retry is due");
        // Its first failure is kept, so its budget runs across restarts,
        // and nothing is posted until the retry.
        assert!(
            matches!(
                &out[..],
                [Output::Request(Request {
                    command: Command::EventsFailing { .. },
                    ..
                })]
            ),
            "{out:?}"
        );
        assert!(due > at(10).monotonic);
        let later = at(due.as_micros().div_ceil(1_000));
        let out = poll(&mut events, later);
        let [Output::Post(again)] = &out[..] else {
            panic!("expected the post again, got {out:?}");
        };
        assert_eq!(again.headers[0], first.headers[0], "the same batch ID");
        assert_eq!(again.body, first.body);
        assert_ne!(again.id, first.id);
    }

    #[test]
    fn a_read_of_nothing_owed_moves_on_and_a_removed_subscription_stops() {
        let mut events = events();
        events.handle(at(0), Input::Policy(policy(true)));
        let out = poll(&mut events, at(0));
        let nothing = Owed {
            through: 5,
            ..Owed::default()
        };
        let out = answer(
            &mut events,
            request(&out),
            Answer::Events(Ok(Some(nothing))),
            at(0),
        );
        assert!(out.is_empty(), "caught up: it waits");
        let out = poll(&mut events, at(200));
        let more = Owed {
            through: 20,
            ..Owed::default()
        };
        let out = answer(
            &mut events,
            request(&out),
            Answer::Events(Ok(Some(more))),
            at(200),
        );
        assert!(
            matches!(
                request(&out).command,
                Command::Acknowledge { through: 20, .. }
            ),
            "past entries it does not owe"
        );
        events.handle(at(201), Input::Policy(policy(false)));
        assert_eq!(poll(&mut events, at(400)).len(), 0);
        assert!(events.feeds.is_empty());
    }

    /// Posts the batch among `out`, and returns it.
    fn the_post(out: &[Output]) -> Post {
        match out {
            [Output::Post(post)] => post.clone(),
            other => panic!("expected a post, got {other:?}"),
        }
    }

    fn failed(events: &mut Events, post: &Post, now: Now) -> Vec<Output> {
        events.handle(
            now,
            Input::Posted {
                post: post.id,
                failure: Some("answered 503".to_owned()),
            },
        );
        poll(events, now)
    }

    #[test]
    fn a_batch_past_its_budget_is_parked_and_the_feed_goes_on() {
        let mut events = events();
        events.handle(at(0), Input::Policy(policy(true)));
        let out = poll(&mut events, at(0));
        let out = answer(
            &mut events,
            request(&out),
            Answer::Events(Ok(Some(owed()))),
            at(0),
        );
        let first = the_post(&out);
        // Failing within its hour, it is posted again.
        failed(&mut events, &first, at(1_000));
        let again = the_post(&poll(&mut events, at(60_000)));
        assert_eq!(again.body, first.body);
        // Failing past it, it is parked with its span, its posts and why.
        let out = failed(&mut events, &again, at(3_601_000));
        let park = request(&out);
        let Command::ParkEvents(parked) = &park.command else {
            panic!("expected the batch parked, got {:?}", park.command);
        };
        assert_eq!((parked.first, parked.through, parked.attempts), (7, 12, 2));
        assert_eq!(parked.failure, "answered 503");
        let out = answer(
            &mut events,
            park,
            Answer::EventsParked(Commit::Committed(())),
            at(3_601_001),
        );
        assert!(
            matches!(
                request(&out).command,
                Command::Events {
                    after: Some(12),
                    ..
                }
            ),
            "it reads on past the parked batch"
        );
    }

    #[test]
    fn a_replay_posts_a_parked_batch_marked_and_takes_its_record_away() {
        let mut events = events();
        events.handle(at(0), Input::Policy(policy(true)));
        poll(&mut events, at(0));
        events.handle(
            at(1),
            Input::Replay {
                ticket: Ticket(77),
                account: ACCOUNT,
                subscription: "hooks".to_owned(),
                first: None,
            },
        );
        let out = poll(&mut events, at(1));
        let asked = out
            .iter()
            .find_map(|output| match output {
                Output::Request(request)
                    if matches!(request.command, Command::ParkedEvents { .. }) =>
                {
                    Some(request)
                }
                _ => None,
            })
            .expect("its parked batches read");
        let parked = ParkedEvents {
            subscription: SUBSCRIPTION,
            first: 7,
            through: 12,
            at: at(0).wall,
            attempts: 9,
            failure: "answered 503".to_owned(),
        };
        let found = Answer::ParkedEvents(Ok(Some((SUBSCRIPTION, vec![parked.clone()]))));
        let out = answer(&mut events, asked, found, at(2));
        assert!(out.iter().any(|output| matches!(
            output,
            Output::Replaying {
                ticket: Ticket(77),
                outcome: Ok(1)
            }
        )));
        // Still parked, its span is read again.
        let check = request(&out[1..]);
        assert!(matches!(
            check.command,
            Command::ParkedEvents {
                from: Some(7),
                limit: 1,
                ..
            }
        ));
        let still = Answer::ParkedEvents(Ok(Some((SUBSCRIPTION, vec![parked]))));
        let out = answer(&mut events, check, still, at(2));
        let read = request(&out);
        assert!(matches!(
            read.command,
            Command::Events {
                after: Some(6),
                until: Some(12),
                limit: 6,
                ..
            }
        ));
        let out = answer(&mut events, read, Answer::Events(Ok(Some(owed()))), at(3));
        let post = out
            .iter()
            .find_map(|output| match output {
                Output::Post(post) => Some(post.clone()),
                _ => None,
            })
            .expect("posted again");
        let body: serde_json::Value = serde_json::from_slice(&post.body).unwrap();
        assert_eq!(body["replay"], true);
        assert_eq!(
            body["events"][1]["id"], "0000000000000009-bounced",
            "the same events"
        );
        assert!(
            post.headers[0].1.contains("-replay-"),
            "a batch ID of its own"
        );
        events.handle(
            at(4),
            Input::Posted {
                post: post.id,
                failure: None,
            },
        );
        let out = poll(&mut events, at(4));
        assert!(out.iter().any(|output| matches!(
            output,
            Output::Request(Request {
                command: Command::UnparkEvents { first: 7, .. },
                ..
            })
        )));
    }

    const SUBSCRIBER: SubscriptionId = SubscriptionId(Id::from_u64(4).unwrap());

    /// Policy with a confirmed subscriber of a topic, to which the
    /// configuration's destination publishes sends and bounces; and events
    /// fed it, posting at most `bytes` a batch, with SNS's signer loaded.
    fn topic_events(bytes: usize) -> Events {
        use aws_lc_rs::encoding::AsDer as _;
        use aws_lc_rs::rsa::{KeyPair, KeySize};
        use base64::Engine as _;
        let mut policy = (*policy(false)).clone();
        for change in [
            Change::Topic {
                id: engine_core::id::TopicId(id(5)),
                account: ACCOUNT,
                name: "feedback".to_owned(),
            },
            Change::Destination {
                id: engine_core::id::DestinationId(id(6)),
                account: ACCOUNT,
                configuration: "receipts".to_owned(),
                name: "receipts-feedback".to_owned(),
                topic: "feedback".to_owned(),
                events: BTreeSet::from([EventKind::Accepted, EventKind::Bounced]),
                enabled: true,
                replaces: false,
            },
            Change::Subscribe {
                id: SUBSCRIBER,
                account: ACCOUNT,
                topic: "feedback".to_owned(),
                endpoint: "https://hooks.example.test/ses".to_owned(),
                token: [7; 32],
            },
            Change::Confirm {
                account: ACCOUNT,
                topic: "feedback".to_owned(),
                token: [7; 32],
            },
        ] {
            policy.apply(change).unwrap();
        }
        let pair = KeyPair::generate(KeySize::Rsa2048).unwrap();
        let der = base64::engine::general_purpose::STANDARD.encode(pair.as_der().unwrap().as_ref());
        let pem = format!("-----BEGIN PRIVATE KEY-----\n{der}\n-----END PRIVATE KEY-----\n");
        let signer =
            sns::Signer::from_pem(&pem, "https://ses.example.test/sns/abc.pem".to_owned()).unwrap();
        let mut events = events();
        events.config.batch_bytes = bytes;
        events.handle(
            at(0),
            Input::Publishing(Arc::new(sns::Publishing {
                signer: Arc::new(signer),
                url: "https://ses.example.test".to_owned(),
                region: "us-east-1".to_owned(),
            })),
        );
        events.handle(at(0), Input::Policy(Arc::new(policy)));
        events
    }

    fn posted(events: &mut Events, post: &Post, failure: Option<&str>, now: Now) -> Vec<Output> {
        events.handle(
            now,
            Input::Posted {
                post: post.id,
                failure: failure.map(str::to_owned),
            },
        );
        poll(events, now)
    }

    #[test]
    fn a_topic_batch_keeps_to_its_bytes_and_its_first_failure() {
        // At most a byte: one notification, however large, and only the
        // span it covers acknowledged.
        let mut events = topic_events(1);
        let out = poll(&mut events, at(0));
        let out = answer(
            &mut events,
            request(&out),
            Answer::Events(Ok(Some(owed()))),
            at(0),
        );
        let post = the_post(&out);
        assert!(
            post.headers
                .iter()
                .any(|(name, value)| *name == sns::MESSAGE_ID && value == "0000000000000007-Send")
        );
        let out = posted(&mut events, &post, None, at(1));
        assert!(matches!(
            request(&out).command,
            Command::Acknowledge { through: 7, .. }
        ));
        // Whole, its first notification failing and then taken: the second's
        // failure is the same batch's, whose budget runs from the first.
        let mut events = topic_events(1 << 20);
        let out = poll(&mut events, at(0));
        let out = answer(
            &mut events,
            request(&out),
            Answer::Events(Ok(Some(owed()))),
            at(0),
        );
        let first = the_post(&out);
        let out = posted(&mut events, &first, Some("answered 503"), at(1));
        assert!(matches!(
            request(&out).command,
            Command::EventsFailing { .. }
        ));
        let mut out = Vec::new();
        let due = events.poll(at(1), &mut out).expect("a retry is due");
        let later = at(due.as_micros().div_ceil(1_000));
        let again = the_post(&poll(&mut events, later));
        let second = the_post(&posted(&mut events, &again, None, later));
        assert!(second.headers.iter().any(|(name, value)| *name == sns::MESSAGE_ID
            && value == "0000000000000009-Bounce"));
        let out = posted(&mut events, &second, Some("answered 503"), later);
        assert!(
            !out.iter().any(|output| matches!(
                output,
                Output::Request(Request {
                    command: Command::EventsFailing { .. },
                    ..
                })
            )),
            "{out:?}"
        );
    }

    #[test]
    fn a_topic_replay_posts_each_notification_marked_then_takes_its_record_away() {
        let mut events = topic_events(1 << 20);
        poll(&mut events, at(0));
        events.handle(
            at(1),
            Input::Replay {
                ticket: Ticket(78),
                account: ACCOUNT,
                subscription: format!("arn:aws:sns:us-east-1:000000000001:feedback:{:016x}", 4),
                first: None,
            },
        );
        let out = poll(&mut events, at(1));
        let asked = out
            .iter()
            .find_map(|output| match output {
                Output::Request(request)
                    if matches!(request.command, Command::ParkedEvents { .. }) =>
                {
                    Some(request)
                }
                _ => None,
            })
            .expect("its parked batches read");
        let parked = ParkedEvents {
            subscription: SUBSCRIBER,
            first: 7,
            through: 12,
            at: at(0).wall,
            attempts: 9,
            failure: "answered 503".to_owned(),
        };
        let found = Answer::ParkedEvents(Ok(Some((SUBSCRIBER, vec![parked.clone()]))));
        let out = answer(&mut events, asked, found, at(2));
        // Checked by the subscriber's ARN.
        let check = out
            .iter()
            .find_map(|output| match output {
                Output::Request(request) => Some(request),
                _ => None,
            })
            .expect("checked");
        assert!(matches!(
            &check.command,
            Command::ParkedEvents { subscription, from: Some(7), .. }
                if subscription.ends_with(":feedback:0000000000000004")
        ));
        let still = Answer::ParkedEvents(Ok(Some((SUBSCRIBER, vec![parked]))));
        let out = answer(&mut events, check, still, at(2));
        let out = answer(
            &mut events,
            request(&out),
            Answer::Events(Ok(Some(owed()))),
            at(3),
        );
        let replayed = |post: &Post| {
            post.headers
                .iter()
                .any(|(name, value)| *name == sns::REPLAY && value == "true")
        };
        let mut ids = Vec::new();
        let mut post = out
            .iter()
            .find_map(|output| match output {
                Output::Post(post) => Some(post.clone()),
                _ => None,
            })
            .expect("posted again");
        loop {
            assert!(replayed(&post), "{post:?}");
            ids.push(
                post.headers
                    .iter()
                    .find(|(name, _)| *name == sns::MESSAGE_ID)
                    .unwrap()
                    .1
                    .clone(),
            );
            let out = posted(&mut events, &post, None, at(4));
            match &out[..] {
                [Output::Post(next)] => post = next.clone(),
                _ => {
                    assert!(out.iter().any(|output| matches!(
                        output,
                        Output::Request(Request {
                            command: Command::UnparkEvents { first: 7, .. },
                            ..
                        })
                    )));
                    break;
                }
            }
        }
        assert_eq!(ids, ["0000000000000007-Send", "0000000000000009-Bounce"]);
    }

    #[test]
    fn a_batch_keeps_to_its_bytes_and_covers_only_what_it_holds() {
        let subscription = policy(true).subscription(SUBSCRIPTION).unwrap().clone();
        let owed = owed();
        let (whole, through) = render::bounded(&subscription, &owed, usize::MAX, false);
        assert_eq!(through, 12);
        let (cut, through) = render::bounded(&subscription, &owed, whole.len() - 1, false);
        assert_eq!(
            through, 7,
            "it covers its one event, and the rest is read again"
        );
        let cut: serde_json::Value = serde_json::from_slice(&cut).unwrap();
        assert_eq!(cut["events"].as_array().unwrap().len(), 1);
        let (one, _) = render::bounded(&subscription, &owed, 1, false);
        assert!(!one.is_empty(), "at least one event, however large");
    }

    #[test]
    fn a_batch_failing_before_a_restart_keeps_its_budget() {
        let restored = |now: Now| {
            let mut events = events();
            events.handle(at(0), Input::Policy(policy(true)));
            let out = poll(&mut events, at(0));
            // Its first failure was at the start.
            let owed = Owed {
                failing_since: Some(at(0).wall),
                ..owed()
            };
            let out = answer(
                &mut events,
                request(&out),
                Answer::Events(Ok(Some(owed))),
                now,
            );
            (events, out)
        };
        // Within its hour, it is posted, and parked at its first failure
        // past the hour.
        let (mut events, out) = restored(at(1_800_000));
        let post = the_post(&out);
        let out = failed(&mut events, &post, at(3_601_000));
        let Command::ParkEvents(parked) = &request(&out).command else {
            panic!("expected it parked, got {out:?}");
        };
        assert_eq!((parked.attempts, &parked.failure[..]), (1, "answered 503"));
        // Past its hour, it is parked at once, never posted again.
        let (_, out) = restored(at(3_601_000));
        let Command::ParkEvents(parked) = &request(&out).command else {
            panic!("expected it parked, got {out:?}");
        };
        assert_eq!((parked.first, parked.through), (7, 12));
        assert_eq!((parked.attempts, &parked.failure[..]), (0, PAST_BUDGET));
    }

    #[test]
    fn a_retry_never_comes_after_its_budgets_deadline() {
        let mut events = events();
        events.handle(at(0), Input::Policy(policy(true)));
        let out = poll(&mut events, at(0));
        let out = answer(
            &mut events,
            request(&out),
            Answer::Events(Ok(Some(owed()))),
            at(0),
        );
        let first = the_post(&out);
        let out = failed(&mut events, &first, at(0));
        // Its first failure is noted with its batch.
        assert!(
            matches!(
                request(&out).command,
                Command::EventsFailing {
                    first: 7,
                    since,
                    ..
                } if since == at(0).wall
            ),
            "{out:?}"
        );
        // Failing again a second before its hour is out, whatever the
        // schedule would say, it wakes at the hour, and is parked then,
        // not posted.
        let again = the_post(&poll(&mut events, at(60_000)));
        events.handle(
            at(3_599_000),
            Input::Posted {
                post: again.id,
                failure: Some("answered 503".to_owned()),
            },
        );
        let mut out = Vec::new();
        let due = events.poll(at(3_599_000), &mut out).expect("a wake");
        assert!(due <= at(3_600_000).monotonic, "{due:?}");
        let out = poll(&mut events, at(3_600_000));
        let Command::ParkEvents(parked) = &request(&out).command else {
            panic!("expected it parked, got {out:?}");
        };
        assert_eq!((parked.attempts, &parked.failure[..]), (2, "answered 503"));
    }

    #[test]
    fn a_replay_reads_its_whole_span_waits_its_turn_and_is_not_queued_twice() {
        let mut events = events();
        events.handle(at(0), Input::Policy(policy(true)));
        let out = poll(&mut events, at(0));
        let out = answer(
            &mut events,
            request(&out),
            Answer::Events(Ok(Some(owed()))),
            at(0),
        );
        let live = the_post(&out);
        // A batch parked before, its events at 2 and 4 of its span, 2 to 6.
        let parked = ParkedEvents {
            subscription: SUBSCRIPTION,
            first: 2,
            through: 6,
            at: at(0).wall,
            attempts: 3,
            failure: "answered 503".to_owned(),
        };
        let replayed = {
            let mut owed = owed();
            owed.entries[0].0 = 2;
            owed.entries[1].0 = 4;
            Owed { through: 6, ..owed }
        };
        let ask = |events: &mut Events, ticket| {
            events.handle(
                at(1),
                Input::Replay {
                    ticket: Ticket(ticket),
                    account: ACCOUNT,
                    subscription: "hooks".to_owned(),
                    first: None,
                },
            );
            poll(events, at(1))
        };
        let listing = |parked: &[ParkedEvents]| {
            Answer::ParkedEvents(Ok(Some((SUBSCRIPTION, parked.to_vec()))))
        };
        let replaying = |out: &[Output], ticket, count| {
            out.iter().any(|output| {
                matches!(
                    output,
                    Output::Replaying { ticket: Ticket(asked), outcome: Ok(queued) }
                        if *asked == ticket && *queued == count
                )
            })
        };
        // Asked for while the feed's batch is with its subscriber: checked,
        // then its whole span read.
        let out = ask(&mut events, 1);
        let out = answer(
            &mut events,
            request(&out),
            listing(std::slice::from_ref(&parked)),
            at(1),
        );
        assert!(replaying(&out, 1, 1));
        let check = request(&out[1..]);
        // Asked again while it is checked, it is not queued again.
        let again = ask(&mut events, 2);
        let again = answer(
            &mut events,
            request(&again),
            listing(std::slice::from_ref(&parked)),
            at(1),
        );
        assert!(replaying(&again, 2, 0));
        let out = answer(
            &mut events,
            check,
            listing(std::slice::from_ref(&parked)),
            at(1),
        );
        let span = request(&out);
        assert!(matches!(
            span.command,
            Command::Events {
                after: Some(1),
                until: Some(6),
                limit: 5,
                ..
            }
        ));
        // Read, it waits for the feed's batch, then goes; the feed's batch
        // is acknowledged, and reading on waits for that.
        let out = answer(&mut events, span, Answer::Events(Ok(Some(replayed))), at(2));
        assert!(out.is_empty(), "one in flight: {out:?}");
        events.handle(
            at(3),
            Input::Posted {
                post: live.id,
                failure: None,
            },
        );
        let out = poll(&mut events, at(3));
        let replay = out
            .iter()
            .find_map(|output| match output {
                Output::Post(post) => Some(post.clone()),
                _ => None,
            })
            .expect("the replay posted");
        assert!(replay.headers[0].1.contains("-replay-"));
        let body: serde_json::Value = serde_json::from_slice(&replay.body).unwrap();
        assert_eq!(
            body["events"].as_array().unwrap().len(),
            2,
            "its whole span"
        );
        let acknowledged = out
            .iter()
            .find_map(|output| match output {
                Output::Request(request)
                    if matches!(request.command, Command::Acknowledge { through: 12, .. }) =>
                {
                    Some(request)
                }
                _ => None,
            })
            .expect("the feed's batch acknowledged");
        // A listing asked for while it is with its subscriber, answered
        // after its replay is taken and its record gone: it is checked
        // again, found gone, and not posted twice.
        let stale = ask(&mut events, 3);
        let stale = request(&stale);
        events.handle(
            at(4),
            Input::Posted {
                post: replay.id,
                failure: None,
            },
        );
        let out = poll(&mut events, at(4));
        let unpark = request(&out);
        assert!(matches!(
            unpark.command,
            Command::UnparkEvents { first: 2, .. }
        ));
        answer(
            &mut events,
            unpark,
            Answer::EventsUnparked(Commit::Committed(())),
            at(4),
        );
        let out = answer(
            &mut events,
            stale,
            listing(std::slice::from_ref(&parked)),
            at(5),
        );
        assert!(replaying(&out, 3, 1));
        let check = request(&out[1..]);
        assert!(matches!(
            check.command,
            Command::ParkedEvents { from: Some(2), .. }
        ));
        let out = answer(&mut events, check, listing(&[]), at(5));
        assert!(out.is_empty(), "not posted again: {out:?}");
        // The feed reads on past its batch, once that is acknowledged.
        let out = answer(
            &mut events,
            acknowledged,
            Answer::Acknowledged(Commit::Committed(())),
            at(6),
        );
        assert!(matches!(
            request(&out).command,
            Command::Events {
                after: Some(12),
                ..
            }
        ));
        // Only the one named: the store gives the next after a batch gone,
        // which is not queued.
        let row = |first| ParkedEvents {
            first,
            through: first,
            ..parked.clone()
        };
        let named = |events: &mut Events, ticket, first| {
            events.handle(
                at(7),
                Input::Replay {
                    ticket: Ticket(ticket),
                    account: ACCOUNT,
                    subscription: "hooks".to_owned(),
                    first: Some(first),
                },
            );
            let out = poll(events, at(7));
            assert!(matches!(
                request(&out).command,
                Command::ParkedEvents { from: Some(asked), limit: 1, .. } if asked == first
            ));
            out
        };
        let read = named(&mut events, 4, 50);
        let out = answer(&mut events, request(&read), listing(&[row(100)]), at(7));
        assert!(replaying(&out, 4, 0));
        let read = named(&mut events, 5, 100);
        let out = answer(&mut events, request(&read), listing(&[row(100)]), at(7));
        assert!(replaying(&out, 5, 1));
        // That one under way, a listing from it queues the rest; and no
        // more than a queue's worth.
        let rows = |firsts: std::ops::Range<u64>| firsts.map(row).collect::<Vec<_>>();
        let out = ask(&mut events, 6);
        let out = answer(&mut events, request(&out), listing(&rows(100..151)), at(8));
        assert!(replaying(&out, 6, 50));
        let out = ask(&mut events, 7);
        let out = answer(&mut events, request(&out), listing(&rows(300..500)), at(8));
        assert!(replaying(&out, 7, REPLAYS_QUEUED - 50));
    }
}
