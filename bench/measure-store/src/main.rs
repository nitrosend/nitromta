//! Measures the store on a real disk.
//!
//! The real store and commit owner run with synchronous commits on the
//! disk under the directory given. Every delivery is accepted, reserved and
//! recorded as delivered, so it costs all three commit points. Each group
//! holds a steady mix, as a busy pipeline would: the outcomes of the last
//! group's reservations, reservations for the last group's acceptances, and
//! new acceptances. Varying the group's size shows what group commit buys.
//! With reads switched on, every reservation also reads its body back
//! through the commit owner's one connection.
//!
//! A probe first times synchronous 4 KiB writes in the same directory, so a
//! result shows whether its syncs reach stable storage.
//!
//! Usage: `measure-store <directory> [seconds per point] [point]`, where a
//! point such as `16384x64` or `16384x64+reads` measures only that body size
//! and group. Results are JSON lines on standard output.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use engine_core::address::Address;
use engine_core::attempt::Evidence;
use engine_core::command::{
    Accept, AcceptMessage, Answer, Authority, Command, Commit, Recipient, RecordOutcome, Request,
    Reservation, Reserve,
};
use engine_core::component::{Component, Ticket};
use engine_core::delivery::{DispatchPermit, Disposition, Generation};
use engine_core::id::{
    AccountId, AttemptId, BodyId, CredentialId, DeliveryId, IdGenerator, IdentityId, Lane,
    MessageId, Shard, SubmissionId,
};
use engine_core::policy::{Change, Origin, Permissions, Secret};
use engine_core::rng::Rng;
use engine_core::time::{Monotonic, Now, Timestamp};
use engine_store::commit_owner::{CommitOwner, GroupLimits};
use engine_store::keys::Keyring;
use engine_store::store::{Store, StoreOptions};
use rusqlite::Connection;
use serde_json::json;

const KIB: usize = 1024;

/// One measurement: a body size, a group size, and whether bodies are read.
struct Point {
    body_bytes: usize,
    group: usize,
    reads: bool,
}

fn points() -> Vec<Point> {
    let mut points = Vec::new();
    for (body_bytes, groups) in [
        (16 * KIB, &[1, 8, 64, 256][..]),
        (100 * KIB, &[1, 8, 64, 256][..]),
        (1024 * KIB, &[1, 8, 32][..]),
    ] {
        for &group in groups {
            points.push(Point {
                body_bytes,
                group,
                reads: false,
            });
        }
    }
    for group in [64, 256] {
        points.push(Point {
            body_bytes: 16 * KIB,
            group,
            reads: true,
        });
    }
    points
}

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let (directory, seconds, only) = match arguments.as_slice() {
        [directory] => (directory, "3", None),
        [directory, seconds] => (directory, seconds.as_str(), None),
        [directory, seconds, point] => (directory, seconds.as_str(), Some(point.as_str())),
        _ => return usage(),
    };
    let Ok(seconds) = seconds.parse() else {
        return usage();
    };
    let points = match only {
        None => points(),
        Some(point) => match parse_point(point) {
            Some(point) => vec![point],
            None => return usage(),
        },
    };
    match run(Path::new(directory), Duration::from_secs(seconds), points) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("measure-store: {error}");
            ExitCode::FAILURE
        }
    }
}

fn usage() -> ExitCode {
    eprintln!(
        "usage: measure-store <directory> [seconds per point] [<body bytes>x<group>[+reads]]"
    );
    ExitCode::from(2)
}

fn run(directory: &Path, duration: Duration, points: Vec<Point>) -> Result<(), String> {
    fs::create_dir_all(directory).map_err(|error| format!("{}: {error}", directory.display()))?;
    emit(json!({
        "environment": {
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "cpus": std::thread::available_parallelism().map_or(0, usize::from),
            "sqlite": rusqlite::version(),
            "directory": directory.display().to_string(),
            "seconds_per_point": duration.as_secs(),
        }
    }));
    emit(json!({ "sync_probe": probe_sync(directory)? }));
    for point in points {
        let measured = measure(directory, &point, duration)?;
        emit(json!({
            "body_bytes": point.body_bytes,
            "group": point.group,
            "reads": point.reads,
            "deliveries_per_second": measured.deliveries_per_second,
            "commit_micros": measured.commit_micros,
            "commits": measured.commits,
        }));
    }
    Ok(())
}

/// Reads a point such as `16384x64` or `16384x64+reads`.
fn parse_point(point: &str) -> Option<Point> {
    let (point, reads) = match point.strip_suffix("+reads") {
        Some(point) => (point, true),
        None => (point, false),
    };
    let (body_bytes, group) = point.split_once('x')?;
    Some(Point {
        body_bytes: body_bytes.parse().ok()?,
        group: group.parse().ok().filter(|&group| group > 0)?,
        reads,
    })
}

fn emit(value: serde_json::Value) {
    println!("{value}");
}

/// Times synchronous 4 KiB writes: what one durable commit costs at least.
fn probe_sync(directory: &Path) -> Result<serde_json::Value, String> {
    let path = directory.join("sync-probe");
    let failed = |error: std::io::Error| format!("{}: {error}", path.display());
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&path)
        .map_err(failed)?;
    let block = [0x5a; 4096];
    let mut latencies = Vec::with_capacity(200);
    for _ in 0..200 {
        file.write_all(&block).map_err(failed)?;
        let started = Instant::now();
        // On macOS this is F_FULLFSYNC, as SQLite uses with fullfsync on.
        file.sync_all().map_err(failed)?;
        latencies.push(started.elapsed());
    }
    fs::remove_file(&path).map_err(failed)?;
    Ok(percentiles(&mut latencies))
}

struct Measured {
    deliveries_per_second: f64,
    commit_micros: serde_json::Value,
    commits: usize,
}

fn measure(directory: &Path, point: &Point, duration: Duration) -> Result<Measured, String> {
    let path = directory.join("measure.db");
    for suffix in ["", "-wal", "-shm"] {
        let _ = fs::remove_file(format!("{}{suffix}", path.display()));
    }
    let failed = |error: &dyn std::fmt::Display| format!("{}: {error}", path.display());
    let connection = Connection::open(&path).map_err(|error| failed(&error))?;
    // Its policy holds no secret: any key serves.
    let keys = Arc::new(Keyring::new(&[(1, [0; 32])]).map_err(|error| failed(&error))?);
    let store =
        Store::open(connection, StoreOptions::default(), keys).map_err(|error| failed(&error))?;
    let after = store.highest_id().map_err(|error| failed(&error))?;
    // Room for the whole mix in one group: outcomes, reservations,
    // acceptances, and body reads.
    let limits = GroupLimits {
        commands: point.group * 4,
        content_bytes: usize::MAX,
    };
    let (mut owner, _) =
        CommitOwner::start(store, limits, wall()).map_err(|error| failed(&error))?;
    let mut ids = IdGenerator::new(Shard::new(0), Lane::new(0).expect("lane 0"), after);
    let authority = provision(&mut owner, &mut ids)?;
    let mut rng = Rng::from_seed(1);
    let bodies: Vec<Bytes> = (0..16)
        .map(|_| {
            let mut body = vec![0; point.body_bytes];
            for chunk in body.chunks_mut(8) {
                chunk.copy_from_slice(&rng.next_u64().to_le_bytes()[..chunk.len()]);
            }
            Bytes::from(body)
        })
        .collect();
    let recipient = Address::parse("rcpt@example.com").expect("a valid address");

    let started = Instant::now();
    let mut accepted: Vec<(DeliveryId, BodyId)> = Vec::new();
    let mut reserved: Vec<DispatchPermit> = Vec::new();
    let mut latencies = Vec::new();
    let mut completed = 0_u64;
    let mut next_ticket = 0;
    let mut responses = Vec::new();
    while started.elapsed() < duration {
        let now = wall();
        let clock = Now {
            wall: now,
            monotonic: Monotonic::from_micros(
                u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
            ),
        };
        let mut pending: BTreeMap<Ticket, (DeliveryId, BodyId)> = BTreeMap::new();
        let mut send = |owner: &mut CommitOwner<Connection>, command: Command| {
            let ticket = Ticket(next_ticket);
            next_ticket += 1;
            owner.handle(clock, Request { ticket, command });
            ticket
        };
        for permit in reserved.drain(..) {
            let outcome = RecordOutcome {
                permit,
                disposition: Disposition::Delivered,
                evidence: Some(Evidence::new(250, "2.0.0 Ok: queued as 4ZzPqB0vXcz9")),
                suppress: false,
                cooled: None,
                feedback: None,
                counted: None,
                now,
            };
            send(&mut owner, Command::RecordOutcome(outcome));
        }
        for (delivery, body) in accepted.drain(..) {
            let reserve = Reserve {
                delivery,
                seen: Generation::FIRST,
                attempt: AttemptId(ids.next(now)),
                egress: None,
                site: None,
                now,
            };
            send(&mut owner, Command::Reserve(reserve));
            if point.reads {
                send(&mut owner, Command::Body(body));
            }
        }
        for index in 0..point.group {
            let message = MessageId(ids.next(now));
            let body = BodyId(ids.next(now));
            let delivery = DeliveryId(ids.next(now));
            let accept = Accept {
                submission: SubmissionId(ids.next(now)),
                authority,
                accepted_at: now,
                expires_at: now.saturating_add(Duration::from_secs(3_600)),
                messages: vec![AcceptMessage {
                    id: message,
                    body,
                    content: bodies[index % bodies.len()].clone(),
                    recipients: vec![Recipient {
                        delivery,
                        address: recipient.clone(),
                    }],
                    mail: None,
                }],
            };
            let ticket = send(&mut owner, Command::Accept(accept));
            pending.insert(ticket, (delivery, body));
        }

        let committing = Instant::now();
        let settled = (0..100).any(|_| owner.poll(clock, &mut responses) != Some(clock.monotonic));
        latencies.push(committing.elapsed());
        if !settled {
            return Err("the commit owner never settled".to_owned());
        }
        for response in responses.drain(..) {
            match response.answer {
                Answer::Accepted(Commit::Committed(())) => {
                    accepted.push(pending[&response.ticket]);
                }
                Answer::Reserved(Commit::Committed(Reservation::Permit(permit))) => {
                    reserved.push(permit);
                }
                Answer::Recorded(Commit::Committed(())) => completed += 1,
                Answer::Body(Ok(Some(_))) => {}
                other => return Err(format!("unexpected answer: {other:?}")),
            }
        }
    }
    let elapsed = started.elapsed().as_secs_f64();
    Ok(Measured {
        deliveries_per_second: (completed as f64 / elapsed).round(),
        commit_micros: percentiles(&mut latencies),
        commits: latencies.len(),
    })
}

/// Creates the identity and login every measured acceptance is sent as,
/// through the commit owner, and returns the authority they carry.
fn provision(
    owner: &mut CommitOwner<Connection>,
    ids: &mut IdGenerator,
) -> Result<Authority, String> {
    let now = wall();
    let account = AccountId(ids.next(now));
    let identity = IdentityId(ids.next(now));
    let credential = CredentialId(ids.next(now));
    let changes = [
        Change::Identity {
            id: identity,
            account,
            name: "example.com".to_owned(),
            signing: None,
            configuration: None,
        },
        Change::Credential {
            id: credential,
            account,
            secret: Secret::Login {
                user: "measure".to_owned(),
                password_sha256: [0; 32],
            },
            identities: None,
            tenants: None,
            permissions: Permissions::SENDS,
        },
    ];
    let clock = Now {
        wall: now,
        monotonic: Monotonic::from_micros(0),
    };
    for (ticket, change) in (0..).zip(changes) {
        let command = Command::ChangePolicy(change);
        owner.handle(
            clock,
            Request {
                ticket: Ticket(u64::MAX - ticket),
                command,
            },
        );
    }
    let mut responses = Vec::new();
    while owner.poll(clock, &mut responses) == Some(clock.monotonic) {}
    let committed = responses.len() == 2
        && responses
            .iter()
            .all(|response| matches!(response.answer, Answer::Policy(Commit::Committed(_))));
    let revision = match responses.last().map(|response| &response.answer) {
        Some(Answer::Policy(Commit::Committed(revision))) if committed => *revision,
        _ => return Err(format!("the sender was not created: {responses:?}")),
    };
    Ok(Authority {
        account,
        credential,
        origin: Origin {
            identity,
            tenant: None,
            configuration: None,
        },
        revision,
        template: None,
    })
}

fn wall() -> Timestamp {
    let since_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    Timestamp::from_micros(u64::try_from(since_epoch.as_micros()).unwrap_or(u64::MAX))
}

fn percentiles(latencies: &mut [Duration]) -> serde_json::Value {
    latencies.sort_unstable();
    let at = |fraction: f64| {
        let index = ((latencies.len() as f64 - 1.0) * fraction).round() as usize;
        latencies
            .get(index)
            .map_or(0, |latency| latency.as_micros())
    };
    json!({ "p50": at(0.5), "p99": at(0.99), "max": at(1.0) })
}
