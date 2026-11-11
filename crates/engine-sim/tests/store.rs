//! The store and its commit owner, on the simulated disk with the power on.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use engine_core::address::Address;
use engine_core::attempt::{AttemptEnd, AttemptResult, Evidence};
use engine_core::budget::{self, Counts, Signal};
use engine_core::command::FeedbackRecorded;
use engine_core::command::{
    Accept, AcceptMessage, AcceptRefusal, Answer, Command, Commit, CooldownChange, Counted,
    DuePosition, Expire, FenceDecision, Inspect, Mailed, Owed, Park, ParkedEvents, Postpone,
    Recipient, RecordOutcome, Release, Reported, Request, Reservation, Reserve, Response,
    SiteCooldown, Suppress, Unfenced, Unsuppress,
};
use engine_core::component::{Component, Ticket};
use engine_core::delivery::{
    Completion, Delivery, DispatchPermit, Disposition, QueueState, Refusal,
};
use engine_core::event::EventKind;
use engine_core::feedback::{Claim, Kind, Report};
use engine_core::id::{
    AttemptId, BodyId, ConfigurationId, CredentialId, DeliveryId, DestinationId, EgressId, HoldId,
    Id, IdGenerator, IdentityId, Lane, MessageId, PoolId, ReportId, Shard, SubmissionId,
    SubscriptionId, TemplateId, TenantId, TopicId,
};
use engine_core::journal::Entry;
use engine_core::message::{Mail, PolicyRevision};
use engine_core::policy::{
    Account, Capping, Caps, Change, Denial, Judgment, Limits, Origin, Permissions, PolicyRefusal,
    Resource, Secret, Target, TemplateContent, Verdict, Warmed,
};
use engine_core::rng::Rng;
use engine_core::status::Status;
use engine_core::sts;
use engine_core::suppression::{List, Reason};
use engine_core::time::{Monotonic, Now, Timestamp};
use engine_rules::Rules;
use engine_sim::disk::Disk;
use engine_sim::sender::{self, Sender};
use engine_sim::vfs::{SimConnection, SimVfs};
use engine_store::commit_owner::{CommitOwner, GroupLimits};
use engine_store::keys::{Keyring, Keys, seal_body};
use engine_store::store::{Encryption, EventLag, Queued, Store, StoreError, StoreOptions};

const START: Timestamp = Timestamp::from_micros(1_800_000_000_000_000);
const LIFETIME: Duration = Duration::from_secs(3_600);
const LIMITS: GroupLimits = GroupLimits {
    commands: 64,
    content_bytes: 1 << 20,
};
const DATABASE: &str = "store.db";

fn later(seconds: u64) -> Timestamp {
    START.saturating_add(Duration::from_secs(seconds))
}

fn now(at: Timestamp) -> Now {
    Now {
        wall: at,
        monotonic: Monotonic::from_micros(at.as_micros() - START.as_micros()),
    }
}

fn vfs(name: &str) -> SimVfs {
    seeded(name, 1)
}

/// A VFS whose disk's power cuts fall as `seed` has them.
fn seeded(name: &str, seed: u64) -> SimVfs {
    let disk = Rc::new(RefCell::new(Disk::new(Rng::from_seed(seed), START)));
    SimVfs::register(name, disk, 1).expect("a VFS name of its own")
}

/// A commit owner over the store on `vfs`, and the IDs to give commands.
struct Harness<'vfs> {
    owner: CommitOwner<SimConnection<'vfs>>,
    ids: IdGenerator,
    next_ticket: u64,
}

impl<'vfs> Harness<'vfs> {
    fn open(vfs: &'vfs SimVfs) -> Self {
        Self::reopen(vfs).0
    }

    /// Opens the store as a restart would, returning the attempts it
    /// recovered.
    fn reopen(vfs: &'vfs SimVfs) -> (Self, Vec<engine_core::attempt::Attempt>) {
        Self::reopen_with(vfs, StoreOptions::default())
    }

    fn reopen_with(
        vfs: &'vfs SimVfs,
        options: StoreOptions,
    ) -> (Self, Vec<engine_core::attempt::Attempt>) {
        let store = Store::open(vfs.open(DATABASE).expect("opens"), options, sender::keys())
            .expect("a valid store");
        let after = store.highest_id().expect("readable");
        let (owner, abandoned) = CommitOwner::start(store, LIMITS, START).expect("recovers");
        let lane = Lane::new(1).expect("a lane");
        let mut harness = Self {
            owner,
            ids: IdGenerator::new(Shard::new(1), lane, after),
            next_ticket: 0,
        };
        harness.provision();
        (harness, abandoned)
    }

    /// Gives a new store its sender; a reopened one already holds it.
    fn provision(&mut self) {
        let sender = Sender::first();
        if self
            .store()
            .policy()
            .credential(sender.credential)
            .is_none()
        {
            let changes = sender
                .changes()
                .into_iter()
                .map(Command::ChangePolicy)
                .collect();
            let answers = self.run(changes, START);
            assert!(answers.iter().all(changed_policy));
        }
    }

    /// Hands every command over, then polls once, as one group.
    fn run(&mut self, commands: Vec<Command>, at: Timestamp) -> Vec<Answer> {
        let first = self.next_ticket;
        for command in commands {
            let ticket = Ticket(self.next_ticket);
            self.next_ticket += 1;
            self.owner.handle(now(at), Request { ticket, command });
        }
        let mut responses = Vec::new();
        // Poll until the commit owner no longer asks to be polled at once,
        // which a handful of polls always reaches.
        let settled =
            (0..100).any(|_| self.owner.poll(now(at), &mut responses) != Some(now(at).monotonic));
        assert!(settled, "the commit owner never settled");
        responses.sort_by_key(|response: &Response| response.ticket);
        assert_eq!(
            responses.len() as u64,
            self.next_ticket - first,
            "every command is answered"
        );
        responses
            .into_iter()
            .map(|response| response.answer)
            .collect()
    }

    fn one(&mut self, command: Command, at: Timestamp) -> Answer {
        self.run(vec![command], at).pop().expect("answered")
    }

    /// An acceptance from the sender, decided under the current policy.
    fn accept(&mut self, recipients: &[&str]) -> Accept {
        let revision = self.store().policy().revision();
        self.accept_under(revision, recipients)
    }

    fn accept_under(&mut self, revision: PolicyRevision, recipients: &[&str]) -> Accept {
        Accept {
            submission: SubmissionId(self.ids.next(START)),
            authority: Sender::first().authority(revision),
            accepted_at: START,
            expires_at: START.saturating_add(LIFETIME),
            messages: vec![self.message(recipients)],
        }
    }

    fn message(&mut self, recipients: &[&str]) -> AcceptMessage {
        AcceptMessage {
            id: MessageId(self.ids.next(START)),
            body: BodyId(self.ids.next(START)),
            content: Bytes::from_static(b"Subject: hello\r\n\r\nHello.\r\n"),
            recipients: recipients
                .iter()
                .map(|address| Recipient {
                    delivery: DeliveryId(self.ids.next(START)),
                    address: Address::parse(address).expect("a valid address"),
                })
                .collect(),
            mail: None,
        }
    }

    fn reserve(&mut self, delivery: &Delivery, at: Timestamp) -> Command {
        Command::Reserve(Reserve {
            delivery: delivery.id(),
            seen: delivery.generation(),
            attempt: AttemptId(self.ids.next(at)),
            egress: None,
            site: None,
            now: at,
        })
    }

    /// Reserves `delivery` for a new attempt, which must commit.
    fn reserved(&mut self, delivery: &Delivery, at: Timestamp) -> DispatchPermit {
        let command = self.reserve(delivery, at);
        committed_permit(self.one(command, at))
    }

    fn delivery(&self, id: DeliveryId) -> Delivery {
        self.owner
            .store()
            .delivery(id)
            .expect("readable")
            .expect("stored")
    }

    fn store(&self) -> &Store<SimConnection<'vfs>> {
        self.owner.store()
    }
}

fn committed_permit(answer: Answer) -> DispatchPermit {
    match answer {
        Answer::Reserved(Commit::Committed(Reservation::Permit(permit))) => permit,
        other => panic!("expected a permit, got {other:?}"),
    }
}

/// The outcome of `permit`'s attempt, with the receiver's reply.
fn outcome(permit: DispatchPermit, disposition: Disposition, at: Timestamp) -> Command {
    Command::RecordOutcome(RecordOutcome {
        permit,
        disposition,
        evidence: Some(Evidence::new(250, "2.0.0 Ok")),
        suppress: false,
        cooled: None,
        feedback: None,
        counted: None,
        now: at,
    })
}

fn accepted(answer: &Answer) -> bool {
    matches!(answer, Answer::Accepted(Commit::Committed(())))
}

fn changed_policy(answer: &Answer) -> bool {
    matches!(answer, Answer::Policy(Commit::Committed(_)))
}

#[test]
fn a_message_is_kept_until_its_deliveries_finish() {
    let vfs = vfs("lifecycle");
    let mut harness = Harness::open(&vfs);
    let accept = harness.accept(&["one@example.com", "two@example.org"]);
    let message = &accept.messages[0];
    let (message_id, body) = (message.id, message.body);
    let deliveries: Vec<DeliveryId> = message
        .recipients
        .iter()
        .map(|recipient| recipient.delivery)
        .collect();
    assert!(accepted(
        &harness.one(Command::Accept(accept.clone()), START)
    ));

    let stored = harness
        .store()
        .message(message_id)
        .expect("readable")
        .expect("stored");
    assert_eq!((stored.submission, stored.body), (accept.submission, body));
    assert_eq!(
        harness.store().body(body).expect("readable"),
        Some(message.content.clone())
    );
    let due = harness.store().due(later(1), None, 10).expect("readable");
    assert_eq!(due.iter().map(Delivery::id).collect::<Vec<_>>(), deliveries);

    let first = harness.delivery(deliveries[0]);
    let permit = harness.reserved(&first, later(1));
    let attempt = permit.attempt();
    assert!(matches!(
        harness.one(outcome(permit, Disposition::Delivered, later(2)), later(2)),
        Answer::Recorded(Commit::Committed(()))
    ));
    assert_eq!(
        harness.delivery(deliveries[0]).state(),
        QueueState::Finished {
            completion: Completion::RemoteAccepted { attempt },
            at: later(2),
        }
    );
    // The attempt's evidence is its entry in the journal.
    let ended = harness
        .store()
        .entries(0, usize::MAX)
        .expect("readable")
        .into_iter()
        .find_map(|(_, entry)| match entry {
            Entry::Attempted {
                attempt: recorded,
                evidence,
                ..
            } if recorded.id == attempt => Some((recorded.ended, evidence)),
            _ => None,
        });
    assert_eq!(
        ended,
        Some((
            Some(AttemptEnd {
                result: AttemptResult::Delivered,
                at: later(2),
            }),
            Some(Evidence::new(250, "2.0.0 Ok"))
        ))
    );
    assert!(
        harness.store().body(body).expect("readable").is_some(),
        "one delivery is unfinished"
    );

    let second = harness.delivery(deliveries[1]);
    let permit = harness.reserved(&second, later(3));
    harness.one(outcome(permit, Disposition::Rejected, later(4)), later(4));
    assert_eq!(
        harness.store().body(body).expect("readable"),
        None,
        "both deliveries finished"
    );
    assert!(
        harness
            .store()
            .message(message_id)
            .expect("readable")
            .is_some()
    );
    assert!(
        harness
            .store()
            .due(later(5), None, 10)
            .expect("readable")
            .is_empty()
    );
    harness.store().verify().expect("intact");
}

#[test]
fn a_message_content_is_read_through_its_message() {
    let vfs = vfs("content");
    let mut harness = Harness::open(&vfs);
    let accept = harness.accept(&["one@example.com"]);
    let message = accept.messages[0].clone();
    assert!(accepted(&harness.one(Command::Accept(accept), START)));
    match harness.one(Command::Content(message.id), START) {
        Answer::Content(Ok(Some(content))) => assert_eq!(content, message.content),
        other => panic!("expected the content, got {other:?}"),
    }
    let unknown = MessageId(harness.ids.next(START));
    assert!(matches!(
        harness.one(Command::Content(unknown), START),
        Answer::Content(Ok(None))
    ));
}

#[test]
fn a_group_shares_one_sync() {
    let vfs = vfs("group");
    let mut harness = Harness::open(&vfs);
    let commands: Vec<Command> = (0..20)
        .map(|_| Command::Accept(harness.accept(&["rcpt@example.com"])))
        .collect();
    let before = vfs.disk().borrow().syncs();
    let answers = harness.run(commands, START);
    assert!(answers.iter().all(accepted));
    assert_eq!(
        vfs.disk().borrow().syncs() - before,
        1,
        "twenty acceptances, one sync"
    );

    let before = vfs.disk().borrow().syncs();
    for _ in 0..5 {
        let command = Command::Accept(harness.accept(&["rcpt@example.com"]));
        assert!(accepted(&harness.one(command, START)));
    }
    assert_eq!(
        vfs.disk().borrow().syncs() - before,
        5,
        "one sync each at low load"
    );
}

#[test]
fn the_journal_holds_each_acceptance_and_attempt_in_commit_order() {
    let vfs = vfs("journal");
    let mut harness = Harness::open(&vfs);
    let addresses: Vec<String> = (0..5).map(|n| format!("r{n}@example.com")).collect();
    let addresses: Vec<&str> = addresses.iter().map(String::as_str).collect();
    let accept = harness.accept(&addresses);
    let body = accept.messages[0].body;
    let deliveries: Vec<DeliveryId> = accept.messages[0]
        .recipients
        .iter()
        .map(|recipient| recipient.delivery)
        .collect();
    assert!(accepted(&harness.one(Command::Accept(accept), START)));
    let permits: Vec<DispatchPermit> = deliveries
        .iter()
        .map(|&id| {
            let delivery = harness.delivery(id);
            harness.reserved(&delivery, later(1))
        })
        .collect();
    // Every outcome in one group, which finishes the message.
    let outcomes = permits
        .into_iter()
        .map(|permit| outcome(permit, Disposition::Delivered, later(2)))
        .collect();
    let answers = harness.run(outcomes, later(2));
    assert!(
        answers
            .iter()
            .all(|answer| matches!(answer, Answer::Recorded(Commit::Committed(()))))
    );
    assert!(
        harness.store().body(body).expect("readable").is_none(),
        "every delivery finished, so the body is gone"
    );

    let entries = harness.store().entries(0, usize::MAX).expect("readable");
    assert_eq!(entries.len(), 6, "one acceptance, then five attempts");
    assert!(matches!(
        &entries[0].1,
        Entry::Accepted { deliveries: made, .. } if *made == deliveries
    ));
    assert!(entries[1..].iter().all(|(_, entry)| matches!(
        entry,
        Entry::Attempted { attempt, .. } if attempt.ended.map(|ended| ended.result) == Some(AttemptResult::Delivered)
    )));
    assert!(entries.windows(2).all(|pair| pair[0].0 < pair[1].0));
    // A reader reads on from where it stopped.
    let on = harness.store().entries(entries[2].0, 2).expect("readable");
    assert_eq!(on, entries[3..5]);
}

#[test]
fn a_due_scan_reads_on_from_where_it_stopped() {
    let vfs = vfs("due");
    let mut harness = Harness::open(&vfs);
    let addresses: Vec<String> = (0..4).map(|n| format!("r{n}@example.com")).collect();
    let addresses: Vec<&str> = addresses.iter().map(String::as_str).collect();
    let accept = harness.accept(&addresses);
    assert!(accepted(&harness.one(Command::Accept(accept), START)));
    let first = harness.store().due(later(1), None, 3).expect("readable");
    assert_eq!(first.len(), 3);
    let last = &first[2];
    let QueueState::Ready { due_at } = last.state() else {
        panic!("a due delivery waits");
    };
    let after = DuePosition {
        due_at,
        delivery: last.id(),
    };
    let rest = harness
        .store()
        .due(later(1), Some(after), 3)
        .expect("readable");
    assert_eq!(rest.len(), 1, "only the one not yet read");
    assert!(first.iter().all(|read| read.id() != rest[0].id()));
}

#[test]
fn a_suppressed_recipient_finishes_without_an_attempt_when_it_falls_due() {
    let vfs = vfs("suppression");
    let mut harness = Harness::open(&vfs);
    let accept = harness.accept(&["Jane@Example.com", "joe@example.com"]);
    let account = accept.authority.account;
    let body = accept.messages[0].body;
    let deliveries: Vec<DeliveryId> = accept.messages[0]
        .recipients
        .iter()
        .map(|recipient| recipient.delivery)
        .collect();
    assert!(accepted(&harness.one(Command::Accept(accept), START)));
    // Suppressed after acceptance, in another case: it still matches.
    let suppress = Command::Suppress(Suppress {
        account,
        addresses: vec![Address::parse("jane@example.com").expect("an address")],
        reason: Reason::Bounce,
        now: later(1),
    });
    assert!(matches!(
        harness.one(suppress, later(1)),
        Answer::Suppressions(Commit::Committed(1))
    ));

    let first = harness.delivery(deliveries[0]);
    let command = harness.reserve(&first, later(2));
    assert!(matches!(
        harness.one(command, later(2)),
        Answer::Reserved(Commit::Committed(Reservation::Suppressed))
    ));
    assert_eq!(
        harness.delivery(deliveries[0]).state(),
        QueueState::Finished {
            completion: Completion::Suppressed,
            at: later(2),
        }
    );
    let entries = harness.store().entries(0, usize::MAX).expect("readable");
    assert!(matches!(
        entries.last(),
        Some((_, Entry::Suppressed { delivery, .. })) if *delivery == deliveries[0]
    ));
    assert!(
        harness.store().body(body).expect("readable").is_some(),
        "the other recipient is still to send"
    );

    // An address not on the list removes nothing, and is sent to.
    let unsuppress = Command::Unsuppress(Unsuppress {
        account,
        addresses: vec![Address::parse("JOE@example.com").expect("an address")],
    });
    assert!(matches!(
        harness.one(unsuppress, later(3)),
        Answer::Suppressions(Commit::Committed(0))
    ));
    let second = harness.delivery(deliveries[1]);
    let permit = harness.reserved(&second, later(3));
    assert_eq!(permit.delivery(), deliveries[1]);
}

#[test]
fn a_suppression_list_reads_back_as_given_a_bounded_page_at_a_time() {
    let vfs = vfs("suppression-list");
    let mut harness = Harness::open(&vfs);
    let account = harness.accept(&["one@example.com"]).authority.account;
    let address = |text: &str| Address::parse(text).expect("an address");
    let suppress = |addresses: Vec<Address>, reason, at| {
        Command::Suppress(Suppress {
            account,
            addresses,
            reason,
            now: at,
        })
    };
    // Many bounces, then one complaint after them all in the list's order.
    let bounced: Vec<Address> = (0..List::MOST_READ)
        .map(|n| address(&format!("b{n:05}@example.com")))
        .collect();
    harness.one(suppress(bounced, Reason::Bounce, later(1)), later(1));
    let complained = suppress(
        vec![address("Zed@Example.com")],
        Reason::Complaint,
        later(2),
    );
    harness.one(complained, later(2));
    let one = Command::Suppression {
        account,
        address: address("zed@example.COM"),
    };
    let Answer::Suppression(Ok(Some(found))) = harness.one(one, later(3)) else {
        panic!("it is on the list");
    };
    assert_eq!(found.address.as_str(), "Zed@Example.com", "as it was given");
    assert_eq!((found.reason, found.at), (Reason::Complaint, later(2)));
    let absent = Command::Suppression {
        account,
        address: address("nobody@example.com"),
    };
    assert!(matches!(
        harness.one(absent, later(3)),
        Answer::Suppression(Ok(None))
    ));
    let list = |after: Option<String>, limit, reasons: Vec<Reason>| {
        Command::Suppressions(List {
            account,
            after,
            limit,
            reasons,
            from: None,
            to: None,
        })
    };
    let page = |harness: &mut Harness, command| match harness.one(command, later(3)) {
        Answer::SuppressionPage(Ok(page)) => page,
        other => panic!("{other:?}"),
    };
    let first = page(&mut harness, list(None, 2, Vec::new()));
    let listed: Vec<&str> = first
        .suppressed
        .iter()
        .map(|found| found.address.as_str())
        .collect();
    assert_eq!(listed, ["b00000@example.com", "b00001@example.com"]);
    let second = page(&mut harness, list(first.next, 2, Vec::new()));
    assert_eq!(second.suppressed[0].address.as_str(), "b00002@example.com");
    // A filter that matches only the last reads no more than its bound: a
    // short page, and a token from the last row read.
    let filtered = page(&mut harness, list(None, 10, vec![Reason::Complaint]));
    assert!(filtered.suppressed.is_empty());
    let rest = page(
        &mut harness,
        list(filtered.next, 10, vec![Reason::Complaint]),
    );
    assert_eq!(rest.suppressed.len(), 1);
    assert_eq!(rest.next, None, "the end of the list");
    // From a time, as ListSuppressedDestinations' StartDate asks.
    let since = Command::Suppressions(List {
        account,
        after: Some("b04990@example.com".to_owned()),
        limit: 100,
        reasons: Vec::new(),
        from: Some(later(2)),
        to: None,
    });
    assert_eq!(page(&mut harness, since).suppressed.len(), 1);
}

#[test]
fn a_delivery_whose_authority_is_withdrawn_finishes_without_an_attempt() {
    let vfs = vfs("withdrawn");
    let mut harness = Harness::open(&vfs);
    let accept = harness.accept(&["one@example.com", "two@example.com"]);
    let body = accept.messages[0].body;
    let deliveries: Vec<DeliveryId> = accept.messages[0]
        .recipients
        .iter()
        .map(|recipient| recipient.delivery)
        .collect();
    assert!(accepted(&harness.one(Command::Accept(accept), START)));
    let first = harness.delivery(deliveries[0]);
    let permit = harness.reserved(&first, later(1));

    // The identity goes while one attempt is in flight: that attempt may
    // finish, but nothing more is sent as it.
    let removal = Command::ChangePolicy(Sender::first().removal());
    assert!(changed_policy(&harness.one(removal, later(2))));
    assert!(matches!(
        harness.one(outcome(permit, Disposition::Delivered, later(3)), later(3)),
        Answer::Recorded(Commit::Committed(()))
    ));
    let second = harness.delivery(deliveries[1]);
    let command = harness.reserve(&second, later(4));
    assert!(matches!(
        harness.one(command, later(4)),
        Answer::Reserved(Commit::Committed(Reservation::Cancelled))
    ));
    assert_eq!(
        harness.delivery(deliveries[1]).state(),
        QueueState::Finished {
            completion: Completion::Cancelled,
            at: later(4),
        }
    );
    let entries = harness.store().entries(0, usize::MAX).expect("readable");
    assert!(matches!(
        entries.last(),
        Some((_, Entry::Cancelled { delivery, .. })) if *delivery == deliveries[1]
    ));
    assert_eq!(
        harness.store().body(body).expect("readable"),
        None,
        "both deliveries finished"
    );
}

#[test]
fn an_acceptance_rendered_from_a_template_its_tenant_has_lost_is_refused() {
    let vfs = vfs("template-withdrawn");
    let mut harness = Harness::open(&vfs);
    let sender = Sender::first();
    let template = TemplateId(harness.ids.next(START));
    let tenant = TenantId(harness.ids.next(START));
    for change in [
        Change::NewTemplate {
            id: template,
            account: sender.account,
            name: "welcome".to_owned(),
            content: TemplateContent {
                subject: "Welcome".to_owned(),
                text: Some("Hello".to_owned()),
                html: None,
            },
            at: START,
        },
        Change::NewTenant {
            id: tenant,
            account: sender.account,
            name: "acme".to_owned(),
            tags: Vec::new(),
            at: START,
        },
        Change::Associate {
            account: sender.account,
            tenant: "acme".to_owned(),
            resource: Resource::Identity(engine_sim::sender::DOMAIN.to_owned()),
        },
        Change::Associate {
            account: sender.account,
            tenant: "acme".to_owned(),
            resource: Resource::Template("welcome".to_owned()),
        },
    ] {
        assert!(changed_policy(
            &harness.one(Command::ChangePolicy(change), START)
        ));
    }
    let decided = harness.store().policy().revision();
    // Rendered from the template for the tenant, as the API decided it.
    let mut rendered = harness.accept_under(decided, &["one@example.com"]);
    rendered.authority.origin = Origin {
        tenant: Some(tenant),
        ..rendered.authority.origin
    };
    rendered.authority.template = Some(template);
    // The tenant loses the template before the acceptance commits.
    let dissociated = Change::Dissociate {
        account: sender.account,
        tenant: "acme".to_owned(),
        resource: Resource::Template("welcome".to_owned()),
    };
    assert!(changed_policy(
        &harness.one(Command::ChangePolicy(dissociated), START)
    ));
    assert!(matches!(
        harness.one(Command::Accept(rendered), START),
        Answer::Accepted(Commit::Refused(AcceptRefusal::Unauthorised(
            Denial::NotAssociated
        )))
    ));
}

#[test]
fn an_acceptance_decided_under_older_policy_is_decided_again() {
    let vfs = vfs("older-policy");
    let mut harness = Harness::open(&vfs);
    let decided = harness.store().policy().revision();
    let unrelated = Command::ChangePolicy(Change::Configuration {
        id: ConfigurationId(harness.ids.next(START)),
        account: Sender::first().account,
        name: "receipts".to_owned(),
        pool: None,
    });
    assert!(changed_policy(&harness.one(unrelated, START)));
    let still_allowed = harness.accept_under(decided, &["one@example.com"]);
    assert!(accepted(
        &harness.one(Command::Accept(still_allowed), START)
    ));

    let removal = Command::ChangePolicy(Sender::first().removal());
    assert!(changed_policy(&harness.one(removal, START)));
    let withdrawn = harness.accept_under(decided, &["two@example.com"]);
    let message = withdrawn.messages[0].id;
    assert!(matches!(
        harness.one(Command::Accept(withdrawn), START),
        Answer::Accepted(Commit::Refused(AcceptRefusal::Unauthorised(
            Denial::UnknownIdentity
        )))
    ));
    assert!(
        harness
            .store()
            .message(message)
            .expect("readable")
            .is_none(),
        "a refusal stores nothing"
    );
}

#[test]
fn policy_is_durable_and_a_refused_change_makes_no_revision() {
    let vfs = vfs("policy");
    let mut harness = Harness::open(&vfs);
    let before = harness.store().policy().revision();
    let dangling = Command::ChangePolicy(Change::Remove(Target::Login("nobody".to_owned())));
    assert!(matches!(
        harness.one(dangling, START),
        Answer::Policy(Commit::Refused(PolicyRefusal::Unknown {
            kind: "login",
            ..
        }))
    ));
    assert_eq!(harness.store().policy().revision(), before);
    let renamed = IdentityId(harness.ids.next(START));
    let (_, put) = Sender::first().renewed(renamed);
    assert!(matches!(
        harness.one(Command::ChangePolicy(put), START),
        Answer::Policy(Commit::Committed(revision)) if revision == PolicyRevision(before.0 + 1)
    ));
    let policy = std::sync::Arc::clone(harness.store().policy());
    assert!(
        policy.identity(Sender::first().identity).is_some() && policy.identity(renamed).is_none(),
        "put under a name it already has, an identity keeps its ID"
    );

    drop(harness);
    let reopened = Harness::open(&vfs);
    let read = reopened.store().policy();
    assert_eq!(read.revision(), policy.revision());
    assert_eq!(
        read.identity(Sender::first().identity),
        policy.identity(Sender::first().identity)
    );
    assert!(read.login("simulation").is_some());
}

#[test]
fn the_daily_quota_admits_no_more_than_it_holds_even_within_one_group() {
    let vfs = vfs("quota");
    let mut harness = Harness::open(&vfs);
    let account = Sender::first().account;
    let quota = Command::ChangePolicy(Change::Account(Account {
        id: account,
        limits: Limits::default(),
        daily_quota: Some(5),
    }));
    assert!(changed_policy(&harness.one(quota, START)));
    // Two acceptances in one group want the last two places.
    let first = harness.accept(&["a@example.com", "b@example.com", "c@example.com"]);
    let second = harness.accept(&["d@example.com", "e@example.com"]);
    let third = harness.accept(&["f@example.com"]);
    let answers = harness.run(
        vec![
            Command::Accept(first),
            Command::Accept(second),
            Command::Accept(third),
        ],
        START,
    );
    assert!(accepted(&answers[0]) && accepted(&answers[1]));
    assert!(matches!(
        answers[2],
        Answer::Accepted(Commit::Refused(AcceptRefusal::QuotaExceeded))
    ));

    // The ledger is durable, and once their minute is a day old the window
    // has moved on.
    drop(harness);
    let mut harness = Harness::open(&vfs);
    let day = 24 * 3_600;
    let recipients = |harness: &mut Harness<'_>, at| harness.owner.store_mut().sent(account, at);
    assert_eq!(recipients(&mut harness, later(day)), 5);
    let mut late = harness.accept(&["g@example.com"]);
    late.accepted_at = later(day + 60);
    late.expires_at = later(day + 3_660);
    assert!(accepted(
        &harness.one(Command::Accept(late), later(day + 60))
    ));
    assert_eq!(recipients(&mut harness, later(day + 60)), 1);
}

#[test]
fn a_refused_command_changes_nothing_while_the_rest_commit() {
    let vfs = vfs("refusal");
    let mut harness = Harness::open(&vfs);
    let first = harness.accept(&["first@example.com"]);
    let last = harness.accept(&["last@example.com"]);
    // Its second message takes the first acceptance's IDs, so it conflicts
    // after its own first message has been written.
    let mut conflicting = harness.accept(&["middle@example.com"]);
    conflicting.messages.push(first.messages[0].clone());
    let written_then_undone = conflicting.messages[0].id;

    let answers = harness.run(
        vec![
            Command::Accept(first),
            Command::Accept(conflicting),
            Command::Accept(last.clone()),
        ],
        START,
    );
    assert!(accepted(&answers[0]) && accepted(&answers[2]));
    assert!(matches!(
        answers[1],
        Answer::Accepted(Commit::Refused(AcceptRefusal::Conflict))
    ));
    assert_eq!(
        harness
            .store()
            .message(written_then_undone)
            .expect("readable"),
        None
    );
    assert!(
        harness
            .store()
            .message(last.messages[0].id)
            .expect("readable")
            .is_some()
    );
    harness.store().verify().expect("intact");
}

#[test]
fn an_acceptance_applied_again_changes_nothing() {
    let vfs = vfs("idempotent");
    let mut harness = Harness::open(&vfs);
    let accept = harness.accept(&["rcpt@example.com"]);
    assert!(accepted(
        &harness.one(Command::Accept(accept.clone()), START)
    ));
    assert!(accepted(&harness.one(Command::Accept(accept), START)));
    assert_eq!(
        harness
            .store()
            .due(later(1), None, 10)
            .expect("readable")
            .len(),
        1
    );

    let empty = Accept {
        messages: Vec::new(),
        ..harness.accept(&["rcpt@example.com"])
    };
    assert!(matches!(
        harness.one(Command::Accept(empty), START),
        Answer::Accepted(Commit::Refused(AcceptRefusal::NoMessages))
    ));
}

#[test]
fn a_stale_view_cannot_reserve() {
    let vfs = vfs("stale");
    let mut harness = Harness::open(&vfs);
    let accept = harness.accept(&["rcpt@example.com"]);
    let delivery = accept.messages[0].recipients[0].delivery;
    harness.one(Command::Accept(accept), START);
    let view = harness.delivery(delivery);
    let permit = harness.reserved(&view, later(1));
    let retry = Disposition::Deferred {
        not_before: later(2),
    };
    harness.one(outcome(permit, retry, later(1)), later(1));

    let stale = harness.reserve(&view, later(3));
    assert!(matches!(
        harness.one(stale, later(3)),
        Answer::Reserved(Commit::Refused(Refusal::Stale { .. }))
    ));
    let missing = Command::Expire(Expire {
        delivery: DeliveryId(harness.ids.next(START)),
        now: later(3),
    });
    assert!(matches!(
        harness.one(missing, later(3)),
        Answer::Expired(Commit::Refused(Refusal::Gone))
    ));
}

#[test]
fn outcomes_commit_before_new_acceptances() {
    let vfs = vfs("priority");
    let mut harness = Harness::open(&vfs);
    harness.owner = {
        let store = Store::open(
            vfs.open("priority.db").expect("opens"),
            StoreOptions::default(),
            sender::keys(),
        )
        .expect("a valid store");
        let limits = GroupLimits {
            commands: 1,
            content_bytes: 1 << 20,
        };
        CommitOwner::start(store, limits, START)
            .expect("recovers")
            .0
    };
    harness.provision();
    let accept = harness.accept(&["rcpt@example.com"]);
    let delivery = accept.messages[0].recipients[0].delivery;
    harness.one(Command::Accept(accept), START);
    let view = harness.delivery(delivery);
    let permit = harness.reserved(&view, later(1));

    let waiting = Command::Accept(harness.accept(&["next@example.com"]));
    let ticket = Ticket(harness.next_ticket);
    harness.owner.handle(
        now(later(2)),
        Request {
            ticket,
            command: waiting,
        },
    );
    harness.owner.handle(
        now(later(2)),
        Request {
            ticket: Ticket(ticket.0 + 1),
            command: outcome(permit, Disposition::Delivered, later(2)),
        },
    );
    let mut responses = Vec::new();
    assert!(
        harness.owner.poll(now(later(2)), &mut responses) == Some(now(later(2)).monotonic),
        "more is waiting"
    );
    assert_eq!(responses.len(), 1);
    assert!(matches!(
        responses[0].answer,
        Answer::Recorded(Commit::Committed(()))
    ));
}

#[test]
fn a_cooldown_kept_apart_commits_no_later_than_the_outcomes_after_it() {
    let vfs = vfs("cool-order");
    let mut harness = Harness::open(&vfs);
    harness.owner = {
        let store = Store::open(
            vfs.open("cool-order.db").expect("opens"),
            StoreOptions::default(),
            sender::keys(),
        )
        .expect("a valid store");
        let limits = GroupLimits {
            commands: 1,
            content_bytes: 1 << 20,
        };
        CommitOwner::start(store, limits, START)
            .expect("recovers")
            .0
    };
    harness.provision();
    let accept = harness.accept(&["rcpt@example.com"]);
    let delivery = accept.messages[0].recipients[0].delivery;
    harness.one(Command::Accept(accept), START);
    let permit = harness.reserved(&harness.delivery(delivery), later(1));
    // A refused session's cooldown, then the outcome it deferred.
    let cooldown = SiteCooldown {
        egress: None,
        site: "Throttled".into(),
        until: later(600),
        throttles: 1,
        reply: None,
    };
    let ticket = Ticket(harness.next_ticket);
    for (offset, command) in [
        Command::Cooldown(CooldownChange::Kept(cooldown)),
        outcome(
            permit,
            Disposition::Deferred {
                not_before: later(600),
            },
            later(2),
        ),
    ]
    .into_iter()
    .enumerate()
    {
        harness.owner.handle(
            now(later(2)),
            Request {
                ticket: Ticket(ticket.0 + offset as u64),
                command,
            },
        );
    }
    let mut responses = Vec::new();
    harness.owner.poll(now(later(2)), &mut responses);
    assert_eq!(responses.len(), 1);
    assert!(
        matches!(responses[0].answer, Answer::Cooled(Commit::Committed(()))),
        "the cooldown commits first: {:?}",
        responses[0].answer
    );
}

#[test]
fn a_restart_recovers_attempts_in_flight_and_never_reissues_an_id() {
    let vfs = vfs("restart");
    let (attempt, delivery, highest) = {
        let mut harness = Harness::open(&vfs);
        let accept = harness.accept(&["rcpt@example.com"]);
        let delivery = accept.messages[0].recipients[0].delivery;
        harness.one(Command::Accept(accept), START);
        let view = harness.delivery(delivery);
        let permit = harness.reserved(&view, later(1));
        (permit.attempt(), delivery, permit.attempt().0)
        // The process stops with the attempt in flight.
    };
    let (harness, abandoned) = Harness::reopen(&vfs);
    assert_eq!(abandoned.len(), 1);
    assert_eq!(
        (abandoned[0].id, abandoned[0].delivery),
        (attempt, delivery)
    );
    assert_eq!(
        abandoned[0].ended.map(|ended| ended.result),
        Some(AttemptResult::Abandoned)
    );
    let recovered = harness.delivery(delivery);
    assert!(matches!(recovered.state(), QueueState::Ready { .. }));
    assert_eq!(recovered.uncertain_attempts(), 1);
    assert!(harness.store().highest_id().expect("readable") >= Some(highest));
    let mut ids = harness.ids;
    assert!(
        ids.next(START) > highest,
        "new IDs sort after every stored one"
    );
}

#[test]
fn expiry_finishes_a_waiting_delivery_and_frees_its_body() {
    let vfs = vfs("expiry");
    let mut harness = Harness::open(&vfs);
    let accept = harness.accept(&["rcpt@example.com"]);
    let (delivery, body) = (
        accept.messages[0].recipients[0].delivery,
        accept.messages[0].body,
    );
    harness.one(Command::Accept(accept), START);
    let end = START.saturating_add(LIFETIME);

    assert!(
        harness
            .store()
            .expiring(later(1), 10)
            .expect("readable")
            .is_empty()
    );
    let expiring = harness.store().expiring(end, 10).expect("readable");
    assert_eq!(
        expiring.iter().map(Delivery::id).collect::<Vec<_>>(),
        [delivery]
    );
    let early = Command::Expire(Expire {
        delivery,
        now: later(1),
    });
    assert!(matches!(
        harness.one(early, later(1)),
        Answer::Expired(Commit::Refused(Refusal::NotExpired))
    ));
    let due = Command::Expire(Expire { delivery, now: end });
    assert!(matches!(
        harness.one(due, end),
        Answer::Expired(Commit::Committed(()))
    ));
    assert!(matches!(
        harness.delivery(delivery).state(),
        QueueState::Finished {
            completion: Completion::Expired,
            ..
        }
    ));
    assert_eq!(harness.store().body(body).expect("readable"), None);
}

#[test]
fn a_restored_store_holds_what_its_copy_held_until_a_decision_and_sends_what_is_new() {
    let vfs = vfs("fenced");
    let mut harness = Harness::open(&vfs);
    let accept = harness.accept(&["one@example.com", "two@example.com", "three@example.com"]);
    let restored: Vec<DeliveryId> = accept.messages[0]
        .recipients
        .iter()
        .map(|recipient| recipient.delivery)
        .collect();
    assert!(accepted(&harness.one(Command::Accept(accept), START)));
    // A decision on a store that was not restored is refused.
    assert!(matches!(
        harness.one(Command::DecideFence(FenceDecision::Release), later(1)),
        Answer::FenceDecided(Commit::Refused(Unfenced))
    ));
    // Copied, then restored as `nitromta restore` restores it: noted as a
    // copy, opened as the engine opens it, and fenced.
    drop(harness);
    let copy = vfs.open(DATABASE).expect("opens");
    // As the store opens it, with no shared memory for its log.
    copy.execute_batch("PRAGMA locking_mode = EXCLUSIVE")
        .expect("exclusive");
    engine_store::store::mark_copied(&copy, later(1)).expect("noted");
    drop(copy);
    let mut harness = Harness::open(&vfs);
    let fence = harness
        .owner
        .store_mut()
        .fence_restored(later(2))
        .expect("fenced");
    assert_eq!(
        (fence.taken, fence.restored, fence.discarding),
        (later(1), later(2), false)
    );
    let answer = harness.one(Command::Fenced, later(2));
    assert!(
        matches!(answer, Answer::Fenced(Ok(Some((_, 3))))),
        "{answer:?}"
    );
    // What the copy held parks at its reservation; new mail goes.
    let reserve_now = |harness: &mut Harness<'_>, id, at| {
        let delivery = harness.delivery(id);
        let command = harness.reserve(&delivery, at);
        harness.one(command, at)
    };
    assert!(matches!(
        reserve_now(&mut harness, restored[0], later(3)),
        Answer::Reserved(Commit::Committed(Reservation::Paused))
    ));
    let accept = harness.accept(&["new@example.com"]);
    let new = accept.messages[0].recipients[0].delivery;
    assert!(accepted(&harness.one(Command::Accept(accept), later(3))));
    assert!(matches!(
        reserve_now(&mut harness, new, later(3)),
        Answer::Reserved(Commit::Committed(Reservation::Permit(_)))
    ));
    // The fence outlives a restart.
    drop(harness);
    let mut harness = Harness::open(&vfs);
    assert!(matches!(
        reserve_now(&mut harness, restored[1], later(4)),
        Answer::Reserved(Commit::Committed(Reservation::Paused))
    ));
    // Discarded: a held delivery is released, and its reservation cancels
    // it, unsent; a waiting one is cancelled as it falls due.
    assert!(matches!(
        harness.one(Command::DecideFence(FenceDecision::Discard), later(5)),
        Answer::FenceDecided(Commit::Committed(_))
    ));
    let held = harness.delivery(restored[0]);
    let release = Command::Release(Release {
        delivery: held.id(),
        seen: held.generation(),
    });
    assert!(matches!(
        harness.one(release, later(5)),
        Answer::Released(Commit::Committed(()))
    ));
    assert!(matches!(
        reserve_now(&mut harness, restored[0], later(6)),
        Answer::Reserved(Commit::Committed(Reservation::Cancelled))
    ));
    assert!(matches!(
        harness.delivery(restored[0]).state(),
        QueueState::Finished {
            completion: Completion::Cancelled,
            ..
        }
    ));
    assert!(matches!(
        reserve_now(&mut harness, restored[2], later(6)),
        Answer::Reserved(Commit::Committed(Reservation::Cancelled))
    ));
    let answer = harness.one(Command::Fenced, later(6));
    assert!(
        matches!(answer, Answer::Fenced(Ok(Some((fence, 1)))) if fence.discarding),
        "{answer:?}"
    );
    // Released: the fence goes, and what it held is sent.
    assert!(matches!(
        harness.one(Command::DecideFence(FenceDecision::Release), later(7)),
        Answer::FenceDecided(Commit::Committed(_))
    ));
    assert!(matches!(
        harness.one(Command::Fenced, later(7)),
        Answer::Fenced(Ok(None))
    ));
    let held = harness.delivery(restored[1]);
    let release = Command::Release(Release {
        delivery: held.id(),
        seen: held.generation(),
    });
    assert!(matches!(
        harness.one(release, later(7)),
        Answer::Released(Commit::Committed(()))
    ));
    assert!(matches!(
        reserve_now(&mut harness, restored[1], later(8)),
        Answer::Reserved(Commit::Committed(Reservation::Permit(_)))
    ));
}

#[test]
fn a_postponed_delivery_leaves_the_due_scan_until_its_time_keeping_its_egress() {
    let vfs = vfs("postponed");
    let mut harness = Harness::open(&vfs);
    let accept = harness.accept(&["one@example.com"]);
    let id = accept.messages[0].recipients[0].delivery;
    assert!(accepted(&harness.one(Command::Accept(accept), START)));
    let egress = Some(EgressId(harness.ids.next(START)));
    let seen = harness.delivery(id).generation();
    let postpone = |seen| {
        Command::Postpone(Postpone {
            delivery: id,
            seen,
            egress,
            until: later(600),
            now: later(1),
        })
    };
    // Put off with no journal entry and no attempt, it keeps its egress,
    // across a restart, and is due again at its time.
    let entries = harness
        .store()
        .entries(0, usize::MAX)
        .expect("readable")
        .len();
    assert!(matches!(
        harness.one(postpone(seen), later(1)),
        Answer::Postponed(Commit::Committed(()))
    ));
    assert_eq!(
        harness
            .store()
            .entries(0, usize::MAX)
            .expect("readable")
            .len(),
        entries
    );
    drop(harness);
    let mut harness = Harness::open(&vfs);
    let delivery = harness.delivery(id);
    assert_eq!(delivery.state(), QueueState::Ready { due_at: later(600) });
    assert_eq!((delivery.egress(), delivery.attempts()), (egress, 0));
    assert!(
        harness
            .store()
            .due(later(599), None, 10)
            .expect("readable")
            .is_empty()
    );
    let due = harness.store().due(later(600), None, 10).expect("readable");
    assert_eq!(due.iter().map(Delivery::id).collect::<Vec<_>>(), [id]);
    // A view of it from before is refused.
    assert!(matches!(
        harness.one(postpone(seen), later(2)),
        Answer::Postponed(Commit::Refused(Refusal::Stale { .. }))
    ));
}

#[test]
fn a_hold_parks_what_it_covers_at_its_reservation_which_still_expires() {
    let vfs = vfs("held");
    let mut harness = Harness::open(&vfs);
    let accept = harness.accept(&["one@example.com", "two@example.com"]);
    let deliveries: Vec<DeliveryId> = accept.messages[0]
        .recipients
        .iter()
        .map(|recipient| recipient.delivery)
        .collect();
    assert!(accepted(&harness.one(Command::Accept(accept), START)));
    let hold = Command::ChangePolicy(Change::Hold {
        id: HoldId(harness.ids.next(START)),
        target: Sender::first().target(),
        accepting: true,
        reason: "investigating".to_owned(),
    });
    assert!(changed_policy(&harness.one(hold, later(1))));
    // Its reservation parks it, in the same commit, with no permit and no
    // journal entry; it keeps when it was due.
    let entries = harness
        .store()
        .entries(0, usize::MAX)
        .expect("readable")
        .len();
    for &id in &deliveries {
        let delivery = harness.delivery(id);
        let command = harness.reserve(&delivery, later(2));
        assert!(matches!(
            harness.one(command, later(2)),
            Answer::Reserved(Commit::Committed(Reservation::Paused))
        ));
        assert_eq!(
            harness.delivery(id).state(),
            QueueState::Held {
                due_at: START,
                since: later(2),
            }
        );
    }
    assert_eq!(
        harness
            .store()
            .entries(0, usize::MAX)
            .expect("readable")
            .len(),
        entries
    );
    // Held, it is out of the due scan, and the held scan finds it, after a
    // restart as before; the queue counts both held.
    assert!(
        harness
            .store()
            .due(later(3), None, 10)
            .expect("readable")
            .is_empty()
    );
    let held_counted = |harness: &Harness<'_>| {
        let kept = harness.store().queued();
        assert_eq!(kept, harness.store().count_queued().expect("countable"));
        kept.held
    };
    assert_eq!(held_counted(&harness), 2);
    drop(harness);
    let mut harness = Harness::open(&vfs);
    let held = harness.store().held(None, 1).expect("readable");
    assert_eq!(
        held.iter().map(Delivery::id).collect::<Vec<_>>(),
        [deliveries[0]]
    );
    let rest = harness
        .store()
        .held(Some(deliveries[0]), 10)
        .expect("readable");
    assert_eq!(
        rest.iter().map(Delivery::id).collect::<Vec<_>>(),
        [deliveries[1]]
    );
    // Not released while a hold covers it; once lifted, due when it was.
    let release = || {
        Command::Release(Release {
            delivery: deliveries[0],
            seen: held[0].generation(),
        })
    };
    assert!(matches!(
        harness.one(release(), later(4)),
        Answer::Released(Commit::Refused(Refusal::Held))
    ));
    let lift = Command::ChangePolicy(Change::Release(Sender::first().target()));
    assert!(changed_policy(&harness.one(lift, later(4))));
    assert!(matches!(
        harness.one(release(), later(4)),
        Answer::Released(Commit::Committed(()))
    ));
    // Parked again only while a hold covers it.
    let delivery = harness.delivery(deliveries[0]);
    let park = Command::Park(Park {
        delivery: delivery.id(),
        seen: delivery.generation(),
        egress: None,
        now: later(4),
    });
    assert!(matches!(
        harness.one(park, later(4)),
        Answer::Parked(Commit::Refused(Refusal::NotHeld))
    ));
    let due = harness.store().due(later(4), None, 10).expect("readable");
    assert_eq!(
        due.iter().map(Delivery::id).collect::<Vec<_>>(),
        [deliveries[0]]
    );
    // Still held at its expiry, it expires: the hold lifted, it was never
    // released.
    let end = START.saturating_add(LIFETIME);
    let expiring = harness.store().expiring(end, 10).expect("readable");
    assert!(
        expiring
            .iter()
            .any(|delivery| delivery.id() == deliveries[1])
    );
    let expire = Command::Expire(Expire {
        delivery: deliveries[1],
        now: end,
    });
    assert!(matches!(
        harness.one(expire, end),
        Answer::Expired(Commit::Committed(()))
    ));
    assert!(harness.store().held(None, 10).expect("readable").is_empty());
    assert_eq!(held_counted(&harness), 0);
}

#[test]
fn secrets_are_sealed_again_under_a_new_key_and_need_it_after() {
    // Each seed cuts the power differently: a file's length may come back
    // as last synced or as last written.
    for seed in 1..=8 {
        rotation(seed);
    }
}

fn rotation(seed: u64) {
    let vfs = seeded(&format!("rotation-{seed}"), seed);
    let ring = |keys: &[(u8, [u8; 32])]| Arc::new(Keyring::new(keys).expect("keys"));
    let open = |keys| {
        Store::open(
            vfs.open(DATABASE).expect("opens"),
            StoreOptions::default(),
            keys,
        )
    };
    let first = (1, [0x11; 32]);
    let second = (2, [0x22; 32]);
    let change = |keys, changes: Vec<Change>| {
        let store = open(keys).expect("opens");
        let (mut owner, _) = CommitOwner::start(store, LIMITS, START).expect("starts");
        let mut responses = Vec::new();
        for (ticket, change) in changes.into_iter().enumerate() {
            let request = Request {
                ticket: Ticket(ticket as u64),
                command: Command::ChangePolicy(change),
            };
            owner.handle(now(START), request);
        }
        while owner.poll(now(START), &mut responses) == Some(now(START).monotonic) {}
        assert!(
            responses
                .iter()
                .all(|response| changed_policy(&response.answer))
        );
    };
    let records = || -> Vec<Vec<u8>> {
        let connection = vfs.open(DATABASE).expect("opens");
        connection
            .execute_batch("PRAGMA locking_mode = EXCLUSIVE")
            .expect("locked");
        connection
            .prepare("SELECT record FROM policy")
            .and_then(|mut statement| {
                statement
                    .query_map([], |row| row.get(0))?
                    .collect::<Result<_, _>>()
            })
            .expect("readable")
    };
    // Logins' secrets, sealed under the first key: the sender's, and forty
    // more, over several pages.
    let sender = Sender::first();
    let departed = |n: u64| format!("departed-{n}");
    let mut changes = sender.changes().to_vec();
    changes.extend((0..40).map(|n| Change::Credential {
        id: CredentialId(Id::from_u64((1 << 40) + n).expect("an ID")),
        account: sender.account,
        secret: Secret::Login {
            user: departed(n),
            password_sha256: [7; 32],
        },
        identities: None,
        tenants: None,
        permissions: Permissions::SENDS,
    }));
    change(ring(&[first]), changes);
    let sealed: Vec<Vec<u8>> = records()
        .iter()
        .flat_map(|record| sealed_in(&ring(&[first]), record))
        .collect();
    assert_eq!(sealed.len(), 41, "each login's");
    // The forty removed: the pages and the space their secrets held are
    // zeroed as they go. Then the power fails, leaving the log's frames.
    {
        let store = open(ring(&[first])).expect("opens");
        let (mut owner, _) = CommitOwner::start(store, LIMITS, START).expect("starts");
        for n in 0..40 {
            let removal = Change::Remove(Target::Login(departed(n)));
            let request = Request {
                ticket: Ticket(n),
                command: Command::ChangePolicy(removal),
            };
            owner.handle(now(START), request);
        }
        let mut responses = Vec::new();
        while owner.poll(now(START), &mut responses) == Some(now(START).monotonic) {}
        assert!(
            responses
                .iter()
                .all(|response| changed_policy(&response.answer))
        );
        vfs.disk().borrow_mut().fail_power_after(0);
        drop(owner);
        vfs.disk().borrow_mut().crash();
    }
    // Opened with a newer key beside it, it seals its secrets again under
    // that one, and then needs no other; nothing the first sealed is left
    // anywhere on the disk, even as a power cut right after the start
    // leaves it.
    let store = open(ring(&[first, second])).expect("opens");
    vfs.disk().borrow_mut().fail_power_after(0);
    drop(store);
    vfs.disk().borrow_mut().crash();
    let disk = vfs.disk().borrow();
    for (path, contents) in disk.files() {
        for secret in &sealed {
            assert!(
                !contents
                    .windows(secret.len())
                    .any(|window| window == &secret[..]),
                "a secret under the first key is still in {path}"
            );
        }
    }
    drop(disk);
    let store = open(ring(&[second])).expect("every secret under the second key");
    assert!(store.policy().login(sender::LOGIN).is_some());
    drop(store);
    let Err(refused) = open(ring(&[first])) else {
        panic!("opened, though the second key is gone");
    };
    assert!(refused.to_string().contains("key 2"), "{refused}");
}

/// Every envelope in `bytes` that opens under `keys`: its key's ID, its
/// place, then its sealed secret.
fn sealed_in(keys: &Keyring, bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut found = Vec::new();
    for start in 0..bytes.len() {
        let Some(place) = bytes.get(start + 1..start + 13) else {
            break;
        };
        let place: [u8; 12] = place.try_into().expect("12 bytes");
        for end in start + 13 + 16..=bytes.len() {
            if keys.open(place, &bytes[start..end]).is_ok() {
                found.push(bytes[start..end].to_vec());
                break;
            }
        }
    }
    found
}

#[test]
fn the_queue_is_counted_as_each_delivery_moves_as_a_count_from_its_rows_finds_it() {
    let vfs = vfs("queued");
    let mut harness = Harness::open(&vfs);
    let check = |harness: &Harness<'_>, waiting, in_flight| {
        let expected = Queued {
            waiting,
            in_flight,
            held: 0,
        };
        assert_eq!(harness.store().queued(), expected, "kept");
        assert_eq!(
            harness.store().count_queued().expect("countable"),
            expected,
            "counted"
        );
    };
    let accepts: Vec<Accept> = (0..4)
        .map(|n| harness.accept(&[&format!("q{n}@example.com")]))
        .collect();
    let deliveries: Vec<DeliveryId> = accepts
        .iter()
        .map(|accept| accept.messages[0].recipients[0].delivery)
        .collect();
    let commands = accepts.into_iter().map(Command::Accept).collect();
    assert!(harness.run(commands, START).iter().all(accepted));
    check(&harness, 4, 0);
    // An acceptance refused after it wrote a delivery, its second's ID
    // taken: what it wrote is undone, and so is what it counted.
    let mut conflicting = harness.accept(&["r0@example.com", "r1@example.com"]);
    conflicting.messages[0].recipients[1].delivery = deliveries[3];
    assert!(matches!(
        harness.one(Command::Accept(conflicting), START),
        Answer::Accepted(Commit::Refused(_))
    ));
    check(&harness, 4, 0);
    // Three taken for attempts, then one delivered, one deferred and one
    // rejected.
    let reservations = deliveries[..3]
        .iter()
        .map(|&delivery| harness.reserve(&harness.delivery(delivery), later(1)))
        .collect();
    let permits: Vec<DispatchPermit> = harness
        .run(reservations, later(1))
        .into_iter()
        .map(committed_permit)
        .collect();
    check(&harness, 1, 3);
    let outcomes = [
        Disposition::Delivered,
        Disposition::Deferred {
            not_before: later(2),
        },
        Disposition::Rejected,
    ]
    .into_iter()
    .zip(permits)
    .map(|(disposition, permit)| outcome(permit, disposition, later(2)))
    .collect();
    harness.run(outcomes, later(2));
    check(&harness, 2, 0);
    // The oldest waiting, the deferred one, was accepted at the start; the
    // other was due at once.
    let (oldest, due) = harness.store().queue_times().expect("readable");
    assert_eq!(oldest, Some(deliveries[1].0.issued_at()));
    assert!(due.is_some_and(|due| due <= START), "{due:?}");
    // The one never tried expires.
    let expire = Command::Expire(Expire {
        delivery: deliveries[3],
        now: START.saturating_add(LIFETIME),
    });
    assert!(matches!(
        harness.one(expire, START.saturating_add(LIFETIME)),
        Answer::Expired(Commit::Committed(()))
    ));
    check(&harness, 1, 0);
    // Opened again, it counts from the rows alike.
    drop(harness);
    let harness = Harness::reopen(&vfs).0;
    check(&harness, 1, 0);
}

#[test]
fn a_store_from_a_newer_release_is_refused() {
    let vfs = vfs("newer");
    drop(Harness::open(&vfs));
    let connection = vfs.open(DATABASE).expect("opens");
    connection
        .execute_batch("PRAGMA locking_mode = EXCLUSIVE; PRAGMA user_version = 99;")
        .expect("writable");
    drop(connection);
    let refused = Store::open(
        vfs.open(DATABASE).expect("opens"),
        StoreOptions::default(),
        sender::keys(),
    );
    assert!(matches!(
        refused,
        Err(StoreError::Newer { version: 99, .. })
    ));
}

#[test]
fn a_topic_subscriber_owes_from_its_confirmation_what_was_published_and_reads_what_was_kept_of_each_message()
 {
    let vfs = vfs("topic-feed");
    let mut harness = Harness::open(&vfs);
    let account = Sender::first().account;
    let configuration = ConfigurationId(harness.ids.next(START));
    let subscriber = SubscriptionId(harness.ids.next(START));
    let topic = |harness: &mut Harness<'_>| TopicId(harness.ids.next(START));
    let topic = topic(&mut harness);
    let changes = vec![
        Command::ChangePolicy(Change::Configuration {
            id: configuration,
            account,
            name: "receipts".to_owned(),
            pool: None,
        }),
        Command::ChangePolicy(Change::Topic {
            id: topic,
            account,
            name: "feedback".to_owned(),
        }),
        Command::ChangePolicy(Change::Destination {
            id: DestinationId(harness.ids.next(START)),
            account,
            configuration: "receipts".to_owned(),
            name: "receipts-feedback".to_owned(),
            topic: "feedback".to_owned(),
            events: BTreeSet::from([EventKind::Accepted]),
            enabled: true,
            replaces: false,
        }),
        Command::ChangePolicy(Change::Subscribe {
            id: subscriber,
            account,
            topic: "feedback".to_owned(),
            endpoint: "https://hooks.example.test/ses".to_owned(),
            token: [3; 32],
        }),
    ];
    assert!(harness.run(changes, START).iter().all(changed_policy));
    let read = |harness: &mut Harness<'_>| {
        let read = Command::Events {
            subscription: subscriber,
            after: None,
            until: None,
            limit: 100,
        };
        match harness.one(read, START) {
            Answer::Events(Ok(owed)) => owed,
            other => panic!("expected events, got {other:?}"),
        }
    };
    let send = |harness: &mut Harness<'_>, mail: Option<Mail>| {
        let mut accept = harness.accept(&["a@example.com"]);
        accept.authority.origin.configuration = Some(configuration);
        accept.messages[0].mail = mail;
        let message = accept.messages[0].id;
        assert!(accepted(&harness.one(Command::Accept(accept), START)));
        message
    };
    // Pending, it has no cursor, and owes nothing of what is sent now.
    send(&mut harness, None);
    assert_eq!(read(&mut harness), None);
    let confirm = Command::ChangePolicy(Change::Confirm {
        account,
        topic: "feedback".to_owned(),
        token: [3; 32],
    });
    assert!(changed_policy(&harness.one(confirm, START)));
    let mail = Mail {
        source: "app@sender.test".to_owned(),
        destination: vec!["a@example.com".to_owned()],
        headers: Bytes::from_static(b"Subject: hello\r\n"),
        truncated: false,
        tags: vec![("campaign".to_owned(), "autumn".to_owned())],
    };
    let kept = send(&mut harness, Some(mail.clone()));
    let bare = send(&mut harness, None);
    let owed = read(&mut harness).expect("confirmed, it owes");
    assert_eq!(owed.entries.len(), 2, "what was sent once it confirmed");
    assert_eq!(
        owed.mailed.get(&kept),
        Some(&Mailed {
            accepted_at: START,
            mail: Some(mail),
        })
    );
    assert_eq!(
        owed.mailed.get(&bare),
        Some(&Mailed {
            accepted_at: START,
            mail: None,
        }),
        "no copy, and when it was accepted all the same"
    );
    // What was published as it was written stays owed once its
    // destination is disabled, and nothing written after it is.
    let disable = Command::ChangePolicy(Change::Destination {
        id: DestinationId(harness.ids.next(START)),
        account,
        configuration: "receipts".to_owned(),
        name: "receipts-feedback".to_owned(),
        topic: "feedback".to_owned(),
        events: BTreeSet::from([EventKind::Accepted]),
        enabled: false,
        replaces: true,
    });
    assert!(changed_policy(&harness.one(disable, START)));
    send(&mut harness, None);
    let owed = read(&mut harness).expect("it owes still");
    assert_eq!(owed.entries.len(), 2, "what was published, and no more");
}

#[test]
fn a_parked_batch_moves_its_cursor_on_and_lasts_until_its_replay_or_its_subscription() {
    let vfs = vfs("parked-events");
    let mut harness = Harness::open(&vfs);
    let account = Sender::first().account;
    let configuration = ConfigurationId(harness.ids.next(START));
    let subscription = SubscriptionId(harness.ids.next(START));
    let changes = vec![
        Command::ChangePolicy(Change::Configuration {
            id: configuration,
            account,
            name: "receipts".to_owned(),
            pool: None,
        }),
        Command::ChangePolicy(Change::Subscription {
            id: subscription,
            account,
            name: "hooks".to_owned(),
            configuration: "receipts".to_owned(),
            url: "https://hooks.example.test/in".to_owned(),
            events: BTreeSet::from([EventKind::Accepted]),
            secret: [1; 32],
        }),
    ];
    assert!(harness.run(changes, START).iter().all(changed_policy));
    for recipient in ["a@example.com", "b@example.com"] {
        let mut accept = harness.accept(&[recipient]);
        accept.authority.origin.configuration = Some(configuration);
        assert!(accepted(&harness.one(Command::Accept(accept), START)));
    }
    let read = |harness: &mut Harness<'_>, after, until| {
        let read = Command::Events {
            subscription,
            after,
            until,
            limit: 100,
        };
        match harness.one(read, START) {
            Answer::Events(Ok(Some(owed))) => owed,
            other => panic!("expected events, got {other:?}"),
        }
    };
    let owed = read(&mut harness, None, None);
    let (first, second) = (owed.entries[0].0, owed.entries[1].0);
    // Its feed has delivered nothing: both entries are its lag.
    assert_eq!(
        harness.store().event_lag().expect("readable"),
        Some(EventLag {
            entries: 2,
            since: Some(START),
        })
    );
    // A read bounded at the first event's position stops there.
    let bounded = read(&mut harness, Some(first - 1), Some(first));
    assert_eq!((bounded.entries.len(), bounded.through), (1, first));
    // The batch at its cursor failing: its first failure is kept with the
    // batch, and read from the cursor, so a restart does not start its
    // budget again; an acknowledgement short of the batch keeps it.
    let failing = |since| Command::EventsFailing {
        subscription,
        first,
        since,
    };
    for since in [START, later(1)] {
        assert!(matches!(
            harness.one(failing(since), later(1)),
            Answer::EventsFailing(Commit::Committed(()))
        ));
    }
    let stale = Command::Acknowledge {
        subscription,
        through: first - 1,
    };
    assert!(matches!(
        harness.one(stale, later(1)),
        Answer::Acknowledged(Commit::Committed(()))
    ));
    drop(harness);
    let mut harness = Harness::reopen(&vfs).0;
    assert_eq!(read(&mut harness, None, None).failing_since, Some(START));
    assert_eq!(
        read(&mut harness, Some(first - 1), None).failing_since,
        None
    );
    let parked = ParkedEvents {
        subscription,
        first,
        through: first,
        at: later(1),
        attempts: 7,
        failure: "answered 503".to_owned(),
    };
    // Counted once at the start, then only as they change.
    let counted = |harness: &Harness<'_>| harness.store().parked_batches().expect("countable");
    assert_eq!(counted(&harness), Some(0));
    assert_eq!(counted(&harness), None);
    assert!(matches!(
        harness.one(Command::ParkEvents(parked.clone()), later(1)),
        Answer::EventsParked(Commit::Committed(()))
    ));
    assert_eq!(counted(&harness), Some(1));
    assert_eq!(counted(&harness), None);
    // A late note of the batch's failure, once its cursor is past it,
    // changes nothing.
    assert!(matches!(
        harness.one(failing(later(1)), later(1)),
        Answer::EventsFailing(Commit::Committed(()))
    ));
    // Its cursor is past it, so the feed goes on with the next, with a
    // budget of its own.
    assert_eq!(
        harness.store().cursor(subscription).expect("readable"),
        Some(first)
    );
    let next = read(&mut harness, None, None);
    assert_eq!((next.entries[0].0, next.failing_since), (second, None));
    let listed = Command::ParkedEvents {
        account,
        subscription: "hooks".to_owned(),
        from: None,
        limit: 100,
    };
    let Answer::ParkedEvents(Ok(Some((found, batches)))) = harness.one(listed, later(1)) else {
        panic!("expected its parked batches");
    };
    assert_eq!((found, batches), (subscription, vec![parked.clone()]));
    // Read a page at a time: from a batch, or past the last.
    let page = |from| Command::ParkedEvents {
        account,
        subscription: "hooks".to_owned(),
        from: Some(from),
        limit: 1,
    };
    assert!(matches!(
        harness.one(page(first), later(1)),
        Answer::ParkedEvents(Ok(Some((_, batches)))) if batches == [parked.clone()]
    ));
    assert!(matches!(
        harness.one(page(first + 1), later(1)),
        Answer::ParkedEvents(Ok(Some((_, batches)))) if batches.is_empty()
    ));
    // A replay taken removes it; it is gone after.
    let unpark = || Command::UnparkEvents {
        subscription,
        first,
    };
    assert!(matches!(
        harness.one(unpark(), later(2)),
        Answer::EventsUnparked(Commit::Committed(()))
    ));
    assert_eq!(counted(&harness), Some(0));
    assert!(matches!(
        harness.one(unpark(), later(2)),
        Answer::EventsUnparked(Commit::Refused(Refusal::Gone))
    ));
    // A subscription removed takes its parked batches with it.
    assert!(matches!(
        harness.one(Command::ParkEvents(parked), later(3)),
        Answer::EventsParked(Commit::Committed(()))
    ));
    let removal = Command::ChangePolicy(Change::Remove(Target::Subscription {
        account,
        name: "hooks".to_owned(),
    }));
    assert!(changed_policy(&harness.one(removal, later(4))));
    let listed = Command::ParkedEvents {
        account,
        subscription: "hooks".to_owned(),
        from: None,
        limit: 100,
    };
    assert!(matches!(
        harness.one(listed, later(4)),
        Answer::ParkedEvents(Ok(None))
    ));
    // Made again under its old ID, it has none: they went with it.
    let again = Command::ChangePolicy(Change::Subscription {
        id: subscription,
        account,
        name: "hooks".to_owned(),
        configuration: "receipts".to_owned(),
        url: "https://hooks.example.test/in".to_owned(),
        events: BTreeSet::from([EventKind::Accepted]),
        secret: [1; 32],
    });
    assert!(changed_policy(&harness.one(again, later(5))));
    let listed = Command::ParkedEvents {
        account,
        subscription: "hooks".to_owned(),
        from: None,
        limit: 100,
    };
    assert!(matches!(
        harness.one(listed, later(5)),
        Answer::ParkedEvents(Ok(Some((_, batches)))) if batches.is_empty()
    ));
}

#[test]
fn a_subscription_is_owed_its_configurations_events_from_its_creation_on() {
    let vfs = vfs("subscription");
    let mut harness = Harness::open(&vfs);
    let account = Sender::first().account;
    let configuration = ConfigurationId(harness.ids.next(START));
    let subscription = SubscriptionId(harness.ids.next(START));
    let put = Command::ChangePolicy(Change::Configuration {
        id: configuration,
        account,
        name: "receipts".to_owned(),
        pool: None,
    });
    assert!(changed_policy(&harness.one(put, START)));
    let under = |harness: &mut Harness<'_>, recipients: &[&str]| {
        let mut accept = harness.accept(recipients);
        accept.authority.origin.configuration = Some(configuration);
        Command::Accept(accept)
    };
    // Mail committed before the subscription is not owed.
    let early = under(&mut harness, &["early@example.com"]);
    assert!(accepted(&harness.one(early, START)));
    let subscribe = Command::ChangePolicy(Change::Subscription {
        id: subscription,
        account,
        name: "hooks".to_owned(),
        configuration: "receipts".to_owned(),
        url: "https://hooks.example.test/in".to_owned(),
        events: BTreeSet::from([EventKind::Accepted, EventKind::Delivered]),
        secret: [1; 32],
    });
    assert!(changed_policy(&harness.one(subscribe, START)));
    // After it, its configuration's mail is owed, and no other.
    let owed = under(&mut harness, &["a@example.com", "b@example.com"]);
    let unowed = Command::Accept(harness.accept(&["c@example.com"]));
    let answers = harness.run(vec![owed, unowed], START);
    assert!(answers.iter().all(accepted));
    let events = |harness: &mut Harness<'_>, after| {
        let read = Command::Events {
            subscription,
            after,
            until: None,
            limit: 100,
        };
        match harness.one(read, START) {
            Answer::Events(Ok(owed)) => owed,
            other => panic!("expected events, got {other:?}"),
        }
    };
    let read = events(&mut harness, None).expect("subscribed");
    assert_eq!(read.entries.len(), 1);
    let (position, entry) = &read.entries[0];
    assert!(matches!(entry, Entry::Accepted { .. }));
    assert!(read.through > *position, "read past what it does not owe");
    let recipients: Vec<&str> = read
        .deliveries
        .values()
        .map(|(_, recipient)| recipient.as_str())
        .collect();
    assert_eq!(recipients, ["a@example.com", "b@example.com"]);
    assert_eq!(
        events(&mut harness, Some(*position))
            .expect("subscribed")
            .entries,
        Vec::new(),
        "read on from a position"
    );

    // Acknowledged, its cursor moves on, and never back, for good.
    for through in [read.through, 0] {
        let acknowledge = Command::Acknowledge {
            subscription,
            through,
        };
        assert!(matches!(
            harness.one(acknowledge, START),
            Answer::Acknowledged(Commit::Committed(()))
        ));
    }
    let empty = Owed {
        through: read.through,
        ..Owed::default()
    };
    assert_eq!(events(&mut harness, None), Some(empty));
    drop(harness);
    let mut harness = Harness::open(&vfs);
    assert_eq!(
        harness.store().cursor(subscription).expect("readable"),
        Some(read.through)
    );

    // Removed, it is owed nothing and acknowledges nothing.
    let remove = Command::ChangePolicy(Change::Remove(Target::Subscription {
        account,
        name: "hooks".to_owned(),
    }));
    assert!(changed_policy(&harness.one(remove, START)));
    assert_eq!(events(&mut harness, None), None);
    let acknowledge = Command::Acknowledge {
        subscription,
        through: read.through,
    };
    assert!(matches!(
        harness.one(acknowledge, START),
        Answer::Acknowledged(Commit::Refused(Refusal::Gone))
    ));
    assert_eq!(
        harness.store().cursor(subscription).expect("readable"),
        None
    );
}

#[test]
fn a_reservation_from_a_capped_egress_counts_in_its_window_and_the_delivery_keeps_its_egress() {
    let vfs = vfs("dispatched");
    let mut harness = Harness::open(&vfs);
    let account = Sender::first().account;
    let (capped, open) = (
        EgressId(harness.ids.next(START)),
        EgressId(harness.ids.next(START)),
    );
    for (id, address, daily_cap) in [
        (capped, "203.0.113.1", Some(500)),
        (open, "203.0.113.2", None),
    ] {
        let put = Command::ChangePolicy(Change::Egress {
            id,
            account,
            address: address.parse().unwrap(),
            helo: "mta.bench.test".to_owned(),
            pool: None,
            daily_cap,
        });
        assert!(changed_policy(&harness.one(put, START)));
    }
    let accept = harness.accept(&["a@example.com", "b@example.com"]);
    let deliveries: Vec<DeliveryId> = accept.messages[0]
        .recipients
        .iter()
        .map(|recipient| recipient.delivery)
        .collect();
    assert!(accepted(&harness.one(Command::Accept(accept), START)));
    let site: Arc<str> = Arc::from("mx.example.com");
    let reserve = |harness: &mut Harness<'_>, delivery, egress| {
        let delivery = harness.delivery(delivery);
        Command::Reserve(Reserve {
            delivery: delivery.id(),
            seen: delivery.generation(),
            attempt: AttemptId(harness.ids.next(later(1))),
            egress: Some(egress),
            site: Some(Arc::clone(&site)),
            now: later(1),
        })
    };
    let commands = vec![
        reserve(&mut harness, deliveries[0], capped),
        reserve(&mut harness, deliveries[1], open),
    ];
    for answer in harness.run(commands, later(1)) {
        assert!(matches!(
            answer,
            Answer::Reserved(Commit::Committed(Reservation::Permit(_)))
        ));
    }
    assert_eq!(harness.delivery(deliveries[0]).egress(), Some(capped));
    assert_eq!(harness.delivery(deliveries[1]).egress(), Some(open));

    // Only the capped egress is counted, and its window is durable.
    drop(harness);
    let harness = Harness::open(&vfs);
    let windows = harness.store().dispatched();
    assert_eq!(windows.len(), 1);
    let (egress, counted_site, window) = &windows[0];
    assert_eq!((*egress, &**counted_site), (capped, "mx.example.com"));
    assert_eq!(window.total(later(2)), 1);
}

#[test]
fn warmup_counts_what_receivers_said_at_a_capped_egress_and_a_complaint_where_it_was_delivered() {
    let vfs = vfs("evidence");
    let mut harness = Harness::open(&vfs);
    let account = Sender::first().account;
    let (capped, open) = (
        EgressId(harness.ids.next(START)),
        EgressId(harness.ids.next(START)),
    );
    for (id, address, daily_cap) in [
        (capped, "203.0.113.1", Some(500)),
        (open, "203.0.113.2", None),
    ] {
        let put = Command::ChangePolicy(Change::Egress {
            id,
            account,
            address: address.parse().unwrap(),
            helo: "mta.bench.test".to_owned(),
            pool: None,
            daily_cap,
        });
        assert!(changed_policy(&harness.one(put, START)));
    }
    let recipients = ["a@example.com", "b@example.com", "c@example.com"];
    let accept = harness.accept(&recipients);
    let message = accept.messages[0].id;
    let deliveries: Vec<DeliveryId> = accept.messages[0]
        .recipients
        .iter()
        .map(|recipient| recipient.delivery)
        .collect();
    assert!(accepted(&harness.one(Command::Accept(accept), START)));
    let site: Arc<str> = Arc::from("mx.example.com");
    let finish = |harness: &mut Harness<'_>, delivery, egress, disposition, signal| {
        let delivery = harness.delivery(delivery);
        let reserve = Command::Reserve(Reserve {
            delivery: delivery.id(),
            seen: delivery.generation(),
            attempt: AttemptId(harness.ids.next(later(1))),
            egress: Some(egress),
            site: Some(Arc::clone(&site)),
            now: later(1),
        });
        let permit = committed_permit(harness.one(reserve, later(1)));
        let Command::RecordOutcome(outcome) = outcome(permit, disposition, later(2)) else {
            unreachable!()
        };
        let counted = Command::RecordOutcome(RecordOutcome {
            counted: Some(Counted {
                site: Arc::clone(&site),
                signal,
                at: later(2),
            }),
            ..outcome
        });
        assert!(matches!(
            harness.one(counted, later(2)),
            Answer::Recorded(Commit::Committed(()))
        ));
    };
    let deferred = Disposition::Deferred {
        not_before: later(60),
    };
    finish(
        &mut harness,
        deliveries[0],
        capped,
        Disposition::Delivered,
        Signal::Delivered,
    );
    finish(
        &mut harness,
        deliveries[1],
        capped,
        deferred,
        Signal::Deferred,
    );
    // Nothing is counted at an egress with no cap.
    finish(
        &mut harness,
        deliveries[2],
        open,
        Disposition::Delivered,
        Signal::Delivered,
    );
    // A complaint about the delivered recipient counts at the site it was
    // delivered at; the mailbox simulator's counts nothing.
    let mut simulated = report(
        &mut harness,
        Some(message),
        Kind::Feedback("abuse".to_owned()),
        &[("a@example.com", false, "")],
        8,
    );
    simulated.simulated = true;
    let complaint = report(
        &mut harness,
        Some(message),
        Kind::Feedback("abuse".to_owned()),
        &[("a@example.com", false, ""), ("c@example.com", false, "")],
        9,
    );
    let complaint = Report {
        authenticated: true,
        ..complaint
    };
    for report in [simulated, complaint] {
        let recorded = harness.one(Command::RecordFeedback(report), later(10));
        assert!(
            matches!(recorded, Answer::Feedback(Commit::Committed(_))),
            "{recorded:?}"
        );
    }

    // Kept across a restart, by UTC day.
    drop(harness);
    let mut harness = Harness::open(&vfs);
    let day = budget::day(later(10));
    let Answer::Evidence(Ok(evidence)) = harness.one(Command::Evidence { day }, later(11)) else {
        panic!("evidence is read");
    };
    assert_eq!(evidence.unrecorded, 0);
    let evidence = evidence.counts;
    assert_eq!(
        evidence,
        vec![(
            capped,
            Arc::clone(&site),
            Counts {
                delivered: 1,
                deferred: 1,
                complained: 1,
                ..Counts::default()
            }
        )]
    );
    let Answer::Evidence(Ok(before)) = harness.one(Command::Evidence { day: day - 1 }, later(11))
    else {
        panic!("evidence is read");
    };
    assert!(before.counts.is_empty(), "nothing the day before");

    // A judgment holds only on the evidence it read: one more complaint of
    // the day, counted before it is asked, and it is refused, then made
    // again on what the day holds now.
    let caps = harness
        .store()
        .policy()
        .egress(capped)
        .unwrap()
        .caps
        .clone();
    let capping = |evidence: &[(EgressId, Arc<str>, Counts)]| {
        let counts = evidence
            .first()
            .map(|(_, _, counts)| *counts)
            .unwrap_or_default();
        Command::ChangePolicy(Change::Caps(vec![Capping {
            egress: capped,
            from: caps.clone(),
            to: Caps {
                warmed: Some(Warmed {
                    day,
                    pool: Judgment {
                        counts,
                        verdict: Verdict::Untested,
                    },
                    sites: BTreeMap::new(),
                }),
                ..caps.clone()
            },
            evidence: evidence
                .iter()
                .map(|(_, site, counts)| (Arc::clone(site), *counts))
                .collect(),
        }]))
    };
    let stale = capping(&evidence);
    let again = report(
        &mut harness,
        Some(message),
        Kind::Feedback("abuse".to_owned()),
        &[("a@example.com", false, "")],
        10,
    );
    let again = Report {
        authenticated: true,
        ..again
    };
    let recorded = harness.one(Command::RecordFeedback(again), later(10));
    assert!(
        matches!(recorded, Answer::Feedback(Commit::Committed(_))),
        "{recorded:?}"
    );
    assert!(matches!(
        harness.one(stale, later(11)),
        Answer::Policy(Commit::Refused(PolicyRefusal::Outdated))
    ));
    let Answer::Evidence(Ok(now)) = harness.one(Command::Evidence { day }, later(11)) else {
        panic!("evidence is read");
    };
    assert_eq!(now.counts[0].2.complained, 2);

    // An attempt from the capped egress reserved on the day, its outcome not
    // yet recorded, says the day's evidence is not all in.
    let accept = harness.accept(&["d@example.com"]);
    let late = accept.messages[0].recipients[0].delivery;
    assert!(accepted(&harness.one(Command::Accept(accept), later(11))));
    let delivery = harness.delivery(late);
    let reserve = Command::Reserve(Reserve {
        delivery: late,
        seen: delivery.generation(),
        attempt: AttemptId(harness.ids.next(later(11))),
        egress: Some(capped),
        site: Some(Arc::clone(&site)),
        now: later(11),
    });
    let permit = committed_permit(harness.one(reserve, later(11)));
    let Answer::Evidence(Ok(waiting)) = harness.one(Command::Evidence { day }, later(11)) else {
        panic!("evidence is read");
    };
    assert_eq!(waiting.unrecorded, 1);
    let Command::RecordOutcome(recorded) = outcome(permit, Disposition::Delivered, later(12))
    else {
        unreachable!()
    };
    assert!(matches!(
        harness.one(Command::RecordOutcome(recorded), later(12)),
        Answer::Recorded(Commit::Committed(()))
    ));
    let Answer::Evidence(Ok(settled)) = harness.one(Command::Evidence { day }, later(12)) else {
        panic!("evidence is read");
    };
    assert_eq!(settled.unrecorded, 0);
    assert!(changed_policy(
        &harness.one(capping(&settled.counts), later(12))
    ));
}

#[test]
fn an_attempt_goes_out_only_from_a_source_current_policy_gives_its_mail() {
    let vfs = vfs("sourced");
    let mut harness = Harness::open(&vfs);
    let account = Sender::first().account;
    let egress = EgressId(harness.ids.next(START));
    let put = |pool: Option<&str>| {
        Command::ChangePolicy(Change::Egress {
            id: egress,
            account,
            address: "203.0.113.1".parse().unwrap(),
            helo: "mta.bench.test".to_owned(),
            pool: pool.map(str::to_owned),
            daily_cap: None,
        })
    };
    assert!(changed_policy(&harness.one(put(None), START)));
    let accept = harness.accept(&["a@example.com", "b@example.com", "c@example.com"]);
    let deliveries: Vec<DeliveryId> = accept.messages[0]
        .recipients
        .iter()
        .map(|recipient| recipient.delivery)
        .collect();
    assert!(accepted(&harness.one(Command::Accept(accept), START)));
    let reserve = |harness: &mut Harness<'_>, delivery, egress, site: Option<&str>| {
        let delivery = harness.delivery(delivery);
        let command = Command::Reserve(Reserve {
            delivery: delivery.id(),
            seen: delivery.generation(),
            attempt: AttemptId(harness.ids.next(later(1))),
            egress,
            site: site.map(Arc::from),
            now: later(1),
        });
        harness.one(command, later(1))
    };
    let permitted = |answer: &Answer| {
        matches!(
            answer,
            Answer::Reserved(Commit::Committed(Reservation::Permit(_)))
        )
    };
    let unsourced = |answer: &Answer| {
        matches!(
            answer,
            Answer::Reserved(Commit::Refused(Refusal::Unsourced))
        )
    };
    let site = Some("mx.example.com");
    // Mail under no pool goes out from the egresses in none, not the host.
    assert!(permitted(&reserve(
        &mut harness,
        deliveries[0],
        Some(egress),
        site
    )));
    assert!(unsourced(&reserve(&mut harness, deliveries[1], None, site)));

    // The egress joins a pool: the mail under none is the host's again.
    let pool = Command::ChangePolicy(Change::Pool {
        id: PoolId(harness.ids.next(START)),
        account,
        name: "warm".to_owned(),
    });
    let answers = harness.run(vec![pool, put(Some("warm"))], START);
    assert!(answers.iter().all(changed_policy));
    assert!(unsourced(&reserve(
        &mut harness,
        deliveries[1],
        Some(egress),
        site
    )));
    assert!(permitted(&reserve(&mut harness, deliveries[1], None, site)));
    // A settlement, which sends nothing, keeps the egress its delivery has.
    assert!(permitted(&reserve(
        &mut harness,
        deliveries[2],
        Some(egress),
        None
    )));
}

/// A store that keeps finished mail for a minute.
fn trimming(vfs: &SimVfs) -> Harness<'_> {
    let options = StoreOptions {
        feedback_window: Duration::from_secs(60),
        ..StoreOptions::default()
    };
    Harness::reopen_with(vfs, options).0
}

fn positions(harness: &Harness<'_>) -> Vec<u64> {
    harness
        .store()
        .entries(0, usize::MAX)
        .expect("readable")
        .into_iter()
        .map(|(position, _)| position)
        .collect()
}

#[test]
fn what_finished_before_the_feedback_window_is_trimmed_and_nothing_else() {
    let vfs = vfs("trim");
    let mut harness = trimming(&vfs);
    let first = harness.accept(&["a1@example.com", "a2@example.com"]);
    let second = harness.accept(&["b1@example.com"]);
    let (waiting_message, finished_message) = (first.messages[0].id, second.messages[0].id);
    let [a1, a2] = [0, 1].map(|n| first.messages[0].recipients[n].delivery);
    let b1 = second.messages[0].recipients[0].delivery;
    let answers = harness.run(vec![Command::Accept(first), Command::Accept(second)], START);
    assert!(answers.iter().all(accepted));
    for (delivery, at) in [(a1, 1), (b1, 2)] {
        let permit = harness.reserved(&harness.delivery(delivery), later(at));
        harness.one(
            outcome(permit, Disposition::Delivered, later(at)),
            later(at),
        );
    }
    let journal = positions(&harness);
    assert_eq!(journal.len(), 4, "two acceptances and two attempts");

    // Within the window, everything stays.
    harness.run(Vec::new(), later(50));
    assert_eq!(positions(&harness), journal);
    assert!(harness.store().delivery(a1).expect("readable").is_some());

    // Past it, what finished goes, with the journal's entries from then:
    // all but the newest, which stays so positions carry on.
    harness.run(Vec::new(), later(70));
    for gone in [a1, b1] {
        assert_eq!(harness.store().delivery(gone).expect("readable"), None);
    }
    assert_eq!(
        harness.store().message(finished_message).expect("readable"),
        None
    );
    assert_eq!(positions(&harness), [journal[3]]);
    // A delivery that still waits keeps itself and its message.
    assert!(harness.store().delivery(a2).expect("readable").is_some());
    assert!(
        harness
            .store()
            .message(waiting_message)
            .expect("readable")
            .is_some()
    );

    let accept = harness.accept(&["c@example.com"]);
    assert!(accepted(&harness.one(Command::Accept(accept), later(71))));
    let after = positions(&harness);
    assert!(
        after.last() > Some(&journal[3]),
        "positions never start again"
    );
    harness.store().verify().expect("intact");
}

#[test]
fn a_subscription_behind_the_window_skips_what_is_trimmed_and_counts_it() {
    let vfs = vfs("trim-cursor");
    let mut harness = trimming(&vfs);
    let account = Sender::first().account;
    let configuration = ConfigurationId(harness.ids.next(START));
    let [lagging, current] = [0, 1].map(|_| SubscriptionId(harness.ids.next(START)));
    let mut changes = vec![Command::ChangePolicy(Change::Configuration {
        id: configuration,
        account,
        name: "receipts".to_owned(),
        pool: None,
    })];
    for (id, name) in [(lagging, "lagging"), (current, "current")] {
        changes.push(Command::ChangePolicy(Change::Subscription {
            id,
            account,
            name: name.to_owned(),
            configuration: "receipts".to_owned(),
            url: "https://hooks.example.test/in".to_owned(),
            events: BTreeSet::from([EventKind::Accepted]),
            secret: [1; 32],
        }));
    }
    assert!(harness.run(changes, START).iter().all(changed_policy));
    let under = |harness: &mut Harness<'_>, recipient: &str| {
        let mut accept = harness.accept(&[recipient]);
        accept.authority.origin.configuration = Some(configuration);
        Command::Accept(accept)
    };
    let early: Vec<Command> = ["a@example.com", "b@example.com", "c@example.com"]
        .into_iter()
        .map(|recipient| under(&mut harness, recipient))
        .collect();
    assert!(harness.run(early, START).iter().all(accepted));
    let journal = positions(&harness);
    let acknowledge = Command::Acknowledge {
        subscription: current,
        through: journal[2],
    };
    assert!(matches!(
        harness.one(acknowledge, later(1)),
        Answer::Acknowledged(Commit::Committed(()))
    ));
    // The current one parked its first batch; the trim takes it with the
    // entries it names.
    let parked = ParkedEvents {
        subscription: current,
        first: journal[0],
        through: journal[0],
        at: later(1),
        attempts: 3,
        failure: "answered 503".to_owned(),
    };
    assert!(matches!(
        harness.one(Command::ParkEvents(parked), later(1)),
        Answer::EventsParked(Commit::Committed(()))
    ));
    // The lagging one's first batch is failing.
    let failing = |first, since| Command::EventsFailing {
        subscription: lagging,
        first,
        since,
    };
    assert!(matches!(
        harness.one(failing(journal[0], later(1)), later(1)),
        Answer::EventsFailing(Commit::Committed(()))
    ));

    // A minute on, the early entries are trimmed as the next commits.
    let late = under(&mut harness, "d@example.com");
    assert!(accepted(&harness.one(late, later(65))));
    let remaining = positions(&harness);
    assert_eq!(remaining.len(), 1, "only the late entry is left");
    let store = harness.store();
    assert_eq!(
        store.cursor(lagging).expect("readable"),
        Some(journal[2]),
        "moved past what was trimmed"
    );
    assert_eq!(store.skipped(lagging).expect("readable"), Some(3));
    assert_eq!(store.cursor(current).expect("readable"), Some(journal[2]));
    assert_eq!(
        store.skipped(current).expect("readable"),
        Some(0),
        "it was given everything"
    );
    let owed = store
        .owed(lagging, None, None, 100)
        .expect("readable")
        .expect("subscribed");
    assert_eq!(
        owed.entries
            .iter()
            .map(|(position, _)| *position)
            .collect::<Vec<_>>(),
        remaining,
        "it is still owed what remains"
    );
    let listed = || Command::ParkedEvents {
        account,
        subscription: "current".to_owned(),
        from: None,
        limit: 100,
    };
    assert!(matches!(
        harness.one(listed(), later(66)),
        Answer::ParkedEvents(Ok(Some((_, batches)))) if batches.is_empty()
    ));
    // The failing batch the trim took no longer runs on its time: the next
    // batch's failure is its own, and a late note of the old one's changes
    // nothing.
    let owed = |harness: &Harness<'_>| {
        harness
            .store()
            .owed(lagging, None, None, 100)
            .expect("readable")
            .expect("subscribed")
            .failing_since
    };
    assert_eq!(owed(&harness), None);
    for (first, since) in [(remaining[0], later(66)), (journal[0], later(67))] {
        assert!(matches!(
            harness.one(failing(first, since), later(67)),
            Answer::EventsFailing(Commit::Committed(()))
        ));
    }
    assert_eq!(owed(&harness), Some(later(66)));
    // A parked batch whose entries were already gone, as a store from
    // before kept one, goes at an idle trim, which commits for it alone.
    drop(harness);
    {
        let connection = vfs.open(DATABASE).expect("opens");
        connection
            .execute_batch("PRAGMA locking_mode = EXCLUSIVE")
            .expect("locked");
        connection
            .execute(
                "INSERT INTO parked_events VALUES (?1, 1, 1, 0, 1, 'answered 503')",
                [i64::try_from(current.0.as_u64()).expect("an ID")],
            )
            .expect("writable");
    }
    let mut harness = trimming(&vfs);
    let at = now(later(200));
    let mut responses = Vec::new();
    for _ in 0..5 {
        harness.owner.poll(at, &mut responses);
    }
    drop(harness);
    let mut harness = trimming(&vfs);
    assert!(matches!(
        harness.one(listed(), later(201)),
        Answer::ParkedEvents(Ok(Some((_, batches)))) if batches.is_empty()
    ));
}

/// A report naming `claims`, each an address, whether delivery to it
/// failed, and its status, judged by the shipped receiver rules as the
/// intake judges them.
fn report(
    harness: &mut Harness<'_>,
    message: Option<MessageId>,
    kind: Kind,
    claims: &[(&str, bool, &str)],
    identity: u8,
) -> Report {
    let rules = Rules::new(&BTreeMap::new()).unwrap();
    Report {
        id: ReportId(harness.ids.next(later(10))),
        message,
        kind,
        recipients: claims
            .iter()
            .map(|&(address, failed, status)| Claim {
                address: Address::parse(address).unwrap(),
                failed,
                status: Status::parse(status),
                rules_out_address: failed
                    && Status::parse(status).is_some_and(|status| rules.rules_out_address(status)),
                diagnostic: None,
            })
            .collect(),
        identity: [identity; 32],
        evidence: Bytes::from_static(b"Subject: report\r\n\r\n"),
        received_at: later(10),
        authenticated: false,
        trusted: true,
        simulated: false,
    }
}

fn recorded(answer: Answer) -> FeedbackRecorded {
    match answer {
        Answer::Feedback(Commit::Committed(recorded)) => recorded,
        other => panic!("expected the report recorded, got {other:?}"),
    }
}

#[test]
fn with_encryption_on_nothing_personal_is_kept_in_the_clear_and_all_of_it_reads_back() {
    let vfs = vfs("sealed");
    let options = |encryption| StoreOptions {
        encryption,
        ..StoreOptions::default()
    };
    let account = Sender::first().account;
    let early = Address::parse("Early.Bird@example.com").unwrap();
    // Suppressed while encryption is off, its key is its address.
    let mut harness = Harness::reopen_with(&vfs, options(Encryption::Off)).0;
    let suppress = |address: &Address| {
        Command::Suppress(Suppress {
            account,
            addresses: vec![address.clone()],
            reason: Reason::Operator,
            now: START,
        })
    };
    assert!(matches!(
        harness.one(suppress(&early), START),
        Answer::Suppressions(Commit::Committed(1))
    ));
    drop(harness);

    // On: the list is rewritten under the index key, and everything new is
    // sealed.
    let mut harness = Harness::reopen_with(&vfs, options(Encryption::Installation)).0;
    assert!(harness.store().is_suppressed(account, &early).unwrap());
    let accept = harness.accept(&["secret.person@example.com"]);
    let message = accept.messages[0].id;
    let delivery = accept.messages[0].recipients[0].delivery;
    assert!(accepted(&harness.one(Command::Accept(accept), START)));
    let permit = harness.reserved(&harness.delivery(delivery), later(1));
    let deferred = Command::RecordOutcome(RecordOutcome {
        permit,
        disposition: Disposition::Deferred {
            not_before: later(60),
        },
        evidence: Some(Evidence::new(
            450,
            "4.2.1 secret.person@example.com is busy",
        )),
        suppress: false,
        cooled: None,
        feedback: None,
        counted: None,
        now: later(2),
    });
    assert!(matches!(
        harness.one(deferred, later(2)),
        Answer::Recorded(Commit::Committed(()))
    ));
    let bounce = report(
        &mut harness,
        Some(message),
        Kind::DeliveryStatus,
        &[("secret.person@example.com", true, "5.1.1")],
        4,
    );
    recorded(harness.one(Command::RecordFeedback(bounce.clone()), later(10)));
    let secret = Address::parse("secret.person@example.com").unwrap();
    assert!(harness.store().is_suppressed(account, &secret).unwrap());
    drop(harness);
    let in_the_clear = |needle: &[u8]| {
        vfs.disk()
            .borrow()
            .files()
            .any(|(_, bytes)| bytes.windows(needle.len()).any(|window| window == needle))
    };
    for personal in [&b"secret.person"[..], b"Early.Bird", b"early.bird"] {
        assert!(
            !in_the_clear(personal),
            "{} is kept in the clear",
            String::from_utf8_lossy(personal)
        );
    }

    // Every part of it reads back, and with encryption off again the list
    // is rewritten as addresses and what was sealed still opens.
    let harness = Harness::reopen_with(&vfs, options(Encryption::Installation)).0;
    assert_eq!(harness.delivery(delivery).recipient(), &secret);
    assert_eq!(
        harness.store().report(bounce.id).unwrap(),
        Some(bounce.clone())
    );
    drop(harness);
    let harness = Harness::reopen_with(&vfs, options(Encryption::Off)).0;
    assert!(harness.store().is_suppressed(account, &early).unwrap());
    assert!(harness.store().is_suppressed(account, &secret).unwrap());
    assert_eq!(harness.delivery(delivery).recipient(), &secret);
    let entries = harness.store().entries(0, usize::MAX).unwrap();
    assert!(entries.iter().any(|(_, entry)| matches!(
        entry,
        Entry::Attempted { evidence: Some(evidence), .. }
            if evidence.text.contains("secret.person@example.com")
    )));
}

#[test]
fn a_full_disk_stops_the_store_losing_nothing_it_acknowledged_and_it_starts_again_with_room() {
    let vfs = vfs("full");
    let mut harness = Harness::open(&vfs);
    // Little room left: the reserve is advisory, so the store can fill it.
    let used = vfs.disk().borrow().used();
    vfs.disk().borrow_mut().set_capacity(Some(used + 64 * 1024));
    let (mut committed, mut unknown, mut refused) = (Vec::new(), Vec::new(), 0);
    for _ in 0..200 {
        let accept = harness.accept(&["a@example.com"]);
        let message = accept.messages[0].id;
        match harness.one(Command::Accept(accept), START) {
            Answer::Accepted(Commit::Committed(())) => committed.push(message),
            Answer::Accepted(Commit::Unknown) => unknown.push(message),
            Answer::Accepted(Commit::Unavailable) => refused += 1,
            other => panic!("an acceptance answered {other:?}"),
        }
    }
    assert!(!committed.is_empty(), "some fit");
    assert!(refused > 0, "the store stopped once the disk was full");
    assert!(
        unknown.len() <= 1,
        "only the commit that failed is in doubt"
    );
    drop(harness);
    // With room again, it starts, sound, holding everything it acknowledged.
    vfs.disk().borrow_mut().set_capacity(None);
    let mut harness = Harness::open(&vfs);
    for message in &committed {
        assert!(harness.store().message(*message).unwrap().is_some());
    }
    let accept = harness.accept(&["b@example.com"]);
    assert!(accepted(&harness.one(Command::Accept(accept), later(1))));
}

#[test]
fn a_tenants_mail_is_sealed_under_its_own_key_and_reads_as_erased_once_it_is_gone() {
    let vfs = vfs("tenant-sealed");
    let options = StoreOptions {
        encryption: Encryption::Tenant,
        ..StoreOptions::default()
    };
    let mut harness = Harness::reopen_with(&vfs, options).0;
    let sender = Sender::first();
    let tenant = TenantId(harness.ids.next(START));
    let put = |id| {
        Command::ChangePolicy(Change::Tenant {
            id,
            account: sender.account,
            name: "acme".to_owned(),
            identities: vec![engine_sim::sender::DOMAIN.to_owned()],
            configurations: Vec::new(),
            limits: Limits::default(),
        })
    };
    // Created without its key, it would keep none of its mail: refused.
    assert!(matches!(
        harness.one(put(tenant), START),
        Answer::Policy(Commit::Refused(PolicyRefusal::Outdated))
    ));
    let key = engine_core::command::DataKey([7; 32]);
    let keyed = Command::TenantKey {
        tenant,
        key: key.clone(),
    };
    assert!(matches!(harness.one(keyed, START), Answer::Keyed(Ok(()))));
    assert!(changed_policy(&harness.one(put(tenant), START)));
    // A put of its name under an ID with no key changes it, creating none.
    let unkeyed = TenantId(harness.ids.next(START));
    assert!(changed_policy(&harness.one(put(unkeyed), START)));
    assert_eq!(
        harness
            .store()
            .policy()
            .tenant_named(sender.account, "acme"),
        Some(tenant)
    );
    // One message under the tenant, one under none.
    let revision = harness.store().policy().revision();
    let mut theirs = harness.accept_under(revision, &["tenant.secret@example.com"]);
    theirs.authority.origin.tenant = Some(tenant);
    let tenants = theirs.messages[0].recipients[0].delivery;
    let their_message = theirs.messages[0].id;
    let ours = harness.accept(&["plain.secret@example.com"]);
    let plain = ours.messages[0].recipients[0].delivery;
    // A sealed body moved into another's row: its envelope names the row it
    // was sealed for.
    let mut moved = harness.accept(&["moved@example.com"]);
    let keys = Keys::new(Arc::new(Keyring::new(&[(1, [9; 32])]).unwrap()));
    let elsewhere = BodyId(harness.ids.next(START));
    moved.messages[0].content = Bytes::from(seal_body(&keys, None, elsewhere.0.as_u64(), b"x"));
    let moved_message = moved.messages[0].id;
    for accept in [theirs, ours, moved] {
        assert!(accepted(&harness.one(Command::Accept(accept), START)));
    }
    assert!(
        harness.store().content(moved_message).is_err(),
        "a body opens in its own row alone"
    );
    // A report about the tenant's message whose claim matches none of its
    // recipients is still the tenant's.
    let unmatched = report(
        &mut harness,
        Some(their_message),
        Kind::DeliveryStatus,
        &[("someone.else@example.com", true, "5.1.1")],
        5,
    );
    recorded(harness.one(Command::RecordFeedback(unmatched.clone()), later(2)));
    let permit = harness.reserved(&harness.delivery(tenants), later(1));
    let deferred = Command::RecordOutcome(RecordOutcome {
        permit,
        disposition: Disposition::Deferred {
            not_before: later(60),
        },
        evidence: Some(Evidence::new(
            450,
            "4.2.1 tenant.secret@example.com is busy",
        )),
        suppress: false,
        cooled: None,
        feedback: None,
        counted: None,
        now: later(2),
    });
    assert!(matches!(
        harness.one(deferred, later(2)),
        Answer::Recorded(Commit::Committed(()))
    ));
    let in_the_clear = |needle: &[u8]| {
        vfs.disk()
            .borrow()
            .files()
            .any(|(_, bytes)| bytes.windows(needle.len()).any(|window| window == needle))
    };
    assert!(!in_the_clear(b"tenant.secret"));
    assert!(!in_the_clear(b"plain.secret"));
    // Its key forgotten, its mail reads as erased, and the rest as it was.
    let forget = Command::ForgetTenantKey(tenant);
    assert!(matches!(
        harness.one(forget, later(3)),
        Answer::Keyed(Ok(()))
    ));
    let erased = Address::parse("erased@erased.invalid").unwrap();
    assert_eq!(harness.delivery(tenants).recipient(), &erased);
    let address = Address::parse("plain.secret@example.com").unwrap();
    assert_eq!(harness.delivery(plain).recipient(), &address);
    let entries = harness.store().entries(0, usize::MAX).unwrap();
    assert!(entries.iter().any(|(_, entry)| matches!(
        entry,
        Entry::Attempted { evidence: Some(evidence), .. } if evidence.text == "[erased]"
    )));
    let kept = harness.store().report(unmatched.id).unwrap().unwrap();
    assert_eq!(kept.recipients[0].address, erased);
    assert!(!in_the_clear(b"someone.else"));
    // Its erased recipient is nobody's to send to: due, it is cancelled.
    let due = harness.delivery(tenants);
    let reserve = harness.reserve(&due, later(61));
    assert!(matches!(
        harness.one(reserve, later(61)),
        Answer::Reserved(Commit::Committed(Reservation::Cancelled))
    ));
    // Opened again without it, the same. With it, what was sealed under it
    // reads; the delivery, cancelled while it was gone, kept nothing.
    drop(harness);
    let harness = Harness::reopen_with(&vfs, options).0;
    assert_eq!(harness.delivery(tenants).recipient(), &erased);
    drop(harness);
    let mut harness = Harness::reopen_with(&vfs, options).0;
    let keyed = Command::TenantKey { tenant, key };
    assert!(matches!(
        harness.one(keyed, later(62)),
        Answer::Keyed(Ok(()))
    ));
    let kept = harness.store().report(unmatched.id).unwrap().unwrap();
    assert_eq!(kept, unmatched);
    let entries = harness.store().entries(0, usize::MAX).unwrap();
    assert!(entries.iter().any(|(_, entry)| matches!(
        entry,
        Entry::Attempted { evidence: Some(evidence), .. }
            if evidence.text.contains("tenant.secret@example.com")
    )));
    assert_eq!(harness.delivery(tenants).recipient(), &erased);
}

#[test]
fn an_untrusted_report_is_its_events_alone_and_the_quarantine_keeps_its_bound() {
    let vfs = vfs("trust");
    let options = StoreOptions {
        quarantine: 2,
        ..StoreOptions::default()
    };
    let mut harness = Harness::reopen_with(&vfs, options).0;
    let account = Sender::first().account;
    let accept = harness.accept(&["a@example.com"]);
    let message = accept.messages[0].id;
    assert!(accepted(&harness.one(Command::Accept(accept), START)));
    // Below the class the operator trusts: its bounce is recorded, with the
    // marker, and suppresses and counts nothing.
    let untrusted = Report {
        trusted: false,
        ..report(
            &mut harness,
            Some(message),
            Kind::DeliveryStatus,
            &[("a@example.com", true, "5.1.1")],
            1,
        )
    };
    let bounced = recorded(harness.one(Command::RecordFeedback(untrusted.clone()), later(10)));
    assert_eq!(
        (
            bounced.deliveries,
            bounced.suppressed,
            bounced.effects.len()
        ),
        (1, 0, 0)
    );
    let address = Address::parse("a@example.com").unwrap();
    assert!(!harness.store().is_suppressed(account, &address).unwrap());
    let entries = harness.store().entries(0, usize::MAX).unwrap();
    assert!(matches!(
        entries.last(),
        Some((
            _,
            Entry::Bounced {
                authenticated: false,
                ..
            }
        ))
    ));
    assert_eq!(
        harness.store().report(untrusted.id).unwrap(),
        Some(untrusted.clone())
    );

    // The same report again, trusted now, as a copy its enrolled reporter
    // signed is: its effects apply once, with an event of their own, and
    // it is the copy kept. Once more, it does nothing.
    let trusted = Report {
        id: ReportId(harness.ids.next(later(10))),
        authenticated: true,
        trusted: true,
        ..untrusted.clone()
    };
    let applied = recorded(harness.one(Command::RecordFeedback(trusted.clone()), later(10)));
    assert_eq!(
        (
            applied.duplicate,
            applied.deliveries,
            applied.suppressed,
            applied.effects.len()
        ),
        (false, 1, 1, 1)
    );
    assert!(harness.store().is_suppressed(account, &address).unwrap());
    let entries = harness.store().entries(0, usize::MAX).unwrap();
    assert!(matches!(
        entries.last(),
        Some((_, Entry::Bounced { authenticated: true, report, .. })) if *report == untrusted.id
    ));
    let kept = harness.store().report(untrusted.id).unwrap().unwrap();
    assert!(
        kept.authenticated && kept.trusted,
        "the trusted copy is kept"
    );
    let again = Report {
        id: ReportId(harness.ids.next(later(10))),
        ..trusted
    };
    let resent = recorded(harness.one(Command::RecordFeedback(again), later(10)));
    assert!(resent.duplicate && resent.effects.is_empty());

    // A copy that said nothing that acts, then a trusted one of the same
    // report saying more: the trusted one acts, and is the copy kept.
    let accept = harness.accept(&["b@example.com"]);
    let other = accept.messages[0].id;
    assert!(accepted(&harness.one(Command::Accept(accept), later(10))));
    let delivered = Report {
        trusted: false,
        ..report(
            &mut harness,
            Some(other),
            Kind::DeliveryStatus,
            &[("b@example.com", false, "2.0.0")],
            2,
        )
    };
    let quiet = recorded(harness.one(Command::RecordFeedback(delivered.clone()), later(10)));
    assert_eq!(quiet.deliveries, 0);
    let failed = Report {
        id: ReportId(harness.ids.next(later(10))),
        authenticated: true,
        trusted: true,
        ..report(
            &mut harness,
            Some(other),
            Kind::DeliveryStatus,
            &[("b@example.com", true, "5.1.1")],
            2,
        )
    };
    let acted = recorded(harness.one(Command::RecordFeedback(failed), later(10)));
    assert_eq!((acted.deliveries, acted.suppressed), (1, 1));
    let kept = harness.store().report(delivered.id).unwrap().unwrap();
    assert!(kept.trusted && kept.recipients[0].failed, "{kept:?}");

    // Reports about none of the engine's deliveries are kept to the bound,
    // one naming no message or one whose token names a message but none of
    // its recipients alike; past it, one is answered and not kept. The
    // same report again is still the one kept.
    let mut uncorrelated = Vec::new();
    for identity in 10..13 {
        let report = match identity {
            11 => report(
                &mut harness,
                Some(message),
                Kind::DeliveryStatus,
                &[("stranger@example.com", true, "5.1.1")],
                identity,
            ),
            _ => report(&mut harness, None, Kind::Unrecognised, &[], identity),
        };
        let answer = recorded(harness.one(Command::RecordFeedback(report.clone()), later(11)));
        uncorrelated.push((report, answer));
    }
    assert!(!uncorrelated[0].1.unkept && !uncorrelated[1].1.unkept);
    assert!(uncorrelated[2].1.unkept, "past the bound");
    assert!(uncorrelated.iter().all(|(_, answer)| answer.unmatched));
    assert_eq!(harness.store().report(uncorrelated[2].0.id).unwrap(), None);
    let first = &uncorrelated[0].0;
    let again = Report {
        id: ReportId(harness.ids.next(later(12))),
        ..first.clone()
    };
    let resent = recorded(harness.one(Command::RecordFeedback(again), later(12)));
    assert!(resent.duplicate && !resent.unkept && !resent.unmatched);
}

#[test]
fn a_report_proves_only_what_its_message_and_recipients_support() {
    let vfs = vfs("feedback");
    let mut harness = Harness::open(&vfs);
    let account = Sender::first().account;
    let shared = harness.accept(&["a@example.com", "B@example.com"]);
    let single = harness.accept(&["c@example.com"]);
    let (shared_message, single_message) = (shared.messages[0].id, single.messages[0].id);
    let answers = harness.run(
        vec![Command::Accept(shared), Command::Accept(single)],
        START,
    );
    assert!(answers.iter().all(accepted));
    let suppressed = |harness: &Harness<'_>, address: &str| {
        harness
            .store()
            .is_suppressed(account, &Address::parse(address).unwrap())
            .unwrap()
    };
    let bounced = |harness: &Harness<'_>| {
        harness
            .store()
            .entries(0, usize::MAX)
            .unwrap()
            .into_iter()
            .filter(|(_, entry)| {
                matches!(
                    EventKind::of(entry),
                    EventKind::Bounced | EventKind::Complained
                )
            })
            .count()
    };

    // A bounce that rules the address out suppresses it; one for a full
    // mailbox is a bounce and no more. The case of an address is its own.
    let bounce = report(
        &mut harness,
        Some(shared_message),
        Kind::DeliveryStatus,
        &[
            ("a@example.com", true, "5.1.1"),
            ("b@example.com", true, "5.2.2"),
        ],
        1,
    );
    let bounce = Report {
        authenticated: true,
        ..bounce
    };
    let first = recorded(harness.one(Command::RecordFeedback(bounce.clone()), later(10)));
    assert_eq!(
        (first.duplicate, first.deliveries, first.suppressed),
        (false, 2, 1)
    );
    // Each effect for the counts: bounces, from the host's own address,
    // for no tenant.
    let host_bounce = Reported {
        complaint: false,
        egress: None,
        tenant: None,
    };
    assert_eq!(first.effects, [host_bounce, host_bounce]);
    assert!(suppressed(&harness, "a@example.com"));
    assert!(!suppressed(&harness, "b@example.com"));
    assert_eq!(bounced(&harness), 2);
    assert_eq!(
        harness.store().report(bounce.id).unwrap(),
        Some(bounce.clone())
    );

    // The same report again, under any ID, changes nothing.
    let again = Report {
        id: ReportId(harness.ids.next(later(11))),
        ..bounce
    };
    let second = recorded(harness.one(Command::RecordFeedback(again), later(11)));
    assert!(second.duplicate);
    assert!(
        second.effects.is_empty(),
        "an effect it had before is not counted again"
    );
    assert_eq!(bounced(&harness), 2);

    // A report about one message cannot reach another message's recipient.
    let forged = report(
        &mut harness,
        Some(shared_message),
        Kind::DeliveryStatus,
        &[("c@example.com", true, "5.1.1")],
        2,
    );
    let third = recorded(harness.one(Command::RecordFeedback(forged), later(12)));
    assert_eq!((third.deliveries, third.suppressed), (0, 0));
    assert!(!suppressed(&harness, "c@example.com"));

    // A complaint that names no recipient is about its message's only one.
    let complaint = report(
        &mut harness,
        Some(single_message),
        Kind::Feedback("abuse".to_owned()),
        &[],
        3,
    );
    let fourth = recorded(harness.one(Command::RecordFeedback(complaint), later(13)));
    assert_eq!((fourth.deliveries, fourth.suppressed), (1, 1));
    assert!(fourth.effects.iter().all(|effect| effect.complaint));
    assert!(suppressed(&harness, "c@example.com"));
    // But one about a message of several recipients proves nothing.
    let unnamed = report(
        &mut harness,
        Some(shared_message),
        Kind::Feedback("abuse".to_owned()),
        &[],
        4,
    );
    let fifth = recorded(harness.one(Command::RecordFeedback(unnamed), later(14)));
    assert_eq!((fifth.deliveries, fifth.suppressed), (0, 0));

    // A report naming no message the engine sent is kept, and no more.
    let uncorrelated = report(
        &mut harness,
        None,
        Kind::DeliveryStatus,
        &[("a@example.com", true, "5.1.1")],
        5,
    );
    let id = uncorrelated.id;
    let sixth = recorded(harness.one(Command::RecordFeedback(uncorrelated), later(15)));
    assert_eq!((sixth.duplicate, sixth.deliveries), (false, 0));
    assert!(harness.store().report(id).unwrap().is_some());
    assert_eq!(bounced(&harness), 3);
    harness.store().verify().expect("intact");
}

#[test]
fn an_entry_inside_the_window_stays_whatever_older_entries_follow_it() {
    let vfs = vfs("trim-order");
    let mut harness = trimming(&vfs);
    // Acceptances decided at 40, at the start, at the start and at 43, and
    // committed in that order: the journal's times run 40, 0, 0, 43.
    for (decided, committed) in [(40, 40), (0, 41), (0, 42), (43, 43)] {
        let mut accept = harness.accept(&["a@example.com"]);
        accept.accepted_at = later(decided);
        assert!(accepted(
            &harness.one(Command::Accept(accept), later(committed))
        ));
    }
    let journal = positions(&harness);
    assert_eq!(journal.len(), 4);

    // Ten seconds past the window, the entry at 40 is inside it, and the
    // older ones behind it wait for it.
    harness.run(Vec::new(), later(70));
    assert_eq!(positions(&harness), journal);
    // Once it is past, they go with it, and the newest stays.
    harness.run(Vec::new(), later(104));
    assert_eq!(positions(&harness), journal[3..]);
}

#[test]
fn a_message_keeps_the_latest_finish_of_its_deliveries() {
    let vfs = vfs("trim-finish");
    let mut harness = trimming(&vfs);
    let account = Sender::first().account;
    let accept = harness.accept(&["a@example.com", "b@example.com"]);
    let message = accept.messages[0].id;
    let [a, b] = [0, 1].map(|n| accept.messages[0].recipients[n].delivery);
    assert!(accepted(&harness.one(Command::Accept(accept), START)));
    let suppress = Command::Suppress(Suppress {
        account,
        addresses: vec![Address::parse("b@example.com").unwrap()],
        reason: Reason::Operator,
        now: START,
    });
    harness.one(suppress, START);
    // One delivery finishes at 101; the other, in a later group, at 99.
    let permit = harness.reserved(&harness.delivery(a), later(100));
    harness.one(
        outcome(permit, Disposition::Delivered, later(101)),
        later(101),
    );
    let reserve = harness.reserve(&harness.delivery(b), later(99));
    assert!(matches!(
        harness.one(reserve, later(102)),
        Answer::Reserved(Commit::Committed(Reservation::Suppressed))
    ));

    // A minute past 101, when the next trim is due: the delivery that
    // finished at 99 goes, and the message stays with the one that finished
    // at 101.
    harness.run(Vec::new(), later(161));
    assert_eq!(harness.store().delivery(b).unwrap(), None);
    assert!(harness.store().delivery(a).unwrap().is_some());
    assert!(harness.store().message(message).unwrap().is_some());
}

#[test]
fn a_wall_clock_that_steps_back_delays_the_trim_and_never_spins() {
    let vfs = vfs("trim-clock");
    let mut harness = trimming(&vfs);
    let mut responses = Vec::new();
    // The next trim is due a minute after the start, by the wall clock.
    let early = Now {
        wall: later(30),
        monotonic: Monotonic::from_micros(500_000_000),
    };
    let wake = harness.owner.poll(early, &mut responses);
    assert!(wake > Some(early.monotonic), "{wake:?}");
}

#[test]
fn a_trim_that_finds_nothing_due_settles_however_much_is_left_to_read() {
    let vfs = vfs("trim-settles");
    let mut harness = trimming(&vfs);
    // A batch of messages, each with one delivery that finished long ago
    // and one still waiting: the finished go, and nothing else may, so the
    // searches of deliveries and of messages go on reading, out of step,
    // and must not keep the store trimming.
    let accepts: Vec<Accept> = (0..1_000)
        .map(|n| harness.accept(&[&format!("a{n}@example.com"), &format!("b{n}@example.com")]))
        .collect();
    let finished: Vec<DeliveryId> = accepts
        .iter()
        .map(|accept| accept.messages[0].recipients[0].delivery)
        .collect();
    let commands = accepts.into_iter().map(Command::Accept).collect();
    assert!(harness.run(commands, START).iter().all(accepted));
    let reservations = finished
        .iter()
        .map(|&delivery| harness.reserve(&harness.delivery(delivery), later(1)))
        .collect();
    let permits: Vec<DispatchPermit> = harness
        .run(reservations, later(1))
        .into_iter()
        .map(committed_permit)
        .collect();
    let outcomes = permits
        .into_iter()
        .map(|permit| outcome(permit, Disposition::Delivered, later(1)))
        .collect();
    harness.run(outcomes, later(1));

    let at = now(later(120));
    let mut responses = Vec::new();
    let settled = (0..20).any(|_| harness.owner.poll(at, &mut responses) != Some(at.monotonic));
    assert!(settled, "the idle store went on trimming");
    assert_eq!(harness.store().delivery(finished[0]).unwrap(), None);
}

#[test]
fn an_inspection_finds_each_delivery_with_the_reply_that_deferred_it() {
    let vfs = vfs("inspect");
    let mut harness = Harness::open(&vfs);
    let accept = harness.accept(&["waits@example.com", "went@example.com"]);
    let message = accept.messages[0].id;
    let [waits, went] = [0, 1].map(|n| accept.messages[0].recipients[n].delivery);
    assert!(accepted(&harness.one(Command::Accept(accept), START)));
    let reply = Evidence {
        rules: "refused".to_owned(),
        ..Evidence::new(451, "4.7.1 try again later")
    };
    let permit = harness.reserved(&harness.delivery(waits), later(1));
    let deferral = Command::RecordOutcome(RecordOutcome {
        permit,
        disposition: Disposition::Deferred {
            not_before: later(60),
        },
        evidence: Some(reply.clone()),
        suppress: false,
        cooled: None,
        feedback: None,
        counted: None,
        now: later(2),
    });
    assert!(matches!(
        harness.one(deferral, later(2)),
        Answer::Recorded(Commit::Committed(()))
    ));
    let permit = harness.reserved(&harness.delivery(went), later(1));
    harness.one(outcome(permit, Disposition::Delivered, later(2)), later(2));

    let inspected = |harness: &mut Harness<'_>, inspect: Inspect| match harness
        .one(Command::Inspect(inspect), later(3))
    {
        Answer::Inspected(Ok(found)) => found
            .into_iter()
            .map(|inspected| (inspected.delivery.id(), inspected.reply))
            .collect::<Vec<_>>(),
        other => panic!("expected the deliveries, got {other:?}"),
    };
    assert_eq!(
        inspected(&mut harness, Inspect::Message(message)),
        [(waits, Some(reply.clone())), (went, None)]
    );
    // In flight again, it waits for nothing.
    let _permit = harness.reserved(&harness.delivery(waits), later(60));
    assert_eq!(
        inspected(&mut harness, Inspect::Delivery(waits)),
        [(waits, None)]
    );
}

#[test]
fn a_rejection_whose_verdict_rules_the_address_out_suppresses_it_with_its_outcome() {
    let vfs = vfs("in-session");
    let mut harness = Harness::open(&vfs);
    let account = Sender::first().account;
    let accept = harness.accept(&["gone@example.com", "spam@example.com", "later@example.com"]);
    let [gone, refused, deferred] = [0, 1, 2].map(|n| accept.messages[0].recipients[n].delivery);
    assert!(accepted(&harness.one(Command::Accept(accept), START)));
    // The verdicts came from the receiver rules; the store does as they say,
    // and suppresses only on a rejection.
    let deferral = Disposition::Deferred {
        not_before: later(60),
    };
    for (delivery, disposition, text, suppress) in [
        (gone, Disposition::Rejected, "5.1.1 no such user", true),
        (
            refused,
            Disposition::Rejected,
            "5.7.1 rejected as spam",
            false,
        ),
        (deferred, deferral, "4.1.1 try again", true),
    ] {
        let permit = harness.reserved(&harness.delivery(delivery), later(1));
        let command = Command::RecordOutcome(RecordOutcome {
            permit,
            disposition,
            evidence: Some(Evidence::new(550, text)),
            suppress,
            cooled: None,
            feedback: None,
            counted: None,
            now: later(2),
        });
        assert!(matches!(
            harness.one(command, later(2)),
            Answer::Recorded(Commit::Committed(()))
        ));
    }
    let suppressed = |address: &str| {
        harness
            .store()
            .is_suppressed(account, &Address::parse(address).unwrap())
            .unwrap()
    };
    assert!(suppressed("gone@example.com"));
    assert!(!suppressed("spam@example.com"), "a refusal of the content");
    assert!(!suppressed("later@example.com"), "not a rejection");
}

#[test]
fn the_same_report_again_has_only_the_effects_it_had_not_had() {
    let vfs = vfs("feedback-again");
    let mut harness = Harness::open(&vfs);
    let account = Sender::first().account;
    let accept = harness.accept(&["a@example.com", "b@example.com"]);
    let message = accept.messages[0].id;
    assert!(accepted(&harness.one(Command::Accept(accept), START)));
    let suppressed = |harness: &Harness<'_>, address: &str| {
        harness
            .store()
            .is_suppressed(account, &Address::parse(address).unwrap())
            .unwrap()
    };
    let first = report(
        &mut harness,
        Some(message),
        Kind::DeliveryStatus,
        &[("a@example.com", true, "5.2.2")],
        7,
    );
    let first = Report {
        authenticated: true,
        ..first
    };
    let recorded = |harness: &mut Harness<'_>, report: Report| match harness
        .one(Command::RecordFeedback(report), later(10))
    {
        Answer::Feedback(Commit::Committed(recorded)) => recorded,
        other => panic!("expected the report recorded, got {other:?}"),
    };
    let once = recorded(&mut harness, first.clone());
    assert_eq!(
        (once.duplicate, once.deliveries, once.suppressed),
        (false, 1, 0)
    );
    // The same report with a status revised has done what it does.
    let revised = Report {
        id: ReportId(harness.ids.next(later(11))),
        recipients: vec![Claim {
            status: Status::parse("5.1.1"),
            rules_out_address: true,
            ..first.recipients[0].clone()
        }],
        ..first.clone()
    };
    let again = recorded(&mut harness, revised);
    assert!(again.duplicate);
    assert!(
        !suppressed(&harness, "a@example.com"),
        "its first status stands"
    );
    // Naming one more recipient, it does that recipient's part alone.
    let more = Report {
        id: ReportId(harness.ids.next(later(12))),
        recipients: vec![
            first.recipients[0].clone(),
            Claim {
                address: Address::parse("b@example.com").unwrap(),
                failed: true,
                status: Status::parse("5.1.1"),
                rules_out_address: true,
                diagnostic: None,
            },
        ],
        ..first.clone()
    };
    let wider = recorded(&mut harness, more);
    assert_eq!(
        (wider.duplicate, wider.deliveries, wider.suppressed),
        (false, 1, 1)
    );
    assert!(suppressed(&harness, "b@example.com"));
    // What it did is recorded under the copy kept as its evidence.
    let reports: Vec<ReportId> = harness
        .store()
        .entries(0, usize::MAX)
        .unwrap()
        .into_iter()
        .filter_map(|(_, entry)| match entry {
            Entry::Bounced { report, .. } => Some(report),
            _ => None,
        })
        .collect();
    assert_eq!(reports, [first.id, first.id]);
    assert!(harness.store().report(first.id).unwrap().is_some());

    // A report under another report's ID, which no listener issues, is
    // neither kept nor acted on.
    let clash = Report {
        identity: [9; 32],
        recipients: vec![Claim {
            address: Address::parse("a@example.com").unwrap(),
            failed: true,
            status: Status::parse("5.1.1"),
            rules_out_address: true,
            diagnostic: None,
        }],
        ..first
    };
    let refused = recorded(&mut harness, clash);
    assert_eq!((refused.duplicate, refused.deliveries), (true, 0));
    assert!(!suppressed(&harness, "a@example.com"));
}

#[test]
fn a_report_finds_its_messages_deliveries_whatever_another_lane_issued_among_them() {
    let vfs = vfs("feedback-lanes");
    let mut harness = Harness::open(&vfs);
    let account = Sender::first().account;
    // 600 recipients take this lane's IDs into a second millisecond, and
    // another lane issues as many among them.
    let addresses: Vec<String> = (0..600).map(|n| format!("r{n}@example.com")).collect();
    let names: Vec<&str> = addresses.iter().map(String::as_str).collect();
    let ours = harness.accept(&names);
    let message = ours.messages[0].id;
    let mut other_lane = IdGenerator::new(Shard::new(1), Lane::new(2).unwrap(), None);
    let recipients: Vec<Address> = (0..600)
        .map(|n| Address::parse(&format!("o{n}@example.org")).unwrap())
        .collect();
    let theirs = Accept {
        submission: SubmissionId(other_lane.next(START)),
        authority: Sender::first().authority(harness.store().policy().revision()),
        accepted_at: START,
        expires_at: START.saturating_add(LIFETIME),
        messages: vec![AcceptMessage::new(
            MessageId(other_lane.next(START)),
            Bytes::from_static(b"Subject: theirs\r\n\r\n"),
            &recipients,
            None,
            &mut other_lane,
            START,
        )],
    };
    let answers = harness.run(vec![Command::Accept(ours), Command::Accept(theirs)], START);
    assert!(answers.iter().all(accepted));
    let last = report(
        &mut harness,
        Some(message),
        Kind::DeliveryStatus,
        &[("r599@example.com", true, "5.1.1")],
        8,
    );
    let last = Report {
        authenticated: true,
        ..last
    };
    match harness.one(Command::RecordFeedback(last), later(10)) {
        Answer::Feedback(Commit::Committed(recorded)) => {
            assert_eq!((recorded.deliveries, recorded.suppressed), (1, 1));
        }
        other => panic!("expected the report recorded, got {other:?}"),
    }
    assert!(
        harness
            .store()
            .is_suppressed(account, &Address::parse("r599@example.com").unwrap())
            .unwrap()
    );
}

#[test]
fn a_report_finds_the_deliveries_retention_left_however_many_it_took_before_them() {
    let vfs = vfs("feedback-gap");
    let mut harness = trimming(&vfs);
    let account = Sender::first().account;
    // The message's body takes its millisecond's last ID, so its 600
    // deliveries fill the next millisecond and run into the one after.
    while harness.ids.next(START).as_u64() % Id::PER_MILLISECOND as u64 != 509 {}
    let addresses: Vec<String> = (0..600).map(|n| format!("r{n}@example.com")).collect();
    let names: Vec<&str> = addresses.iter().map(String::as_str).collect();
    let accept = harness.accept(&names);
    let message = accept.messages[0].id;
    let deliveries: Vec<DeliveryId> = accept.messages[0]
        .recipients
        .iter()
        .map(|recipient| recipient.delivery)
        .collect();
    assert!(accepted(&harness.one(Command::Accept(accept), START)));
    // The first millisecond's deliveries finish at once, and are trimmed.
    let first = &deliveries[..Id::PER_MILLISECOND];
    let reservations = first
        .iter()
        .map(|&delivery| harness.reserve(&harness.delivery(delivery), later(1)))
        .collect();
    let permits: Vec<DispatchPermit> = harness
        .run(reservations, later(1))
        .into_iter()
        .map(committed_permit)
        .collect();
    let outcomes = permits
        .into_iter()
        .map(|permit| outcome(permit, Disposition::Delivered, later(1)))
        .collect();
    harness.run(outcomes, later(1));
    harness.run(Vec::new(), later(70));
    assert_eq!(harness.store().delivery(first[0]).unwrap(), None);

    let late = report(
        &mut harness,
        Some(message),
        Kind::DeliveryStatus,
        &[("r599@example.com", true, "5.1.1")],
        10,
    );
    let late = Report {
        authenticated: true,
        ..late
    };
    match harness.one(Command::RecordFeedback(late), later(71)) {
        Answer::Feedback(Commit::Committed(recorded)) => assert_eq!(recorded.deliveries, 1),
        other => panic!("expected the report recorded, got {other:?}"),
    }
    assert!(
        harness
            .store()
            .is_suppressed(account, &Address::parse("r599@example.com").unwrap())
            .unwrap()
    );
}

#[test]
fn a_recipientless_report_is_about_a_message_of_one_recipient_not_one_left() {
    let vfs = vfs("feedback-left");
    let mut harness = trimming(&vfs);
    let account = Sender::first().account;
    let accept = harness.accept(&["a@example.com", "b@example.com"]);
    let message = accept.messages[0].id;
    let first = accept.messages[0].recipients[0].delivery;
    assert!(accepted(&harness.one(Command::Accept(accept), START)));
    let permit = harness.reserved(&harness.delivery(first), later(1));
    harness.one(outcome(permit, Disposition::Delivered, later(1)), later(1));
    harness.run(Vec::new(), later(70));
    assert_eq!(harness.store().delivery(first).unwrap(), None, "trimmed");

    // One delivery is left, but either recipient could have complained.
    let complaint = report(
        &mut harness,
        Some(message),
        Kind::Feedback("abuse".to_owned()),
        &[],
        11,
    );
    match harness.one(Command::RecordFeedback(complaint), later(71)) {
        Answer::Feedback(Commit::Committed(recorded)) => assert_eq!(recorded.deliveries, 0),
        other => panic!("expected the report recorded, got {other:?}"),
    }
    assert!(
        !harness
            .store()
            .is_suppressed(account, &Address::parse("b@example.com").unwrap())
            .unwrap()
    );
    // Naming the remaining recipient does not make a shared token private
    // after retention: the original recipient count still governs effects.
    let named = report(
        &mut harness,
        Some(message),
        Kind::Feedback("abuse".to_owned()),
        &[("b@example.com", false, "")],
        12,
    );
    match harness.one(Command::RecordFeedback(named), later(71)) {
        Answer::Feedback(Commit::Committed(recorded)) => {
            assert_eq!((recorded.deliveries, recorded.suppressed), (1, 0));
            assert!(recorded.effects.is_empty());
        }
        other => panic!("expected the report recorded, got {other:?}"),
    }
    assert!(
        !harness
            .store()
            .is_suppressed(account, &Address::parse("b@example.com").unwrap())
            .unwrap()
    );
}

#[test]
fn a_sites_cooldown_is_kept_with_its_outcome_until_a_probe_ends_it() {
    let vfs = vfs("cooldowns");
    let mut harness = trimming(&vfs);
    let accept = harness.accept(&["a@example.com", "b@example.com"]);
    let [throttled, probe] = [0, 1].map(|n| accept.messages[0].recipients[n].delivery);
    assert!(accepted(&harness.one(Command::Accept(accept), START)));
    let reply = Evidence {
        rules: "refused Throttled/slow".to_owned(),
        ..Evidence::new(451, "4.7.1 slow down")
    };
    let began = SiteCooldown {
        egress: None,
        site: "Throttled".into(),
        until: later(600),
        throttles: 1,
        reply: Some(reply),
    };
    let record = |harness: &mut Harness<'_>, delivery, disposition, cooled, at| {
        let permit = harness.reserved(&harness.delivery(delivery), at);
        let outcome = Command::RecordOutcome(RecordOutcome {
            permit,
            disposition,
            evidence: None,
            suppress: false,
            cooled: Some(cooled),
            feedback: None,
            counted: None,
            now: at,
        });
        assert!(matches!(
            harness.one(outcome, at),
            Answer::Recorded(Commit::Committed(()))
        ));
    };
    let kept = |harness: &mut Harness<'_>, at| match harness.one(Command::Dispatched, at) {
        Answer::Dispatched(Ok(ledger)) => ledger.cooldowns,
        other => panic!("expected the ledger, got {other:?}"),
    };
    let change = |harness: &mut Harness<'_>, change: CooldownChange, at| {
        assert!(matches!(
            harness.one(Command::Cooldown(change), at),
            Answer::Cooled(Commit::Committed(()))
        ));
    };
    let cool = |harness: &mut Harness<'_>, cooldown: SiteCooldown, at| {
        change(harness, CooldownChange::Kept(cooldown), at);
    };
    record(
        &mut harness,
        throttled,
        Disposition::Deferred {
            not_before: later(600),
        },
        CooldownChange::Kept(began.clone()),
        later(2),
    );
    assert_eq!(kept(&mut harness, later(3)), std::slice::from_ref(&began));
    // A refused session stretches it; one that ends sooner, committed
    // after, does not shorten it.
    let stretched = SiteCooldown {
        until: later(900),
        ..began.clone()
    };
    cool(&mut harness, stretched.clone(), later(4));
    cool(&mut harness, began.clone(), later(5));
    assert_eq!(
        kept(&mut harness, later(6)),
        std::slice::from_ref(&stretched)
    );
    // A delivered probe ends it, and the store forgets it.
    record(
        &mut harness,
        probe,
        Disposition::Delivered,
        CooldownChange::Ended {
            egress: None,
            site: "Throttled".into(),
        },
        later(901),
    );
    assert_eq!(kept(&mut harness, later(902)), []);
    // One that ran out with no probe is kept, retention or not, until the
    // scheduler says it has ended.
    let again = SiteCooldown {
        until: later(950),
        ..began
    };
    cool(&mut harness, again.clone(), later(903));
    harness.run(Vec::new(), later(1_000_000));
    assert_eq!(
        kept(&mut harness, later(1_000_001)),
        std::slice::from_ref(&again)
    );
    change(
        &mut harness,
        CooldownChange::Ended {
            egress: None,
            site: again.site,
        },
        later(1_000_002),
    );
    assert_eq!(kept(&mut harness, later(1_000_003)), []);
}

#[test]
fn an_mta_sts_policy_is_kept_until_it_runs_out_and_the_latest_fetch_stands() {
    let vfs = vfs("sts-policies");
    let mut harness = trimming(&vfs);
    let fetched = |id: &str, at| sts::Policy {
        domain: "example.com".into(),
        id: id.into(),
        mode: sts::Mode::Enforce,
        mx: vec!["mx.example.com".into(), "*.mail.example.com".into()],
        max_age: Duration::from_secs(3_600),
        fetched_at: at,
    };
    let keep = |harness: &mut Harness<'_>, policy: &sts::Policy, at| {
        assert!(matches!(
            harness.one(Command::KeepSts(policy.clone()), at),
            Answer::StsKept(Commit::Committed(()))
        ));
    };
    let read = |harness: &mut Harness<'_>, at, domain: Option<&str>, limit| {
        let command = Command::StsPolicies {
            now: at,
            domain: domain.map(Into::into),
            limit,
        };
        match harness.one(command, at) {
            Answer::StsPolicies(Ok(policies)) => policies,
            other => panic!("expected the policies, got {other:?}"),
        }
    };
    let kept = |harness: &mut Harness<'_>, at| read(harness, at, None, usize::MAX);
    let first = fetched("1", later(10));
    keep(&mut harness, &first, later(10));
    assert_eq!(kept(&mut harness, later(20)), std::slice::from_ref(&first));
    // A later fetch replaces it; an earlier one committed after does not.
    let second = fetched("2", later(100));
    keep(&mut harness, &second, later(100));
    keep(&mut harness, &fetched("1", later(50)), later(101));
    assert_eq!(
        kept(&mut harness, later(102)),
        std::slice::from_ref(&second)
    );
    // Read by its domain, or among those fetched last; another domain's
    // fetched before it is left out of one.
    let other = sts::Policy {
        domain: "other.example".into(),
        ..fetched("1", later(90))
    };
    keep(&mut harness, &other, later(102));
    assert_eq!(
        read(&mut harness, later(102), Some("example.com"), 1),
        std::slice::from_ref(&second)
    );
    assert_eq!(
        read(&mut harness, later(102), None, 1),
        std::slice::from_ref(&second)
    );
    assert_eq!(
        read(&mut harness, later(102), Some("nowhere.example"), 1),
        []
    );
    // A restart keeps them.
    drop(harness);
    let mut harness = trimming(&vfs);
    assert_eq!(
        kept(&mut harness, later(103)),
        [second.clone(), other.clone()]
    );
    // Once they have run out, they serve no more, and the next trim deletes
    // them.
    let expired = later(100 + 3_600);
    assert_eq!(kept(&mut harness, expired), []);
    harness.run(Vec::new(), later(10_000));
    assert_eq!(
        harness
            .store()
            .sts_policies(later(103), None, usize::MAX)
            .expect("readable"),
        [],
        "deleted, not only past their end"
    );
}

#[test]
fn an_outcomes_report_is_recorded_after_it_in_its_commit_for_its_delivery_alone() {
    let vfs = vfs("outcome-feedback");
    let mut harness = Harness::open(&vfs);
    // Two deliveries at one address, by case: each takes its own report.
    let accept = harness.accept(&["complaint@example.com", "COMPLAINT@example.com"]);
    let message = accept.messages[0].id;
    let deliveries: Vec<DeliveryId> = accept.messages[0]
        .recipients
        .iter()
        .map(|recipient| recipient.delivery)
        .collect();
    assert!(accepted(&harness.one(Command::Accept(accept), START)));
    let permits: Vec<DispatchPermit> = deliveries
        .iter()
        .map(|delivery| harness.reserved(&harness.delivery(*delivery), later(1)))
        .collect();
    let mut kinds_after = Vec::new();
    for (index, permit) in permits.into_iter().enumerate() {
        // The same complaint of the message at the address, as the
        // simulator makes it for each.
        let complaint = report(
            &mut harness,
            Some(message),
            Kind::Feedback("abuse".to_owned()),
            &[("complaint@example.com", false, "")],
            7,
        );
        let Command::RecordOutcome(delivered) =
            outcome(permit, Disposition::Delivered, later(2 + index as u64))
        else {
            unreachable!()
        };
        let carrying = Command::RecordOutcome(RecordOutcome {
            feedback: Some(Box::new(complaint)),
            ..delivered
        });
        assert!(matches!(
            harness.one(carrying, later(2 + index as u64)),
            Answer::Recorded(Commit::Committed(()))
        ));
        kinds_after.push(
            harness
                .store()
                .entries(0, usize::MAX)
                .unwrap()
                .into_iter()
                .map(|(_, entry)| EventKind::of(&entry))
                .collect::<Vec<_>>(),
        );
    }
    // The first's complaint follows its delivery, and nothing of the
    // second's runs ahead of it; then the second's follows its own.
    assert_eq!(
        kinds_after[0],
        [
            EventKind::Accepted,
            EventKind::Delivered,
            EventKind::Complained
        ]
    );
    assert_eq!(
        kinds_after[1],
        [
            EventKind::Accepted,
            EventKind::Delivered,
            EventKind::Complained,
            EventKind::Delivered,
            EventKind::Complained
        ]
    );
}

#[test]
fn a_keys_scan_finds_every_record_still_sealed_under_it_a_page_at_a_time() {
    let vfs = vfs("key-held");
    let options = StoreOptions {
        encryption: Encryption::Installation,
        ..StoreOptions::default()
    };
    let mut harness = Harness::reopen_with(&vfs, options).0;
    // More recipients than a page reads, and a body sealed as acceptance
    // seals one.
    let recipients: Vec<String> = (0..1_005).map(|n| format!("r{n}@example.com")).collect();
    let recipients: Vec<&str> = recipients.iter().map(String::as_str).collect();
    let mut accept = harness.accept(&recipients);
    let body = accept.messages[0].body;
    let keys = Keys::new(engine_sim::sender::keys());
    accept.messages[0].content = Bytes::from(seal_body(&keys, None, body.0.as_u64(), b"x"));
    assert!(accepted(&harness.one(Command::Accept(accept), START)));
    let scan = |harness: &mut Harness<'_>, key| {
        let (mut held, mut pages, mut from) = (BTreeMap::new(), 0, None);
        loop {
            let page = match harness.one(Command::KeyHeld { key, from }, START) {
                Answer::KeyHeld(Ok(page)) => page,
                other => panic!("a scan answered {other:?}"),
            };
            *held.entry(page.table).or_insert(0) += page.held;
            pages += 1;
            match page.next {
                Some(next) => from = Some(next),
                None => return (held, pages),
            }
        }
    };
    // Each table in turn, the deliveries over two pages.
    let (held, pages) = scan(&mut harness, 1);
    assert_eq!(pages, 8, "{held:?}");
    assert_eq!((held["deliveries"], held["bodies"]), (1_005, 1), "{held:?}");
    // Nothing is under a key that sealed none of it.
    let (held, _) = scan(&mut harness, 2);
    assert!(held.values().all(|&held| held == 0), "{held:?}");
}
