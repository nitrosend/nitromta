# SES fidelity fixtures

What real SES v2 answered and published, recorded with disposable resources
and the mailbox simulator alone, as the recording below says, which
`crates/engine-events/src/ses.rs` checks the engine's events against,
member by member.

- `events.json`: each event SES published to an SNS destination, by type and
  the mailbox simulator's address it went to, or `tenant` for the one sent
  for a tenant: `Send`, `Delivery`, `Bounce` and `Complaint`, with SES's
  `mail` object.
- `sns-envelope.json`: the SNS notification each arrived in.
- `errors.json`: SES's answers to four refused requests: a sender no
  identity covers (`MessageRejected`), an unknown configuration set and an
  address not on the suppression list (`NotFoundException`), and a send for
  a tenant its sending identity is not associated with
  (`AccessDeniedException`, 403).

Generated IDs and timestamps are replaced, and so is everything of the
recording account's: its number, its domain, the caller and the addresses
SES saw it from or sent from.

## Recording, 30 October 2026

In us-east-1, every resource disposable and named `nitromta-fixture-*`,
created for the run and deleted after it. Mail went only to the mailbox
simulator, from an address at a subdomain of the account's verified domain,
under the run's own configuration set, so nothing reached the account's
reputation or its own event destinations.

1. Created an SQS queue and an SNS topic, the topic subscribed to the queue.
2. Created a configuration set publishing every event type to the topic.
3. Sent one message each to `success@`, `bounce@`, `complaint@`,
   `suppressionlist@` and `ooto@simulator.amazonses.com`, with a tag.
4. Made three requests SES refuses.
5. Read the events from the queue until each message had its own.
6. Deleted the configuration set, the topic and the queue.

Cost: eight SES requests, five of them messages, at $0.10 a thousand; the SNS
and SQS requests within the free tier. Under a tenth of a cent.

A second run the same day created a `nitromta-fixture-*` tenant with only
the run's configuration set associated, and sent one message for it, which
SES refused: the address's identity, the account's verified domain, was not
associated with the tenant, and associating it would touch that identity,
which these rules forbid. Cost: a few SES requests, under a tenth of a cent.

## What they settled

- The mailbox simulator's replies, word for word, which the engine's
  simulator now gives: `250 Ok`; a bounce's
  `550 5.1.1 As requested: user unknown <address>`; and the suppressed
  address bounced `Permanent`, `General`, with
  `(suppressed address: address)`, not a subtype of its own.
- A complaint's `complaintSubType`, `null` but for a suppressed address.
- A send for a tenant whose identity is not associated with it: SES answers
  403 `AccessDeniedException`, `{"Message": "Tenant not associated with
  resources [<identity's ARN>]."}`. The engine answers 400
  `BadRequestException` with the same opening; the status and type differ.
- A tenant's events, from a third run with the account's verified domain
  associated with the run's tenant for one send, then dissociated:
  SES tags them `ses:tenant` with the tenant's name, which the SES adapter
  now adds too, and gives the `mail` object a `tenant` member, its
  `tenantName` and `tenantId`, which the engine does not give yet. There is
  no `ses:tenant-name` tag.
- Members the engine does not give yet: the `mail` object's `sourceArn`; a
  delivery's and a bounce's `remoteMtaIp` and `reportingMTA`; a complaint's
  `userAgent` and `arrivalDate`; and two of SES's own tags,
  `ses:source-tls-version` and, once delivered, `ses:outgoing-ip`. The rest
  of SES's own tags, `ses:operation`, `ses:configuration-set`,
  `ses:from-domain`, `ses:caller-identity` and `ses:source-ip`, the SES
  adapter adds as it accepts the message (`crates/engine-api/src/snapshot.rs`).
