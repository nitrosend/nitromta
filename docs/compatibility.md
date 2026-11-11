# Compatibility

What the engine serves, to whom, and where it answers differently from
Amazon SES.

## The SES v2 API

On `[ses] listen`, over HTTPS, signed with AWS Signature Version 4 by an
access key from `nitromta access-key create`. The engine serves these
operations; any other is refused `BadRequestException`, which no SDK
retries.

| Area | Operations |
|---|---|
| Sending | `SendEmail` (simple, raw and template content), `SendBulkEmail` (template content) |
| Templates | `CreateEmailTemplate`, `GetEmailTemplate`, `UpdateEmailTemplate`, `DeleteEmailTemplate`, `ListEmailTemplates` |
| Identities | `CreateEmailIdentity` (domains, with Bring Your Own DKIM), `GetEmailIdentity`, `DeleteEmailIdentity`, `ListEmailIdentities`, `PutEmailIdentityDkimAttributes`, `PutEmailIdentityDkimSigningAttributes`, `PutEmailIdentityFeedbackAttributes`, `PutEmailIdentityMailFromAttributes` |
| Configuration sets | `CreateConfigurationSet`, `GetConfigurationSet`, `ListConfigurationSets`, `PutConfigurationSetReputationOptions`, `PutConfigurationSetDeliveryOptions`, `CreateConfigurationSetEventDestination`, `GetConfigurationSetEventDestinations`, `UpdateConfigurationSetEventDestination`, `DeleteConfigurationSetEventDestination` |
| Tenants | `CreateTenant`, `GetTenant`, `ListTenants`, `CreateTenantResourceAssociation`, `DeleteTenantResourceAssociation`, `ListTenantResources`, `ListResourceTenants` |
| Reputation | `GetReputationEntity`, `UpdateReputationEntityCustomerManagedStatus` |
| Account | `GetAccount` |
| Suppression list | `PutSuppressedDestination`, `GetSuppressedDestination`, `DeleteSuppressedDestination`, `ListSuppressedDestinations` |
| Dedicated IPs | `CreateDedicatedIpPool`, `PutDedicatedIpInPool`, `GetDedicatedIp`, `GetDedicatedIps` |

Within those operations, a few fields the engine does not act on are
refused by name, never ignored:

- **Simple content** takes no attachments (send them in raw content), and
  is sent as UTF-8: a part may name no charset, `UTF-8` or `UTF8`, or
  `US-ASCII` or `ASCII` when its text is ASCII; any other is refused.
- **Template content** is a template the account keeps, by its
  `TemplateName` or by a `TemplateArn` of this account and region, or the
  request's own `TemplateContent`. Mail sent for a tenant uses a kept
  template only once it is associated with the tenant
  (`CreateTenantResourceAssociation`), as SES has it. A template's parts
  are filled by `{{name}}`, `{{{name}}}` and dotted names such as
  `{{user.name}}` alone: a template with a block (`{{#if}}`, `{{#each}}`),
  a partial or a comment is refused as it is created. A kept template's
  parts come to at most 512 KiB, an account keeps at most 10,000, and
  tags are not kept on them.
- **`SendBulkEmail`**'s rendered messages together come to at most the largest
  request the API takes: 54,381,912 bytes, from
  `[submission] max_message_bytes` at its default. An entry past that is
  answered `MESSAGE_REJECTED`, and so is every entry after it, while those
  before it are sent, so a very large batch is best split.
- **`PutConfigurationSetDeliveryOptions`** takes the pool alone: a
  `TlsPolicy` of `REQUIRE` and `MaxDeliverySeconds` are refused, as
  transport security is the installation's (`[delivery] require_tls`,
  MTA-STS and DANE) and a message's lifetime is `[submission]
  lifetime_seconds`.

An access key sends unless it was made with `--manage-only`, and manages
the account through the API only when made with `--manage` or
`--manage-only`. A key or login scoped to identities or tenants sends as
those alone.

Raw content may carry `X-SES-CONFIGURATION-SET`, `X-SES-TENANT` and
`X-SES-MESSAGE-TAGS` header fields, which the engine honours and removes,
as SES does; it removes `X-SES-SOURCE-ARN`, `X-SES-FROM-ARN` and
`X-SES-RETURN-PATH-ARN` too. A message is given the `Date` and
`Message-ID` fields it lacks, as SES gives them, its `Message-ID` naming
the `MessageId` the answer gives.

## The SNS subset

On the same listener, at its root: `CreateTopic`, `GetTopicAttributes`,
`Subscribe`, `ConfirmSubscription`, `Unsubscribe` and
`ListSubscriptionsByTopic`, for HTTPS subscribers, enough for an application
that receives SES's events through SNS to receive the engine's. A new
subscriber is sent its `SubscriptionConfirmation`, and every message is
signed with SignatureVersion 2 under `[sns] key`, whose certificate the
listener serves for subscribers to verify against.

## Events

Through a configuration set's event destinations, the engine publishes
SES-shaped events to SNS topics: `Send`, `Delivery`, `DeliveryDelay`,
`Bounce` and `Complaint`, as SES writes them, with their tags.

Native subscriptions (`create_subscription` on the admin socket) post a
configuration's events to a URL in signed batches, of the kinds named:
`accepted`, `delivered`, `captured`, `deferred`, `bounced`, `uncertain`,
`expired`, `suppressed`, `cancelled` and `complained`. A batch that fails
is retried, and parked once its retries are spent, to be replayed with
`nitromta replay`. The same event can be posted again after a lost
response, under the same ID, so a subscriber must treat it as the same
event.

## SMTP

**Submission**, on `[submission] listen`: STARTTLS, which is required before
`AUTH PLAIN`; `PIPELINING`, `SIZE`, `8BITMIME` and `ENHANCEDSTATUSCODES`.
The login decides the account, and the message's one From address the
identity it is sent as. A message is given the `Date` and `Message-ID`
fields it lacks, its `Message-ID` naming the ID the acceptance's reply
gives.

**Delivery**: to each domain's MX hosts, over STARTTLS. TLS is required by
default (`[delivery] require_tls = true`): mail to a receiver that does not
offer STARTTLS is tried again until it expires; set it to `false` to
deliver in the clear to such receivers. MTA-STS (RFC 8461) and DANE (RFC
7672) are on by default; a domain's policy decides which exchanges it may
go to and how their certificates must be verified.
Each IP sends with its own HELO name, and mail is signed with DKIM as its
identity says.

**Feedback**, on `[feedback] listen`, the return path domain's MX: delivery
status notifications (RFC 3464) and complaint reports (RFC 5965), matched
to the mail they are about by its return path, or the same token in its
`X-NitroMTA-Report` header, for a report that has lost it. By default a report
that matches a message originally sent to one recipient may suppress that
recipient and count toward its IP's warmup. A message sent to several
recipients shares its correlation token, so an external report about it
must be authenticated before it may suppress or count. An unsigned report
is still recorded as an event, and a later authenticated copy applies its
effects once. With `[feedback] trusted = "authenticated"`, only one
whose DKIM signature verifies for a reporter enrolled in
`[feedback] reporters` does, and any other is recorded as an event alone.
[Deliverability](deliverability.md#receiving-complaint-reports) says how to
receive each provider's reports.

## The SDKs, tested

`cargo xtask sdk` runs the official SES v2 SDKs, pinned, against the
engine: `@aws-sdk/client-sesv2` and Nodemailer's SES transport in
JavaScript, `boto3` and django-ses in Python, and `aws-sdk-sesv2` in Ruby.
[`sdk/README.md`](../sdk/README.md) lists the scenario each runs.

## Where the engine differs from SES

- **Identities.** `CreateEmailIdentity` creates domain identities alone,
  each with its own DKIM key (Bring Your Own DKIM); Easy DKIM and email
  address identities are refused, and an address at a verified domain
  sends as that domain. The engine verifies each such identity, and each
  MAIL FROM domain put through the API, by looking up its records with its
  own resolver: a pending check at once and then less often, a verified
  one daily. An identity put through the admin socket is not checked;
  `nitromta doctor` checks it instead.
- **Event fields not given:** `mail.sourceArn`; a delivery's and a bounce's
  `remoteMtaIp` and `reportingMTA`; a `DeliveryDelay`'s `expirationTime`; a
  complaint's `userAgent` and `arrivalDate`; the `mail.tenant` object; and
  the tags
  `ses:source-tls-version` and `ses:outgoing-ip`. Every other member SES
  writes, the engine writes the same way, checked against events recorded
  from SES (`fixtures/ses`).
- **A tenant not associated with the identity it sends as** is refused 400
  `BadRequestException` opening "Tenant not associated with resources", where
  SES answers 403 `AccessDeniedException`.
- **Open and click tracking** are not given: a configuration set's
  `TrackingOptions` is refused, and there are no `Open` or `Click` events.
- **No request is made idempotent.** As with SES, a `SendEmail` retried
  after its answer was lost sends a second message.
- **8BITMIME is negotiated on delivery.** Content is sent unchanged, with
  `BODY=8BITMIME` when the receiver offers it. If the receiver does not,
  7-bit content still sends; 8-bit content fails permanently with a local
  `5.6.3` diagnostic, without suppressing the recipient. Submit raw content
  with a 7-bit-safe transfer encoding to reach those receivers too.
- **One host.** The engine runs on one host, with its store on that host's
  disk. There are no regions; `[ses] region` is the one it signs and
  answers as.
