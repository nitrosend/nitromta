# Migrating from SES

An application that sends through Amazon SES keeps its code. It is given
the engine's endpoint and an access key of its own, and sends as it did.
What moves is what SES kept for it: its domains and their DKIM keys, its
event destinations, its suppression list, its templates and tenants, and
the IPs it sends from.

The examples use `mta.example.com`, the host name given to `nitromta setup`,
whose certificate the SES API serves, and the configuration at
`/etc/nitromta/config.toml`, as in [installation](install.md).

## 1. Point the application at the engine

Uncomment the `[ses]` table in the configuration, and the API listens on
443. Create an access key for the application:

```sh
sudo -u nitromta nitromta access-key create --config /etc/nitromta/config.toml --account 1
```

Add `--identity example.com` to let it send as that domain alone, and
`--manage` if the application also creates identities, configuration sets
or templates through the API. Its ID and secret are printed once; the
application reads them as it read its SES keys.

Then the endpoint, and the region the engine answers as (`[ses] region`,
`us-east-1` unless changed), in each SDK:

```python
# boto3
ses = boto3.client("sesv2", endpoint_url="https://mta.example.com", region_name="us-east-1")
```

```js
// @aws-sdk/client-sesv2, and Nodemailer's SES transport through it
const ses = new SESv2Client({ endpoint: "https://mta.example.com", region: "us-east-1" });
const transport = nodemailer.createTransport({ SES: { sesClient: ses, SendEmailCommand } });
```

```ruby
# aws-sdk-sesv2
ses = Aws::SESV2::Client.new(endpoint: "https://mta.example.com", region: "us-east-1")
```

```python
# django-ses
EMAIL_BACKEND = "django_ses.SESBackend"
USE_SES_V2 = True
AWS_SES_REGION_NAME = "us-east-1"
AWS_SES_REGION_ENDPOINT_URL = "https://mta.example.com"
```

These are the configurations `cargo xtask sdk` runs against the engine
([`sdk/README.md`](../sdk/README.md)).

An application that sends through SES's SMTP interface is given a login
instead, and sends to `mta.example.com` on port 587, with STARTTLS and
`AUTH PLAIN`:

```sh
sudo -u nitromta nitromta login create --config /etc/nitromta/config.toml --account 1 --user app
```

## 2. Bring your domains

SES's Easy DKIM keys stay with Amazon, so the engine signs with a key of
your own. Give each domain one under a new selector, so SES's records can
stay published until the move is done. Through the admin socket, as
[installation](install.md#5-give-it-its-policy) shows, with `put_identity`
and its private key; or through the API, with `CreateEmailIdentity` and its
`DkimSigningAttributes` (Bring Your Own DKIM), which the engine checks
before it sends as the domain.

Then publish what `nitromta doctor` prints for each: the DKIM record of the
new selector, and DMARC if the domain has none. Bounces come back to the
engine's own return path domain, whose MX must name this host and whose SPF
must cover its IPs; `doctor` checks that the domain has an MX, and that its
SPF covers each egress. An email address identity is not
needed: an address at a domain the engine knows sends as that domain.

## 3. Events

An application that receives SES's events through SNS keeps its handler.
The engine serves SNS beside the SES API once its configuration has an
`[sns]` table, which `setup` does not write: the HTTPS origin applications
reach the API at, and an RSA key and certificate its messages are signed
with. Make the key and certificate as the engine's user:

```sh
sudo -u nitromta openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
  -subj /CN=mta.example.com -keyout /etc/nitromta/sns.key -out /etc/nitromta/sns.crt
```

Add the table, and restart the engine, since a reload reads keys and
certificates again but no new table:

```toml
[sns]
url = "https://mta.example.com"
key = "/etc/nitromta/sns.key"
certificate = "/etc/nitromta/sns.crt"
```

Then create the topic and the subscription on the engine, at the same
endpoint, and point the configuration set's event destination at it:
`CreateTopic`, `Subscribe` with the handler's HTTPS URL, and
`CreateConfigurationSetEventDestination`. The handler is sent its
`SubscriptionConfirmation`, then `Send`, `Delivery`, `DeliveryDelay`,
`Bounce` and `Complaint` events as SES writes them.

Each message is signed with SNS's SignatureVersion 2 under the engine's own
key, and its `SigningCertURL` is on the engine's host. A handler that
verifies signatures and accepts certificates only from `amazonaws.com`
must accept that host instead.

Native subscriptions are the other way in: `create_subscription` on the
admin socket posts a configuration's events to a URL in signed batches,
retried and replayed ([compatibility](compatibility.md#events)).

## 4. The suppression list

Export the account's list from SES:

```sh
aws sesv2 list-suppressed-destinations \
  --query 'SuppressedDestinationSummaries[].[EmailAddress,Reason]' --output text > suppressed.tsv
```

And load it through the admin socket, at most 10,000 addresses a request:

```sh
jq -R -s -c '
  [split("\n")[] | select(length > 0) | split("\t")]
  | group_by(.[1])[]
  | (.[0][1] | ascii_downcase) as $reason
  | [.[][0]] | _nwise(10000)
  | {op: "suppress", account: 1, reason: $reason, addresses: .}
' suppressed.tsv | sudo -u nitromta nitromta admin --config /etc/nitromta/config.toml
```

`PutSuppressedDestination` through the API takes them one at a time, as
SES does.

## 5. Templates and tenants

Templates are created as SES creates them, with `CreateEmailTemplate`:
list SES's with `list-email-templates`, read each with
`get-email-template`, and create it on the engine. Their parts are filled
by `{{name}}`, `{{{name}}}` and dotted names; a template with a block, a
partial or a comment is refused as it is created. Tenants are created and
associated with their identities, configuration sets and templates as in
SES.

## 6. Move the mail

The engine sends from addresses you own, and a new address has no
reputation yet. Give each egress a starting cap, and keep sending most mail
through SES while warmup raises the caps receiver by receiver
([operations](operations.md#warming-up-an-ip)); move more of it to the
engine as they rise.

## Where it differs

Open and click tracking are not given, no request is made idempotent,
identities are domains with their own DKIM keys, a few event fields are
absent, and the engine runs on one host.
[Compatibility](compatibility.md#where-the-engine-differs-from-ses) lists
each.
