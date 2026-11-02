# The SDK matrix

The official SES v2 SDKs, and two applications built on them, run against the
engine. Each is pinned with every dependency it needs:

| Directory | What runs | Pinned by |
|---|---|---|
| `javascript` | `@aws-sdk/client-sesv2`, then Nodemailer's SES transport | `package-lock.json` |
| `python` | `boto3`, then django-ses over SES v2 | `requirements.txt`, with each file's hash |
| `ruby` | `aws-sdk-sesv2` at the version Nitrosend sends with, each gem at the version Nitrosend resolves | `Gemfile.lock`, with checksums |

`cargo xtask sdk` installs each from its lockfile and runs
`crates/engine/tests/sdk.rs`, which starts the engine's binary with the SES API
on and capture mode, gives each script a key that may send and manage, and
judges what it prints. It needs Node, Python 3 and Ruby with Bundler; the gate
does not run it.

## The scenario

Every script takes the same steps, in order, and prints one line of JSON for
each, named by `step`:

1. `send_simple`: `SendEmail` with simple content, a subject, text and HTML.
2. `send_raw`: `SendEmail` with raw content and no destination, sent to the
   addresses its own fields name.
3. `send_bulk`: `SendBulkEmail` with inline template content and two entries:
   one whose data fills the template, `SUCCESS`, and one whose data misses a
   name it uses, `MESSAGE_REJECTED`.
4. `account`: `GetAccount`, sending enabled and a quota.
5. `rejected`: `SendEmail` from an address no identity of the account covers,
   refused `MessageRejected`.
6. `identity`: `GetEmailIdentity` of the sending domain, verified.
7. `identities`: `ListEmailIdentities` a page of one at a time, the sending
   domain among them.
8. `configuration_sets`: `CreateConfigurationSet` of `first` and `second`,
   then `ListConfigurationSets` a page of one at a time, the two in order.
9. `templates`: `CreateEmailTemplate`, `UpdateEmailTemplate`,
   `GetEmailTemplate` and `ListEmailTemplates`, `SendEmail` by the template's
   name, then `DeleteEmailTemplate` and the template not found.
10. `suppression`: `PutSuppressedDestination`, `GetSuppressedDestination` and
   `DeleteSuppressedDestination`, then the address not found.
11. `unimplemented`: an operation the engine does not implement, refused
    `BadRequestException` on the first attempt, never retried.

JavaScript then sends through Nodemailer, its `verify` first, and Python
through django-ses, each with HTML and an attachment. Every message the
scenario sends is captured, by its subject.

Beside the scenario, `crates/engine/tests/sdk.rs` follows the steps
`nitromta setup --capture` prints, as a newcomer would: the engine run, its
policy given through the admin socket, an access key made, a message sent with
`boto3` to the SES API they name, trusting the certificate setup made, and
found in the inspector.

The scripts read where to send and as whom from the environment: `SES_ENDPOINT`,
`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_CA_BUNDLE` (and
`NODE_EXTRA_CA_CERTS`), `FROM`, `TO`, `DOMAIN` and `SUPPRESS`.
