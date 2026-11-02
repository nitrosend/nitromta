# Changelog

## 0.1.4 - 2026-11-02

### Added

- **Packages:** each release publishes `.deb` and `.rpm` packages for
  x86_64 and arm64, which install the binary, the systemd unit and the
  engine's system user; `nitromta-bin` on the AUR; and macOS binaries for
  Apple silicon and Intel, for capture mode.
- **Homebrew:** `brew install nitrosend/tap/nitromta`, on macOS and Linux.

## 0.1.3 - 2026-11-02

### Added

- **Benchmarks:** NitroMTA, KumoMTA and Postfix measured by the harness on
  an AWS c7gd.metal server, each committing every message to disk before
  accepting it: 3,313, 1,048 and 806 messages a second
  ([benchmarks](docs/benchmarks.md)).

## 0.1.2 - 2026-11-02

### Added

- **The benchmark harness:** `cargo harness` builds NitroMTA, KumoMTA, and
  Postfix with OpenDKIM from source and measures each on the same machine
  under the same rules. Its profiles cover throttled and distant receivers,
  the backlog, the SES API, and crash recovery, including killing the
  process under load.

## 0.1.1 - 2026-11-02

### Added

- **The SDK matrix:** `cargo xtask sdk` runs the official SES v2 SDKs
  against the engine, each pinned by its lockfile: `@aws-sdk/client-sesv2`
  and Nodemailer's SES transport in JavaScript, `boto3` and django-ses in
  Python, and `aws-sdk-sesv2` in Ruby.
- **Migrating from SES:** a guide to moving an application, its domains,
  events, suppression list and templates from Amazon SES.

## 0.1.0 - 2026-11-02

The first release.

### Added

- **The SES v2 API:** `SendEmail` and `SendBulkEmail`, by simple, raw or
  template content; email templates, kept and sent by name; identities with
  Bring Your Own DKIM, verified by their DNS records; configuration sets and
  their event destinations; tenants and their associations; reputation
  entities; the account; the suppression list; and dedicated IPs and pools.
  Signed with Signature Version 4 by access keys scoped to identities and
  tenants.
- **Events:** SES-shaped `Send`, `Delivery`, `DeliveryDelay`, `Bounce` and
  `Complaint` events published through an SNS subset to HTTPS subscribers,
  and native subscriptions posting signed batches, retried, parked and
  replayed.
- **SMTP submission** with STARTTLS and `AUTH PLAIN`, honouring SES's
  `X-SES-CONFIGURATION-SET`, `X-SES-TENANT` and `X-SES-MESSAGE-TAGS`.
- **Delivery:** DKIM signing, STARTTLS, MTA-STS and DANE, an egress per
  sending IP with its own HELO name, per-receiver connection limits and
  throttle cooldowns from a bundle of receiver rules, retries on a jittered
  schedule, and expiry.
- **IP warmup:** daily caps at each receiver for each egress, judged daily
  from what receivers said, with mail a cap has no room for put off in the
  store.
- **Feedback:** delivery status notifications and complaint reports matched
  to their mail by its return path, suppressing their recipients, with
  reporters authenticated by DKIM when the operator asks.
- **Capture mode,** which runs the whole engine on one machine and shows
  each message in a browser instead of sending it.
- **The CLI:** `setup`, `doctor`, `explain`, `queue`, `list`, `pause`,
  `resume`, `drain`, `parked`, `replay`, `backup`, `restore` with its fence,
  `migrate`, `check`, and key rotation; health and Prometheus metrics.
- **Durability:** every acceptance committed with a synced write before it
  is answered, tested by failing the power at every I/O operation and by
  moving a store to a new host.
- **Encryption at rest** of personal data, off by default for a store on an
  encrypted disk: under the installation's key, or each tenant's mail under
  a key of its own, so removing the tenant erases it (`[store] encryption`).
- **Hooks** compiled into a build of one's own, for admission and dispatch.
- **Hardening:** the engine refuses to run as root, seals the secrets it
  stores under keys kept apart from its store, bounds every listener's
  connections and every request it has not yet verified, and runs under a
  hardened systemd unit.
