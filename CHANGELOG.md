# Changelog

## 0.3.0 - 2026-11-11

### Fixed

- A drained backlog no longer refuses new mail when the store has reusable
  pages. Disk admission and `doctor` count that space while reserving room
  for the write-ahead log. `store_reusable_bytes` exposes it.
- A disk too full to check the store reports that the check could not finish
  instead of calling the store damaged and recommending a backup restore.
- Unsigned external feedback for a message sent to several recipients no
  longer suppresses or counts against any of them. An authenticated copy can
  still apply its effects once; reports for one-recipient messages and a
  transport's own delivery-scoped reports keep their existing behaviour.
- Outbound SMTP negotiates 8BITMIME. A receiver without it still takes 7-bit
  mail; 8-bit content fails locally before MAIL, without suppressing an
  address or counting the failure as the receiver's reputation signal.
- Release builds require the Rust gate and the official SDK matrix to pass
  at the release tag. The README capture example includes identity setup,
  credentials and certificate trust.
- Container releases publish the `latest` tag as well as the version tag,
  so the unversioned image reference resolves to the current release.

### Added

- `[receivers.<Provider>.warmup] promote = false` holds automatic cap increases
  for that provider while keeping automatic reductions. The hold is visible
  in `nitromta list`; other providers continue warming independently.

## 0.2.2 - 2026-11-06

### Added

- Complaint reports that have lost their return path now find their message.
  Each message goes out with its return path token in an `X-NitroMTA-Report`
  header as well, outside its signature. Microsoft's reports carry no return
  path and no recipient, so this reaches a message with one recipient.
- `reports_unmatched_total`, the reports about none of the engine's deliveries.
- A page on deliverability: how warmup works, how provider settings layer, what
  each provider reports back, and how to configure warmup for any provider.

### Changed

- The rules shipped in `rules/receivers.toml` give `Outlook` warmup defaults:
  half the shared ladder's pace to 10,000 a day, and a deferral holding a cap
  from 0.5%. `[receivers.Outlook.warmup]` overrides them, as any provider's
  settings can be configured. An egress already warming moves to them at its
  next judgment.

### Fixed

- `put_egress` no longer changes a cap warmup is using. Run again, a line naming
  no cap removed the egress's own cap, and a line naming one set it back. It can
  still start warmup on an egress with no cap, and `put_cap` changes a cap after
  that.
- `nitromta doctor` no longer says to ask the provider about port 25 when this
  host does not hold an egress's address.

## 0.2.1 - 2026-11-04

### Fixed

- The `.deb`, `.rpm` and AUR packages depend on `ca-certificates`. On a
  host without them, such as a bare container image, the engine could not
  build its resolver and did not start.

## 0.2.0 - 2026-11-04

### Changed

- **DANE takes DNSSEC's verdict from the resolver on this host, as Postfix
  does.** Delivery's lookups ask that resolver whether it validated each
  answer (the AD bit), so it must validate DNSSEC itself, and the engine no
  longer does. Through a resolver elsewhere, or one that does not
  validate, such as Docker's or most routers', mail goes as it would
  without DANE, and `doctor` and the log say DANE is not in effect; until
  now every lookup failed and the mail waited until `[delivery] dane =
  false` was set. Mail to zones the engine's own validation wrongly called
  bogus, such as an unsigned zone with no NS records at its apex, is
  delivered.
- `/health/dispatch` no longer answers 503 while the resolver does not
  validate DNSSEC, as the mail goes on without DANE.

### Removed

- `[delivery] trust_anchor`. The resolver's own trust anchor is the one
  that counts: delete the line from your configuration before upgrading, or
  the engine will not start.

## 0.1.6 - 2026-11-03

### Fixed

- Mail submitted over SMTP, or as raw content through the SES API, is given
  the `Date` and `Message-ID` fields it lacks before it is signed, as SES
  gives them, its `Message-ID` naming the ID its acceptance gives. It went
  without them, and Gmail refuses mail with no `Message-ID`.
- `nitromta <command> --help` prints that command's forms, where it answered
  that `--help` is not an option of the command, and `nitromta run --help`
  no longer asks for `--config`.
- `[delivery] port`, the port receivers are reached on, is documented, and
  `nitromta setup` writes it commented out with its default.

## 0.1.5 - 2026-11-03

### Added

- **Reference pages:** the [command line](docs/reference/cli.md) and the
  [configuration](docs/reference/configuration.md) `nitromta setup` writes,
  each checked against the binary by a test, and the guides at
  [nitromta.com/docs](https://nitromta.com/docs/).
- **Raw benchmark results:** the published session as the harness wrote it,
  in `docs/results`.

### Fixed

- `nitromta --help` prints every command and its options, where it answered
  that `--help` needs a value.
- `nitromta doctor`'s warning for an identity whose return path is outside
  its domain ended mid-sentence.
- The `.deb` and `.rpm` packages create the engine's user on a host without
  systemd, such as a container.

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
