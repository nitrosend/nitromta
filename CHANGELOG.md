# Changelog

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
