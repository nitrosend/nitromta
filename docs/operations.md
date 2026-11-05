# Operations

How to see what the engine is doing with your mail, and how to change it.
Every command below talks to the running engine through its admin socket,
as its own user or root, and takes `--json` for the API's own lines.

## Why is this message waiting?

```sh
nitromta explain --config /etc/nitromta/config.toml --message <id>
```

For each of the message's deliveries: its state and since when, when it
expires, how many attempts it has had and how many of them were uncertain,
the egress it goes out from, the last reply its receiver gave with the
receiver rules that reply matched, and where the scheduler holds it and
why: looking up its route, behind others in its queue, waiting for its
site's cooldown to end, waiting for its egress's daily cap to have room,
or paused by a hold. `--delivery <id>` explains one delivery.

## What is queued?

```sh
nitromta queue --config /etc/nitromta/config.toml
```

First, the unfinished deliveries the store holds: waiting, in flight and
held. Then each queue the scheduler holds in memory, those with the most
waiting first: its receiver site (a provider such as Google or Microsoft,
as the receiver rules group their exchanges, or the exchange itself), the
egress it goes out from, how many deliveries are due in it, how many it has
put off since the engine started until a capped egress has room, the
transactions under way at its site, any cooldown, and when its egress's
budget frees. Mail the scheduler does not hold in memory, not yet due for
a retry or a cap's room, is in the store's count alone; `explain` says
where any one delivery waits. `--json` adds the reply that began each
cooldown, and a capped queue's cap with warmup's last judgment of it.

## Is it healthy?

On `[operator] listen`:

| Path | Answers |
|---|---|
| `/health/live` | 200 while the process serves |
| `/health/accept` | 200 while it accepts mail; 503, with the reason, once its store has failed, while it stops, or while new mail is refused for want of disk or of room for mail awaiting its commit |
| `/health/dispatch` | 200 while it delivers; 503 once its store or scheduler has failed, or while it stops |
| `/metrics` | Prometheus's text format |

The metrics, each prefixed `nitromta_`, among them:

- `messages_accepted_total`, `recipients_accepted_total`,
  `accepted_bytes_total`, and `acceptance_seconds`, a histogram of the time
  from a submission to its answer;
- `attempts_total` by result (`delivered`, `captured`, `deferred`,
  `throttled`, `rejected`, `uncertain`, `not_sent`), and the same by site,
  by egress and by tenant, with `outcome_seconds`;
- `queue_deliveries` by state, `queue_oldest_seconds` and
  `queue_due_lag_seconds`, how far behind its due time the most overdue
  delivery is;
- `event_lag_entries` and `event_lag_seconds`, for the furthest-behind
  subscription, and the event batches posted, parked and replayed;
- `reports_total`, the bounce and complaint reports recorded,
  `reports_suppressing_total`, the recipients they suppressed, and
  `reports_unkept_total`, those naming no message of the engine's that
  were not kept once the quarantine was full; and `reports_by_egress_total`
  and `reports_by_tenant_total`, the reports by kind;
- `store_bytes`, `store_free_bytes`, `pending_bytes`,
  `refused_for_storage_total`, `commit_groups_total` and
  `commit_seconds_total`;
- `authentication_failures_total`, and `connections_refused_total` by
  listener (`submission`, `ses`, `feedback`, `operator`);
- `process_cpu_seconds_total`, `process_resident_memory_bytes` and
  `disk_written_bytes_total`, on Linux.

Logs go to standard output, as JSON lines by default (`[log] format`), at
`[log] level` (`info` by default).

## Checking the installation

`nitromta doctor` checks the configuration, store, certificates, clock and
resolver, and each egress and identity against the DNS, and says what to
change (see [installation](install.md)). `nitromta check` checks a stopped
engine's store.

## Holding and releasing mail

```sh
nitromta pause --config <file> --account 1 --tenant acme --reason "complaints from one list"
nitromta resume --config <file> --account 1 --tenant acme
```

A hold covers an account, or one of its tenants, configurations, identities
or egresses. Mail it covers is kept, not sent, until it is resumed, and new
mail under it is refused unless the hold was made `--accepting`. A held
egress keeps its mail rather than moving it to another. A hold does not
stop the clock: held mail still expires when its lifetime ends
(`[submission] lifetime_seconds`, three days by default), so a hold longer
than that loses what it holds.

`nitromta drain --config <file> --wait` stops taking new mail and waits for
the queue to be delivered, for a planned stop; `undrain` takes mail again.

## Warming up an IP

Warmup is optional, and a daily cap is what turns it on: an egress with no
cap sends as much as it is given. A new address starts at the ladder's first
rung, 50 messages a day at each receiver, with `"daily_cap":50` on
`put_egress`, or afterwards:

```sh
echo '{"op":"put_cap","account":1,"address":"203.0.113.10","daily_cap":50}' | \
  sudo -u nitromta nitromta admin --config /etc/nitromta/config.toml
```

An egress may have a daily cap at each receiver site. With
`[warmup] automatic = true`, the default, the engine judges each capped
egress once a day from what its receivers said, and raises, holds or lowers
its caps along the receiver rules' ladder; otherwise caps change only by
`put_cap` on the admin socket.

Each receiver climbs on its own. A cap rises a rung after a clean day on
which replies reached half of it; complaints, bounces, deferrals or
throttling hold it or take it down a rung. Past the last rung there is no
cap, and warmup is done. `nitromta list --config <file> egresses` shows each
egress's caps and its last judgment.

Mail a cap has no room for is put off in the store, not held in memory, so a
warming IP never delays mail to other receivers, and `queue` counts it. It
still expires when its lifetime ends (`[submission] lifetime_seconds`, three
days by default), so send a warming address no more than its caps allow, and
keep the rest on the sender you have.

## Events

`nitromta parked --config <file> --account 1 --subscription <name>` lists a
subscription's batches that ran out of retries, with why the last post
failed; `nitromta replay` posts them again, all of them or the one named.

## Keys

The installation's keys seal the secrets in policy, and message bodies
while encryption is on. To rotate them:

1. `nitromta key --to /etc/nitromta/keys` writes the next key;
2. a restart seals every secret under it;
3. `nitromta key retire --config <file> --id <old>` takes the old key out,
   once nothing it sealed is left.

`nitromta key list --config <file>` shows the keys and which one seals.

## The rest of policy

`nitromta list --config <file> <kind>` lists accounts, identities, tenants,
configurations, pools, egresses, logins, access keys, subscriptions and
holds. Policy changes are JSON lines on `nitromta admin`: `put_account`,
`put_identity`, `put_configuration`, `put_pool`, `put_egress`, `put_cap`,
`put_tenant`, `create_login`, `create_access_key`, `create_subscription`,
`suppress` and `unsuppress`, and a `remove_` for each kind. Each takes
effect at once and is kept in the store.
