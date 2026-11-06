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
  `reports_unmatched_total`, those about none of the engine's deliveries,
  `reports_unkept_total`, those naming no message of the engine's that
  were not kept once the quarantine was full; and `reports_by_egress_total`
  and `reports_by_tenant_total`, the reports by kind;
- `store_bytes`, the store's file; `store_reusable_bytes`, its free pages;
  `store_free_bytes`, the free space on its disk; `pending_bytes`,
  `refused_for_storage_total`, `commit_groups_total` and
  `commit_seconds_total`;
- `authentication_failures_total`, and `connections_refused_total` by
  listener (`submission`, `ses`, `feedback`, `operator`);
- `process_cpu_seconds_total`, `process_resident_memory_bytes` and
  `disk_written_bytes_total`, on Linux.

Logs go to standard output, as JSON lines by default (`[log] format`), at
`[log] level` (`info` by default).

## How much disk the store needs

The store does not grow forever. A message's body is deleted as its last
delivery finishes, and what is kept of finished mail, for the bounces and
complaints that come after it, is deleted after `[store]
feedback_window_seconds`, seven days by default. So its size follows how much
mail is sent in that window, and how much is waiting.

Measured through the engine, each finished recipient of a message to one
recipient keeps about 420 bytes. It keeps about 1.8 KB when its configuration
publishes SES-shaped events, which keep the message's header block to say in
those events; that is with a 750-byte header block, and a longer one keeps
more, up to 10 KiB.

| Mail a day | No SES-shaped events | SES-shaped events |
|---:|---:|---:|
| 100,000 | 0.3 GB | 1.2 GB |
| 1,000,000 | 3 GB | 12 GB |
| 10,000,000 | 30 GB | 125 GB |

Mail still waiting adds its bodies on top: 1,000,000 messages of 16 KiB are
another 16 GB, for up to `[submission] lifetime_seconds`, three days by
default. This is how a warming IP uses the disk, since mail its caps have no
room for waits in the store.

A shorter `feedback_window_seconds` makes the store smaller. A report that
comes later than that no longer finds its mail, and counts in
`reports_unmatched_total`, and a subscriber down for longer misses the events
trimmed meanwhile.

### Space inside the store

The file does not shrink as mail is deleted. Its pages go free, new mail fills
them before the file grows, and `store_bytes` stays at its peak while
`store_reusable_bytes` says how much of that is free.

The reserve counts them. New mail is refused while the free space on the disk
and the store's free pages together are below `[store] reserve_mib`, or while
the disk itself has less than 128 MiB, or the reserve if that is smaller, which
a commit's log needs whatever the store holds free.

To give the disk back after a backlog that will not come again, stop the engine
and rebuild the file, with room on the disk for a copy of what the store still
holds, using `sqlite3` 3.37 or later:

```sh
sudo -u nitromta sqlite3 /var/lib/nitromta/store.db VACUUM
```

### When the disk fills

The store stops rather than answer for what it could not keep: `/health/accept`
and `/health/dispatch` answer 503, and the log says `database or disk is full`.
A full disk does not damage it. Make room, by growing the disk or removing
something else from it, and start the engine, which goes on delivering what it
holds.

Do not restore a backup over it, which loses whatever was accepted since the
copy was taken. If the disk is too full for the store even to be checked, the
engine says so as it refuses to start: `it could not be checked, so nothing is
known to be wrong with it`. It says a store is damaged only when the check
found damage.

### After a stop that did not close the store

The engine checks the whole store before it starts, and says so in its log
first: `the store was not closed at the last stop; checking it before the
engine starts`. Nothing listens until the check ends, which takes longer the
more the store holds. Let it finish, since a restart begins it again.

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

Warmup is optional, and a daily cap is what turns it on.
[Deliverability](deliverability.md) says how it works, how each provider is
treated, and how to set your own warmup for each. To see and change caps:

```sh
nitromta list --config /etc/nitromta/config.toml egresses
echo '{"op":"put_cap","account":1,"address":"203.0.113.10","daily_cap":50}' | \
  sudo -u nitromta nitromta admin --config /etc/nitromta/config.toml
```

`list` shows each egress's caps and its last judgment. `put_cap` sets the
egress's own cap, or with `"site":"Outlook"` one receiver's, as `queue` and
`explain` name them, and with no `daily_cap` removes it.

Mail a cap has no room for is put off in the store, not held in memory, so
`queue` counts it, and `explain` says which cap it waits for.

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
