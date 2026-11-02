# Durability

What an answer from the engine promises, what survives which failure, and
where the limits are.

## What an acceptance means

The engine answers a submission, over SMTP or the SES API, only once the
message, its body and a delivery for each recipient are committed to its
store with a synced write. From that answer on, the message survives a
crash of the process, a loss of power, and a restart: it is delivered,
bounced or expired, and never silently dropped. Before the answer, nothing
was promised, and nothing is left behind.

The store is one SQLite database in write-ahead logging mode, with every
commit synced, and one writer that groups concurrent commits into one
sync. Deliveries, attempts, outcomes, the event journal, suppression, policy
and the dispatch ledger are all in it, so each change is one transaction:
no state lives only in memory that a restart could lose, other than what
can be rebuilt from the store.

## What each failure leaves

| Failure | What follows |
|---|---|
| Before an acceptance commits | No success was returned; nothing is kept |
| After it commits, with the answer lost | The message exists; a client that retries sends a second one |
| The process dies before or during an attempt | The attempt is recovered as uncertain and tried again |
| A receiver accepts, and the engine dies before recording it | The message may have been delivered; trying again can deliver it twice, and the attempt is counted as uncertain |
| An event subscriber is down | Sending is unaffected; events are retried, parked, and replayed on request, for as long as the journal keeps them (below) |
| A subscriber handles an event and its answer is lost | The same event, with the same ID, is posted again |
| The store reports corruption | The affected work stops and the evidence is kept; nothing is skipped or repaired into an apparent success |
| The disk fills | The store stops, answering nothing it could not keep; at most the commit that failed is in doubt, and the engine starts sound once there is room |

The one unavoidable window is SMTP's own: the receiver's final reply hands
it the message, and a reply lost after that leaves the outcome unknown. No
local transaction makes that exchange exactly once, so the engine delivers
at least once, and counts each uncertain attempt
(`nitromta_attempts_total{result="uncertain"}`) so the window is visible.

## How it is tested

- **Power loss.** A simulated disk and a pipeline of acceptance, dispatch,
  receiver and outcome fail the power at every I/O operation, then recover,
  and check every acknowledged commit after each recovery. A receiver sees a
  delivery twice only when an uncertain attempt was counted. The same runs
  stop the engine gracefully, and fill the disk, at random points.
- **Process loss.** The release binary, sending 500 messages a second, is
  killed and started again: in each run, about 4,960 recipients had been
  acknowledged and 4,840 were still queued at the kill, none was lost and
  none delivered twice, and the engine was accepting again 0.4 seconds
  after it started.
- **Host loss.** A message accepted and held on one host, its store on a
  volume of its own; the host powered off; the volume moved to a fresh host
  with the package installed and the configuration and keys restored from
  their copy; the engine started there holding the delivery, and sent it.
- **Corruption.** A store left open by a crash is checked as the engine
  starts, and a damaged one refused.

The power-loss and simulation tests run in `cargo xtask check`; the process
loss runs in the benchmark harness (`cargo harness kill`).

## Backup and restore

`nitromta backup --config <file> --to <file>` copies the store while the
engine runs, a few pages at a time between its own commits, or while it is
stopped. `nitromta restore` puts a copy in place of a stopped engine's
store, fenced: every delivery the copy holds that was not finished when it
was taken is held, since the original may have sent it since, until the
operator decides, with `nitromta fence --config <file> release` to send
them or `nitromta fence --config <file> discard` to cancel each as it falls
due.

The secrets in a backup, as in the store, are sealed under the
installation's keys, which are never in it, and so are message bodies while
encryption is on: keep a copy of the keys and the configuration apart from
both the host and its backups.

## The limits

- **One host.** The store is on one host's disk. Losing the disk loses
  what was accepted since the last backup; there is no replication and no
  failover. A volume that outlives its host, as cloud block storage does,
  can be attached to another host and started there.
- **At least once.** See SMTP's window above.
- **No idempotency key.** A client that retries a submission whose answer
  was lost sends a second message, as with SES.
- **Events are kept for the feedback window.** The journal, and the
  batches parked from it, are kept for `[store] feedback_window_seconds`
  (seven days by default). A
  subscriber down for longer misses what was trimmed meanwhile, counted in
  its cursor's skipped positions, and a parked batch past the window can
  no longer be replayed.
- **The disk reserve is advisory.** New mail is refused once free space
  falls below `[store] reserve_mib`, but mail already accepted, outcomes,
  the log and checkpoints can still fill the disk; then the store stops,
  answering nothing it could not keep, until it is restarted with space
  free.
