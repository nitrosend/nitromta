# Benchmarks

NitroMTA, KumoMTA and Postfix, measured on the same machine under the same
rules by the harness in [`bench/harness`](../bench/harness/README.md),
which anyone can run:

```sh
cargo harness quick
```

## Results

AWS c7gd.metal, 2 November 2026: Graviton3, 64 cores, no hypervisor,
Debian 13, Docker Engine 29.9.2, each system's queue on the server's local
NVMe. NitroMTA's rate is 3.16 times KumoMTA's and 4.11 times Postfix's.
The harness judged every flush durable, and the CPU gauges were within
0.1% of each other.

| | Messages a second | Runs | CPU per message |
|---|--:|--:|--:|
| NitroMTA | 3,313 | 3,313 · 3,313 · 3,282 | 1.169 ms |
| KumoMTA | 1,048 | 1,048 · 1,110 · 1,048 | 2.492 ms |
| Postfix | 806 | 813 · 806 · 806 | 4.969 ms |

The session sent 1,352,423 messages across the nine runs, about 275,000 in
each of NitroMTA's, and every one was delivered once, its DKIM signature
verified and its body intact. None was refused or lost.

## Raw results

[`results/2026-11-02-c7gd-metal.json`](results/2026-11-02-c7gd-metal.json)
is the session above as the harness wrote it: every step of every run, with
its rates, latency percentiles, CPU, memory and disk writes, and the
versions, image ids and machine. It records the SHA-256 of every
configuration file the systems ran with, and each matches the file in
[`bench/harness/images`](../bench/harness/images): KumoMTA's
[`init.lua`](../bench/harness/images/kumomta/init.lua), Postfix's
[`main.cf`](../bench/harness/images/postfix/main.cf) and
[`master.cf`](../bench/harness/images/postfix/master.cf), and NitroMTA's
[`config.toml`](../bench/harness/images/nitromta/config.toml).

## What is measured

Each system's highest sustained rate: the load is offered at a fixed rate,
doubling from 250 messages a second until a step misses a budget, then
bisected six times, to within about 1.5%. A step passes when no submission
is refused, at least 99% of the offered rate is accepted, the 99th
percentile of submission is at most a second and of delivery at most two,
and every message arrives once, signed and intact.

- **The mail:** 16 KiB messages to one recipient each, signed with an
  RSA-2048 DKIM key, submitted over SMTP with STARTTLS on 64 connections
  and delivered over TLS to a sink that checks every signature. NitroMTA
  runs with its events, suppression list and egresses in use.
- **The promise:** every system commits a message to disk before it
  accepts it. KumoMTA is configured to sync its spool before replying, as
  NitroMTA and Postfix do.
- **The machine:** each system gets 4 CPUs and 2 GiB of memory; the load
  generator and sink get the rest. A CPU gauge (SHA-256 throughput) is
  taken with every run, and a session whose gauges differ by more than a
  tenth is labelled unequal.
- **The versions:** NitroMTA from this repository, KumoMTA
  2026.09.29-b90d8bc1, and Postfix 3.11.7 with OpenDKIM 2.11.0-Beta2, each
  built from source ([`bench/harness/recipe.toml`](../bench/harness/recipe.toml)).
- **Runs:** three of each system, interleaved, reported as the median.

Every run writes its raw results to `target/harness/<run>/result.json`:
the command, the versions, the environment and every step.

## Running it

It needs rustup and Docker. The first run builds every image from source,
KumoMTA's in about eleven minutes; later runs reuse them.

- `--systems nitromta,kumomta` measures those named.
- `--repetitions n` takes the place of the three runs.
- `--message-bytes n` measures another message size.
- `--without signing` or `--without tls` shows what DKIM or TLS on delivery
  costs.

[`bench/harness/README.md`](../bench/harness/README.md) describes the other
profiles: many domains with one throttled, receivers at a distance, the
backlog, the SES API against KumoMTA's HTTP injection, and the crash tests.
