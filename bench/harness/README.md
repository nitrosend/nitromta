# The benchmark harness

```sh
cargo harness quick
```

This measures NitroMTA, KumoMTA and Postfix (signing through OpenDKIM) on this machine under the same rules, from source builds anyone can reproduce.

It needs rustup and a container runtime with the `docker` command. It has been run with Docker Desktop on macOS; a Linux host with Docker runs it the same way. The first run builds every image from source and takes a while, because KumoMTA is a large Rust build. Later runs reuse the build cache.

`cargo harness quick --systems kumomta-async` measures KumoMTA as it ships, which acknowledges before its spool write is synced. Any profile also takes:
- `--repetitions n`, in place of the profile's repetitions;
- `--message-bytes n`, another message size, such as 102400 or 1048576;
- `--without signing`, `--without tls` or both: an ablation, in which every system runs without DKIM signing or without TLS on delivery, to show what that part costs. Submission keeps its TLS, since authentication needs it.

```sh
cargo harness smoke
```

This measures NitroMTA alone, for regressions. Each repetition builds a backlog of 20,000 recipients for its memory per queued recipient, then offers a fixed 2,000 messages a second for thirty seconds, well below saturation. It reports CPU and bytes written per message, memory per queued recipient and p99 latency, against the last smoke run on the same machine and runtime. A cost is marked changed when its median moved further than the wider of the two runs' ranges. It takes a few minutes once the images are built.

```sh
cargo harness throttled
```

This is many domains with one throttled destination. Recipients are spread over 1,000 domains on the sink, and a tenth go to a receiver of their own. That receiver allows 2 sessions and 50 messages a second, and answers 421 and closes beyond that. Budgets judge the sink's messages only. The throttled receiver's messages may be held, and are counted apart; once the search is over the throttle lifts, and every held message must arrive. The throttled receiver counts the sessions it refused, which shows how hard each system pushes a receiver that is refusing it. Every system retries on the same schedule: 10 seconds first, doubling, a minute at most. KumoMTA answers throttling as its deployments do, through its traffic-shaping automation daemon, which suspends the throttled receiver's site when it answers 421, for as long as the first retry waits.

```sh
cargo harness sites
```

This is receivers at a distance. Recipients are spread over 1,000 domains on 10 receiver sites, each with an exchange of its own, and the sink answers every exchange, the TLS handshake included, after a 30 ms round trip. Connection reuse, pipelining and concurrency count as well as CPU. Each system may open the same connections to each site.

```sh
cargo harness backlog
```

This is the backlog, personalised as most senders' mail is: 100,000 messages of one recipient each, every one a body of its own, spread over 1,000 domains and accepted while the sink refuses every session. `cargo harness backlog-shared` is its labelled variant: 1,000,000 recipients as 20,000 messages of 50, which share each message's body and favour a design that stores a body once. Each measures each system's memory with the backlog queued, a graceful stop and a start until a message is accepted again, and the drain once the sink opens. The sink opens only once every delivery waits at the longest retry interval, so no system's drain starts nearer its next attempts than another's. Each drain is reported as its time to empty and its peak: the most recipients that arrived in any five seconds. Every recipient must arrive exactly once.

```sh
cargo harness api
```

This is the API-ingress comparison, labelled apart from SMTP: NitroMTA's SES v2 `SendEmail` against KumoMTA's HTTP injection (Postfix has no HTTP API). Both receive the same messages as the SMTP runs, over HTTPS, with every request authenticated: SigV4 for SES, signed by the harness's own signer, and Basic authentication for KumoMTA. Each request carries one message to one recipient. Everything after ingress (signing, durability, delivery and the sink's checks) is the same as for SMTP.

```sh
cargo harness crash
```

These are the crash tests. Each system runs on LazyFS, a file system that keeps the file data written but not yet synced in its own memory. Under a steady 500 messages a second, the container is killed ten seconds in, which loses that data with LazyFS as a power failure would, and the system starts again on what it synced. Until it accepts again, the sink takes only 100 messages a second and refuses the rest for now, so most of what the system acknowledged is still queued at the kill, some waiting to retry and some in flight. Every recipient it acknowledged must arrive; deliveries in flight at the crash may arrive twice, and are counted until nothing has arrived for ten seconds longer than the longest retry interval.

A run counts only when it tested something. Some of the recipients the system acknowledged must still have been queued when it was killed, so it had mail to recover. LazyFS's cache must have been under 90% full just before the kill: once every page is used, LazyFS writes to the volume whether or not the data was synced.

LazyFS loses only file data. Creating, renaming and removing files and directories, and changing their modes, reach the volume at once, so these tests find mail acknowledged before its data was synced, but not a missing sync of a directory. The harness's LazyFS image adds the two operations its release leaves out, creating a FIFO or socket and reporting free space, which Postfix and KumoMTA need of their spools.

```sh
cargo harness kill
```

The same test with the process alone lost, part of the recovery evidence: the system runs on its own volume, without LazyFS, so the kill loses the process and what it held in memory, but not what it wrote and had not yet synced, as when the process dies and the host stays up.

## What a run does

1. **Checks the machine.** The profile names the CPUs and memory each system under test gets, and the fewest the tools need. A machine without them is refused, with what is missing.
2. **Builds** every image named in `recipe.toml`: KumoMTA, Postfix, OpenDKIM and unbound from their tagged sources, and the harness's own tools and the ceilings from this repository.
3. **Places** each system under test on its own CPU set with a memory limit, and the tools (the load generator, the sink and the resolver) on the CPUs left.
4. **Measures the tools' capacity** with nothing between them. No system is measured above half of it.
5. **Measures the ceilings** with the engine's own code on one of the systems' CPUs: RSA-2048 DKIM signatures of a 16 KiB message, and SigV4 verifications. Each system's rate is read as a share of what signing alone allows on its CPUs.
6. **Probes durability.** It times a flush on the queue volume. On macOS it compares that with the host's own durable flush (`F_FULLFSYNC`) on the same drive: a flush that returns faster than the drive can make a write durable stopped short of stable storage. Such a run is labelled not durable: ratios between systems still hold, but synchronous-commit claims do not. On Linux, a host with no visible hypervisor is labelled durable and a virtualised one unverified.
7. **Searches** for each system's highest sustained rate. It doubles the offered rate until a step misses a budget, then bisects. Systems are interleaved and repeated within the session: a reported comparison has at least three repetitions, and a run with fewer says it is a check. Each run measures the speed of its CPUs, and a session whose runs differ by more than a tenth is labelled unequal.

## What every system does

- Accepts authenticated submission on port 587: AUTH PLAIN after STARTTLS. In the API-ingress comparison, it accepts authenticated HTTPS requests on port 8443 instead.
- Signs with the same RSA-2048 key: `rsa-sha256`, relaxed/relaxed, over From, To, Subject, Date and Message-ID.
- Resolves the sink by its MX through the same local unbound, and delivers to it over required STARTTLS without verifying its certificate.
- Keeps to the same connections per receiver site and retries on the same schedule. The profile's `[delivery]` sets both (64 connections; first after 10 seconds, doubling, at most a minute apart), and the harness passes them to every system's configuration.
- Acknowledges after a durable write (`sync`), or before one in a separately labelled run (`async`).

Each system's configuration is in `images/<system>/`, with the reason for every setting that differs from the system's defaults. Maintainers are invited to correct them. A change shows in the configuration digests of every later result.

## How a step is judged

The load generator records when each message was due, sent and answered. The sink checks every message independently of whoever sent it, with its own DKIM verifier, the body's digest and the connection's TLS, and records when it arrived. The observer joins the two records.

- **A step counts** only if nothing accepted was lost or delivered twice, and every arrival passed every check. A step that does not count ends that system's run with the reason.
- **A step meets its budgets** if no submission was refused, the profile's share of the offered rate was accepted, and the 99th percentiles of submission and delivery latency are within the profile's budgets.

CPU, memory and bytes written come from each system's cgroup, which counts every process the system runs.

## Results

Each run writes `target/harness/<time>-<profile>/`:
- `result.json`: the command, the harness's commit, the recipe and profile, every image's id and source commits, the digest of every configuration file, the machine and runtime, the durability judgement, and every step;
- `logs/`: each system's log;
- `files/`: the keys and DNS zone the run generated.

## Not yet

- Postfix has no crash result. With the sink holding mail back, LazyFS's own memory grows without bound under Postfix's queue, which creates, renames and removes files as it defers mail, until the kernel kills LazyFS: 1.9 GiB at a 2 GiB limit, 2.9 GiB at 3 GiB, against a 1 GiB cache. An earlier run, before mail was held back, lost 3 acknowledged recipients and moved 3 damaged queue files aside at the restart. Both point at LazyFS rather than Postfix, but neither is shown, so neither is a claim about Postfix.
- Only the smoke, quick, sites, throttled, backlog, backlog-shared, API, crash and kill profiles exist. The quick profile's comparisons are of minutes on one machine, labelled with it; the full profile, with sustained runs, the million-recipient backlog and the aged store, is not built yet.
- The tools' capacity is measured over SMTP only, so an API run's ceiling does not yet include the cost of the load generator's HTTP and signing work.
