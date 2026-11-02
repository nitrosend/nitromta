//! `harness run <profile>`. It checks the machine, builds
//! every image from the recipe, places the systems under test and the tools on
//! separate CPUs, judges whether the queue volume is durable, then finds each
//! system's highest rate within the profile's budgets. Systems are
//! interleaved and repeated within the session, and every step is judged by
//! the observer from outside the system.
//!
//! A run leaves `target/harness/<time>-<profile>/` with `result.json`, the
//! systems' logs, and the keys and DNS zone it generated.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::rsa::{KeyPair, KeySize};
use aws_lc_rs::signature::KeyPair as _;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};

use crate::api::Ingress;
use crate::args::Args;
use crate::clock;
use crate::docker;
use crate::load;
use crate::observe::{Expected, Observer, Spread, Step};
use crate::probe;
use crate::recipe::{self, Ablation, Budgets, Durability, Profile, Recipe, System};
use crate::records::{Ack, Arrival};

/// The benchmark's own network, with fixed addresses so that the DNS zone can
/// name them: outside Docker's default address pools (172.17.0.0/16 to
/// 172.31.0.0/16, and 192.168.0.0/16), so no other project's network is
/// ever given it.
const NETWORK: &str = "harness";
const SUBNET: &str = "10.89.0.0/24";
const DNS_IP: &str = "10.89.0.2";
const SINK_IP: &str = "10.89.0.3";
const THROTTLED_IP: &str = "10.89.0.4";
const SUT_IP: &str = "10.89.0.10";
/// A production-shaped system's second egress.
const SUT_SECOND_IP: &str = "10.89.0.11";
const LOAD_IP: &str = "10.89.0.20";

const DNS: &str = "harness-dns";
const SINK: &str = "harness-sink";
const THROTTLED: &str = "harness-sink-throttled";
const SUT: &str = "harness-sut";
const LOAD: &str = "harness-load";
const VOLUME: &str = "harness-spool";
/// Every container the harness starts carries this label, so leftovers from
/// an interrupted run are found and removed.
const LABEL: &str = "harness";
/// The label an image built from the harness's own files carries: a digest
/// of everything it was built from.
const INPUTS: &str = "harness.inputs";

const SUT_NAME: &str = "sut.bench.test";
const SINK_NAME: &str = "mx.sink.test";
const SINK_DOMAIN: &str = "sink.test";
/// The throttled receiver, a site of its own: its own domain, exchange and
/// address.
const THROTTLED_NAME: &str = "mx.throttled.test";
const THROTTLED_DOMAIN: &str = "throttled.test";
/// The signing domain and selector every system is configured with.
const SIGNING_DOMAIN: &str = "bench.test";
const SELECTOR: &str = "bench";
const SENDER: &str = "load@bench.test";
const USER: &str = "bench";
/// The SES access key NitroMTA's configuration names; its secret is the
/// run's password.
const ACCESS_KEY: &str = "AKIDBENCH";

pub fn main(argv: &[String]) -> Result<(), String> {
    let args = Args::parse(
        argv,
        &["systems", "repetitions", "message-bytes", "without"],
    )?;
    let [name] = args.positional() else {
        return Err(
            "usage: harness run <profile> [--systems a,b] [--repetitions n] [--message-bytes n] [--without signing,tls]"
                .to_owned(),
        );
    };
    let harness = Path::new(env!("CARGO_MANIFEST_DIR"));
    let repository = harness
        .join("../..")
        .canonicalize()
        .map_err(|error| error.to_string())?;
    let recipe: Recipe = recipe::load(&harness.join("recipe.toml"))?;
    let mut profile: Profile =
        recipe::load(&harness.join("profiles").join(format!("{name}.toml")))?;
    if let Some(systems) = args.get("systems") {
        profile.systems = systems.split(',').map(str::to_owned).collect();
    }
    profile.repetitions = args.parse_or("repetitions", profile.repetitions)?;
    // Message sizes other than the profile's, such as 100 KiB and 1 MiB.
    profile.workload.message_bytes =
        args.parse_or("message-bytes", profile.workload.message_bytes)?;
    if let Some(without) = args.get("without") {
        profile.without = without
            .split(',')
            .map(recipe::Ablation::parse)
            .collect::<Result<_, _>>()?;
    }
    recipe.check(&profile.systems)?;
    let _awake = Awake::hold()?;

    let started = clock::now_micros();
    let out = repository
        .join("target/harness")
        .join(format!("{}-{name}", clock::compact_utc(started)));
    fs::create_dir_all(out.join("logs")).map_err(|error| format!("{}: {error}", out.display()))?;

    let info: serde_json::Value =
        serde_json::from_str(&docker::text(&["info", "--format", "{{json .}}"])?)
            .map_err(|error| format!("docker info: {error}"))?;
    let placement = place(&info, &profile)?;
    let images = build(&recipe, &profile, harness, &repository)?;
    let secrets = Secrets::generate(&out, &profile.workload)?;

    let _cleanup = Cleanup;
    Cleanup::remove();
    docker::run(&[
        "network", "create", "--label", LABEL, "--subnet", SUBNET, NETWORK,
    ])?;
    start_tools(&placement, &out)?;
    let session = Session {
        profile: &profile,
        recipe: &recipe,
        placement: &placement,
        secrets: &secrets,
        out: &out,
        issued: Mutex::new(None),
    };
    let capacity = session.capacity()?;
    println!("harness: the tools carry {capacity:.0} messages/s on their own");
    let ceilings = if profile.ceilings {
        session.ceilings()?
    } else {
        serde_json::Value::Null
    };
    let host_sync = host_full_sync(&out)?;

    let mut runs = Vec::new();
    for repetition in 0..profile.repetitions {
        let mut order = profile.systems.clone();
        if repetition % 2 == 1 {
            order.reverse();
        }
        for system in &order {
            if !runs.is_empty() && profile.search.cooldown_seconds > 0.0 {
                std::thread::sleep(Duration::from_secs_f64(profile.search.cooldown_seconds));
            }
            println!("harness: {system}, repetition {}", repetition + 1);
            let run = session.system(system, repetition, capacity);
            match (&run.error, &run.crash, &run.backlog, &run.sustained_rate) {
                (Some(error), ..) => println!("harness: {system}: {error}"),
                (None, Some(crash), ..) => println!(
                    "harness: {system}: {} recipients acknowledged, {} of them still queued at the crash, none lost",
                    crash.acknowledged, crash.queued_at_crash
                ),
                (None, None, Some(backlog), _) => println!(
                    "harness: {system}: {} recipients drained in {:.0} s",
                    backlog.recipients, backlog.drain_seconds
                ),
                (None, None, None, Some(rate)) => {
                    println!("harness: {system}: {rate:.0} messages/s");
                }
                (None, None, None, None) => println!("harness: {system}: no rate met the budgets"),
            }
            runs.push(run);
        }
    }

    let durability = runs
        .iter()
        .find_map(|run| run.probe.as_ref())
        .map(|probe| judge_durability(probe, host_sync.as_ref()));
    let summary = summarise(&profile, &recipe, &runs);
    let gauges: Vec<f64> = runs
        .iter()
        .filter_map(|run| run.probe.as_ref().map(|probe| probe.hash_mb_s))
        .filter(|gauge| *gauge > 0.0)
        .collect();
    let gauge_spread = (!gauges.is_empty()).then(|| {
        let fastest = gauges.iter().copied().fold(f64::MIN, f64::max);
        let slowest = gauges.iter().copied().fold(f64::MAX, f64::min);
        fastest / slowest - 1.0
    });
    let result = Report {
        schema: 1,
        profile: name.clone(),
        command: std::env::args().collect(),
        started: clock::iso_utc(started),
        finished: clock::iso_utc(clock::now_micros()),
        harness: commit(&repository),
        environment: Environment::gather(info),
        placement,
        images,
        configuration: configuration(&recipe, &profile, harness)?,
        durability,
        host_full_sync_us: host_sync,
        capacity,
        ceilings,
        gauge_spread,
        settings: profile.clone(),
        recipe: recipe.clone(),
        runs,
        summary,
        limitations: vec![
            "Each system's durability is set in its configuration and inspected in its source, but not yet proven by a crash test.".to_owned(),
            "The quick profile measures each system for minutes on one machine in one session: its ratios hold for that machine, labelled with it; sustained runs, the million-recipient backlog and the aged store belong to the full profile, which is not built yet.".to_owned(),
        ],
    };
    let path = out.join("result.json");
    let json = serde_json::to_string_pretty(&result).map_err(|error| error.to_string())?;
    fs::write(&path, json).map_err(|error| format!("{}: {error}", path.display()))?;
    print_summary(&result);
    if profile.fixed.is_some() {
        let current = serde_json::to_value(&result).map_err(|error| error.to_string())?;
        println!("\ncosts, as the median and range of each run's repetitions:");
        for line in crate::compare::compare(&out, name, &current) {
            println!("{line}");
        }
    }
    println!("harness: wrote {}", path.display());
    Ok(())
}

/// Keeps a Mac awake through a run. On battery power a Mac runs its CPUs
/// slower and may sleep part way through, so a run there is refused: a smoke
/// run on battery slept through two hours of its first repetition (28 October
/// 2026). Elsewhere it does nothing.
struct Awake(Option<std::process::Child>);

impl Awake {
    fn hold() -> Result<Self, String> {
        if !cfg!(target_os = "macos") {
            return Ok(Self(None));
        }
        let power = std::process::Command::new("pmset")
            .args(["-g", "ps"])
            .output()
            .map_err(|error| format!("pmset: {error}"))?;
        if String::from_utf8_lossy(&power.stdout).contains("'Battery Power'") {
            return Err(
                "this Mac is on battery power, which slows its CPUs and lets it sleep during a run; connect it to power".to_owned(),
            );
        }
        // No idle or system sleep while the run lasts, and none after it
        // ends, however it ends.
        let pid = std::process::id().to_string();
        let child = std::process::Command::new("caffeinate")
            .args(["-i", "-s", "-w", &pid])
            .spawn()
            .map_err(|error| format!("caffeinate: {error}"))?;
        Ok(Self(Some(child)))
    }
}

impl Drop for Awake {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// The CPUs and memory the systems under test and the tools get,
/// after checking that the runtime has them.
#[derive(Clone, Serialize)]
struct Placement {
    sut_cpus: String,
    sut_memory_mib: u64,
    tool_cpus: String,
}

fn place(info: &serde_json::Value, profile: &Profile) -> Result<Placement, String> {
    let wanted = &profile.placement;
    let cpus = info["NCPU"].as_u64().unwrap_or(0) as usize;
    let memory_mib = info["MemTotal"].as_u64().unwrap_or(0) / (1024 * 1024);
    let mut missing = Vec::new();
    if cpus < wanted.sut_cpus + wanted.tool_cpus {
        missing.push(format!(
            "{} CPUs ({} for each system under test and at least {} for the tools), and the container runtime has {cpus}",
            wanted.sut_cpus + wanted.tool_cpus,
            wanted.sut_cpus,
            wanted.tool_cpus
        ));
    }
    let memory = wanted.sut_memory_mib + wanted.tool_memory_mib;
    if memory_mib < memory {
        missing.push(format!(
            "{memory} MiB of memory, and the container runtime has {memory_mib} MiB"
        ));
    }
    if !missing.is_empty() {
        return Err(format!(
            "this profile needs {}",
            missing.join("; it also needs ")
        ));
    }
    Ok(Placement {
        sut_cpus: format!("0-{}", wanted.sut_cpus - 1),
        sut_memory_mib: wanted.sut_memory_mib,
        tool_cpus: format!("{}-{}", wanted.sut_cpus, cpus - 1),
    })
}

/// An image as built: its id and the source commits it was built from.
#[derive(Serialize)]
struct Built {
    id: String,
    sources: BTreeMap<String, String>,
    base: BTreeMap<String, String>,
}

fn build(
    recipe: &Recipe,
    profile: &Profile,
    harness: &Path,
    repository: &Path,
) -> Result<BTreeMap<String, Built>, String> {
    let mut names: BTreeSet<&str> = recipe::TOOLS
        .into_iter()
        .filter(|tool| profile.ceilings || *tool != "ceilings")
        .collect();
    let systems: BTreeSet<&str> = profile
        .systems
        .iter()
        .map(|system| recipe.systems[system].image.as_str())
        .collect();
    names.extend(&systems);
    let mut built = BTreeMap::new();
    for name in names {
        let context = if recipe.images[name].repository {
            repository.to_path_buf()
        } else {
            harness.join("images").join(name)
        };
        let image = build_image(
            recipe,
            harness,
            name,
            &format!("harness-{name}"),
            &context,
            &[],
        )?;
        built.insert(name.to_owned(), image);
    }
    // For the crash tests that lose power, each system's own image with
    // LazyFS beneath its spool.
    if profile.crash.as_ref().is_some_and(|crash| crash.power) {
        for system in systems {
            let image = build_image(
                recipe,
                harness,
                "lazyfs",
                &format!("harness-{system}-lazyfs"),
                &harness.join("images/lazyfs"),
                &[("BASE", format!("harness-{system}"))],
            )?;
            built.insert(format!("{system}-lazyfs"), image);
        }
    }
    Ok(built)
}

/// Builds `images/<name>` as `tag` from `context`, with the recipe's base
/// images, the image's sources and any `extra` build arguments, and records
/// what it was built from.
fn build_image(
    recipe: &Recipe,
    harness: &Path,
    name: &str,
    tag: &str,
    context: &Path,
    extra: &[(&str, String)],
) -> Result<Built, String> {
    let image = &recipe.images[name];
    let mut args: Vec<String> = ["build", "--tag", tag, "--label", LABEL, "--file"]
        .iter()
        .map(|arg| (*arg).to_owned())
        .collect();
    args.push(
        harness
            .join("images")
            .join(name)
            .join("Dockerfile")
            .display()
            .to_string(),
    );
    for (key, value) in [
        ("BUILD_BASE", recipe.base.build.as_str()),
        ("RUNTIME_BASE", recipe.base.runtime.as_str()),
    ]
    .into_iter()
    .chain(extra.iter().map(|(key, value)| (*key, value.as_str())))
    {
        args.extend(["--build-arg".to_owned(), format!("{key}={value}")]);
    }
    for source in &image.sources {
        let named = source.to_ascii_uppercase().replace('-', "_");
        let source = &recipe.sources[source];
        args.extend([
            "--build-arg".to_owned(),
            format!("{named}_URL={}", source.url),
        ]);
        args.extend([
            "--build-arg".to_owned(),
            format!("{named}_TAG={}", source.tag),
        ]);
    }
    args.push(context.display().to_string());
    // An image built from the harness's own files rather than the
    // repository's, such as a pinned system's, is built again only when
    // what it is built from changes: its build takes minutes, KumoMTA's
    // eleven, and the builder's cache may not have kept its layers.
    let inputs = if image.repository {
        None
    } else {
        Some(inputs(&harness.join("images").join(name), &args, extra)?)
    };
    let built = inputs.as_ref().is_some_and(|inputs| {
        docker::text(&[
            "image",
            "inspect",
            "--format",
            &format!("{{{{index .Config.Labels \"{INPUTS}\"}}}}"),
            tag,
        ])
        .is_ok_and(|label| label == *inputs)
    });
    if built {
        println!("harness: {tag} is built from these inputs already");
    } else {
        if let Some(inputs) = &inputs {
            let at = args.len() - 1;
            args.splice(at..at, ["--label".to_owned(), format!("{INPUTS}={inputs}")]);
        }
        println!("harness: building {tag}");
        docker::shown_run(&args.iter().map(String::as_str).collect::<Vec<_>>())?;
    }
    let id = docker::text(&["image", "inspect", "--format", "{{.Id}}", tag])?;
    let listed = docker::text(&[
        "run",
        "--rm",
        "--entrypoint",
        "cat",
        tag,
        "/etc/harness/sources",
    ])?;
    let sources = listed
        .lines()
        .filter_map(|line| line.split_once(' '))
        .map(|(source, commit)| (source.to_owned(), commit.to_owned()))
        .collect();
    let mut base = BTreeMap::new();
    for image in [&recipe.base.build, &recipe.base.runtime] {
        if let Ok(digest) = docker::text(&[
            "image",
            "inspect",
            "--format",
            "{{index .RepoDigests 0}}",
            image,
        ]) {
            base.insert(image.clone(), digest);
        }
    }
    Ok(Built { id, sources, base })
}

/// A digest of what an image is built from: every file in its directory,
/// by path, its build's arguments, and the image each `extra` argument
/// names, as it is now.
fn inputs(directory: &Path, args: &[String], extra: &[(&str, String)]) -> Result<String, String> {
    let mut files = Vec::new();
    let mut pending = vec![directory.to_path_buf()];
    while let Some(next) = pending.pop() {
        for entry in fs::read_dir(&next).map_err(|error| format!("{}: {error}", next.display()))? {
            let path = entry.map_err(|error| error.to_string())?.path();
            if path.is_dir() {
                pending.push(path);
            } else {
                files.push(path);
            }
        }
    }
    files.sort();
    let mut context = aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA256);
    for path in &files {
        let relative = path.strip_prefix(directory).unwrap_or(path);
        context.update(relative.display().to_string().as_bytes());
        context.update(&[0]);
        context.update(&fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?);
        context.update(&[0]);
    }
    for arg in args {
        context.update(arg.as_bytes());
        context.update(&[0]);
    }
    for (_, value) in extra {
        if let Ok(id) = docker::text(&["image", "inspect", "--format", "{{.Id}}", value]) {
            context.update(id.as_bytes());
        }
    }
    Ok(context
        .finish()
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

/// The keys and password one run uses, written beside its result.
struct Secrets {
    /// The DKIM public key as DNS publishes it: base64 SubjectPublicKeyInfo.
    dkim_public: String,
    password: String,
}

impl Secrets {
    fn generate(out: &Path, workload: &recipe::Workload) -> Result<Self, String> {
        let failed = |what: &str| format!("generating {what}");
        let pair = KeyPair::generate(KeySize::Rsa2048).map_err(|_| failed("the DKIM key"))?;
        let private = pair.as_der().map_err(|_| failed("the DKIM key"))?;
        let public = pair
            .public_key()
            .as_der()
            .map_err(|_| failed("the DKIM key"))?;
        let dkim_public = STANDARD.encode(public.as_ref());
        let identity = crate::tls::self_signed(SUT_NAME)?;
        let mut password = [0u8; 16];
        aws_lc_rs::rand::fill(&mut password).map_err(|_| failed("the password"))?;

        let files = out.join("files/sut");
        for (path, contents) in [
            ("tls/sut.crt", identity.certificate),
            ("tls/sut.key", identity.key),
            ("dkim/private.pem", pem("PRIVATE KEY", private.as_ref())),
        ] {
            let path = files.join(path);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).map_err(|error| error.to_string())?;
            }
            fs::write(&path, contents).map_err(|error| format!("{}: {error}", path.display()))?;
        }
        let zone = out.join("files/unbound.conf");
        fs::write(
            &zone,
            unbound_conf(&dkim_public, workload.domains, workload.sites),
        )
        .map_err(|error| format!("{}: {error}", zone.display()))?;
        Ok(Self {
            dkim_public,
            password: crate::hex(&password),
        })
    }
}

fn pem(label: &str, der: &[u8]) -> String {
    let encoded = STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in encoded.as_bytes().chunks(64) {
        out.push_str(&String::from_utf8_lossy(line));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

/// Unbound answers every name itself and refuses to recurse, so nothing
/// leaves the benchmark's network, and every system resolves through the
/// same local unbound. The sink's `domains` (`d0.sink.test` and on,
/// when there is more than one) share its exchange; the throttled receiver
/// has its own.
/// The DNS zone: the sink's domains, spread over `sites` exchanges, each a
/// receiver site of its own, all answering at the sink's address.
fn unbound_conf(dkim_public: &str, domains: usize, sites: usize) -> String {
    let record = format!("v=DKIM1; k=rsa; p={dkim_public}");
    let strings: Vec<String> = record
        .as_bytes()
        .chunks(255)
        .map(|chunk| format!("\"{}\"", String::from_utf8_lossy(chunk)))
        .collect();
    let exchange = |n: usize| {
        if sites > 1 {
            format!("mx{}.{SINK_DOMAIN}", n % sites)
        } else {
            SINK_NAME.to_owned()
        }
    };
    let spread: String = (0..domains)
        .filter(|_| domains > 1)
        .map(|n| {
            format!(
                "    local-data: \"d{n}.{SINK_DOMAIN}. 3600 IN MX 10 {}.\"\n",
                exchange(n)
            )
        })
        .chain((0..sites).filter(|_| sites > 1).map(|site| {
            format!(
                "    local-data: \"{}. 3600 IN A {SINK_IP}\"\n",
                exchange(site)
            )
        }))
        .collect();
    format!(
        "server:
    interface: 0.0.0.0
    access-control: 0.0.0.0/0 allow
    do-ip6: no
    do-daemonize: no
    username: \"\"
    chroot: \"\"
    use-syslog: no
    logfile: \"\"
    verbosity: 0
    num-threads: 2
    module-config: \"iterator\"
    local-zone: \".\" static
    local-data: \"{SINK_DOMAIN}. 3600 IN MX 10 {SINK_NAME}.\"
    local-data: \"{SINK_NAME}. 3600 IN A {SINK_IP}\"
    local-data: \"{THROTTLED_DOMAIN}. 3600 IN MX 10 {THROTTLED_NAME}.\"
    local-data: \"{THROTTLED_NAME}. 3600 IN A {THROTTLED_IP}\"
    local-data: \"{SUT_NAME}. 3600 IN A {SUT_IP}\"
    local-data: \"load.{SIGNING_DOMAIN}. 3600 IN A {LOAD_IP}\"
    local-data: '{SELECTOR}._domainkey.{SIGNING_DOMAIN}. 3600 IN TXT {}'
    local-data-ptr: \"{SINK_IP} {SINK_NAME}.\"
    local-data-ptr: \"{THROTTLED_IP} {THROTTLED_NAME}.\"
    local-data-ptr: \"{SUT_IP} {SUT_NAME}.\"
    local-data-ptr: \"{LOAD_IP} load.{SIGNING_DOMAIN}.\"
{spread}",
        strings.join(" ")
    )
}

/// Removes everything the harness started, when a run ends however it ends.
struct Cleanup;

impl Cleanup {
    fn remove() {
        if let Ok(listed) = docker::text(&[
            "ps",
            "--all",
            "--quiet",
            "--filter",
            &format!("label={LABEL}"),
        ]) {
            for container in listed.lines() {
                docker::quietly(&["rm", "--force", "--volumes", container]);
            }
        }
        docker::quietly(&["volume", "rm", "--force", VOLUME]);
        docker::quietly(&["network", "rm", NETWORK]);
    }
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        Self::remove();
    }
}

/// The common options of every container on the benchmark's network.
fn container(name: &str, ip: &str, cpus: &str) -> Vec<String> {
    [
        "--name",
        name,
        "--label",
        LABEL,
        "--network",
        NETWORK,
        "--ip",
        ip,
        "--cpuset-cpus",
        cpus,
        "--dns",
        DNS_IP,
    ]
    .iter()
    .map(|arg| (*arg).to_owned())
    .collect()
}

fn start_tools(placement: &Placement, out: &Path) -> Result<(), String> {
    let mut dns = vec!["create".to_owned()];
    dns.extend(container(DNS, DNS_IP, &placement.tool_cpus));
    dns.push("harness-unbound".to_owned());
    docker::run(&dns.iter().map(String::as_str).collect::<Vec<_>>())?;
    let zone = out.join("files/unbound.conf").display().to_string();
    docker::run(&["cp", &zone, &format!("{DNS}:/etc/unbound/unbound.conf")])?;
    docker::run(&["start", DNS])?;

    let mut load = vec!["run".to_owned(), "--detach".to_owned()];
    load.extend(container(LOAD, LOAD_IP, &placement.tool_cpus));
    load.extend([
        "harness-harness".to_owned(),
        "sleep".to_owned(),
        "infinity".to_owned(),
    ]);
    docker::run(&load.iter().map(String::as_str).collect::<Vec<_>>())?;
    Ok(())
}

struct Session<'a> {
    profile: &'a Profile,
    recipe: &'a Recipe,
    placement: &'a Placement,
    secrets: &'a Secrets,
    out: &'a Path,
    /// The credentials the system under test issued, read once it started.
    issued: Mutex<Option<Issued>>,
}

/// The secrets a system issued itself, by ingress.
#[derive(Clone, Deserialize)]
struct Issued {
    smtp: Login,
    ses: Login,
    /// Its event subscription's secret, production-shaped.
    #[serde(default)]
    hooks: String,
}

#[derive(Clone, Deserialize)]
struct Login {
    user: String,
    password: String,
}

/// One system's run in one repetition.
#[derive(Serialize)]
struct SystemRun {
    system: String,
    repetition: usize,
    durability: Durability,
    probe: Option<probe::Report>,
    sink_sessions: BTreeMap<String, u64>,
    /// The most sessions the system kept open to the sink at once.
    sink_most_open: Option<u64>,
    /// What its event subscription delivered, production-shaped.
    hooks: Option<crate::hooks::Stats>,
    /// The throttled receiver's counters: what it took, and what it refused.
    throttled_sink: Option<crate::sink::Stats>,
    /// Once the search was over and the throttle lifted, how the held
    /// messages arrived.
    release: Option<Release>,
    /// The backlog profile's measurements, in place of a search.
    backlog: Option<BacklogRecord>,
    /// A crash test's account, in place of a search.
    crash: Option<CrashRecord>,
    warmup: Option<StepRecord>,
    steps: Vec<StepRecord>,
    /// The highest offered rate whose step met every budget.
    sustained_rate: Option<f64>,
    /// Why the search stopped short of finding where the system fails.
    limited_by: Option<String>,
    error: Option<String>,
}

#[derive(Clone, Serialize)]
struct Release {
    /// Messages held for the throttled receiver when the throttle lifted.
    held: u64,
    /// How long they took to arrive, or the deadline when some did not.
    seconds: f64,
    /// Accepted messages that never arrived.
    missing: u64,
}

#[derive(Clone, Serialize)]
struct BacklogRecord {
    /// Recipients accepted into the backlog.
    recipients: u64,
    /// The system's own memory before the backlog: what it uses idle.
    idle_anon_mib: f64,
    /// How long it took to submit.
    fill_seconds: f64,
    /// Once it settled: the system's own memory, and with its file cache.
    queued_anon_mib: f64,
    queued_memory_mib: f64,
    /// A graceful stop, then from the start until a message was accepted.
    stop_seconds: f64,
    start_seconds: f64,
    /// Once it settled after the start.
    restarted_anon_mib: f64,
    restarted_memory_mib: f64,
    /// From the sink opening until every recipient arrived, or the deadline
    /// when some did not.
    drain_seconds: f64,
    drain_recipients_per_second: f64,
    /// The most recipients that arrived in any five seconds of the drain, a
    /// second: how fast the system delivers once its retries come due.
    drain_peak_per_second: f64,
    /// Whether that peak passed half the tools' capacity, so the tools, not
    /// the system, may have set it.
    drain_above_headroom: bool,
    drain: Usage,
    /// The drain's highest memory, its file cache included.
    drain_peak_memory_mib: f64,
    /// The drain by the address its sessions came from, the system's
    /// egresses.
    drain_by_source: Vec<SourceDrain>,
    /// Recipients accepted that never arrived.
    missing: u64,
}

#[derive(Clone, Serialize)]
struct SourceDrain {
    address: String,
    /// Recipients that arrived from it.
    recipients: u64,
    /// When the last of them arrived, after the drain's first arrival from
    /// any address. Both times are the sink's, so no two clocks meet.
    last_seconds: f64,
}

#[derive(Clone, Serialize)]
struct CrashRecord {
    /// Recipients the system acknowledged before it was killed.
    acknowledged: u64,
    /// Of those, the recipients that had not arrived when it was killed,
    /// which it had to recover from what it synced.
    queued_at_crash: u64,
    /// Whether the power failed with it, or the process alone was lost.
    power: bool,
    /// How full LazyFS's cache was just before the kill, in percent of its
    /// pages: none without the power failing.
    cache_percent: f64,
    /// When, into the load, the container was killed.
    killed_after_seconds: f64,
    /// From the start until a message was accepted again.
    start_seconds: f64,
    /// Recipients that arrived, before the crash and after it.
    delivered: u64,
    /// Second and later arrivals: deliveries in flight at the crash, which
    /// may arrive twice.
    duplicates: u64,
    /// Acknowledged recipients that never arrived: loss.
    missing: u64,
    /// From the start until every acknowledged recipient arrived, or the
    /// deadline when some did not.
    drain_seconds: f64,
}

#[derive(Clone, Serialize)]
struct StepRecord {
    #[serde(flatten)]
    observed: Step,
    drain_seconds: f64,
    usage: Usage,
    /// Why the step missed its budgets; empty when it met them.
    misses: Vec<String>,
    errors: Vec<String>,
}

/// Runs whose CPU gauges differ by more than this are an unequal session.
const UNEQUAL_GAUGES: f64 = 0.1;
/// The fewest repetitions a reported comparison has.
const REPORTED_REPETITIONS: usize = 3;

/// The window a drain's peak rate is measured over.
const PEAK_WINDOW: Duration = Duration::from_secs(5);

/// After a crash, once nothing acknowledged is missing, how long nothing
/// must arrive beyond the longest retry interval before the system is done
/// with, so any repeat it had scheduled has come.
const SETTLE: Duration = Duration::from_secs(10);

/// LazyFS writes to the volume, synced or not, once every page of its cache
/// is used. A crash test whose cache was fuller than this just before the
/// kill does not count.
const CACHE_PERCENT_LIMIT: f64 = 90.0;

/// The most arrivals in any `window`, a second. `at` holds arrival times in
/// microseconds.
fn peak_rate(at: &mut [i64], window: Duration) -> f64 {
    at.sort_unstable();
    let span = i64::try_from(window.as_micros()).unwrap_or(i64::MAX);
    let mut start = 0;
    let mut most = 0;
    for end in 0..at.len() {
        while at[end] - at[start] >= span {
            start += 1;
        }
        most = most.max(end - start + 1);
    }
    most as f64 / window.as_secs_f64()
}

/// The system under test's cgroup counters over a step and its drain, which
/// count every process the system runs.
#[derive(Clone, Serialize)]
struct Usage {
    cpu_seconds: f64,
    cpu_ms_per_message: Option<f64>,
    memory_mib: f64,
    peak_memory_mib: f64,
    written_mib: f64,
    written_kib_per_message: Option<f64>,
}

#[derive(Clone, Copy, Default)]
struct Counters {
    cpu_us: u64,
    /// Memory charged to the system, its file cache included.
    memory: u64,
    peak: u64,
    /// The system's own memory: anonymous pages, no file cache.
    anon: u64,
    written: u64,
}

impl Session<'_> {
    /// Whether every system runs with this part, rather than without it.
    fn has(&self, part: Ablation) -> bool {
        !self.profile.without.contains(&part)
    }

    /// What every arrival must have passed, given what the systems run
    /// without.
    fn expected(&self) -> Expected {
        Expected {
            signed: self.has(Ablation::Signing),
            tls: self.has(Ablation::Tls),
        }
    }

    /// How fast the load generator and the sink run together, with nothing
    /// between them: the most the harness can measure on this machine.
    fn capacity(&self) -> Result<f64, String> {
        // Always against an open sink, whatever the profile does with it.
        self.start_one(SINK, SINK_IP, SINK_NAME, SINK_DOMAIN, &[])?;
        let seconds = self.profile.search.headroom_seconds;
        let output = docker::run(&[
            "exec",
            LOAD,
            "harness",
            "load",
            "--target",
            &format!("{SINK_IP}:25"),
            "--server-name",
            SINK_NAME,
            "--connections",
            &self.profile.workload.connections.to_string(),
            "--seconds",
            &seconds.to_string(),
            "--size",
            &self.profile.workload.message_bytes.to_string(),
            "--domain",
            SINK_DOMAIN,
        ])?;
        let summary = summary(&output.stderr)?;
        docker::quietly(&["rm", "--force", SINK]);
        Ok(summary.accepted as f64 / seconds)
    }

    /// The component ceilings, measured with the engine's own
    /// code on the first of the systems' CPUs.
    fn ceilings(&self) -> Result<serde_json::Value, String> {
        let cpu = self
            .placement
            .sut_cpus
            .split([',', '-'])
            .next()
            .unwrap_or("0");
        let output = docker::text(&[
            "run",
            "--rm",
            "--label",
            LABEL,
            "--cpuset-cpus",
            cpu,
            "harness-ceilings",
        ])?;
        serde_json::from_str(&output).map_err(|error| format!("the ceilings: {error}"))
    }

    /// Starts the sink, and the throttled receiver when the profile has
    /// one.
    fn start_sink(&self) -> Result<(), String> {
        // For a backlog, the sink refuses every session until it is
        // released.
        let mut extra = vec![
            "--round-trip-ms".to_owned(),
            self.profile.workload.round_trip_ms.to_string(),
        ];
        if self.profile.backlog.is_some() {
            extra.extend(["--throttle-connections".to_owned(), "0".to_owned()]);
        }
        // For a crash, it takes too little to keep up until it is released.
        if let Some(crash) = &self.profile.crash {
            extra.extend([
                "--throttle-connections".to_owned(),
                crash.sink_connections.to_string(),
                "--throttle-rate".to_owned(),
                crash.sink_rate.to_string(),
            ]);
        }
        if !self.has(Ablation::Tls) {
            extra.extend(["--starttls".to_owned(), "false".to_owned()]);
        }
        self.start_one(SINK, SINK_IP, SINK_NAME, SINK_DOMAIN, &extra)?;
        if let Some(throttle) = &self.profile.throttle {
            let limits = [
                "--throttle-connections".to_owned(),
                throttle.connections.to_string(),
                "--throttle-rate".to_owned(),
                throttle.rate.to_string(),
                "--round-trip-ms".to_owned(),
                self.profile.workload.round_trip_ms.to_string(),
            ]
            .into_iter()
            .chain(
                (!self.has(Ablation::Tls))
                    .then(|| ["--starttls".to_owned(), "false".to_owned()])
                    .into_iter()
                    .flatten(),
            )
            .collect::<Vec<_>>();
            self.start_one(
                THROTTLED,
                THROTTLED_IP,
                THROTTLED_NAME,
                THROTTLED_DOMAIN,
                &limits,
            )?;
        }
        Ok(())
    }

    fn start_one(
        &self,
        name: &str,
        ip: &str,
        hostname: &str,
        domain: &str,
        extra: &[String],
    ) -> Result<(), String> {
        docker::quietly(&["rm", "--force", name]);
        let mut args = vec!["run".to_owned(), "--detach".to_owned()];
        args.extend(container(name, ip, &self.placement.tool_cpus));
        args.extend(
            [
                "harness-harness",
                "harness",
                "sink",
                "--hostname",
                hostname,
                "--domain",
                domain,
                "--dkim-domain",
                SIGNING_DOMAIN,
                "--dkim-selector",
                SELECTOR,
                "--dkim-key",
                &self.secrets.dkim_public,
            ]
            .iter()
            .map(|arg| (*arg).to_owned()),
        );
        args.extend(extra.iter().cloned());
        docker::run(&args.iter().map(String::as_str).collect::<Vec<_>>())?;
        // A sink is ready when its control port answers.
        wait("the sink", Duration::from_secs(30), || {
            docker::run(&["exec", name, "harness", "sink-ctl", "stats"])
                .map(|_| ())
                .map_err(NotReady::Yet)
        })
    }

    /// Arrivals at every sink since the last take.
    fn take(&self) -> Result<Vec<Arrival>, String> {
        let mut arrivals = Vec::new();
        let sinks = if self.profile.throttle.is_some() {
            &[SINK, THROTTLED][..]
        } else {
            &[SINK][..]
        };
        for sink in sinks {
            arrivals.extend(Arrival::decode_all(
                &docker::run(&["exec", sink, "harness", "sink-ctl", "take"])?.stdout,
            )?);
        }
        Ok(arrivals)
    }

    /// Builds a backlog while the sink refuses every session, reads the
    /// system's memory, restarts it, then opens the sink and waits for every
    /// recipient to arrive. Returns the record, and the next message ID.
    fn backlog(
        &self,
        system: &System,
        backlog: &recipe::Backlog,
        capacity: f64,
    ) -> Result<(BacklogRecord, u64), String> {
        const MIB: f64 = 1024.0 * 1024.0;
        let per_message = u64::from(self.profile.workload.recipients.max(1));
        let mut observer =
            Observer::new(0.0, self.profile.workload.recipients).expecting(self.expected());
        let settle = Duration::from_secs_f64(backlog.settle_seconds);
        let idle = counters()?;

        // Fill: every message submitted as fast as the system takes them.
        let output = self.load(
            system,
            self.profile.workload.connections,
            0.0,
            3600.0,
            1,
            Some(backlog.messages),
        )?;
        let summary = summary(&output.stderr)?;
        let acks = Ack::decode_all(&output.stdout)?;
        let refused = acks.iter().filter(|ack| !ack.accepted()).count();
        if refused > 0 || (acks.len() as u64) < backlog.messages {
            return Err(format!(
                "{refused} of {} messages were refused while the backlog filled ({:?}); {}",
                acks.len(),
                summary.failures,
                summary.errors.join("; ")
            ));
        }
        observer.step(0.0, 0.0, &acks, &[]);
        let filled = Instant::now();
        let fill_seconds = (summary.ended - summary.started) as f64 / 1e6;
        let mut next_id = 1 + acks.len() as u64;
        std::thread::sleep(settle);
        let queued = counters()?;

        // A graceful stop, then a start: useful again once a message is
        // accepted, which joins the backlog.
        let stopping = Instant::now();
        docker::run(&["stop", "--time", "60", SUT])?;
        let stop_seconds = stopping.elapsed().as_secs_f64();
        let starting = Instant::now();
        docker::run(&["start", SUT])?;
        let deadline = starting + Duration::from_secs(600);
        let start_seconds = loop {
            if let Ok(output) = self.load(system, 1, 0.0, 60.0, next_id, Some(1)) {
                let acks = Ack::decode_all(&output.stdout)?;
                next_id += acks.len() as u64;
                observer.step(0.0, 0.0, &acks, &[]);
                if acks.iter().any(Ack::accepted) {
                    break starting.elapsed().as_secs_f64();
                }
            }
            if Instant::now() >= deadline {
                return Err("no message was accepted within 10 minutes of the start".to_owned());
            }
            std::thread::sleep(Duration::from_millis(100));
        };
        std::thread::sleep(settle);
        let restarted = counters()?;

        // Every system's deliveries retry on the same schedule. Twice its
        // longest interval after the last acceptance, every delivery has
        // reached that interval, so no system's drain starts nearer its next
        // attempts than another's.
        if backlog.open_at_longest_retry {
            let longest = Duration::from_secs(2 * self.profile.delivery.retry_max_seconds);
            if let Some(rest) = longest.checked_sub(filled.elapsed()) {
                std::thread::sleep(rest);
            }
        }

        // Drain: the sink opens, and every recipient must arrive once.
        let before = counters()?;
        docker::run(&["exec", SINK, "harness", "sink-ctl", "release"])?;
        let draining = Instant::now();
        let deadline = draining + Duration::from_secs_f64(backlog.drain_seconds);
        let (outstanding, _) = observer.outstanding();
        let mut delivered = 0;
        let mut arrived = Vec::new();
        let mut sources: BTreeMap<std::net::IpAddr, (u64, i64)> = BTreeMap::new();
        loop {
            let taken = self.take()?;
            arrived.extend(taken.iter().map(|arrival| arrival.at));
            for arrival in &taken {
                let (recipients, last) = sources.entry(arrival.source).or_insert((0, i64::MIN));
                *recipients += 1;
                *last = (*last).max(arrival.at);
            }
            let step = observer.step(0.0, 0.0, &[], &taken);
            delivered += step.delivered;
            let faults: Vec<String> = step
                .faults()
                .into_iter()
                .filter(|fault| !fault.contains("never reached the sink"))
                .collect();
            if !faults.is_empty() {
                return Err(faults.join("; "));
            }
            if step.missing == 0 || Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        let drain_seconds = draining.elapsed().as_secs_f64();
        let after = counters()?;
        let (missing, _) = observer.outstanding();
        if missing > 0 {
            return Err(format!(
                "{missing} of {outstanding} recipients never arrived, {drain_seconds:.0} s after the sink opened"
            ));
        }
        let first = arrived.iter().min().copied().unwrap_or_default();
        let drain_by_source = sources
            .into_iter()
            .map(|(address, (recipients, last))| SourceDrain {
                address: address.to_string(),
                recipients,
                last_seconds: (last - first) as f64 / 1e6,
            })
            .collect();
        let peak = peak_rate(&mut arrived, PEAK_WINDOW);
        let record = BacklogRecord {
            recipients: backlog.messages * per_message,
            idle_anon_mib: idle.anon as f64 / MIB,
            fill_seconds,
            queued_anon_mib: queued.anon as f64 / MIB,
            queued_memory_mib: queued.memory as f64 / MIB,
            stop_seconds,
            start_seconds,
            restarted_anon_mib: restarted.anon as f64 / MIB,
            restarted_memory_mib: restarted.memory as f64 / MIB,
            drain_seconds,
            drain_recipients_per_second: delivered as f64 / drain_seconds,
            drain_peak_per_second: peak,
            drain_above_headroom: peak > capacity / self.profile.search.headroom,
            drain: usage(before, after, delivered),
            drain_peak_memory_mib: after.peak as f64 / MIB,
            drain_by_source,
            missing,
        };
        Ok((record, next_id))
    }

    /// Kills the system part way through a steady load, starts it again, and
    /// waits for every recipient it acknowledged.
    fn crash(&self, system: &System, crash: &recipe::Crash) -> Result<CrashRecord, String> {
        let mut observer =
            Observer::new(0.0, self.profile.workload.recipients).expecting(self.expected());
        let killing = Instant::now();
        let output = std::thread::scope(|scope| {
            let load = scope.spawn(|| {
                self.load(
                    system,
                    self.profile.workload.connections,
                    crash.rate,
                    crash.seconds,
                    1,
                    None,
                )
            });
            std::thread::sleep(Duration::from_secs_f64(crash.after_seconds));
            // How much a power failure loses: none of it, on the process's
            // own volume.
            let cache_percent = if crash.power {
                cache_percent()
            } else {
                Ok(0.0)
            };
            // The container dies at once, the system and LazyFS together:
            // every write of file data not yet synced lived only in LazyFS's
            // memory, and is lost with it, as in a power failure. Dropping
            // LazyFS's cache first would leave the system running on a disk
            // that had lost writes, so it could acknowledge a commit whose
            // sync succeeded only because the data it was to sync was
            // already gone.
            docker::run(&["kill", SUT])?;
            let killed_after_seconds = killing.elapsed().as_secs_f64();
            let output = load
                .join()
                .map_err(|_| "the load generator panicked".to_owned())??;
            Ok::<_, String>((output, killed_after_seconds, cache_percent?))
        });
        let (output, killed_after_seconds, cache_percent) = output?;
        if cache_percent > CACHE_PERCENT_LIMIT {
            return Err(format!(
                "LazyFS's cache was {cache_percent:.0}% full at the crash; once full, it writes to the volume unsynced, so the crash cannot lose what a power failure would"
            ));
        }
        let acks = Ack::decode_all(&output.stdout)?;
        let acknowledged = acks.iter().filter(|ack| ack.accepted()).count() as u64
            * u64::from(self.profile.workload.recipients.max(1));
        let mut faults = Vec::new();
        // Everything that arrived before the crash: the load ran on for a
        // while after it, so the sink has written down every one.
        let mut steps = vec![observer.step(0.0, 0.0, &acks, &self.take()?)];
        let (queued_at_crash, _) = observer.outstanding();
        if queued_at_crash == 0 {
            return Err(
                "every recipient it acknowledged had arrived before the crash, so it had nothing to recover".to_owned(),
            );
        }
        let mut next_id = acks.iter().map(|ack| ack.id).max().unwrap_or(0) + 1;

        let starting = Instant::now();
        docker::run(&["start", SUT])?;
        let deadline = starting + Duration::from_secs(600);
        let start_seconds = loop {
            if let Ok(output) = self.load(system, 1, 0.0, 60.0, next_id, Some(1)) {
                let acks = Ack::decode_all(&output.stdout)?;
                next_id += acks.len() as u64;
                steps.push(observer.step(0.0, 0.0, &acks, &[]));
                if acks.iter().any(Ack::accepted) {
                    break starting.elapsed().as_secs_f64();
                }
            }
            if Instant::now() >= deadline {
                return Err("no message was accepted within 10 minutes of the start".to_owned());
            }
            std::thread::sleep(Duration::from_millis(100));
        };
        // From now on the sink takes everything, so what it held back can
        // arrive.
        docker::run(&["exec", SINK, "harness", "sink-ctl", "release"])?;

        let deadline = starting + Duration::from_secs_f64(crash.drain_seconds);
        let quiet = Duration::from_secs(self.profile.delivery.retry_max_seconds) + SETTLE;
        let mut drained = None;
        let mut last_arrival = Instant::now();
        loop {
            let arrivals = self.take()?;
            if !arrivals.is_empty() {
                last_arrival = Instant::now();
            }
            let step = observer.step(0.0, 0.0, &[], &arrivals);
            if step.missing == 0 {
                drained.get_or_insert_with(|| starting.elapsed().as_secs_f64());
            }
            steps.push(step);
            // Once nothing is missing, it is watched until nothing has
            // arrived for longer than its longest retry interval, so a
            // delivery it repeats late is counted. The deadline is for the
            // missing alone.
            let settled = drained.is_some() && last_arrival.elapsed() >= quiet;
            if settled || (drained.is_none() && Instant::now() >= deadline) {
                break;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        let drain_seconds = drained.unwrap_or_else(|| starting.elapsed().as_secs_f64());
        for step in &steps {
            // Arriving twice is allowed after a crash, and counted; every
            // other fault is not.
            faults.extend(step.faults().into_iter().filter(|fault| {
                !fault.contains("more than once") && !fault.contains("never reached the sink")
            }));
        }
        if !faults.is_empty() {
            return Err(faults.join("; "));
        }
        let (missing, _) = observer.outstanding();
        Ok(CrashRecord {
            acknowledged,
            queued_at_crash,
            power: crash.power,
            cache_percent,
            killed_after_seconds,
            start_seconds,
            delivered: steps.iter().map(|step| step.delivered).sum(),
            duplicates: steps.iter().map(|step| step.duplicates).sum(),
            missing,
            drain_seconds,
        })
    }

    /// Lifts the throttle, then waits for every held message to arrive.
    fn release(
        &self,
        context: &mut Context,
        throttle: &recipe::Throttle,
    ) -> Result<Release, String> {
        let (_, held_back) = context.observer.outstanding();
        docker::run(&["exec", THROTTLED, "harness", "sink-ctl", "release"])?;
        let started = Instant::now();
        let deadline = started + Duration::from_secs_f64(throttle.release_seconds);
        loop {
            let arrivals = self.take()?;
            let step = context.observer.step(0.0, 0.0, &[], &arrivals);
            let faults = step.faults();
            let (missing, held) = context.observer.outstanding();
            let left = missing + held;
            let other: Vec<String> = faults
                .into_iter()
                .filter(|fault| !fault.contains("never reached the sink"))
                .collect();
            if !other.is_empty() {
                return Err(other.join("; "));
            }
            if left == 0 || Instant::now() >= deadline {
                return Ok(Release {
                    held: held_back,
                    seconds: started.elapsed().as_secs_f64(),
                    missing: left,
                });
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }

    fn system(&self, name: &str, repetition: usize, capacity: f64) -> SystemRun {
        let system = &self.recipe.systems[name];
        let mut run = SystemRun {
            system: name.to_owned(),
            repetition,
            durability: system.durability,
            probe: None,
            sink_sessions: BTreeMap::new(),
            sink_most_open: None,
            hooks: None,
            throttled_sink: None,
            release: None,
            backlog: None,
            crash: None,
            warmup: None,
            steps: Vec::new(),
            sustained_rate: None,
            limited_by: None,
            error: None,
        };
        if let Err(error) = self.measure(system, capacity, &mut run) {
            run.error = Some(error);
        }
        if let Ok(stats) = docker::run(&["exec", SINK, "harness", "sink-ctl", "stats"])
            && let Ok(stats) = serde_json::from_slice::<crate::sink::Stats>(&stats.stdout)
        {
            run.sink_sessions = stats.sessions;
            run.sink_most_open = Some(stats.most_open);
        }
        if self.production(system)
            && let Ok(stats) = docker::run(&["exec", SINK, "harness", "hooks-ctl", "stats"])
            && let Ok(stats) = serde_json::from_slice::<crate::hooks::Stats>(&stats.stdout)
        {
            if stats.refused > 0 && run.error.is_none() {
                run.error = Some(format!(
                    "the event receiver refused {} batches, unsigned or wrongly signed",
                    stats.refused
                ));
            }
            run.hooks = Some(stats);
        }
        if self.profile.throttle.is_some()
            && let Ok(stats) = docker::run(&["exec", THROTTLED, "harness", "sink-ctl", "stats"])
            && let Ok(stats) = serde_json::from_slice::<crate::sink::Stats>(&stats.stdout)
        {
            run.throttled_sink = Some(stats);
        }
        self.keep_logs(system, &format!("{name}-{}", repetition + 1));
        docker::quietly(&["rm", "--force", SUT]);
        docker::quietly(&["rm", "--force", SINK]);
        docker::quietly(&["rm", "--force", THROTTLED]);
        docker::quietly(&["volume", "rm", "--force", VOLUME]);
        run
    }

    fn measure(&self, system: &System, capacity: f64, run: &mut SystemRun) -> Result<(), String> {
        self.start_sink()?;
        // The production shape's subscriber, beside the sink.
        if self.production(system) {
            docker::run(&["exec", "--detach", SINK, "harness", "hooks"])?;
        }
        docker::run(&["volume", "create", "--label", LABEL, VOLUME])?;
        let probe = docker::text(&[
            "run",
            "--rm",
            "--label",
            LABEL,
            "--cpuset-cpus",
            &self.placement.sut_cpus,
            "--volume",
            &format!("{VOLUME}:/spool"),
            "harness-harness",
            "harness",
            "probe",
            "--dir",
            "/spool",
        ])?;
        run.probe =
            Some(serde_json::from_str(&probe).map_err(|error| format!("the probe: {error}"))?);
        self.start_sut(system)?;
        if let Some(crash) = &self.profile.crash {
            let record = self.crash(system, crash)?;
            let lost = record.missing;
            run.crash = Some(record);
            if lost > 0 {
                return Err(format!(
                    "{lost} acknowledged recipients were lost in the crash"
                ));
            }
            return Ok(());
        }
        let mut next_id = 1;
        if let Some(backlog) = &self.profile.backlog {
            let (record, after) = self.backlog(system, backlog, capacity)?;
            if let Some(budget) = self.profile.budgets.backlog_anon_mib {
                let held = record.queued_anon_mib.max(record.restarted_anon_mib);
                if held > budget {
                    return Err(format!(
                        "the backlog held {held:.0} MiB of anonymous memory, over the {budget:.0} MiB budget"
                    ));
                }
            }
            run.backlog = Some(record);
            next_id = after;
        }
        let search = &self.profile.search;
        let ceiling = capacity / search.headroom;
        if let Some(fixed) = &self.profile.fixed {
            if fixed.rate > ceiling {
                return Err(format!(
                    "the tools carry {capacity:.0} messages/s here, so a fixed rate above {ceiling:.0}/s is not measured"
                ));
            }
            let mut context = self.warm_up(system, next_id, run)?;
            let step = self.step(system, &mut context, fixed.rate, fixed.seconds)?;
            let (pass, faults) = (step.misses.is_empty(), step.observed.faults());
            run.steps.push(step);
            if !faults.is_empty() {
                return Err(faults.join("; "));
            }
            run.sustained_rate = pass.then_some(fixed.rate);
            return Ok(());
        }
        if self.profile.backlog.is_some() {
            return Ok(());
        }

        // Double the offered rate until a step misses its budgets, then
        // bisect between the last rate that met them and the first that
        // did not.
        let mut context = self.warm_up(system, next_id, run)?;
        let mut met: Option<f64> = None;
        let mut missed: Option<f64> = None;
        let mut rate = search.start_rate;
        while missed.is_none() {
            if rate > ceiling {
                run.limited_by = Some(format!(
                    "the tools carry {capacity:.0} messages/s here, so no rate above {ceiling:.0}/s is measured"
                ));
                break;
            }
            let step = self.step(system, &mut context, rate, search.step_seconds)?;
            let (pass, faults) = (step.misses.is_empty(), step.observed.faults());
            run.steps.push(step);
            if !faults.is_empty() {
                return Err(faults.join("; "));
            }
            if pass {
                met = Some(rate);
                rate *= 2.0;
            } else {
                missed = Some(rate);
            }
        }
        if let Some(mut high) = missed {
            let mut low = met.unwrap_or(0.0);
            for _ in 0..search.bisections {
                let mid = ((low + high) / 2.0).round();
                if mid <= low || mid >= high {
                    break;
                }
                let step = self.step(system, &mut context, mid, search.step_seconds)?;
                let (pass, faults) = (step.misses.is_empty(), step.observed.faults());
                run.steps.push(step);
                if !faults.is_empty() {
                    return Err(faults.join("; "));
                }
                if pass {
                    low = mid;
                    met = Some(mid);
                } else {
                    high = mid;
                }
            }
        }
        run.sustained_rate = met;
        if let Some(throttle) = &self.profile.throttle {
            let release = self.release(&mut context, throttle)?;
            let missing = release.missing;
            run.release = Some(release);
            if missing > 0 {
                return Err(format!(
                    "{missing} accepted messages never arrived, {:.0} s after the throttle lifted",
                    throttle.release_seconds
                ));
            }
        }
        Ok(())
    }

    /// The warm-up step, with the observer that the steps after it share.
    fn warm_up(
        &self,
        system: &System,
        next_id: u64,
        run: &mut SystemRun,
    ) -> Result<Context, String> {
        let search = &self.profile.search;
        let mut context = Context {
            observer: Observer::new(
                self.profile
                    .throttle
                    .as_ref()
                    .map_or(0.0, |throttle| throttle.share),
                self.profile.workload.recipients,
            )
            .expecting(self.expected()),
            next_id,
        };
        let warmup = self.step(
            system,
            &mut context,
            search.warmup_rate,
            search.warmup_seconds,
        )?;
        let faults = warmup.observed.faults();
        run.warmup = Some(warmup);
        if !faults.is_empty() {
            return Err(faults.join("; "));
        }
        Ok(context)
    }

    fn start_sut(&self, system: &System) -> Result<(), String> {
        let memory = format!("{}m", self.placement.sut_memory_mib);
        // For a crash test the volume lies beneath the spool, which LazyFS
        // mounts over it.
        let on_lazyfs = self.profile.crash.as_ref().is_some_and(|crash| crash.power);
        let volume = if on_lazyfs {
            format!("{VOLUME}:/lazyfs-root")
        } else {
            format!("{VOLUME}:{}", system.spool)
        };
        let mut args = vec!["create".to_owned()];
        args.extend(container(SUT, SUT_IP, &self.placement.sut_cpus));
        args.extend(
            [
                "--hostname",
                SUT_NAME,
                "--memory",
                &memory,
                "--memory-swap",
                &memory,
                "--ulimit",
                "nofile=65536:65536",
                "--volume",
                &volume,
                "--env",
                &format!("BENCH_PASSWORD={}", self.secrets.password),
            ]
            .iter()
            .map(|arg| (*arg).to_owned()),
        );
        if on_lazyfs {
            args.extend([
                "--device".to_owned(),
                "/dev/fuse".to_owned(),
                "--cap-add".to_owned(),
                "SYS_ADMIN".to_owned(),
                "--env".to_owned(),
                format!("BENCH_SPOOL={}", system.spool),
            ]);
        }
        // The delivery settings every system is given alike.
        let delivery = &self.profile.delivery;
        for (key, value) in [
            ("BENCH_CONNECTIONS", delivery.connections.to_string()),
            (
                "BENCH_RETRY_FIRST_SECONDS",
                delivery.retry_first_seconds.to_string(),
            ),
            (
                "BENCH_RETRY_MAX_SECONDS",
                delivery.retry_max_seconds.to_string(),
            ),
            ("BENCH_SITES", self.profile.workload.sites.to_string()),
            ("BENCH_SIGN", self.has(Ablation::Signing).to_string()),
            ("BENCH_DELIVERY_TLS", self.has(Ablation::Tls).to_string()),
            // A throttling response, as each system's deployments run one,
            // where the profile has a throttled receiver.
            ("BENCH_TSA", self.profile.throttle.is_some().to_string()),
        ] {
            args.extend(["--env".to_owned(), format!("{key}={value}")]);
        }
        // Production-shaped, it sends from two egresses, the second an
        // address it adds itself, and posts its events beside the sink.
        if self.production(system) {
            args.extend(["--cap-add".to_owned(), "NET_ADMIN".to_owned()]);
            for (key, value) in [
                ("BENCH_PRODUCTION", "true".to_owned()),
                ("BENCH_FIRST_ADDRESS", SUT_IP.to_owned()),
                ("BENCH_SECOND_ADDRESS", SUT_SECOND_IP.to_owned()),
                ("BENCH_HOOKS_URL", format!("http://{SINK_IP}:8080/hooks")),
            ] {
                args.extend(["--env".to_owned(), format!("{key}={value}")]);
            }
        }
        for (key, value) in &system.env {
            args.extend(["--env".to_owned(), format!("{key}={value}")]);
        }
        args.push(if on_lazyfs {
            format!("harness-{}-lazyfs", system.image)
        } else {
            format!("harness-{}", system.image)
        });
        docker::run(&args.iter().map(String::as_str).collect::<Vec<_>>())?;
        let files = self.out.join("files/sut/.").display().to_string();
        docker::run(&["cp", &files, &format!("{SUT}:/etc/bench")])?;
        *self.issued() = None;
        docker::run(&["start", SUT])?;
        // Ready when a connection gets through STARTTLS and authentication,
        // or an API's TLS handshake; a container that has exited never will
        // be. A system that issues its own secrets has written them first.
        wait("the system under test", Duration::from_secs(120), || {
            let running = docker::text(&["inspect", "--format", "{{.State.Running}}", SUT])
                .map_err(NotReady::Never)?;
            if running != "true" {
                return Err(NotReady::Never(
                    "its container exited; its log is kept with the result".to_owned(),
                ));
            }
            if let Some(path) = &system.credentials
                && self.issued().is_none()
            {
                let text = docker::text(&["exec", SUT, "cat", path]).map_err(NotReady::Yet)?;
                let issued: Issued = serde_json::from_str(&text)
                    .map_err(|error| NotReady::Never(format!("{path}: {error}")))?;
                // The event receiver checks every batch from the first.
                if self.production(system) {
                    if issued.hooks.is_empty() {
                        return Err(NotReady::Never(
                            "it issued no secret for its event subscription".to_owned(),
                        ));
                    }
                    docker::run(&[
                        "exec",
                        SINK,
                        "harness",
                        "hooks-ctl",
                        "secret",
                        &issued.hooks,
                    ])
                    .map_err(NotReady::Never)?;
                }
                *self.issued() = Some(issued);
            }
            self.load(system, 1, 0.0, 0.0, 1, None)
                .map(|_| ())
                .map_err(NotReady::Yet)
        })
    }

    /// Whether `system` runs production-shaped.
    fn production(&self, system: &System) -> bool {
        system.production && self.has(Ablation::Production)
    }

    fn issued(&self) -> MutexGuard<'_, Option<Issued>> {
        self.issued.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Runs the load generator against the system under test, through its
    /// ingress.
    fn load(
        &self,
        system: &System,
        connections: usize,
        rate: f64,
        seconds: f64,
        id_base: u64,
        messages: Option<u64>,
    ) -> Result<docker::Output, String> {
        let (user, password) = match (&*self.issued(), system.ingress) {
            (Some(issued), Ingress::Ses) => (issued.ses.user.clone(), issued.ses.password.clone()),
            (Some(issued), _) => (issued.smtp.user.clone(), issued.smtp.password.clone()),
            (None, Ingress::Ses) => (ACCESS_KEY.to_owned(), self.secrets.password.clone()),
            (None, Ingress::Smtp | Ingress::Kumomta) => {
                (USER.to_owned(), self.secrets.password.clone())
            }
        };
        let share = self
            .profile
            .throttle
            .as_ref()
            .map_or(0.0, |throttle| throttle.share);
        let mut args = vec![
            "exec".to_owned(),
            LOAD.to_owned(),
            "harness".to_owned(),
            "load".to_owned(),
            "--ingress".to_owned(),
            system.ingress.name().to_owned(),
            "--target".to_owned(),
            format!("{SUT_IP}:{}", system.port),
            "--server-name".to_owned(),
            SUT_NAME.to_owned(),
            "--connections".to_owned(),
            connections.to_string(),
            "--rate".to_owned(),
            rate.to_string(),
            "--seconds".to_owned(),
            seconds.to_string(),
            "--size".to_owned(),
            self.profile.workload.message_bytes.to_string(),
            "--id-base".to_owned(),
            id_base.to_string(),
            "--user".to_owned(),
            user,
            "--password".to_owned(),
            password,
            "--sender".to_owned(),
            SENDER.to_owned(),
            "--domain".to_owned(),
            SINK_DOMAIN.to_owned(),
            "--domains".to_owned(),
            self.profile.workload.domains.to_string(),
            "--recipients".to_owned(),
            self.profile.workload.recipients.to_string(),
            "--throttled-share".to_owned(),
            share.to_string(),
            "--throttled-domain".to_owned(),
            THROTTLED_DOMAIN.to_owned(),
        ];
        if let Some(messages) = messages {
            args.extend(["--messages".to_owned(), messages.to_string()]);
        }
        docker::run(&args.iter().map(String::as_str).collect::<Vec<_>>())
    }

    /// One step: offered load, the drain that follows, and the observer's
    /// account of both.
    fn step(
        &self,
        system: &System,
        context: &mut Context,
        rate: f64,
        seconds: f64,
    ) -> Result<StepRecord, String> {
        let before = counters()?;
        let output = self.load(
            system,
            self.profile.workload.connections,
            rate,
            seconds,
            context.next_id,
            None,
        )?;
        let summary = summary(&output.stderr)?;
        let acks = Ack::decode_all(&output.stdout)?;
        context.next_id += acks.len() as u64;

        let draining = Instant::now();
        let deadline = draining + Duration::from_secs_f64(self.profile.search.drain_seconds);
        // The drain waits for this step's messages, but not for those a
        // throttled receiver may be holding back.
        let share = self
            .profile
            .throttle
            .as_ref()
            .map_or(0.0, |throttle| throttle.share);
        let mut pending: HashSet<u64> = acks
            .iter()
            .filter(|ack| ack.accepted() && !load::throttled(ack.id, share))
            .map(|ack| ack.id)
            .collect();
        let mut arrivals = Vec::new();
        loop {
            let taken = self.take()?;
            for arrival in &taken {
                pending.remove(&arrival.id);
            }
            arrivals.extend(taken);
            if pending.is_empty() || Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        let drain_seconds = draining.elapsed().as_secs_f64();
        let after = counters()?;

        let observed = context.observer.step(rate, seconds, &acks, &arrivals);
        let usage = usage(before, after, observed.delivered);
        let misses = misses(&observed, &self.profile.budgets);
        Ok(StepRecord {
            observed,
            drain_seconds,
            usage,
            misses,
            errors: summary.errors,
        })
    }

    fn keep_logs(&self, system: &System, name: &str) {
        let mut kept = String::new();
        if let Ok(output) = docker::run(&["logs", SUT]) {
            kept.push_str(&String::from_utf8_lossy(&output.stdout));
            kept.push_str(&output.stderr);
        }
        if let Some(log) = &system.log
            && let Ok(output) = docker::run(&["exec", SUT, "tail", "-n", "2000", log])
        {
            kept.push_str(&format!("\n==> {log}\n"));
            kept.push_str(&String::from_utf8_lossy(&output.stdout));
        }
        let _ = fs::write(self.out.join("logs").join(format!("{name}.log")), kept);
    }
}

struct Context {
    observer: Observer,
    next_id: u64,
}

fn summary(stderr: &str) -> Result<load::Summary, String> {
    let line = stderr.lines().last().unwrap_or_default();
    serde_json::from_str(line)
        .map_err(|error| format!("the load generator's summary: {error}: {stderr}"))
}

enum NotReady {
    Yet(String),
    Never(String),
}

fn wait(
    what: &str,
    limit: Duration,
    mut ready: impl FnMut() -> Result<(), NotReady>,
) -> Result<(), String> {
    let deadline = Instant::now() + limit;
    loop {
        match ready() {
            Ok(()) => return Ok(()),
            Err(NotReady::Never(error)) => return Err(format!("{what} will not start: {error}")),
            Err(NotReady::Yet(error)) if Instant::now() >= deadline => {
                return Err(format!(
                    "{what} was not ready after {} s: {error}",
                    limit.as_secs()
                ));
            }
            Err(NotReady::Yet(_)) => std::thread::sleep(Duration::from_millis(500)),
        }
    }
}

/// How full LazyFS's cache is, in percent of its pages: asked for on its
/// FIFO, and read from the report it writes to the system's log.
fn cache_percent() -> Result<f64, String> {
    // The daemon's clock may differ from this one a little.
    let since = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .saturating_sub(Duration::from_secs(5))
        .as_secs()
        .to_string();
    let reports = || -> Result<Vec<f64>, String> {
        let output = docker::run(&["logs", "--since", &since, SUT])?;
        let text = String::from_utf8_lossy(&output.stdout) + output.stderr.as_str();
        Ok(text
            .lines()
            .filter(|line| line.contains("[lazyfs.cmds]: cache usage"))
            .filter_map(|line| {
                line.rsplit(" is ")
                    .next()?
                    .trim()
                    .strip_suffix('%')?
                    .parse()
                    .ok()
            })
            .collect())
    };
    let before = reports()?.len();
    // The request waits for LazyFS to open its FIFO, which it never does
    // once it is gone.
    let ask = "timeout 5 sh -c 'echo lazyfs::display-cache-usage > /run/lazyfs.fifo'";
    if docker::run(&["exec", SUT, "sh", "-c", ask]).is_err() {
        let events = docker::text(&["exec", SUT, "cat", "/sys/fs/cgroup/memory.events"])?;
        let killed = events.lines().any(|line| {
            line.strip_prefix("oom_kill ")
                .is_some_and(|count| count.trim() != "0")
        });
        return Err(if killed {
            "LazyFS is not running: the system's container ran out of memory, and the kernel killed a process".to_owned()
        } else {
            "LazyFS is not running".to_owned()
        });
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(&percent) = reports()?.get(before) {
            return Ok(percent);
        }
        if Instant::now() >= deadline {
            return Err("LazyFS did not report how full its cache is".to_owned());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// The system under test's cgroup counters, read from inside its container.
fn counters() -> Result<Counters, String> {
    let script = "cd /sys/fs/cgroup && for f in cpu.stat memory.current memory.peak memory.stat io.stat; do echo \"== $f\"; cat $f; done";
    docker::text(&["exec", SUT, "sh", "-c", script]).map(|text| Counters::parse(&text))
}

impl Counters {
    /// Parses the cgroup files `counters` prints, each after a `== name`
    /// line.
    fn parse(text: &str) -> Self {
        let mut counters = Counters::default();
        let mut section = "";
        for line in text.lines() {
            if let Some(name) = line.strip_prefix("== ") {
                section = name;
                continue;
            }
            let number = |text: &str| text.trim().parse::<u64>().unwrap_or(0);
            match section {
                "cpu.stat" => {
                    if let Some(value) = line.strip_prefix("usage_usec ") {
                        counters.cpu_us = number(value);
                    }
                }
                "memory.current" => counters.memory = number(line),
                "memory.peak" => counters.peak = number(line),
                "memory.stat" => {
                    if let Some(value) = line.strip_prefix("anon ") {
                        counters.anon = number(value);
                    }
                }
                "io.stat" => {
                    counters.written += line
                        .split_whitespace()
                        .filter_map(|field| field.strip_prefix("wbytes="))
                        .map(number)
                        .sum::<u64>();
                }
                _ => {}
            }
        }
        counters
    }
}

fn usage(before: Counters, after: Counters, delivered: u64) -> Usage {
    const MIB: f64 = 1024.0 * 1024.0;
    let cpu_seconds = after.cpu_us.saturating_sub(before.cpu_us) as f64 / 1e6;
    let written = after.written.saturating_sub(before.written) as f64;
    let per_message = |total: f64| (delivered > 0).then(|| total / delivered as f64);
    Usage {
        cpu_seconds,
        cpu_ms_per_message: per_message(cpu_seconds * 1000.0),
        memory_mib: after.memory as f64 / MIB,
        peak_memory_mib: after.peak as f64 / MIB,
        written_mib: written / MIB,
        written_kib_per_message: per_message(written / 1024.0),
    }
}

/// Why a step missed the profile's budgets; empty when it met them.
fn misses(step: &Step, budgets: &Budgets) -> Vec<String> {
    let mut misses = Vec::new();
    if !step.refused.is_empty() {
        let codes: Vec<String> = step
            .refused
            .iter()
            .map(|(code, count)| format!("{count} with {code}"))
            .collect();
        misses.push(format!("submissions were refused: {}", codes.join(", ")));
    }
    if step.accepted_rate < budgets.accepted_share * step.offered_rate {
        misses.push(format!(
            "accepted {:.0}/s of {:.0}/s offered",
            step.accepted_rate, step.offered_rate
        ));
    }
    for (name, spread, budget) in [
        ("submission", step.submit_ms, budgets.submit_p99_ms),
        ("delivery", step.delivery_ms, budgets.delivery_p99_ms),
    ] {
        if let Some(spread) = spread
            && spread.p99 > budget
        {
            misses.push(format!(
                "p99 {name} {:.0} ms is over the {budget:.0} ms budget",
                spread.p99
            ));
        }
    }
    misses
}

/// Whether a flush on the queue volume reaches stable storage.
#[derive(Serialize)]
struct Judgement {
    label: &'static str,
    reason: String,
}

fn judge_durability(probe: &probe::Report, host: Option<&Spread>) -> Judgement {
    // Load only ever slows a flush, so the fastest flushes are the evidence:
    // one that returns well before the drive could make a write durable did
    // not wait for the drive.
    if let Some(host) = host {
        let guest = probe.sync_us.min;
        if guest * 2.0 < host.min {
            return Judgement {
                label: "not durable",
                reason: format!(
                    "the fastest flush in the container runtime's virtual machine returned in {guest:.0} µs, but this host's drive never made a write durable in under {:.0} µs, so flushes stop short of stable storage; ratios between systems hold, synchronous-commit claims do not",
                    host.min
                ),
            };
        }
        return Judgement {
            label: "durable",
            reason: format!(
                "no flush in the virtual machine returned faster than half the host's fastest durable flush ({guest:.0} µs against {:.0} µs)",
                host.min
            ),
        };
    }
    if cfg!(target_os = "linux") {
        if probe.virtualisation.is_empty() {
            return Judgement {
                label: "durable",
                reason: "no hypervisor is visible, so a flush goes to the device".to_owned(),
            };
        }
        return Judgement {
            label: "unverified",
            reason: format!(
                "virtualised ({}): whether a flush reaches stable storage depends on the hypervisor's disk",
                probe.virtualisation.join("; ")
            ),
        };
    }
    Judgement {
        label: "unverified",
        reason: "the harness cannot tell on this host whether a flush reaches stable storage"
            .to_owned(),
    }
}

#[cfg(target_os = "macos")]
fn host_full_sync(out: &Path) -> Result<Option<Spread>, String> {
    probe::host_full_sync(out, 200).map(Some)
}

#[cfg(not(target_os = "macos"))]
fn host_full_sync(_out: &Path) -> Result<Option<Spread>, String> {
    Ok(None)
}

/// What a result needs to be reproduced and checked.
#[derive(Serialize)]
struct Report {
    schema: u32,
    profile: String,
    command: Vec<String>,
    started: String,
    finished: String,
    harness: Commit,
    environment: Environment,
    placement: Placement,
    images: BTreeMap<String, Built>,
    /// The SHA-256 of every file each image is built from.
    configuration: BTreeMap<String, String>,
    durability: Option<Judgement>,
    host_full_sync_us: Option<Spread>,
    /// Messages per second the tools carry on their own.
    capacity: f64,
    /// The component ceilings on one of the systems' CPUs.
    ceilings: serde_json::Value,
    /// How far apart the runs' CPU gauges were: the fastest over the slowest,
    /// less one.
    gauge_spread: Option<f64>,
    settings: Profile,
    recipe: Recipe,
    runs: Vec<SystemRun>,
    summary: Vec<Line>,
    limitations: Vec<String>,
}

#[derive(Serialize)]
struct Commit {
    commit: Option<String>,
    modified: bool,
}

fn commit(repository: &Path) -> Commit {
    let git = |args: &[&str]| {
        std::process::Command::new("git")
            .arg("-C")
            .arg(repository)
            .args(args)
            .output()
            .ok()
            .filter(|output| output.status.success())
            .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
    };
    Commit {
        commit: git(&["rev-parse", "HEAD"]),
        modified: git(&["status", "--porcelain"]).is_some_and(|status| !status.is_empty()),
    }
}

fn configuration(
    recipe: &Recipe,
    profile: &Profile,
    harness: &Path,
) -> Result<BTreeMap<String, String>, String> {
    let mut images: BTreeSet<&str> = recipe::TOOLS.into_iter().collect();
    images.extend(
        profile
            .systems
            .iter()
            .map(|system| recipe.systems[system].image.as_str()),
    );
    let mut digests = BTreeMap::new();
    for image in images {
        let dir = harness.join("images").join(image);
        let mut entries: Vec<PathBuf> = fs::read_dir(&dir)
            .map_err(|error| format!("{}: {error}", dir.display()))?
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .collect();
        entries.sort();
        for path in entries {
            let bytes = fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))?;
            let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &bytes);
            let name = path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default();
            digests.insert(
                format!("images/{image}/{name}"),
                crate::hex(digest.as_ref()),
            );
        }
    }
    Ok(digests)
}

/// The machine and the container runtime, captured with every result.
#[derive(Serialize)]
struct Environment {
    os: &'static str,
    arch: &'static str,
    cpu: Option<String>,
    cores: usize,
    /// Each kind of core and how many there are, where the host reports
    /// them: the container runtime's CPUs may run on any of them.
    core_types: Vec<String>,
    memory_bytes: Option<u64>,
    kernel: Option<String>,
    power: Option<String>,
    thermal: Option<String>,
    runtime: BTreeMap<&'static str, serde_json::Value>,
}

impl Environment {
    fn gather(info: serde_json::Value) -> Self {
        let command = |program: &str, args: &[&str]| {
            std::process::Command::new(program)
                .args(args)
                .output()
                .ok()
                .filter(|output| output.status.success())
                .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        };
        let (cpu, memory_bytes, power, thermal) = if cfg!(target_os = "macos") {
            (
                command("sysctl", &["-n", "machdep.cpu.brand_string"]),
                command("sysctl", &["-n", "hw.memsize"]).and_then(|bytes| bytes.parse().ok()),
                command("pmset", &["-g", "ps"])
                    .and_then(|text| text.lines().next().map(str::to_owned)),
                command("pmset", &["-g", "therm"]),
            )
        } else {
            let cpuinfo = fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
            let meminfo = fs::read_to_string("/proc/meminfo").unwrap_or_default();
            (
                cpuinfo.lines().find_map(|line| {
                    line.strip_prefix("model name")
                        .map(|rest| rest.trim_start_matches([' ', '\t', ':']).to_owned())
                }),
                meminfo
                    .lines()
                    .find_map(|line| line.strip_prefix("MemTotal:"))
                    .and_then(|kib| kib.trim().trim_end_matches(" kB").parse::<u64>().ok())
                    .map(|kib| kib * 1024),
                None,
                None,
            )
        };
        let core_types = if cfg!(target_os = "macos") {
            let levels = command("sysctl", &["-n", "hw.nperflevels"])
                .and_then(|levels| levels.parse::<usize>().ok())
                .unwrap_or(0);
            (0..levels)
                .filter_map(|level| {
                    let name = command("sysctl", &["-n", &format!("hw.perflevel{level}.name")])?;
                    let count = command(
                        "sysctl",
                        &["-n", &format!("hw.perflevel{level}.physicalcpu")],
                    )?;
                    Some(format!("{count} {name}"))
                })
                .collect()
        } else {
            Vec::new()
        };
        let runtime = [
            "ServerVersion",
            "OperatingSystem",
            "KernelVersion",
            "Architecture",
            "NCPU",
            "MemTotal",
            "Driver",
            "CgroupVersion",
        ]
        .into_iter()
        .map(|key| (key, info[key].clone()))
        .collect();
        Self {
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
            cpu,
            cores: std::thread::available_parallelism().map_or(0, usize::from),
            core_types,
            memory_bytes,
            kernel: command("uname", &["-sr"]),
            power,
            thermal,
            runtime,
        }
    }
}

/// One system's results across its repetitions.
#[derive(Serialize)]
struct Line {
    system: String,
    durability: Durability,
    /// Each repetition's sustained rate; `None` where it found none.
    rates: Vec<Option<f64>>,
    median_rate: Option<f64>,
    /// The median rate divided by each other system's.
    ratios: BTreeMap<String, f64>,
    /// At the highest rate each repetition sustained.
    cpu_ms_per_message: Vec<Option<f64>>,
    submit_p99_ms: Vec<Option<f64>>,
    delivery_p99_ms: Vec<Option<f64>>,
}

fn summarise(profile: &Profile, recipe: &Recipe, runs: &[SystemRun]) -> Vec<Line> {
    let mut lines: Vec<Line> = profile
        .systems
        .iter()
        .map(|system| {
            let mine: Vec<&SystemRun> = runs.iter().filter(|run| &run.system == system).collect();
            let best = |run: &SystemRun| {
                run.sustained_rate
                    .and_then(|rate| {
                        run.steps.iter().rev().find(|step| {
                            step.observed.offered_rate == rate && step.misses.is_empty()
                        })
                    })
                    .cloned()
            };
            let at_best: Vec<Option<StepRecord>> = mine.iter().map(|run| best(run)).collect();
            let mut rates: Vec<f64> = mine.iter().filter_map(|run| run.sustained_rate).collect();
            rates.sort_by(f64::total_cmp);
            let median_rate = (!rates.is_empty() && rates.len() == mine.len()).then(|| {
                let middle = rates.len() / 2;
                if rates.len().is_multiple_of(2) {
                    (rates[middle - 1] + rates[middle]) / 2.0
                } else {
                    rates[middle]
                }
            });
            Line {
                system: system.clone(),
                durability: recipe.systems[system].durability,
                rates: mine.iter().map(|run| run.sustained_rate).collect(),
                median_rate,
                ratios: BTreeMap::new(),
                cpu_ms_per_message: at_best
                    .iter()
                    .map(|step| step.as_ref().and_then(|step| step.usage.cpu_ms_per_message))
                    .collect(),
                submit_p99_ms: at_best
                    .iter()
                    .map(|step| {
                        step.as_ref()
                            .and_then(|step| step.observed.submit_ms.map(|spread| spread.p99))
                    })
                    .collect(),
                delivery_p99_ms: at_best
                    .iter()
                    .map(|step| {
                        step.as_ref()
                            .and_then(|step| step.observed.delivery_ms.map(|spread| spread.p99))
                    })
                    .collect(),
            }
        })
        .collect();
    let medians: Vec<(String, Option<f64>)> = lines
        .iter()
        .map(|line| (line.system.clone(), line.median_rate))
        .collect();
    for line in &mut lines {
        for (other, rate) in &medians {
            if let (Some(mine), Some(theirs)) = (line.median_rate, rate)
                && other != &line.system
            {
                line.ratios.insert(other.clone(), mine / theirs);
            }
        }
    }
    lines
}

fn print_summary(report: &Report) {
    if let Some(durability) = &report.durability {
        println!("\ndurability: {} ({})", durability.label, durability.reason);
    }
    println!(
        "\n{:<16} {:<6} {:>12}  {:<22} {:>10} {:>14} {:>14}",
        "system", "acks", "rate/s", "repetitions", "CPU ms/msg", "p99 submit ms", "p99 deliver ms"
    );
    let shown = |values: &[Option<f64>], decimals: usize| {
        values
            .iter()
            .map(|value| value.map_or("-".to_owned(), |value| format!("{value:.decimals$}")))
            .collect::<Vec<_>>()
            .join(" ")
    };
    for line in &report.summary {
        println!(
            "{:<16} {:<6} {:>12}  {:<22} {:>10} {:>14} {:>14}",
            line.system,
            format!("{:?}", line.durability).to_ascii_lowercase(),
            line.median_rate
                .map_or("-".to_owned(), |rate| format!("{rate:.0}")),
            shown(&line.rates, 0),
            shown(&line.cpu_ms_per_message, 3),
            shown(&line.submit_p99_ms, 0),
            shown(&line.delivery_p99_ms, 0),
        );
        for (other, ratio) in &line.ratios {
            println!("{:<16} {ratio:.2}x {other}", "");
        }
    }
    let signs = report.ceilings["dkim_rsa2048_signs_per_second"].as_f64();
    let verifies = report.ceilings["sigv4_verifies_per_second"].as_f64();
    if let (Some(signs), Some(verifies)) = (signs, verifies) {
        let cpus = report.settings.placement.sut_cpus;
        println!(
            "\nceilings on one of the systems' CPUs: {signs:.0} RSA-2048 DKIM signatures of a 16 KiB message a second, {verifies:.0} SigV4 verifications"
        );
        if !report.settings.without.contains(&Ablation::Signing) {
            for line in &report.summary {
                if let Some(rate) = line.median_rate {
                    println!(
                        "  {}: {rate:.0}/s is {:.0}% of the {:.0} a second that signing alone allows on {cpus} CPUs",
                        line.system,
                        100.0 * rate / (signs * cpus as f64),
                        signs * cpus as f64
                    );
                }
            }
        }
    }
    println!("\nin order, with each run's CPU gauge (SHA-256 MB/s on the system's CPUs):");
    for run in &report.runs {
        println!(
            "  {} repetition {}: {} messages/s, gauge {}, at most {} sessions to the sink at once",
            run.system,
            run.repetition + 1,
            run.sustained_rate
                .map_or("-".to_owned(), |rate| format!("{rate:.0}")),
            run.probe
                .as_ref()
                .map_or("-".to_owned(), |probe| format!("{:.0}", probe.hash_mb_s)),
            run.sink_most_open
                .map_or("-".to_owned(), |open| open.to_string()),
        );
        if let Some(hooks) = &run.hooks {
            let events: Vec<String> = hooks
                .events
                .iter()
                .map(|(kind, count)| format!("{count} {kind}"))
                .collect();
            println!(
                "    events, production-shaped: {} in {} batches, {} posted again, {} refused",
                events.join(", "),
                hooks.batches,
                hooks.repeated,
                hooks.refused
            );
        }
    }
    if let Some(spread) = report.gauge_spread
        && spread > UNEQUAL_GAUGES
    {
        println!(
            "the gauges differ by {:.0}%: an unequal session, whose ratios are read only beside them",
            spread * 100.0
        );
    }
    if !report.settings.without.is_empty() {
        let parts: Vec<String> = report
            .settings
            .without
            .iter()
            .map(|part| format!("{part:?}").to_ascii_lowercase())
            .collect();
        println!(
            "an ablation, every system without {}: what that part costs, not the systems as they run",
            parts.join(" and ")
        );
    }
    if report.settings.repetitions < REPORTED_REPETITIONS {
        println!(
            "fewer than {REPORTED_REPETITIONS} repetitions: a check, not a reported comparison"
        );
    }
    if report.settings.backlog.is_some() {
        println!(
            "\n{:<16} {:>10} {:>9} {:>14} {:>9} {:>9} {:>12} {:>10} {:>9}",
            "backlog",
            "recipients",
            "fill s",
            "queued MiB",
            "stop s",
            "start s",
            "drain s",
            "peak/s",
            "CPU ms",
        );
        for run in &report.runs {
            let Some(backlog) = &run.backlog else {
                continue;
            };
            println!(
                "{:<16} {:>10} {:>9.1} {:>14} {:>9.1} {:>9.1} {:>12.1} {:>10} {:>9.3}",
                run.system,
                backlog.recipients,
                backlog.fill_seconds,
                format!(
                    "{:.0} ({:.0})",
                    backlog.queued_anon_mib, backlog.queued_memory_mib
                ),
                backlog.stop_seconds,
                backlog.start_seconds,
                backlog.drain_seconds,
                format!(
                    "{:.0}{}",
                    backlog.drain_peak_per_second,
                    if backlog.drain_above_headroom {
                        "*"
                    } else {
                        ""
                    }
                ),
                backlog.drain.cpu_ms_per_message.unwrap_or_default(),
            );
            if backlog.drain_by_source.len() > 1 {
                let sources: Vec<String> = backlog
                    .drain_by_source
                    .iter()
                    .map(|source| {
                        format!(
                            "{} from {}, the last {:.1} s in",
                            source.recipients, source.address, source.last_seconds
                        )
                    })
                    .collect();
                println!("  drained by source: {}", sources.join("; "));
            }
        }
        println!(
            "queued MiB is the system's own memory once the backlog settled, with its file cache in brackets; peak/s is the most recipients that arrived in any five seconds, a second, marked * above half the tools' capacity; CPU ms is per recipient drained"
        );
    }
    if report.settings.crash.is_some() {
        println!("\ncrash tests:");
        for run in &report.runs {
            match (&run.crash, &run.error) {
                (Some(crash), _) => println!(
                    "  {} repetition {}: killed {:.1} s in, {}; {} recipients acknowledged, {} still queued, {} lost, {} delivered twice; accepting again {:.1} s after the start",
                    run.system,
                    run.repetition + 1,
                    crash.killed_after_seconds,
                    if crash.power {
                        format!(
                            "the power failing, LazyFS's cache {:.0}% full",
                            crash.cache_percent
                        )
                    } else {
                        "the process alone".to_owned()
                    },
                    crash.acknowledged,
                    crash.queued_at_crash,
                    crash.missing,
                    crash.duplicates,
                    crash.start_seconds
                ),
                (None, Some(error)) => println!(
                    "  {} repetition {}: {error}",
                    run.system,
                    run.repetition + 1
                ),
                (None, None) => {}
            }
        }
    }
    if report.settings.throttle.is_some() {
        println!("\nthe throttled receiver, and each system's memory:");
        for run in &report.runs {
            let peak = run
                .steps
                .iter()
                .map(|step| step.usage.peak_memory_mib)
                .fold(0.0, f64::max);
            let refusals = run.throttled_sink.as_ref().map_or("-".to_owned(), |sink| {
                format!(
                    "refused {} sessions and took {} ({:.1} refusals per message)",
                    sink.refused,
                    sink.received,
                    sink.refused as f64 / sink.received.max(1) as f64
                )
            });
            let release = run.release.as_ref().map_or("-".to_owned(), |release| {
                format!(
                    "{} held when it lifted, {} missing after {:.0} s",
                    release.held, release.missing, release.seconds
                )
            });
            println!(
                "  {} repetition {}: {refusals}; {release}; peak memory {peak:.0} MiB",
                run.system,
                run.repetition + 1,
            );
        }
    }
    for run in &report.runs {
        if let Some(error) = &run.error {
            println!("{} repetition {}: {error}", run.system, run.repetition + 1);
        }
        if let Some(limit) = &run.limited_by {
            println!("{} repetition {}: {limit}", run.system, run.repetition + 1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_zone_publishes_the_key_in_short_strings() {
        let key = "A".repeat(400);
        let zone = unbound_conf(&key, 1, 1);
        let record = zone
            .lines()
            .find(|line| line.contains("_domainkey"))
            .unwrap();
        let strings: Vec<&str> = record.split('"').skip(1).step_by(2).collect();
        assert!(strings.iter().all(|string| string.len() <= 255));
        assert_eq!(strings.concat(), format!("v=DKIM1; k=rsa; p={key}"));
        assert!(!zone.contains("d0.sink.test"));
    }

    #[test]
    fn the_zone_spreads_domains_and_gives_the_throttled_receiver_its_own_exchange() {
        let zone = unbound_conf("key", 3, 1);
        for n in 0..3 {
            assert!(zone.contains(&format!("\"d{n}.sink.test. 3600 IN MX 10 mx.sink.test.\"")));
        }
        assert!(!zone.contains("d3.sink.test"));
        assert!(zone.contains("\"throttled.test. 3600 IN MX 10 mx.throttled.test.\""));
        assert!(zone.contains("\"mx.throttled.test. 3600 IN A 10.89.0.4\""));
    }

    #[test]
    fn domains_spread_over_sites_each_with_its_own_exchange() {
        let zone = unbound_conf("key", 4, 2);
        assert!(zone.contains("\"d0.sink.test. 3600 IN MX 10 mx0.sink.test.\""));
        assert!(zone.contains("\"d1.sink.test. 3600 IN MX 10 mx1.sink.test.\""));
        assert!(zone.contains("\"d2.sink.test. 3600 IN MX 10 mx0.sink.test.\""));
        assert!(zone.contains("\"mx1.sink.test. 3600 IN A 10.89.0.3\""));
        assert!(!zone.contains("mx2.sink.test"));
    }

    #[test]
    fn placement_says_what_is_missing() {
        let profile: Profile =
            recipe::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("profiles/quick.toml"))
                .unwrap();
        let small = serde_json::json!({ "NCPU": 2, "MemTotal": 512u64 * 1024 * 1024 });
        let error = place(&small, &profile).err().unwrap();
        assert!(
            error.contains("CPUs") && error.contains("memory"),
            "{error}"
        );
        let large = serde_json::json!({ "NCPU": 18, "MemTotal": 8u64 << 30 });
        let placement = place(&large, &profile).unwrap();
        assert_eq!(
            placement.sut_cpus,
            format!("0-{}", profile.placement.sut_cpus - 1)
        );
        assert_eq!(
            placement.tool_cpus,
            format!("{}-17", profile.placement.sut_cpus)
        );
    }

    #[test]
    fn a_drain_peaks_where_the_most_arrivals_share_a_window() {
        let second = 1_000_000;
        // Ten arrivals in the first second, then one a second.
        let mut at: Vec<i64> = (0..10).map(|n| n * 1_000).collect();
        at.extend((1..=20).map(|n| n * second));
        // The first five seconds hold the ten, and four more.
        assert_eq!(peak_rate(&mut at, Duration::from_secs(5)), 14.0 / 5.0);
        assert_eq!(peak_rate(&mut [], Duration::from_secs(5)), 0.0);
    }

    #[test]
    fn cgroup_counters_are_read_from_their_files() {
        let text = "== cpu.stat\nusage_usec 2500000\nuser_usec 2000000\nsystem_usec 500000\n\
                    == memory.current\n104857600\n== memory.peak\n209715200\n\
                    == io.stat\n254:0 rbytes=1 wbytes=4096 rios=1 wios=1 dbytes=0 dios=0\n\
                    254:16 rbytes=0 wbytes=1024 rios=0 wios=1 dbytes=0 dios=0\n";
        let counters = Counters::parse(text);
        assert_eq!(
            (
                counters.cpu_us,
                counters.memory,
                counters.peak,
                counters.written
            ),
            (2_500_000, 104_857_600, 209_715_200, 5120)
        );
        let after = Counters {
            cpu_us: 4_500_000,
            written: 5120 + 10 * 1024,
            ..counters
        };
        let usage = usage(counters, after, 1000);
        assert_eq!(usage.cpu_seconds, 2.0);
        assert_eq!(usage.cpu_ms_per_message, Some(2.0));
        assert_eq!(usage.written_kib_per_message, Some(0.01));
        assert_eq!(usage.peak_memory_mib, 200.0);
        assert_eq!(super::usage(counters, after, 0).cpu_ms_per_message, None);
    }

    #[test]
    fn a_step_misses_on_refusals_shortfall_or_latency() {
        let budgets = Budgets {
            submit_p99_ms: 100.0,
            delivery_p99_ms: 200.0,
            accepted_share: 0.99,
            backlog_anon_mib: None,
        };
        let mut observer = Observer::default();
        let acks: Vec<Ack> = (1..=100)
            .map(|id| Ack {
                id,
                due: 0,
                sent: 0,
                replied: 50_000,
                code: 250,
            })
            .collect();
        let arrivals: Vec<Arrival> = (1..=100)
            .map(|id| Arrival {
                id,
                recipient: 0,
                at: 100_000,
                checks: 15,
                source: std::net::Ipv4Addr::LOCALHOST.into(),
            })
            .collect();
        let step = observer.step(100.0, 1.0, &acks, &arrivals);
        assert_eq!(misses(&step, &budgets), Vec::<String>::new());

        let slow = Step {
            submit_ms: Some(Spread {
                p99: 150.0,
                ..step.submit_ms.unwrap()
            }),
            ..step.clone()
        };
        assert!(misses(&slow, &budgets)[0].contains("submission"));
        let short = Step {
            accepted_rate: 98.0,
            ..step.clone()
        };
        assert!(misses(&short, &budgets)[0].contains("accepted 98/s"));
        let refused = Step {
            refused: BTreeMap::from([(451, 1)]),
            ..step
        };
        assert!(misses(&refused, &budgets)[0].contains("1 with 451"));
    }

    #[test]
    fn a_flush_faster_than_the_drive_is_not_durable() {
        let probe = |min: f64, p50: f64| probe::Report {
            writes: 1,
            sync_us: Spread {
                min,
                p50,
                p95: p50,
                p99: p50,
                max: p50,
            },
            filesystem: None,
            write_cache: None,
            virtualisation: Vec::new(),
            hash_mb_s: 0.0,
        };
        let host = Spread {
            min: 3500.0,
            p50: 4000.0,
            p95: 4500.0,
            p99: 5000.0,
            max: 6000.0,
        };
        let judged = |min, p50| judge_durability(&probe(min, p50), Some(&host)).label;
        assert_eq!(judged(200.0, 240.0), "not durable");
        // A busy machine slows the median, but the fastest flushes still
        // give the virtual machine away (measured during a large build).
        assert_eq!(judged(250.0, 2000.0), "not durable");
        assert_eq!(judged(3600.0, 3800.0), "durable");
    }
}
