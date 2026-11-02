//! The durability probe: how long a durable write takes
//! on the volume a system under test keeps its queue on, and what can be seen
//! from inside a container of the machine beneath it. The runner judges from
//! this, and from the host, whether a flush on that volume reaches stable
//! storage.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::args::Args;
use crate::observe::{Spread, spread};

/// The size of each durable write: one page, appended, as a write-ahead log
/// appends.
const WRITE: usize = 4096;

#[derive(Clone, Serialize, Deserialize)]
pub struct Report {
    pub writes: usize,
    /// Each append and its `fdatasync`, in microseconds.
    pub sync_us: Spread,
    pub filesystem: Option<String>,
    /// The block device's `queue/write_cache`: "write back" when it holds
    /// writes in a volatile cache that flushes must empty.
    pub write_cache: Option<String>,
    /// Signs of a hypervisor; empty when none were found.
    pub virtualisation: Vec<String>,
    /// SHA-256 throughput on one of the CPUs the probe ran on, in MB/s: a
    /// gauge of how fast those CPUs were at the time. A machine that slows
    /// through a session (heat, or its cores reassigned) shows here.
    #[serde(default)]
    pub hash_mb_s: f64,
}

pub fn main(argv: &[String]) -> Result<(), String> {
    let args = Args::parse(argv, &["dir", "writes"])?;
    let report = probe(
        Path::new(args.required("dir")?),
        args.parse_or("writes", 1000)?,
    )?;
    println!(
        "{}",
        serde_json::to_string(&report).map_err(|error| error.to_string())?
    );
    Ok(())
}

fn probe(dir: &Path, writes: usize) -> Result<Report, String> {
    let path = dir.join(".harness-probe");
    let failed = |error: std::io::Error| format!("{}: {error}", path.display());
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&path)
        .map_err(failed)?;
    let page = vec![0x5a; WRITE];
    let mut micros = Vec::with_capacity(writes);
    for _ in 0..writes.max(1) {
        let start = Instant::now();
        file.write_all(&page).map_err(failed)?;
        file.sync_data().map_err(failed)?;
        micros.push(start.elapsed().as_secs_f64() * 1e6);
    }
    drop(file);
    fs::remove_file(&path).map_err(failed)?;
    let (filesystem, device) = mount(dir).unzip();
    Ok(Report {
        writes: micros.len(),
        sync_us: spread(&mut micros).unwrap_or_default(),
        filesystem,
        write_cache: device.and_then(|device| write_cache(&device)),
        virtualisation: virtualisation(),
        hash_mb_s: hash_speed(),
    })
}

/// Hashes 256 MiB with SHA-256, in 1 MiB pieces, and returns the rate.
fn hash_speed() -> f64 {
    const PIECE: usize = 1024 * 1024;
    const PIECES: usize = 256;
    let piece = vec![0xa5; PIECE];
    let start = Instant::now();
    let mut context = aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA256);
    for _ in 0..PIECES {
        context.update(&piece);
    }
    let digest = context.finish();
    let seconds = start.elapsed().as_secs_f64().max(f64::MIN_POSITIVE);
    std::hint::black_box(digest);
    (PIECE * PIECES) as f64 / 1e6 / seconds
}

/// The filesystem type and `major:minor` device of the mount holding `dir`,
/// from `/proc/self/mountinfo`.
fn mount(dir: &Path) -> Option<(String, String)> {
    let mountinfo = fs::read_to_string("/proc/self/mountinfo").ok()?;
    let dir = dir.to_string_lossy();
    mountinfo
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split(' ').collect();
            let separator = fields.iter().position(|&field| field == "-")?;
            let point = *fields.get(4)?;
            let inside = dir == point || point == "/" || dir.starts_with(&format!("{point}/"));
            let mount = (
                fields.get(separator + 1)?.to_string(),
                fields.get(2)?.to_string(),
            );
            inside.then_some((point.len(), mount))
        })
        .max_by_key(|(length, _)| *length)
        .map(|(_, mount)| mount)
}

fn write_cache(device: &str) -> Option<String> {
    // A partition has no queue of its own; its disk's is one level up.
    [
        format!("/sys/dev/block/{device}/queue/write_cache"),
        format!("/sys/dev/block/{device}/../queue/write_cache"),
    ]
    .iter()
    .find_map(|path| fs::read_to_string(path).ok())
    .map(|mode| mode.trim().to_owned())
}

/// Whether a DMI product name is one of EC2's bare-metal instances: a
/// family with its generation, such as `c7g` or `u7i-12tb`, and the size
/// `metal` or `metal-<n>xl`, such as `c7g.metal` or `m7i.metal-24xl`.
fn bare_metal(product: &str) -> bool {
    let Some((family, size)) = product.trim().split_once('.') else {
        return false;
    };
    let family = family.starts_with(|c: char| c.is_ascii_lowercase())
        && family.contains(|c: char| c.is_ascii_digit())
        && family
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    let size = size == "metal"
        || size
            .strip_prefix("metal-")
            .and_then(|size| size.strip_suffix("xl"))
            .is_some_and(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()));
    family && size
}

/// What the DMI vendor and product say of a hypervisor. An EC2 bare-metal
/// instance names Amazon EC2 as its vendor, with no hypervisor between the
/// system and its CPUs and disks: there, and only there, that one match is
/// no evidence.
fn dmi_evidence(vendor: &str, product: &str) -> Vec<String> {
    let ec2_metal = vendor.trim() == "Amazon EC2" && bare_metal(product);
    [("sys_vendor", vendor), ("product_name", product)]
        .into_iter()
        .filter(|(_, value)| {
            HYPERVISORS
                .iter()
                .any(|name| value.contains(name) && !(ec2_metal && *name == "Amazon EC2"))
        })
        .map(|(file, value)| format!("DMI {file}: {}", value.trim()))
        .collect()
}

const HYPERVISORS: [&str; 14] = [
    "QEMU",
    "KVM",
    "VMware",
    "VirtualBox",
    "innotek",
    "Xen",
    "Microsoft Corporation",
    "Amazon EC2",
    "Google",
    "Parallels",
    "Bochs",
    "BHYVE",
    "OpenStack",
    "Apple Virtualization",
];

fn virtualisation() -> Vec<String> {
    let mut found = Vec::new();
    if fs::read_to_string("/proc/cpuinfo").is_ok_and(|cpuinfo| {
        cpuinfo.lines().any(|line| {
            line.starts_with("flags") && line.split_whitespace().any(|flag| flag == "hypervisor")
        })
    }) {
        found.push("the CPU reports the hypervisor flag".to_owned());
    }
    let dmi =
        |file: &str| fs::read_to_string(format!("/sys/class/dmi/id/{file}")).unwrap_or_default();
    found.extend(dmi_evidence(&dmi("sys_vendor"), &dmi("product_name")));
    if let Ok(kind) = fs::read_to_string("/sys/hypervisor/type")
        && !kind.trim().is_empty()
    {
        found.push(format!("/sys/hypervisor/type: {}", kind.trim()));
    }
    if Path::new("/proc/device-tree/hypervisor").exists() {
        found.push("the device tree has a hypervisor node".to_owned());
    }
    found
}

/// The host's own durable-write latency on macOS, where the container
/// runtime's Linux runs in a virtual machine: each append is followed by
/// `F_FULLFSYNC`, which waits for the drive itself. A flush in the
/// virtual machine that returns much faster stopped short of the drive.
#[cfg(target_os = "macos")]
pub fn host_full_sync(dir: &Path, writes: usize) -> Result<Spread, String> {
    let path = dir.join(".harness-probe");
    let failed = |error: std::io::Error| format!("{}: {error}", path.display());
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&path)
        .map_err(failed)?;
    let page = vec![0x5a; WRITE];
    let mut micros = Vec::with_capacity(writes);
    for _ in 0..writes.max(1) {
        let start = Instant::now();
        file.write_all(&page).map_err(failed)?;
        rustix::fs::fcntl_fullfsync(&file).map_err(|error| failed(error.into()))?;
        micros.push(start.elapsed().as_secs_f64() * 1e6);
    }
    drop(file);
    fs::remove_file(&path).map_err(failed)?;
    Ok(spread(&mut micros).unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_probe_times_durable_writes() {
        let dir = std::env::temp_dir().join(format!("harness-probe-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let report = probe(&dir, 8).unwrap();
        assert_eq!(report.writes, 8);
        assert!(report.sync_us.p50 > 0.0 && report.sync_us.max >= report.sync_us.p50);
        assert!(!dir.join(".harness-probe").exists());
        fs::remove_dir(&dir).unwrap();
    }

    #[test]
    fn only_ec2s_bare_metal_sizes_are_bare_metal() {
        for product in [
            "c7g.metal\n",
            "m7i.metal-24xl",
            "c7i.metal-48xl",
            "u7i-12tb.metal",
        ] {
            assert!(bare_metal(product), "{product}");
        }
        for product in [
            "c7g.4xlarge",
            "m7i.48xlarge",
            "metal",
            ".metal",
            "anything.metal",
            "c7g.metal-garbage",
            "c7g.metal-xl",
            "C7G.metal",
            "Standard PC (Q35 + ICH9, 2009)",
        ] {
            assert!(!bare_metal(product), "{product}");
        }
    }

    #[test]
    fn only_ec2s_own_vendor_name_is_excused_on_its_bare_metal() {
        assert!(dmi_evidence("Amazon EC2\n", "c7g.metal\n").is_empty());
        assert_eq!(dmi_evidence("Amazon EC2", "c7g.4xlarge").len(), 1);
        assert_eq!(dmi_evidence("QEMU", "c7g.metal").len(), 1);
        assert_eq!(dmi_evidence("Amazon EC2", "anything.metal").len(), 1);
        assert!(dmi_evidence("Dell Inc.", "PowerEdge R760").is_empty());
    }
}
