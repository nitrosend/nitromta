//! Least privilege: the engine runs without root, and on Linux
//! holds at most the one capability a listener below port 1024 needs,
//! CAP_NET_BIND_SERVICE. It checks before it opens anything, and does not
//! start otherwise: the service unit it ships with grants exactly that.
//!
//! On Linux, root's user ID kept as the real, saved or file-system one
//! would let the process take root back, and root's group as any of its
//! groups opens what that group may; so either refuses the start, as do
//! capabilities beyond the one in any set a thread or a later program could
//! use. No program it might start gains a privilege either: the engine
//! sets no-new-privileges first, on the thread that runs it, which every
//! thread it starts inherits; so it starts only as its process's one
//! thread, and a build's hooks are made after the check. Those are the
//! thread's own IDs and capabilities, which may differ from the process's.
//!
//! Elsewhere, only the real and effective user IDs are checked: the saved
//! one cannot be read there. The engine's production platform is Linux.
//!
//! Nor does the engine leave a core dump, which would hold the
//! installation's keys and the secrets they open.

/// CAP_NET_BIND_SERVICE's bit (linux/capability.h).
#[cfg(target_os = "linux")]
const NET_BIND_SERVICE: u64 = 1 << 10;

/// Refuses to go on with more privilege than the engine needs.
pub fn check() -> Result<(), String> {
    let root = "nitromta does not run as root: run it as a user of its own, with CAP_NET_BIND_SERVICE to listen below port 1024";
    if rustix::process::geteuid().is_root() || rustix::process::getuid().is_root() {
        return Err(root.to_owned());
    }
    #[cfg(target_os = "linux")]
    {
        rustix::thread::set_no_new_privs(true)
            .map_err(|error| format!("setting no-new-privileges: {error}"))?;
        // A thread started before this one set it could still gain
        // privileges.
        let threads = std::fs::read_dir("/proc/self/task")
            .map_err(|error| format!("/proc/self/task: {error}"))?
            .count();
        if threads > 1 {
            return Err(format!(
                "nitromta starts as its process's one thread, and {threads} were running: a thread started before it could gain privileges"
            ));
        }
        let status = std::fs::read_to_string("/proc/thread-self/status")
            .map_err(|error| format!("/proc/thread-self/status: {error}"))?;
        if ids(&status, "Uid:")?.contains(&0) {
            return Err(format!(
                "{root}; its real, saved or file-system user ID is root's, which it could take back"
            ));
        }
        if ids(&status, "Gid:")?.contains(&0) || ids(&status, "Groups:")?.contains(&0) {
            return Err(
                "nitromta does not run in root's group: give its user a group of its own"
                    .to_owned(),
            );
        }
        for set in ["CapPrm:", "CapEff:", "CapInh:", "CapAmb:"] {
            let held = match capabilities(&status, set) {
                Ok(held) => held,
                // Kernels before 4.3 have no ambient set.
                Err(_) if set == "CapAmb:" => 0,
                Err(error) => return Err(error),
            };
            let extra = held & !NET_BIND_SERVICE;
            if extra != 0 {
                return Err(format!(
                    "nitromta holds capabilities it does not need ({} {extra:#x}); it needs CAP_NET_BIND_SERVICE at most",
                    set.trim_end_matches(':')
                ));
            }
        }
    }
    Ok(())
}

/// Leaves no core dump: none is written, and on Linux, none is handed to a
/// program the kernel would pipe one to, which ignores the limit. Called
/// before anything reads a key.
pub fn no_core_dumps() -> Result<(), String> {
    let none = rustix::process::Rlimit {
        current: Some(0),
        maximum: Some(0),
    };
    rustix::process::setrlimit(rustix::process::Resource::Core, none)
        .map_err(|error| format!("turning core dumps off: {error}"))?;
    #[cfg(target_os = "linux")]
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
        .map_err(|error| format!("turning core dumps off: {error}"))?;
    Ok(())
}

/// The capability set `field` names in a process's status.
#[cfg(any(target_os = "linux", test))]
fn capabilities(status: &str, field: &str) -> Result<u64, String> {
    status
        .lines()
        .find_map(|line| line.strip_prefix(field))
        .and_then(|mask| u64::from_str_radix(mask.trim(), 16).ok())
        .ok_or_else(|| format!("/proc/self/status gives no {field}"))
}

/// The IDs `field` lists in a process's status: its user or group IDs, or
/// its supplementary groups, which may be none.
#[cfg(any(target_os = "linux", test))]
fn ids(status: &str, field: &str) -> Result<Vec<u32>, String> {
    let line = status
        .lines()
        .find_map(|line| line.strip_prefix(field))
        .ok_or_else(|| format!("/proc/self/status gives no {field}"))?;
    line.split_whitespace()
        .map(|id| {
            id.parse()
                .map_err(|_| format!("/proc/self/status: {field} {line}"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const STATUS: &str = "Name:\tnitromta\nUid:\t998\t998\t0\t998\nGid:\t998\t998\t998\t998\nGroups:\t\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000400\nCapEff:\t0000000000000400\n";

    #[test]
    fn the_capabilities_and_ids_are_read_from_the_status() {
        assert_eq!(capabilities(STATUS, "CapPrm:"), Ok(1 << 10));
        assert!(capabilities(STATUS, "CapAmb:").is_err());
        // A saved user ID of root's shows among the user IDs.
        assert_eq!(ids(STATUS, "Uid:"), Ok(vec![998, 998, 0, 998]));
        assert_eq!(ids(STATUS, "Groups:"), Ok(vec![]));
        assert!(ids("Uid:\tx\n", "Uid:").is_err());
    }

    #[test]
    fn no_core_dump_is_left() {
        assert_eq!(no_core_dumps(), Ok(()));
        let limit = rustix::process::getrlimit(rustix::process::Resource::Core);
        assert_eq!((limit.current, limit.maximum), (Some(0), Some(0)));
        #[cfg(target_os = "linux")]
        assert_eq!(
            rustix::process::dumpable_behavior(),
            Ok(rustix::process::DumpableBehavior::NotDumpable)
        );
    }
}
