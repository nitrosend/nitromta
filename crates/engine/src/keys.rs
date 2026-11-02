//! The installation's keys file: the keys that seal the secrets
//! in policy, kept apart from the store and its backups. One key a line,
//! its ID and its 32 bytes in hex; the highest ID is the one secrets are
//! sealed under. Only its owner may read it.
//!
//! `nitromta key --to <file>` writes a new key, with the next ID, creating
//! the file if need be. A restart then seals every secret under it, and
//! the older keys' lines may go once it has, and once the mail sealed under
//! them is gone while encryption is on, which `key retire`
//! checks. Run as root, it keeps the
//! file's owner, so the engine's user can still read it; a file it
//! creates is its caller's. Two at once take turns through a lock file
//! beside it, `<file>.lock`, its owner's alone, and whoever writes the
//! keys must be able to read their directory, whose sync makes a new
//! file durable. Each writes the keys whole to a file of its own beside
//! them first, `<file>.new-<random>`, which it removes if it fails; one
//! left by a writer that was killed holds keys, and may be removed.
//!
//! A keys file is one store's. The running engine holds a second lock file
//! beside it, `<file>.engine`, from before it reads the keys until its
//! store is closed, so a second engine on the same keys refuses to start,
//! and the engine `key retire` asks is the only one whose store a key can
//! seal.

use std::io::{Read as _, Write as _};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use engine_store::keys::Keyring;

/// The keys in the file at `path`.
pub fn load(path: &Path) -> Result<Keyring, String> {
    let keys = parse_file(path)?;
    Keyring::new(&keys).map_err(|problem| format!("the keys at {}: {problem}", path.display()))
}

/// The keys in the file at `path`, refused if anyone but its owner may read
/// it.
fn parse_file(path: &Path) -> Result<Vec<(u8, [u8; 32])>, String> {
    let failed =
        |problem: &dyn std::fmt::Display| format!("the keys at {}: {problem}", path.display());
    // Opened once, so the file checked is the file read.
    let mut file = std::fs::File::open(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            failed(&format!(
                "{error}; write one with `nitromta key --to {}`",
                path.display()
            ))
        } else {
            failed(&error)
        }
    })?;
    let metadata = file.metadata().map_err(|error| failed(&error))?;
    if !metadata.is_file() {
        return Err(failed(&"it is not a file"));
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(failed(
            &"anyone but its owner may read it; make it its owner's alone (mode 600)",
        ));
    }
    let mut text = String::new();
    file.read_to_string(&mut text)
        .map_err(|error| failed(&error))?;
    parse(&text).map_err(|problem| failed(&problem))
}

/// Writes a new key to the file at `path`, with the next ID, creating it
/// if need be, and returns its ID once the file holding it is durable.
pub fn generate(path: &Path) -> Result<u8, String> {
    rewrite(path, Writing::Replacing, next)?.ok_or_else(|| "a replacing write writes".to_owned())
}

/// Writes a new keys file at `path`, with its first key, and returns that
/// key's ID once the file is durable: `None`, with nothing changed, if a
/// file is there already, however it came there.
pub fn create(path: &Path) -> Result<Option<u8>, String> {
    rewrite(path, Writing::New, next)
}

/// The keys file's text with a new key, and the key's ID: the next.
fn next(mut text: String, keys: &[(u8, [u8; 32])]) -> Result<(String, u8), String> {
    let id = match keys.iter().map(|(id, _)| *id).max() {
        // 255 marks data sealed under a tenant's key.
        Some(254..) => return Err("it holds key 254, the last there may be".to_owned()),
        Some(highest) => highest + 1,
        None => 1,
    };
    let mut key = [0; 32];
    aws_lc_rs::rand::fill(&mut key).map_err(|_| "no randomness for a key".to_owned())?;
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    text.push_str(&format!("{id} {}\n", hex(&key)));
    Ok((text, id))
}

/// The IDs of the keys in the file at `path`, oldest first: never the keys.
pub fn ids(path: &Path) -> Result<Vec<u8>, String> {
    let mut ids: Vec<u8> = parse_file(path)?.into_iter().map(|(id, _)| id).collect();
    ids.sort_unstable();
    Ok(ids)
}

/// Takes key `id`'s line out of the file at `path`, once no secret is
/// sealed under it: never the newest, which new secrets are sealed under,
/// nor `sealing`, the one a running engine seals every secret under.
pub fn retire(path: &Path, id: u8, sealing: u8) -> Result<(), String> {
    let retired = rewrite(path, Writing::Replacing, |text, keys| {
        let newest = keys.iter().map(|(id, _)| *id).max();
        if newest == Some(id) {
            return Err(format!(
                "key {id} is the newest, which new secrets are sealed under"
            ));
        }
        if id == sealing {
            return Err(format!(
                "the engine seals every secret under key {id}: a restart seals them under the newest, and then it may go"
            ));
        }
        if !keys.iter().any(|(key, _)| *key == id) {
            return Err(format!("it holds no key {id}"));
        }
        let kept: String = text
            .lines()
            .filter(|line| line.split_whitespace().next() != Some(&id.to_string()))
            .map(|line| format!("{line}\n"))
            .collect();
        Ok((kept, ()))
    })?;
    retired.ok_or_else(|| "a replacing write writes".to_owned())
}

/// Holds the keys file at `path` for the running engine until what it
/// returns is dropped, through `<file>.engine`: refused while another
/// engine holds it. The engine makes that file if it is not there and it
/// can; `key --to` and `setup` make it with the keys, for an engine that
/// cannot write their directory.
pub fn hold(path: &Path) -> Result<std::fs::File, String> {
    let keys = canonical(path)?;
    let held = beside(&keys, ".engine");
    let failed = |problem: &dyn std::fmt::Display| {
        format!(
            "the keys at {}: {} {problem}",
            path.display(),
            held.display()
        )
    };
    // Read alone where it is there, as on a read-only system.
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(&held)
    {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(&held)
            .map_err(|error| {
                // Made empty, the keys' owner's alone, as setup makes it: as
                // root, under a service whose /etc is read-only.
                let owner = std::fs::metadata(&keys)
                    .map(|keys| format!(" -o {} -g {}", keys.uid(), keys.gid()))
                    .unwrap_or_default();
                failed(&format!(
                    "is not there, and cannot be made ({error}): make it with `install -m 600{owner} /dev/null {}`",
                    held.display()
                ))
            })?,
        Err(error) => return Err(failed(&error)),
        Ok(file) => file,
    };
    match rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(file),
        Err(rustix::io::Errno::WOULDBLOCK) => Err(format!(
            "the keys at {} are another running engine's: each store has a keys file of its own",
            path.display()
        )),
        Err(error) => Err(failed(&error)),
    }
}

/// The keys file `path` names, whatever links lead to it, so every name for
/// one file finds the same lock files beside it: the file itself if it is
/// there, or its directory's, if it is to be made.
fn canonical(path: &Path) -> Result<std::path::PathBuf, String> {
    let failed = |error: &dyn std::fmt::Display| format!("the keys at {}: {error}", path.display());
    match std::fs::canonicalize(path) {
        Ok(path) => Ok(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let name = path
                .file_name()
                .ok_or_else(|| failed(&"it names no file"))?;
            let parent = match path.parent() {
                Some(parent) if !parent.as_os_str().is_empty() => parent,
                _ => Path::new("."),
            };
            Ok(std::fs::canonicalize(parent)
                .map_err(|error| failed(&error))?
                .join(name))
        }
        Err(error) => Err(failed(&error)),
    }
}

/// `path` with `suffix` after its name.
fn beside(path: &Path, suffix: &str) -> std::path::PathBuf {
    let mut beside = path.as_os_str().to_owned();
    beside.push(suffix);
    beside.into()
}

/// Whether a write may replace a keys file there, or writes only a new one.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Writing {
    Replacing,
    New,
}

/// A file a write made for itself, removed unless it is put in place.
struct Staged<'a> {
    path: &'a Path,
    placed: bool,
}

impl Drop for Staged<'_> {
    fn drop(&mut self) {
        if !self.placed {
            let _ = std::fs::remove_file(self.path);
        }
    }
}

/// Rewrites the keys file at `path` as `change` makes it from its text and
/// keys, creating it if need be, and returns what `change` did once the
/// file is durable; or, `New`, writes one only where there is none, and
/// returns `None` where there is. Two at once take turns, through a lock
/// file beside it which only the keys' owner can open: anyone else could
/// hold a lock on their directory. The new file keeps the old one's owner,
/// so root's rotation leaves it the engine user's, and so does the
/// engine's own lock file, made here if it is not there.
fn rewrite<T>(
    path: &Path,
    writing: Writing,
    change: impl FnOnce(String, &[(u8, [u8; 32])]) -> Result<(String, T), String>,
) -> Result<Option<T>, String> {
    let failed =
        |problem: &dyn std::fmt::Display| format!("the keys at {}: {problem}", path.display());
    let beside_made = |name: &Path| {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(name)
            .map_err(|error| failed(&format!("{}: {error}", name.display())))
    };
    // The file whatever name it was given by, so every writer takes the
    // same lock, and the file itself is replaced, not a link to it.
    let path = &canonical(path)?;
    let lock = beside_made(&beside(path, ".lock"))?;
    rustix::fs::flock(&lock, rustix::fs::FlockOperation::LockExclusive)
        .map_err(|error| failed(&error))?;
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let directory = std::fs::File::open(parent).map_err(|error| {
        failed(&format!(
            "its directory, which must be readable to make a new file durable: {error}"
        ))
    })?;
    let (text, owner) = match std::fs::File::open(path) {
        Ok(_) if writing == Writing::New => return Ok(None),
        Ok(mut file) => {
            let metadata = file.metadata().map_err(|error| failed(&error))?;
            let mut text = String::new();
            file.read_to_string(&mut text)
                .map_err(|error| failed(&error))?;
            (text, Some((metadata.uid(), metadata.gid())))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (String::new(), None),
        Err(error) => return Err(failed(&error)),
    };
    let keys = parse(&text).map_err(|problem| failed(&problem))?;
    let (text, changed) = change(text, &keys).map_err(|problem| failed(&problem))?;
    let engine = beside_made(&beside(path, ".engine"))?;
    // Written whole to a file of this write's own beside it, its owner's
    // alone, then put in its place; removed if it is not.
    let mut random = [0u8; 8];
    aws_lc_rs::rand::fill(&mut random).map_err(|_| failed(&"no randomness"))?;
    let written = beside(path, &format!(".new-{}", hex(&random)));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(&written)
        .map_err(|error| failed(&error))?;
    let mut staged = Staged {
        path: &written,
        placed: false,
    };
    if let Some((user, group)) = owner {
        std::os::unix::fs::fchown(&file, Some(user), Some(group))
            .map_err(|error| failed(&error))?;
        // The lock files too, so their owner can take them.
        let _ = std::os::unix::fs::fchown(&lock, Some(user), Some(group));
        let _ = std::os::unix::fs::fchown(&engine, Some(user), Some(group));
    }
    file.write_all(text.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|error| failed(&error))?;
    match writing {
        Writing::Replacing => {
            std::fs::rename(&written, path).map_err(|error| failed(&error))?;
            staged.placed = true;
        }
        // A link is made only where nothing is, whoever else writes there.
        Writing::New => match std::fs::hard_link(&written, path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => return Ok(None),
            Err(error) => return Err(failed(&error)),
        },
    }
    drop(staged);
    directory.sync_all().map_err(|error| failed(&error))?;
    Ok(Some(changed))
}

/// Each key a line: its ID and its 32 bytes in hex. Blank lines and those
/// starting `#` are skipped.
fn parse(text: &str) -> Result<Vec<(u8, [u8; 32])>, String> {
    text.lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty() && !line.trim_start().starts_with('#'))
        .map(|(number, line)| {
            let bad = || {
                format!(
                    "line {} is not a key's ID and its 64 hex digits",
                    number + 1
                )
            };
            let (id, key) = line.trim().split_once(' ').ok_or_else(bad)?;
            let id: u8 = id.parse().map_err(|_| bad())?;
            let key = crate::config::hex(key.trim())
                .and_then(|key| <[u8; 32]>::try_from(key).ok())
                .ok_or_else(bad)?;
            Ok((id, key))
        })
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_written_one_a_line_with_the_next_id_and_read_back_by_their_owner_alone() {
        let dir = std::env::temp_dir().join(format!("nitromta-keys-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("keys");
        assert_eq!(generate(&path), Ok(1));
        assert_eq!(generate(&path), Ok(2));
        assert_eq!(load(&path).map(|keys| keys.current()), Ok(2));
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(load(&path).is_err_and(|why| why.contains("its owner's alone")));
        std::fs::write(&path, "1 not-a-key\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load(&path).is_err_and(|why| why.contains("line 1")));
        assert!(load(&dir.join("absent")).is_err_and(|why| why.contains("nitromta key --to")));
        assert!(load(&dir).is_err_and(|why| why.contains("not a file")));
        // 255 marks a tenant's key: the file ends at 254, which
        // it can still be read with.
        let key = "00".repeat(32);
        std::fs::write(&path, format!("254 {key}\n")).unwrap();
        assert!(generate(&path).is_err_and(|why| why.contains("key 254, the last")));
        assert_eq!(load(&path).map(|keys| keys.current()), Ok(254));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_older_key_is_retired_but_never_the_newest_nor_the_one_in_use() {
        let dir = std::env::temp_dir().join(format!("nitromta-keys-retire-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("keys");
        for _ in 0..3 {
            generate(&path).unwrap();
        }
        assert_eq!(ids(&path), Ok(vec![1, 2, 3]));
        assert!(retire(&path, 3, 3).is_err_and(|why| why.contains("the newest")));
        assert!(
            retire(&path, 2, 2).is_err_and(|why| why.contains("seals every secret under key 2"))
        );
        assert!(retire(&path, 9, 3).is_err_and(|why| why.contains("no key 9")));
        assert_eq!(retire(&path, 1, 3), Ok(()));
        assert_eq!(ids(&path), Ok(vec![2, 3]));
        assert_eq!(load(&path).map(|keys| keys.current()), Ok(3));
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn one_engine_holds_the_keys_and_a_new_file_is_written_only_where_none_is() {
        let dir = std::env::temp_dir().join(format!("nitromta-keys-held-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("keys");
        assert_eq!(create(&path), Ok(Some(1)));
        let written = std::fs::read(&path).unwrap();
        assert_eq!(create(&path), Ok(None));
        assert_eq!(std::fs::read(&path).unwrap(), written);
        // Nothing of a write's own is left beside the keys.
        let mut beside: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        beside.sort();
        assert_eq!(beside, ["keys", "keys.engine", "keys.lock"]);
        let held = hold(&path).unwrap();
        assert!(hold(&path).is_err_and(|why| why.contains("another running engine's")));
        // So is every other name for the same file.
        let alias = dir.join("alias");
        std::os::unix::fs::symlink(&path, &alias).unwrap();
        assert!(hold(&alias).is_err_and(|why| why.contains("another running engine's")));
        // A writer still takes its turn while an engine holds the keys.
        assert_eq!(generate(&path), Ok(2));
        drop(held);
        assert!(hold(&path).is_ok());
        // Where the engine cannot make its lock file, as under a service
        // whose /etc is read-only, it says how to.
        std::fs::remove_file(dir.join("keys.engine")).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();
        let refused = hold(&path);
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(refused.is_err_and(|why| why.contains("install -m 600 -o ")
            && why.contains("/dev/null")
            && why.ends_with("keys.engine`")),);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn keys_written_at_once_each_take_an_id_of_their_own() {
        let dir =
            std::env::temp_dir().join(format!("nitromta-keys-at-once-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("keys");
        let start = std::sync::Arc::new(std::sync::Barrier::new(8));
        let writers: Vec<_> = (0..8)
            .map(|_| {
                let (path, start) = (path.clone(), std::sync::Arc::clone(&start));
                std::thread::spawn(move || {
                    start.wait();
                    generate(&path)
                })
            })
            .collect();
        let mut ids: Vec<u8> = writers
            .into_iter()
            .map(|writer| writer.join().unwrap().unwrap())
            .collect();
        ids.sort_unstable();
        assert_eq!(ids, (1..=8).collect::<Vec<_>>());
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(parse(&text).unwrap().len(), 8, "{text}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
