//! Backups and restores.
//!
//! A backup copies the store with SQLite's backup API. While the engine
//! runs, its store thread takes a bounded step of pages between commit
//! groups, so commits go first, and the API keeps the copy current with the
//! writes the same connection makes as it goes: the copy is the store at
//! one commit. A stopped engine's store is copied the same way, at once.
//! The copy is written to a file of its own beside its destination, its
//! owner's alone, notes when it was taken, is synced, and is put in place
//! only where nothing is.
//!
//! A restore runs while the engine is stopped. It opens the copy as the
//! engine would, which checks its schema and that the keys file holds every
//! key its secrets are sealed under, checks its pages, and fences it: every
//! delivery the copy held unfinished waits for the operator's decision,
//! since any may have been delivered after the copy was taken. The store
//! there is moved aside, never deleted, and the copy put in its place.

use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

use engine_core::policy::Fence;
use engine_core::time::Timestamp;
use engine_store::store::Store as SqliteStore;
use rusqlite::Connection;
use rusqlite::backup::{Backup, StepResult};

use crate::config::Config;
use crate::keys;

/// The pages a step copies: a megabyte of the store's 4 KiB pages, a
/// millisecond or two of the store thread's time.
const PAGES_A_STEP: i32 = 256;
/// How many times over the store's size a copy may write before it gives
/// up on a store that grows faster than it.
const OUTPACED: u64 = 4;

/// A copy made.
#[derive(Clone, Copy, Debug)]
pub struct Copied {
    /// When the copy was the store.
    pub taken: Timestamp,
    pub bytes: u64,
}

/// Copies the store `source` holds to `to`, running `between` after each
/// step: the store thread's own turn, which commits what came meanwhile.
/// It stops, removing what it wrote, if `between` says the engine is
/// stopping. `now` is the time the copy is taken at once it is complete.
pub fn copy(
    source: &Connection,
    to: &Path,
    now: impl Fn() -> Timestamp,
    mut between: impl FnMut() -> bool,
) -> Result<Copied, String> {
    let failed = |error: &dyn std::fmt::Display| format!("the backup {}: {error}", to.display());
    if to.exists() {
        return Err(failed(
            &"something is there already; a backup writes over nothing",
        ));
    }
    let staged = staging(to)?;
    let mut cleanup = Cleanup(Some(staged.clone()));
    let mut copy = Connection::open(&staged).map_err(|error| failed(&error))?;
    let taken = {
        let backup = Backup::new(source, &mut copy).map_err(|error| failed(&error))?;
        let (mut copied, mut most) = (0_u64, None);
        loop {
            // Anything else is more to copy; or busy or locked, on this
            // connection's own store never, and tried again at the next
            // step.
            if backup.step(PAGES_A_STEP).map_err(|error| failed(&error))? == StepResult::Done {
                break now();
            }
            // A store that grows faster than its copy, as commits come
            // between steps, would never be copied: given up once it has
            // copied the store's size when the copy began several times
            // over.
            let step = u64::from(PAGES_A_STEP.unsigned_abs());
            copied += step;
            let most = *most.get_or_insert_with(|| {
                OUTPACED * u64::from(backup.progress().pagecount.unsigned_abs()).max(step)
            });
            if copied > most {
                return Err(failed(
                    &"the store grows faster than its copy; try again when it is quieter",
                ));
            }
            if !between() {
                return Err(failed(&"the engine stopped before the copy was complete"));
            }
        }
    };
    // A file of its own, whatever log the store keeps, at this release's
    // schema, noting when it was taken.
    copy.query_row("PRAGMA journal_mode = DELETE", [], |_| Ok(()))
        .map_err(|error| failed(&error))?;
    engine_store::store::migrate_copy(&copy).map_err(|error| failed(&error))?;
    engine_store::store::mark_copied(&copy, taken).map_err(|error| failed(&error))?;
    drop(copy);
    let bytes = place(&staged, to, Placing::New)?;
    cleanup.0 = None;
    Ok(Copied { taken, bytes })
}

/// Copies the stopped store at `store` to `to`, refused while an engine
/// holds it.
pub fn stopped(store: &Path, to: &Path, now: impl Fn() -> Timestamp) -> Result<Copied, String> {
    let failed =
        |error: &dyn std::fmt::Display| format!("the store at {}: {error}", store.display());
    if !store.exists() {
        return Err(failed(&"there is none"));
    }
    // Held as the engine holds it, alone, with no shared memory beside it,
    // so no engine starts on it while it is copied; read, never written.
    let source = Connection::open_with_flags(store, rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE)
        .map_err(|error| failed(&error))?;
    source
        .execute_batch("PRAGMA locking_mode = EXCLUSIVE")
        .map_err(|error| failed(&error))?;
    source
        .query_row("SELECT count(*) FROM sqlite_schema", [], |_| Ok(()))
        .map_err(|error| {
            if error.sqlite_error_code() == Some(rusqlite::ErrorCode::DatabaseBusy) {
                failed(&"the engine holds it; give its configuration an admin socket, which a backup asks")
            } else {
                failed(&error)
            }
        })?;
    copy(&source, to, now, || true)
}

/// A restore done: the fence it set, how many deliveries it covers, and
/// where the store that was there went.
pub struct Restored {
    pub fence: Fence,
    pub unfinished: u64,
    pub aside: Option<PathBuf>,
    /// The copy's tenants with no key of their own here, while per-tenant
    /// keys are on.
    pub unkeyed: usize,
}

/// Restores the copy at `from` as the store `config` names, fenced, while
/// the engine is stopped.
pub fn restore(config: &Config, from: &Path, now: Timestamp) -> Result<Restored, String> {
    let store = &config.store.path;
    let failed = |error: &dyn std::fmt::Display| format!("restoring {}: {error}", from.display());
    // No engine starts while it runs: one takes these first.
    let _held = keys::hold(&config.store.keys)
        .map_err(|why| format!("{why}; stop the engine first, which restores need"))?;
    let keyring = std::sync::Arc::new(keys::load(&config.store.keys)?);
    let tenant_keys = crate::sealing::Sealer::load(
        config.store.encryption,
        std::sync::Arc::clone(&keyring),
        &config.store.keys,
    )?
    .tenant_keys()?;
    // The store as it is, if anything still holds it, or its write-ahead
    // log folded in, so it stands alone when it is put aside: a log moved
    // aside apart from its store would leave the store at its name without
    // the commits the log holds, were the restore stopped before the copy
    // takes the name. A store too damaged to read is put aside as it is,
    // its log of no use to it: that is what a restore is for.
    if store.exists()
        && let Ok(current) = Connection::open(store)
    {
        let checkpointed = current.execute_batch(
            "PRAGMA locking_mode = EXCLUSIVE; BEGIN IMMEDIATE; ROLLBACK;
             PRAGMA wal_checkpoint(TRUNCATE);",
        );
        if let Err(error) = checkpointed {
            match error.sqlite_error_code() {
                Some(rusqlite::ErrorCode::DatabaseBusy) => {
                    return Err(failed(&"the engine holds the store; stop the engine first"));
                }
                Some(rusqlite::ErrorCode::NotADatabase | rusqlite::ErrorCode::DatabaseCorrupt) => {}
                _ => {
                    return Err(failed(&format!(
                        "its log could not be folded into it ({error}), so its last commits would be left apart from it; free what it needs, or move it aside by hand"
                    )));
                }
            }
        }
    }
    // The copy itself is never changed: a file of the restore's own is.
    let staged = staging(store)?;
    let mut cleanup = Cleanup(Some(staged.clone()));
    std::fs::copy(from, &staged).map_err(|error| failed(&error))?;
    let check = Connection::open(&staged).map_err(|error| failed(&error))?;
    engine_store::store::verify(&check).map_err(|error| failed(&error))?;
    drop(check);
    // Opened as the engine opens it: its schema brought up to date, every
    // secret unsealed with these keys and sealed again under the newest, its
    // personal data sealed as the engine seals it.
    let connection = Connection::open(&staged).map_err(|error| failed(&error))?;
    let mut opened = SqliteStore::open(connection, config.store.options(), keyring)
        .map_err(|error| failed(&error))?;
    for (tenant, key) in &tenant_keys {
        opened.add_tenant_key(*tenant, key);
    }
    // The tenants whose keys the copy needs and this installation lacks:
    // their mail in it reads as erased.
    let keyed: std::collections::BTreeSet<_> =
        tenant_keys.iter().map(|(tenant, _)| *tenant).collect();
    let unkeyed = opened
        .policy()
        .tenants()
        .filter(|tenant| !keyed.contains(&tenant.id))
        .count();
    let fence = opened.fence_restored(now).map_err(|error| failed(&error))?;
    let unfinished = opened
        .fenced()
        .map_err(|error| failed(&error))?
        .map_or(0, |(_, unfinished)| unfinished);
    drop(opened);
    self_contained(&staged).map_err(|error| failed(&error))?;
    let aside = if store.exists() {
        // A name nothing has, which a rename never writes over.
        let seconds = now.as_micros() / 1_000_000;
        let aside = (0..)
            .map(|n| match n {
                0 => PathBuf::from(format!("{}.before-restore-{seconds}", store.display())),
                n => PathBuf::from(format!("{}.before-restore-{seconds}-{n}", store.display())),
            })
            .find(|aside| !aside.exists())
            .expect("a free name");
        // The store keeps its name until the copy takes it in one rename:
        // a stop at any point leaves a store there, the old or the new.
        std::fs::hard_link(store, &aside).map_err(|error| failed(&error))?;
        for suffix in ["-wal", "-shm"] {
            let mut sidecar = store.as_os_str().to_owned();
            sidecar.push(suffix);
            let mut moved = aside.as_os_str().to_owned();
            moved.push(suffix);
            if Path::new(&sidecar).exists() {
                std::fs::rename(&sidecar, &moved).map_err(|error| failed(&error))?;
            }
        }
        Some(aside)
    } else {
        None
    };
    place(&staged, store, Placing::Replacing)?;
    cleanup.0 = None;
    Ok(Restored {
        fence,
        unfinished,
        aside,
        unkeyed: if config.store.encryption == crate::config::Encryption::Tenant {
            unkeyed
        } else {
            0
        },
    })
}

/// Folds `path`'s write-ahead log into it and takes it out of WAL mode, so
/// the one file holds everything, the fence included: a close's own
/// checkpoint may fail and leave the log behind, which would not move with
/// it. Refused if the log is not empty after.
fn self_contained(path: &Path) -> Result<(), String> {
    let connection = Connection::open(path).map_err(|error| error.to_string())?;
    let busy: i64 = connection
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))
        .map_err(|error| error.to_string())?;
    let mode: String = connection
        .query_row("PRAGMA journal_mode = DELETE", [], |row| row.get(0))
        .map_err(|error| error.to_string())?;
    drop(connection);
    let mut log = path.as_os_str().to_owned();
    log.push("-wal");
    if busy != 0 || !mode.eq_ignore_ascii_case("delete") || Path::new(&log).exists() {
        return Err("the copy's write-ahead log could not be folded into it".to_owned());
    }
    Ok(())
}

/// A new file beside `path`, its owner's alone, for a copy to be written to
/// and then put in place.
fn staging(path: &Path) -> Result<PathBuf, String> {
    let mut random = [0u8; 8];
    aws_lc_rs::rand::fill(&mut random).map_err(|_| "no randomness".to_owned())?;
    let hex: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
    let staged = PathBuf::from(format!("{}.partial-{hex}", path.display()));
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&staged)
        .map_err(|error| format!("{}: {error}", staged.display()))?;
    Ok(staged)
}

/// Whether a file is put where nothing is, or in place of what is there.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Placing {
    New,
    Replacing,
}

/// Syncs `staged` and puts it at `to`, syncing their directory, and returns
/// its size.
fn place(staged: &Path, to: &Path, placing: Placing) -> Result<u64, String> {
    let failed = |error: &dyn std::fmt::Display| format!("{}: {error}", to.display());
    let file = std::fs::File::open(staged).map_err(|error| failed(&error))?;
    file.sync_all().map_err(|error| failed(&error))?;
    let bytes = file.metadata().map_err(|error| failed(&error))?.len();
    match placing {
        // A link is made only where nothing is.
        Placing::New => {
            std::fs::hard_link(staged, to).map_err(|error| failed(&error))?;
            std::fs::remove_file(staged).map_err(|error| failed(&error))?;
        }
        Placing::Replacing => std::fs::rename(staged, to).map_err(|error| failed(&error))?,
    }
    let directory = match to.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    std::fs::File::open(directory)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| failed(&error))?;
    Ok(bytes)
}

/// Removes a staged file, with its sidecars, unless it was put in place.
struct Cleanup(Option<PathBuf>);

impl Drop for Cleanup {
    fn drop(&mut self) {
        if let Some(staged) = &self.0 {
            for suffix in ["", "-journal", "-wal", "-shm"] {
                let mut file = staged.as_os_str().to_owned();
                file.push(suffix);
                let _ = std::fs::remove_file(file);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A store of its own in the temporary directory, at this release's
    /// schema, with `pages` pages of filler beside it.
    fn store(name: &str, pages: usize) -> (PathBuf, Connection) {
        let directory =
            std::env::temp_dir().join(format!("nitromta-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        let source = Connection::open(directory.join("store.db")).unwrap();
        source
            .execute_batch("PRAGMA journal_mode = WAL; CREATE TABLE filler (data BLOB);")
            .unwrap();
        engine_store::store::migrate_copy(&source).unwrap();
        for _ in 0..pages {
            source
                .execute("INSERT INTO filler (data) VALUES (zeroblob(4000))", [])
                .unwrap();
        }
        (directory, source)
    }

    #[test]
    fn a_copy_takes_steps_with_commits_between_them_and_holds_them_whole() {
        let (directory, source) = store("backup-steps", 4 * 256);
        source
            .execute_batch("CREATE TABLE turns (turn INTEGER, half INTEGER)")
            .unwrap();
        let mut turns = 0;
        let copied = copy(
            &source,
            &directory.join("copy.db"),
            || Timestamp::from_micros(0),
            || {
                // A commit of two rows, as the store thread's turn commits
                // what came meanwhile.
                turns += 1;
                source
                    .execute_batch(&format!(
                        "BEGIN; INSERT INTO turns VALUES ({turns}, 0); INSERT INTO filler (data) VALUES (zeroblob(4000)); INSERT INTO turns VALUES ({turns}, 1); COMMIT;"
                    ))
                    .unwrap();
                true
            },
        );
        assert!(copied.is_ok(), "{copied:?}");
        assert!(turns >= 4, "a step at a time, not one: {turns} turns");
        let copy = Connection::open(directory.join("copy.db")).unwrap();
        engine_store::store::verify(&copy).unwrap();
        // Every commit made before it was complete, each whole.
        let held: i64 = copy
            .query_row("SELECT count(*) FROM turns", [], |row| row.get(0))
            .unwrap();
        assert_eq!(held, 2 * turns);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn a_store_growing_faster_than_its_copy_is_given_up() {
        let (directory, source) = store("backup-outpaced", 256);
        let to = directory.join("copy.db");
        let copied = copy(
            &source,
            &to,
            || Timestamp::from_micros(0),
            || {
                // Twice a step's pages each turn.
                source
                    .execute_batch(
                        "INSERT INTO filler (data) SELECT zeroblob(4000) FROM filler LIMIT 512",
                    )
                    .unwrap();
                true
            },
        );
        assert!(
            copied
                .as_ref()
                .is_err_and(|why| why.contains("grows faster than its copy")),
            "{copied:?}"
        );
        assert!(!to.exists());
        let _ = std::fs::remove_dir_all(directory);
    }
}
