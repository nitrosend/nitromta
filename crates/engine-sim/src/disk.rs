//! The simulated disk: files whose unsynced writes and directory changes a
//! power failure may keep, lose or tear.
//!
//! It models what SQLite assumes of a disk under the production Unix VFS:
//! - **Sectors.** 4096-byte sectors with powersafe overwrite, so a write
//!   interrupted by a power failure damages only the bytes it was writing.
//! - **File syncs.** A sync makes the file's contents durable.
//! - **Directory syncs.** A file's directory entry, its existence, is
//!   durable only after the directory is synced, which makes every entry in
//!   it durable. As the Unix VFS does, a new journal or WAL syncs the
//!   directory on its first sync, and a deletion syncs it when asked to.
//!
//! A power failure is armed to strike a chosen I/O operation, so a run can
//! fail at every possible point. That operation fails, as does every later
//! one, until [`Disk::crash`] applies the failure:
//! - each unsynced piece of a written range, split at 512-byte physical
//!   sectors, independently keeps its new bytes, keeps its old ones, or
//!   becomes garbage;
//! - a file whose length changed since its last sync takes either length,
//!   and space it never synced holds garbage;
//! - a file created or deleted since the last directory sync may or may
//!   not exist.

use std::collections::BTreeMap;
use std::hash::{DefaultHasher, Hash, Hasher};

use engine_core::rng::Rng;
use engine_core::time::Timestamp;

/// The unit a power failure keeps, loses or garbles on its own.
const PHYSICAL_SECTOR: usize = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Handle(u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiskError {
    NotFound,
    /// A file is open at most once: each database has one connection.
    AlreadyOpen,
    /// The power has failed; nothing more reaches the disk.
    PoweredOff,
    /// The disk is full: the write would take its files past its capacity,
    /// and none of it lands.
    Full,
}

/// How a file is opened.
#[derive(Clone, Copy, Debug, Default)]
pub struct OpenOptions {
    pub create: bool,
    /// Closing the file deletes it. Such a file is unlinked as it is opened,
    /// so it never survives a crash.
    pub delete_on_close: bool,
    /// If the file is created, its first sync also syncs the directory, as
    /// the production VFS does for a new journal or WAL.
    pub sync_directory_when_new: bool,
}

pub struct Disk {
    files: BTreeMap<String, File>,
    open: BTreeMap<Handle, Open>,
    next_handle: u32,
    next_temporary: u32,
    rng: Rng,
    now: Timestamp,
    /// Operations left before the power fails, when a failure is armed.
    failure_in: Option<u64>,
    powered: bool,
    /// The most bytes its files may hold together, when it is bounded.
    capacity: Option<u64>,
    /// Successful syncs so far, by file.
    syncs: BTreeMap<String, u64>,
    /// Bytes written so far, by file.
    written: BTreeMap<String, u64>,
}

struct Open {
    path: String,
    delete_on_close: bool,
}

#[derive(Default, Hash)]
struct File {
    /// What the process sees; `None` once deleted.
    live: Option<Vec<u8>>,
    /// The contents as of the file's last sync.
    synced: Vec<u8>,
    /// Whether the directory durably records the file as existing.
    entry_durable: bool,
    /// Whether the file's next sync also syncs the directory.
    sync_directory: bool,
    /// Disjoint byte ranges written since the last sync, start to end.
    dirty: BTreeMap<usize, usize>,
}

impl Disk {
    pub fn new(rng: Rng, now: Timestamp) -> Self {
        Self {
            files: BTreeMap::new(),
            open: BTreeMap::new(),
            next_handle: 0,
            next_temporary: 0,
            rng,
            now,
            failure_in: None,
            powered: true,
            capacity: None,
            syncs: BTreeMap::new(),
            written: BTreeMap::new(),
        }
    }

    pub fn now(&self) -> Timestamp {
        self.now
    }

    pub fn set_now(&mut self, now: Timestamp) {
        self.now = now;
    }

    pub fn is_powered(&self) -> bool {
        self.powered
    }

    /// Successful syncs so far, to show what a commit costs.
    pub fn syncs(&self) -> u64 {
        self.syncs.values().sum()
    }

    /// Successful syncs of one file so far. In WAL mode, only a checkpoint
    /// syncs the main database file.
    pub fn syncs_of(&self, path: &str) -> u64 {
        self.syncs.get(path).copied().unwrap_or(0)
    }

    /// Bytes written to one file so far, whether or not they were synced.
    pub fn written_to(&self, path: &str) -> u64 {
        self.written.get(path).copied().unwrap_or(0)
    }

    /// Bounds what its files may hold together to `bytes`, or no longer.
    /// A write or truncation that would grow them past it fails as full.
    pub fn set_capacity(&mut self, bytes: Option<u64>) {
        self.capacity = bytes;
    }

    /// What its files hold together.
    pub fn used(&self) -> u64 {
        self.files
            .values()
            .map(|file| file.live.as_ref().map_or(0, Vec::len) as u64)
            .sum()
    }

    /// Whether growing a file of `length` bytes to `end` would take the
    /// files past the disk's capacity.
    fn overfills(&self, length: usize, end: usize) -> bool {
        let growth = end.saturating_sub(length) as u64;
        self.capacity
            .is_some_and(|capacity| growth > 0 && self.used() + growth > capacity)
    }

    /// Arms a power failure to strike the `operations`th I/O operation
    /// from now.
    pub fn fail_power_after(&mut self, operations: u64) {
        self.failure_in = Some(operations);
    }

    /// Opens `path`, or a new temporary file when it is `None`.
    pub fn open(&mut self, path: Option<&str>, options: OpenOptions) -> Result<Handle, DiskError> {
        self.operate()?;
        let path = match path {
            Some(path) => path.to_owned(),
            None => {
                self.next_temporary += 1;
                format!("temporary-{}", self.next_temporary)
            }
        };
        if self.open.values().any(|open| open.path == path) {
            return Err(DiskError::AlreadyOpen);
        }
        let file = self.files.entry(path.clone()).or_default();
        if file.live.is_none() {
            if !options.create {
                return Err(DiskError::NotFound);
            }
            file.live = Some(Vec::new());
            file.sync_directory = options.sync_directory_when_new;
        }
        self.next_handle += 1;
        let handle = Handle(self.next_handle);
        self.open.insert(
            handle,
            Open {
                path,
                delete_on_close: options.delete_on_close,
            },
        );
        Ok(handle)
    }

    pub fn close(&mut self, handle: Handle) {
        if let Some(open) = self.open.remove(&handle)
            && open.delete_on_close
        {
            self.files.remove(&open.path);
        }
    }

    /// Reads into `buffer` from `offset`, returning how many bytes the file
    /// had there.
    pub fn read(
        &mut self,
        handle: Handle,
        offset: usize,
        buffer: &mut [u8],
    ) -> Result<usize, DiskError> {
        self.operate()?;
        let live = self.live(handle)?;
        let available = live.len().saturating_sub(offset).min(buffer.len());
        buffer[..available].copy_from_slice(&live[offset..offset + available]);
        Ok(available)
    }

    pub fn write(&mut self, handle: Handle, offset: usize, data: &[u8]) -> Result<(), DiskError> {
        // A write the power failure strikes may still partly reach the
        // disk, so it lands unsynced before the failure is reported. Once
        // the power is off, nothing lands.
        let was_powered = self.powered;
        let struck = self.operate();
        if !was_powered {
            return struck;
        }
        let path = self
            .open
            .get(&handle)
            .ok_or(DiskError::NotFound)?
            .path
            .clone();
        let end = offset + data.len();
        let length = self.file(handle)?.live.as_ref().map_or(0, Vec::len);
        if self.overfills(length, end) {
            return Err(DiskError::Full);
        }
        let file = self.file(handle)?;
        let live = file.live.as_mut().ok_or(DiskError::NotFound)?;
        if live.len() < end {
            live.resize(end, 0);
        }
        live[offset..end].copy_from_slice(data);
        mark(&mut file.dirty, offset, end);
        *self.written.entry(path).or_default() += data.len() as u64;
        struck
    }

    pub fn truncate(&mut self, handle: Handle, length: usize) -> Result<(), DiskError> {
        self.operate()?;
        let previous = self.file(handle)?.live.as_ref().map_or(0, Vec::len);
        if self.overfills(previous, length) {
            return Err(DiskError::Full);
        }
        let file = self.file(handle)?;
        let live = file.live.as_mut().ok_or(DiskError::NotFound)?;
        let previous = live.len();
        live.resize(length, 0);
        if length > previous {
            mark(&mut file.dirty, previous, length);
        } else {
            file.dirty.retain(|&start, _| start < length);
            for end in file.dirty.values_mut() {
                *end = (*end).min(length);
            }
        }
        Ok(())
    }

    /// Makes the file's contents durable, and the directory too when the
    /// file asks for that on its first sync.
    pub fn sync(&mut self, handle: Handle) -> Result<(), DiskError> {
        self.operate()?;
        let path = self
            .open
            .get(&handle)
            .ok_or(DiskError::NotFound)?
            .path
            .clone();
        let file = self.file(handle)?;
        let live = file.live.as_ref().ok_or(DiskError::NotFound)?;
        file.synced.resize(live.len(), 0);
        for (&start, &end) in &file.dirty {
            file.synced[start..end].copy_from_slice(&live[start..end]);
        }
        file.dirty.clear();
        if std::mem::take(&mut file.sync_directory) {
            self.sync_directory();
        }
        *self.syncs.entry(path).or_default() += 1;
        Ok(())
    }

    pub fn size(&mut self, handle: Handle) -> Result<usize, DiskError> {
        self.operate()?;
        Ok(self.live(handle)?.len())
    }

    /// Deletes `path`. The deletion is durable once the directory is
    /// synced, which `sync_directory` does now.
    pub fn delete(&mut self, path: &str, sync_directory: bool) -> Result<(), DiskError> {
        self.operate()?;
        let file = self.files.get_mut(path).ok_or(DiskError::NotFound)?;
        if file.live.take().is_none() {
            return Err(DiskError::NotFound);
        }
        file.dirty.clear();
        if !file.entry_durable {
            // Its creation never reached the disk, so nothing can return.
            self.files.remove(path);
        }
        if sync_directory {
            self.sync_directory();
        }
        Ok(())
    }

    pub fn exists(&self, path: &str) -> bool {
        self.files.get(path).is_some_and(|file| file.live.is_some())
    }

    pub fn fill_random(&mut self, buffer: &mut [u8]) {
        garble(buffer, &mut self.rng);
    }

    /// Applies a power failure: the process is gone, so every open file is
    /// closed, and each file becomes what a disk could hold afterwards.
    /// The power then returns.
    pub fn crash(&mut self) {
        // Temporary files are unlinked as they are opened, so none survives.
        for open in std::mem::take(&mut self.open).into_values() {
            if open.delete_on_close {
                self.files.remove(&open.path);
            }
        }
        let files = std::mem::take(&mut self.files);
        for (path, file) in files {
            if let Some(contents) = survive(file, &mut self.rng) {
                let file = File {
                    live: Some(contents.clone()),
                    synced: contents,
                    entry_durable: true,
                    sync_directory: false,
                    dirty: BTreeMap::new(),
                };
                self.files.insert(path, file);
            }
        }
        self.failure_in = None;
        self.powered = true;
    }

    /// Each file the process sees, and what it holds.
    pub fn files(&self) -> impl Iterator<Item = (&str, &[u8])> {
        self.files
            .iter()
            .filter_map(|(path, file)| Some((path.as_str(), file.live.as_deref()?)))
    }

    /// A digest of every file, to prove a seed replays to the same disk.
    pub fn digest(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.files.hash(&mut hasher);
        hasher.finish()
    }

    /// Makes every directory entry durable: files that exist, and the
    /// absence of files that were deleted.
    fn sync_directory(&mut self) {
        self.files.retain(|_, file| file.live.is_some());
        for file in self.files.values_mut() {
            file.entry_durable = true;
        }
    }

    /// Counts one I/O operation against an armed power failure.
    fn operate(&mut self) -> Result<(), DiskError> {
        if !self.powered {
            return Err(DiskError::PoweredOff);
        }
        match self.failure_in {
            Some(0) => {
                self.powered = false;
                self.failure_in = None;
                Err(DiskError::PoweredOff)
            }
            Some(remaining) => {
                self.failure_in = Some(remaining - 1);
                Ok(())
            }
            None => Ok(()),
        }
    }

    fn file(&mut self, handle: Handle) -> Result<&mut File, DiskError> {
        let path = &self.open.get(&handle).ok_or(DiskError::NotFound)?.path;
        self.files.get_mut(path).ok_or(DiskError::NotFound)
    }

    fn live(&mut self, handle: Handle) -> Result<&Vec<u8>, DiskError> {
        self.file(handle)?.live.as_ref().ok_or(DiskError::NotFound)
    }
}

/// Records `start..end` as written, merging it with the ranges it touches.
fn mark(dirty: &mut BTreeMap<usize, usize>, start: usize, end: usize) {
    let (mut start, mut end) = (start, end);
    let touching: Vec<usize> = dirty
        .range(..=end)
        .filter(|&(_, &range_end)| range_end >= start)
        .map(|(&range_start, _)| range_start)
        .collect();
    for range_start in touching {
        let range_end = dirty.remove(&range_start).expect("listed above");
        start = start.min(range_start);
        end = end.max(range_end);
    }
    dirty.insert(start, end);
}

/// What one file holds after a power failure, if it still exists.
fn survive(file: File, rng: &mut Rng) -> Option<Vec<u8>> {
    let exists = file.live.is_some();
    // A creation or deletion the directory has not durably recorded may or
    // may not have reached the disk.
    let survives = if exists == file.entry_durable {
        exists
    } else {
        rng.below(2) == 0
    };
    if !survives {
        return None;
    }
    let mut contents = file.synced;
    let Some(live) = file.live else {
        // A deletion that never reached the disk: the file is back as it
        // was last synced.
        return Some(contents);
    };
    let synced_length = contents.len();
    let length = if rng.below(2) == 0 {
        synced_length
    } else {
        live.len()
    };
    contents.resize(length, 0);
    if length > synced_length {
        garble(&mut contents[synced_length..], rng);
    }
    for (&start, &end) in &file.dirty {
        let end = end.min(length);
        let mut piece = start;
        while piece < end {
            let piece_end = ((piece / PHYSICAL_SECTOR + 1) * PHYSICAL_SECTOR).min(end);
            match rng.below(3) {
                0 => contents[piece..piece_end].copy_from_slice(&live[piece..piece_end]),
                1 => {}
                _ => garble(&mut contents[piece..piece_end], rng),
            }
            piece = piece_end;
        }
    }
    Some(contents)
}

fn garble(bytes: &mut [u8], rng: &mut Rng) {
    for chunk in bytes.chunks_mut(8) {
        let noise = rng.next_u64().to_le_bytes();
        chunk.copy_from_slice(&noise[..chunk.len()]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// How the production VFS opens a new journal or WAL.
    const JOURNAL: OpenOptions = OpenOptions {
        create: true,
        delete_on_close: false,
        sync_directory_when_new: true,
    };
    /// How it opens a new main database.
    const DATABASE: OpenOptions = OpenOptions {
        create: true,
        delete_on_close: false,
        sync_directory_when_new: false,
    };
    const EXISTING: OpenOptions = OpenOptions {
        create: false,
        delete_on_close: false,
        sync_directory_when_new: false,
    };

    fn disk(seed: u64) -> Disk {
        Disk::new(Rng::from_seed(seed), Timestamp::from_micros(0))
    }

    fn contents(disk: &mut Disk, path: &str) -> Option<Vec<u8>> {
        let handle = disk.open(Some(path), EXISTING).ok()?;
        let length = disk.size(handle).expect("powered");
        let mut buffer = vec![0; length];
        disk.read(handle, 0, &mut buffer).expect("powered");
        disk.close(handle);
        Some(buffer)
    }

    #[test]
    fn synced_data_survives_every_crash() {
        for seed in 0..200 {
            let mut disk = disk(seed);
            let handle = disk.open(Some("wal"), JOURNAL).expect("created");
            disk.write(handle, 0, &[7; 3000]).expect("powered");
            disk.sync(handle).expect("powered");
            disk.crash();
            assert_eq!(
                contents(&mut disk, "wal"),
                Some(vec![7; 3000]),
                "seed {seed}"
            );
        }
    }

    #[test]
    fn a_new_file_exists_durably_only_once_its_directory_is_synced() {
        let (mut vanished, mut stayed) = (false, false);
        for seed in 0..100 {
            let mut disk = disk(seed);
            let database = disk.open(Some("db"), DATABASE).expect("created");
            disk.write(database, 0, b"page").expect("powered");
            disk.sync(database).expect("powered");
            disk.crash();
            match contents(&mut disk, "db") {
                Some(after) => {
                    assert_eq!(after, b"page");
                    stayed = true;
                }
                None => vanished = true,
            }
        }
        assert!(vanished && stayed);

        // A new WAL's first sync syncs the directory, recording the database
        // created before it as well.
        for seed in 0..100 {
            let mut disk = disk(seed);
            let database = disk.open(Some("db"), DATABASE).expect("created");
            let wal = disk.open(Some("db-wal"), JOURNAL).expect("created");
            disk.sync(wal).expect("powered");
            disk.close(database);
            disk.crash();
            assert_eq!(contents(&mut disk, "db"), Some(Vec::new()), "seed {seed}");
        }
    }

    #[test]
    fn unsynced_writes_are_kept_lost_or_garbled_by_sector() {
        let (mut kept, mut lost, mut garbled) = (false, false, false);
        for seed in 0..200 {
            let mut disk = disk(seed);
            let handle = disk.open(Some("wal"), JOURNAL).expect("created");
            disk.write(handle, 0, &[1; 2048]).expect("powered");
            disk.sync(handle).expect("powered");
            disk.write(handle, 0, &[2; 2048]).expect("powered");
            disk.crash();
            let after = contents(&mut disk, "wal").expect("the directory was synced");
            assert_eq!(after.len(), 2048);
            for sector in after.chunks(PHYSICAL_SECTOR) {
                match sector {
                    _ if sector.iter().all(|&byte| byte == 2) => kept = true,
                    _ if sector.iter().all(|&byte| byte == 1) => lost = true,
                    _ => garbled = true,
                }
            }
        }
        assert!(kept && lost && garbled);
    }

    #[test]
    fn a_changed_length_survives_as_either_length() {
        let (mut shorter, mut longer) = (false, false);
        for seed in 0..100 {
            let mut disk = disk(seed);
            let handle = disk.open(Some("wal"), JOURNAL).expect("created");
            disk.write(handle, 0, &[1; 1024]).expect("powered");
            disk.sync(handle).expect("powered");
            disk.write(handle, 1024, &[2; 1024]).expect("powered");
            disk.crash();
            match contents(&mut disk, "wal")
                .expect("the directory was synced")
                .len()
            {
                1024 => shorter = true,
                2048 => longer = true,
                other => panic!("seed {seed}: a length of {other}"),
            }
        }
        assert!(shorter && longer);
    }

    #[test]
    fn a_powersafe_write_damages_only_what_it_wrote() {
        for seed in 0..200 {
            let mut disk = disk(seed);
            let handle = disk.open(Some("wal"), JOURNAL).expect("created");
            disk.write(handle, 0, &[1; 512]).expect("powered");
            disk.sync(handle).expect("powered");
            disk.write(handle, 100, &[2; 50]).expect("powered");
            disk.crash();
            let after = contents(&mut disk, "wal").expect("the directory was synced");
            let untouched = after[..100].iter().chain(&after[150..]);
            assert!(untouched.into_iter().all(|&byte| byte == 1), "seed {seed}");
        }
    }

    #[test]
    fn an_armed_failure_strikes_its_operation_and_every_later_one() {
        let mut disk = disk(1);
        let handle = disk.open(Some("db"), DATABASE).expect("created");
        disk.fail_power_after(2);
        assert!(disk.write(handle, 0, b"one").is_ok());
        assert!(disk.write(handle, 3, b"two").is_ok());
        assert_eq!(disk.sync(handle), Err(DiskError::PoweredOff));
        assert_eq!(disk.write(handle, 6, b"three"), Err(DiskError::PoweredOff));
        assert!(!disk.is_powered());
        disk.crash();
        assert!(disk.is_powered());
        // Nothing was synced, so the file may not exist at all, and the
        // write after the failure never reached the disk.
        if let Some(after) = contents(&mut disk, "db") {
            assert!(after.len() <= 6);
        }
    }

    #[test]
    fn an_unsynced_deletion_may_be_undone() {
        let (mut undone, mut kept) = (false, false);
        for seed in 0..100 {
            let mut disk = disk(seed);
            let handle = disk.open(Some("wal"), JOURNAL).expect("created");
            disk.write(handle, 0, b"frames").expect("powered");
            disk.sync(handle).expect("powered");
            disk.close(handle);
            disk.delete("wal", false).expect("exists");
            assert!(!disk.exists("wal"));
            disk.crash();
            match contents(&mut disk, "wal") {
                Some(after) => {
                    assert_eq!(after, b"frames");
                    undone = true;
                }
                None => kept = true,
            }
        }
        assert!(undone && kept);

        let mut disk = disk(0);
        let handle = disk.open(Some("wal"), JOURNAL).expect("created");
        disk.sync(handle).expect("powered");
        disk.close(handle);
        disk.delete("wal", true).expect("exists");
        disk.crash();
        assert!(
            !disk.exists("wal"),
            "a deletion with a directory sync is durable"
        );
    }

    #[test]
    fn a_file_is_open_at_most_once() {
        let mut disk = disk(0);
        let handle = disk.open(Some("db"), DATABASE).expect("created");
        assert_eq!(disk.open(Some("db"), EXISTING), Err(DiskError::AlreadyOpen));
        disk.close(handle);
        assert!(disk.open(Some("db"), EXISTING).is_ok());
        assert_eq!(
            disk.open(Some("missing"), EXISTING),
            Err(DiskError::NotFound)
        );
    }
}
