//! The simulated [`Disk`] as a SQLite VFS, so the real, unmodified SQLite
//! runs on it. SQLite reaches storage only through these callbacks, and
//! takes its time from them. Its random number generator is seeded from
//! the run's seed, so a run replays exactly.
//!
//! This is the only file in the workspace allowed `unsafe` code
//! (architecture.toml): SQLite's VFS is a C interface. Every simulated
//! connection runs on the simulation's one thread, and SQLite never calls
//! one callback from inside another, so each callback borrows the disk only
//! for its own duration.
//!
//! The VFS has no shared-memory methods, so a database runs in WAL mode
//! only in exclusive locking mode, through one connection.
//!
//! SQLite's random number generator is process-wide. A test that asserts a
//! seed replays exactly must therefore be the only test using SQLite in its
//! test binary; tests that check only behaviour may run side by side, each
//! on its own disk under its own VFS name.

#![allow(unsafe_code)]

use std::borrow::Borrow;
use std::cell::RefCell;
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};
use std::ptr;
use std::rc::Rc;

use rusqlite::{Connection, OpenFlags, ffi};

use crate::disk::{Disk, DiskError, Handle, OpenOptions};

const MAX_PATHNAME: c_int = 512;
/// The production Unix VFS's sector size.
const SECTOR_SIZE: c_int = 4096;
/// The Julian day number of the Unix epoch, in milliseconds.
const UNIX_EPOCH_JULIAN_MILLIS: i64 = 210_866_760_000_000;

#[derive(Debug)]
pub enum RegisterError {
    /// A VFS of that name is already registered in this process.
    InUse,
    /// The name holds a NUL byte.
    BadName,
    Sqlite(c_int),
}

/// The simulated disk, registered as a SQLite VFS until dropped.
pub struct SimVfs {
    /// Heap-allocated, so `vfs` can point at it wherever `self` moves.
    name: CString,
    vfs: Box<ffi::sqlite3_vfs>,
    disk: Rc<RefCell<Disk>>,
}

impl SimVfs {
    /// Registers `disk` as a VFS called `name`, and seeds SQLite's random
    /// number generator with `seed`.
    pub fn register(name: &str, disk: Rc<RefCell<Disk>>, seed: u32) -> Result<Self, RegisterError> {
        let name = CString::new(name).map_err(|_| RegisterError::BadName)?;
        // SAFETY: `name` is a valid C string.
        if !unsafe { ffi::sqlite3_vfs_find(name.as_ptr()) }.is_null() {
            return Err(RegisterError::InUse);
        }
        let mut vfs = Box::new(ffi::sqlite3_vfs {
            iVersion: 2,
            szOsFile: c_int::try_from(size_of::<SimFile>()).expect("a small struct"),
            mxPathname: MAX_PATHNAME,
            pNext: ptr::null_mut(),
            zName: name.as_ptr(),
            pAppData: Rc::as_ptr(&disk).cast_mut().cast(),
            xOpen: Some(open),
            xDelete: Some(delete),
            xAccess: Some(access),
            xFullPathname: Some(full_pathname),
            xDlOpen: None,
            xDlError: None,
            xDlSym: None,
            xDlClose: None,
            xRandomness: Some(randomness),
            xSleep: Some(sleep),
            xCurrentTime: Some(current_time),
            xGetLastError: Some(last_error),
            xCurrentTimeInt64: Some(current_time_int64),
            xSetSystemCall: None,
            xGetSystemCall: None,
            xNextSystemCall: None,
        });
        // Without a seed, SQLite seeds its generator from the operating
        // system. Zero means unset, so the seed is never zero.
        let seed = c_int::from_ne_bytes(seed.max(1).to_ne_bytes());
        // SAFETY: PRNG_SEED takes an int and a database pointer, which may
        // be null.
        unsafe {
            ffi::sqlite3_test_control(
                ffi::SQLITE_TESTCTRL_PRNG_SEED,
                seed,
                ptr::null_mut::<ffi::sqlite3>(),
            );
        }
        // SAFETY: the VFS and the disk it points at live as long as `Self`,
        // which unregisters the VFS when dropped.
        let code = unsafe { ffi::sqlite3_vfs_register(&raw mut *vfs, 0) };
        if code != ffi::SQLITE_OK {
            return Err(RegisterError::Sqlite(code));
        }
        Ok(Self { name, vfs, disk })
    }

    /// Opens, or creates, the database at `path` on the simulated disk.
    pub fn open(&self, path: &str) -> rusqlite::Result<SimConnection<'_>> {
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE;
        let connection = Connection::open_with_flags_and_vfs(path, flags, self.name.as_c_str())?;
        Ok(SimConnection {
            connection,
            _vfs: PhantomData,
        })
    }

    pub fn disk(&self) -> &Rc<RefCell<Disk>> {
        &self.disk
    }
}

impl Drop for SimVfs {
    fn drop(&mut self) {
        // SAFETY: registered in `register`. Every connection borrows `self`,
        // so none is still open.
        unsafe { ffi::sqlite3_vfs_unregister(&raw mut *self.vfs) };
    }
}

/// A connection to a database on the simulated disk. It borrows its VFS,
/// so it cannot outlive it.
pub struct SimConnection<'vfs> {
    connection: Connection,
    _vfs: PhantomData<&'vfs SimVfs>,
}

impl Deref for SimConnection<'_> {
    type Target = Connection;

    fn deref(&self) -> &Connection {
        &self.connection
    }
}

/// So a test can install SQLite's hooks before the store takes the
/// connection.
impl DerefMut for SimConnection<'_> {
    fn deref_mut(&mut self) -> &mut Connection {
        &mut self.connection
    }
}

/// So the store can hold a simulated connection.
impl Borrow<Connection> for SimConnection<'_> {
    fn borrow(&self) -> &Connection {
        &self.connection
    }
}

/// SQLite's file handle, extended with ours. `base` must come first.
#[repr(C)]
struct SimFile {
    base: ffi::sqlite3_file,
    disk: *const RefCell<Disk>,
    handle: Handle,
}

static IO_METHODS: ffi::sqlite3_io_methods = ffi::sqlite3_io_methods {
    iVersion: 1,
    xClose: Some(close),
    xRead: Some(read),
    xWrite: Some(write),
    xTruncate: Some(truncate),
    xSync: Some(sync),
    xFileSize: Some(file_size),
    xLock: Some(lock),
    xUnlock: Some(lock),
    xCheckReservedLock: Some(check_reserved_lock),
    xFileControl: Some(file_control),
    xSectorSize: Some(sector_size),
    xDeviceCharacteristics: Some(device_characteristics),
    xShmMap: None,
    xShmLock: None,
    xShmBarrier: None,
    xShmUnmap: None,
    xFetch: None,
    xUnfetch: None,
};

/// # Safety
/// `vfs` is the VFS [`SimVfs::register`] built, whose `pAppData` points at
/// the disk the [`SimVfs`] keeps alive.
unsafe fn disk_of<'a>(vfs: *mut ffi::sqlite3_vfs) -> &'a RefCell<Disk> {
    unsafe { &*(*vfs).pAppData.cast::<RefCell<Disk>>() }
}

/// # Safety
/// `file` was initialised by [`open`] and not yet closed.
unsafe fn file_of<'a>(file: *mut ffi::sqlite3_file) -> (&'a RefCell<Disk>, Handle) {
    let file = unsafe { &*file.cast::<SimFile>() };
    (unsafe { &*file.disk }, file.handle)
}

/// # Safety
/// `name` is null or a valid C string.
unsafe fn path_of<'a>(name: *const c_char) -> Result<Option<&'a str>, ()> {
    if name.is_null() {
        return Ok(None);
    }
    unsafe { CStr::from_ptr(name) }
        .to_str()
        .map(Some)
        .map_err(|_| ())
}

unsafe extern "C" fn open(
    vfs: *mut ffi::sqlite3_vfs,
    name: ffi::sqlite3_filename,
    file: *mut ffi::sqlite3_file,
    flags: c_int,
    out_flags: *mut c_int,
) -> c_int {
    // SQLite never closes a file whose open failed, which it knows by a
    // null method table.
    unsafe { (*file).pMethods = ptr::null() };
    let disk = unsafe { disk_of(vfs) };
    let Ok(path) = (unsafe { path_of(name) }) else {
        return ffi::SQLITE_CANTOPEN;
    };
    let journal =
        ffi::SQLITE_OPEN_MAIN_JOURNAL | ffi::SQLITE_OPEN_SUPER_JOURNAL | ffi::SQLITE_OPEN_WAL;
    let options = OpenOptions {
        create: flags & ffi::SQLITE_OPEN_CREATE != 0,
        delete_on_close: flags & ffi::SQLITE_OPEN_DELETEONCLOSE != 0,
        // As the production Unix VFS does for a new journal or WAL.
        sync_directory_when_new: flags & journal != 0,
    };
    let Ok(handle) = disk.borrow_mut().open(path, options) else {
        return ffi::SQLITE_CANTOPEN;
    };
    let opened = SimFile {
        base: ffi::sqlite3_file {
            pMethods: &raw const IO_METHODS,
        },
        disk: ptr::from_ref(disk),
        handle,
    };
    // SAFETY: SQLite allocated `szOsFile` bytes for the file, which is the
    // size of `SimFile`.
    unsafe { file.cast::<SimFile>().write(opened) };
    if !out_flags.is_null() {
        unsafe { *out_flags = flags };
    }
    ffi::SQLITE_OK
}

unsafe extern "C" fn delete(
    vfs: *mut ffi::sqlite3_vfs,
    name: *const c_char,
    sync_directory: c_int,
) -> c_int {
    let disk = unsafe { disk_of(vfs) };
    let Ok(Some(path)) = (unsafe { path_of(name) }) else {
        return ffi::SQLITE_IOERR_DELETE;
    };
    match disk.borrow_mut().delete(path, sync_directory != 0) {
        Ok(()) => ffi::SQLITE_OK,
        Err(DiskError::NotFound) => ffi::SQLITE_IOERR_DELETE_NOENT,
        Err(_) => ffi::SQLITE_IOERR_DELETE,
    }
}

unsafe extern "C" fn access(
    vfs: *mut ffi::sqlite3_vfs,
    name: *const c_char,
    _flags: c_int,
    out: *mut c_int,
) -> c_int {
    let disk = unsafe { disk_of(vfs) };
    let exists = matches!(unsafe { path_of(name) }, Ok(Some(path)) if disk.borrow().exists(path));
    unsafe { *out = c_int::from(exists) };
    ffi::SQLITE_OK
}

unsafe extern "C" fn full_pathname(
    _vfs: *mut ffi::sqlite3_vfs,
    name: *const c_char,
    out_length: c_int,
    out: *mut c_char,
) -> c_int {
    // Simulated paths are already canonical.
    let name = unsafe { CStr::from_ptr(name) }.to_bytes_with_nul();
    if usize::try_from(out_length).is_ok_and(|length| name.len() <= length) {
        unsafe { ptr::copy_nonoverlapping(name.as_ptr().cast::<c_char>(), out, name.len()) };
        ffi::SQLITE_OK
    } else {
        ffi::SQLITE_CANTOPEN
    }
}

unsafe extern "C" fn randomness(
    vfs: *mut ffi::sqlite3_vfs,
    length: c_int,
    out: *mut c_char,
) -> c_int {
    let disk = unsafe { disk_of(vfs) };
    let bytes = usize::try_from(length).unwrap_or(0);
    let buffer = unsafe { std::slice::from_raw_parts_mut(out.cast::<u8>(), bytes) };
    disk.borrow_mut().fill_random(buffer);
    length
}

/// Time is simulated, so sleeping takes none.
unsafe extern "C" fn sleep(_vfs: *mut ffi::sqlite3_vfs, microseconds: c_int) -> c_int {
    microseconds
}

/// The simulated wall clock, as a Julian day number in milliseconds.
///
/// # Safety
/// As for [`disk_of`].
unsafe fn julian_millis(vfs: *mut ffi::sqlite3_vfs) -> i64 {
    let disk = unsafe { disk_of(vfs) };
    let millis = i64::try_from(disk.borrow().now().as_millis()).unwrap_or(i64::MAX);
    UNIX_EPOCH_JULIAN_MILLIS.saturating_add(millis)
}

unsafe extern "C" fn current_time(vfs: *mut ffi::sqlite3_vfs, out: *mut f64) -> c_int {
    unsafe { *out = julian_millis(vfs) as f64 / 86_400_000.0 };
    ffi::SQLITE_OK
}

unsafe extern "C" fn current_time_int64(vfs: *mut ffi::sqlite3_vfs, out: *mut i64) -> c_int {
    unsafe { *out = julian_millis(vfs) };
    ffi::SQLITE_OK
}

unsafe extern "C" fn last_error(
    _vfs: *mut ffi::sqlite3_vfs,
    _length: c_int,
    _out: *mut c_char,
) -> c_int {
    0
}

unsafe extern "C" fn close(file: *mut ffi::sqlite3_file) -> c_int {
    let (disk, handle) = unsafe { file_of(file) };
    disk.borrow_mut().close(handle);
    ffi::SQLITE_OK
}

unsafe extern "C" fn read(
    file: *mut ffi::sqlite3_file,
    buffer: *mut c_void,
    amount: c_int,
    offset: i64,
) -> c_int {
    let (disk, handle) = unsafe { file_of(file) };
    let (Ok(amount), Ok(offset)) = (usize::try_from(amount), usize::try_from(offset)) else {
        return ffi::SQLITE_IOERR_READ;
    };
    let buffer = unsafe { std::slice::from_raw_parts_mut(buffer.cast::<u8>(), amount) };
    match disk.borrow_mut().read(handle, offset, buffer) {
        Ok(read) if read == amount => ffi::SQLITE_OK,
        Ok(read) => {
            // SQLite requires the rest of a short read to be zeroed.
            buffer[read..].fill(0);
            ffi::SQLITE_IOERR_SHORT_READ
        }
        Err(_) => ffi::SQLITE_IOERR_READ,
    }
}

unsafe extern "C" fn write(
    file: *mut ffi::sqlite3_file,
    data: *const c_void,
    amount: c_int,
    offset: i64,
) -> c_int {
    let (disk, handle) = unsafe { file_of(file) };
    let (Ok(amount), Ok(offset)) = (usize::try_from(amount), usize::try_from(offset)) else {
        return ffi::SQLITE_IOERR_WRITE;
    };
    let data = unsafe { std::slice::from_raw_parts(data.cast::<u8>(), amount) };
    match disk.borrow_mut().write(handle, offset, data) {
        Ok(()) => ffi::SQLITE_OK,
        Err(DiskError::Full) => ffi::SQLITE_FULL,
        Err(_) => ffi::SQLITE_IOERR_WRITE,
    }
}

unsafe extern "C" fn truncate(file: *mut ffi::sqlite3_file, size: i64) -> c_int {
    let (disk, handle) = unsafe { file_of(file) };
    let Ok(size) = usize::try_from(size) else {
        return ffi::SQLITE_IOERR_TRUNCATE;
    };
    match disk.borrow_mut().truncate(handle, size) {
        Ok(()) => ffi::SQLITE_OK,
        Err(DiskError::Full) => ffi::SQLITE_FULL,
        Err(_) => ffi::SQLITE_IOERR_TRUNCATE,
    }
}

/// Every sync is a full sync, whatever SQLite asks for.
unsafe extern "C" fn sync(file: *mut ffi::sqlite3_file, _flags: c_int) -> c_int {
    let (disk, handle) = unsafe { file_of(file) };
    match disk.borrow_mut().sync(handle) {
        Ok(()) => ffi::SQLITE_OK,
        Err(_) => ffi::SQLITE_IOERR_FSYNC,
    }
}

unsafe extern "C" fn file_size(file: *mut ffi::sqlite3_file, out: *mut i64) -> c_int {
    let (disk, handle) = unsafe { file_of(file) };
    match disk.borrow_mut().size(handle) {
        Ok(size) => {
            unsafe { *out = i64::try_from(size).unwrap_or(i64::MAX) };
            ffi::SQLITE_OK
        }
        Err(_) => ffi::SQLITE_IOERR_FSTAT,
    }
}

/// Each database has one connection, so every lock is granted.
unsafe extern "C" fn lock(_file: *mut ffi::sqlite3_file, _level: c_int) -> c_int {
    ffi::SQLITE_OK
}

unsafe extern "C" fn check_reserved_lock(_file: *mut ffi::sqlite3_file, out: *mut c_int) -> c_int {
    unsafe { *out = 0 };
    ffi::SQLITE_OK
}

unsafe extern "C" fn file_control(
    _file: *mut ffi::sqlite3_file,
    _op: c_int,
    _argument: *mut c_void,
) -> c_int {
    ffi::SQLITE_NOTFOUND
}

unsafe extern "C" fn sector_size(_file: *mut ffi::sqlite3_file) -> c_int {
    SECTOR_SIZE
}

/// What the production Unix VFS claims by default, so the simulation runs
/// SQLite's production code paths.
unsafe extern "C" fn device_characteristics(_file: *mut ffi::sqlite3_file) -> c_int {
    ffi::SQLITE_IOCAP_POWERSAFE_OVERWRITE
}
