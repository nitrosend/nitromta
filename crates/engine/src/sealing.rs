//! Sealing in the shell: bodies sealed as acceptance takes them
//! and opened as they are sent, under the installation's key or, while
//! per-tenant keys are on, each tenant's. A tenant's key is a file of its
//! own in a directory beside the keys file, `<keys file>.tenants/`, named by
//! the tenant's ID in hex and its owner's alone, written and synced before
//! the change that creates the tenant is asked, and removed once the tenant
//! is: what it sealed, in the store and in every backup, can then no longer
//! be opened. The store reads no file: the shell gives it each key.

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::Duration;

use engine_core::command::{Answer, Command, DataKey};
use engine_core::id::{BodyId, Id, TenantId};
use engine_core::policy::Change;
use engine_store::keys::{self, Keyring, Keys, Unopened};

use crate::config::Encryption;
use crate::policy::Current;
use crate::store::Store;

/// How often removed tenants' keys are looked for.
const TICK: Duration = Duration::from_secs(1);

/// What a tenant's key file is written as before it is published under its
/// own name, so a stop part-way never leaves a key file in part.
const MAKING: &str = ".making";

pub struct Sealer {
    encryption: Encryption,
    keys: RwLock<Keys>,
    /// Where tenants' keys are kept.
    directory: PathBuf,
    /// The tenants whose creation is being asked, whose keys are made and
    /// which policy may not hold yet.
    creating: Mutex<BTreeSet<TenantId>>,
    /// Held while which keys to erase is decided and they are erased, and
    /// while a creation begins: none begins part-way through a decision,
    /// so none's key is taken for one whose tenant is gone.
    deciding: tokio::sync::Mutex<()>,
}

impl Sealer {
    /// The installation's keys, and every tenant's key in the directory
    /// beside `keys_file`, which is made, its owner's alone, while
    /// per-tenant keys are on. A key file a stop left in part, never
    /// published, is removed.
    pub fn load(
        encryption: Encryption,
        installation: Arc<Keyring>,
        keys_file: &Path,
    ) -> Result<Self, String> {
        // Beside the file itself, wherever the path to it was given from.
        let keys_file = std::fs::canonicalize(keys_file)
            .map_err(|error| format!("{}: {error}", keys_file.display()))?;
        let mut name = keys_file.as_os_str().to_owned();
        name.push(".tenants");
        let directory = PathBuf::from(name);
        let failed = |error: &dyn std::fmt::Display| {
            format!("tenants' keys at {}: {error}", directory.display())
        };
        if encryption == Encryption::Tenant && !directory.exists() {
            std::fs::create_dir(&directory).map_err(|error| failed(&error))?;
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
                .map_err(|error| failed(&error))?;
            sync_directory(directory.parent().unwrap_or(Path::new(".")))
                .map_err(|error| failed(&error))?;
        }
        if directory.exists() {
            let mut abandoned = false;
            for entry in std::fs::read_dir(&directory).map_err(|error| failed(&error))? {
                let path = entry.map_err(|error| failed(&error))?.path();
                if path
                    .file_name()
                    .and_then(OsStr::to_str)
                    .is_some_and(|name| name.ends_with(MAKING))
                {
                    std::fs::remove_file(&path).map_err(|error| failed(&error))?;
                    abandoned = true;
                }
            }
            if abandoned {
                sync_directory(&directory).map_err(|error| failed(&error))?;
            }
        }
        let found = read_keys(&directory)?;
        // A tenant given a key was promised that erasing it erases its mail:
        // sealed under any other, or none, its mail would outlive its key.
        if encryption != Encryption::Tenant && !found.is_empty() {
            let kept = match found.len() {
                1 => "a tenant's key is".to_owned(),
                n => format!("{n} tenants' keys are"),
            };
            return Err(failed(&format!(
                "{kept} kept here, so its mail is sealed under its own: encryption stays `tenant` until every tenant with a key is removed"
            )));
        }
        let mut keys = Keys::new(installation);
        for (tenant, key) in &found {
            keys.add_tenant(tenant.0.as_u64(), key);
        }
        Ok(Self {
            encryption,
            keys: RwLock::new(keys),
            directory,
            creating: Mutex::new(BTreeSet::new()),
            deciding: tokio::sync::Mutex::new(()),
        })
    }

    /// Every tenant's key its directory holds, for a store, which must hold
    /// them all before it reads a record.
    pub fn tenant_keys(&self) -> Result<Vec<(TenantId, DataKey)>, String> {
        read_keys(&self.directory)
    }

    /// `content` as body `body` of `tenant`'s mail is kept: sealed while
    /// encryption is on, under the tenant's key if per-tenant keys are and
    /// it has one; none while it is off.
    pub fn seal_body(
        &self,
        tenant: Option<TenantId>,
        body: BodyId,
        content: &[u8],
    ) -> Option<Vec<u8>> {
        let tenant = match self.encryption {
            Encryption::Off => return None,
            Encryption::Installation => None,
            Encryption::Tenant => tenant.map(|tenant| tenant.0.as_u64()),
        };
        let keys = self.keys.read().unwrap_or_else(PoisonError::into_inner);
        Some(keys::seal_body(&keys, tenant, body.0.as_u64(), content))
    }

    /// A kept body's content: as it is, unless it was sealed, when it is
    /// opened under whichever key sealed it, whatever encryption is now.
    pub fn open_body(&self, stored: &[u8]) -> Result<Option<Vec<u8>>, Unopened> {
        let keys = self.keys.read().unwrap_or_else(PoisonError::into_inner);
        keys::open_body(&keys, stored)
    }

    /// `content`, file `file` of capture `capture`, as capture mode keeps
    /// it beside `body`, the stored body it was made from: sealed under the
    /// key the body is, so it is erased with it; as it is if the body is.
    pub fn seal_capture(&self, body: &[u8], capture: u64, file: u32, content: &[u8]) -> Vec<u8> {
        match keys::sealed_for(body) {
            None => content.to_vec(),
            Some(tenant) => {
                let keys = self.keys.read().unwrap_or_else(PoisonError::into_inner);
                keys::seal_capture(&keys, tenant, capture, file, content)
            }
        }
    }

    /// A captured file's content, `file` of capture `capture`: opened if it
    /// was sealed, and only in its own place.
    pub fn open_capture(
        &self,
        kept: Vec<u8>,
        capture: u64,
        file: u32,
    ) -> Result<Vec<u8>, Unopened> {
        if !keys::capture_in_place(&kept, capture, file) {
            return Err(Unopened::Damaged);
        }
        let keys = self.keys.read().unwrap_or_else(PoisonError::into_inner);
        Ok(keys::open_capture(&keys, &kept)?.unwrap_or(kept))
    }

    fn has(&self, tenant: TenantId) -> bool {
        self.keys
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .has_tenant(tenant.0.as_u64())
    }

    /// Makes `tenant`'s key and keeps it: its file written whole under a
    /// name of its own and synced, then published under the tenant's,
    /// never over another, and its directory synced.
    fn make(&self, tenant: TenantId) -> Result<DataKey, String> {
        let mut key = [0; 32];
        aws_lc_rs::rand::fill(&mut key)
            .map_err(|_| "no randomness for a tenant's key".to_owned())?;
        let path = self.path(tenant);
        let failed = |error: &dyn std::fmt::Display| format!("{}: {error}", path.display());
        let mut making = path.as_os_str().to_owned();
        making.push(MAKING);
        let making = PathBuf::from(making);
        let written = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&making)
            .and_then(|mut file| {
                writeln!(file, "{}", hex(&key))?;
                file.sync_all()
            })
            .and_then(|()| std::fs::hard_link(&making, &path));
        // Gone whether or not it was published: the key is the published
        // file's alone.
        let removed = std::fs::remove_file(&making);
        written.and(removed).map_err(|error| failed(&error))?;
        sync_directory(&self.directory).map_err(|error| failed(&error))?;
        let key = DataKey(key);
        self.keys
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .add_tenant(tenant.0.as_u64(), &key);
        Ok(key)
    }

    /// Makes `tenant`'s key, while per-tenant keys are on and it has none,
    /// then gives it to the store. Done before the change that creates the
    /// tenant is asked, so none of its mail is sealed under another key.
    pub async fn ensure(&self, store: &Store, tenant: TenantId) -> Result<(), String> {
        if self.encryption != Encryption::Tenant || self.has(tenant) {
            return Ok(());
        }
        let key = self.make(tenant)?;
        match store.ask(Command::TenantKey { tenant, key }).await {
            Some(Answer::Keyed(Ok(()))) => Ok(()),
            _ => Err("the store could not take a tenant's key".to_owned()),
        }
    }

    /// Asks the store `command`, first making the key of the tenant it may
    /// create, if it may create one, as `ensure` does: any tenant put, which
    /// creates one when, as the store applies it, the account has none of
    /// its name, and one created through SES's API. Until the answer, that
    /// key is kept whether or not policy holds the tenant yet, and whether
    /// or not the caller still waits for it; then, if no tenant was created
    /// under it, it goes.
    pub async fn ask(
        self: &Arc<Self>,
        store: &Store,
        policy: &Arc<Current>,
        command: Command,
    ) -> Result<Option<Answer>, String> {
        let Some(tenant) = self.creates(&command) else {
            return Ok(store.ask(command).await);
        };
        let (sealer, store, policy) = (Arc::clone(self), store.clone(), Arc::clone(policy));
        tokio::spawn(async move { sealer.create(&store, &policy, tenant, command).await })
            .await
            .map_err(|_| "a tenant's creation stopped".to_owned())?
    }

    async fn create(
        &self,
        store: &Store,
        policy: &Current,
        tenant: TenantId,
        command: Command,
    ) -> Result<Option<Answer>, String> {
        let _creation = {
            let _deciding = self.deciding.lock().await;
            self.creating().insert(tenant);
            Creation(self, tenant)
        };
        self.ensure(store, tenant).await?;
        let answer = store.ask(command).await;
        // Policy is published before a change is answered.
        if !tenants_of(policy).contains(&tenant)
            && let Err(why) = self.erase(store, tenant).await
        {
            tracing::warn!(why = %why, "a key made for a tenant never created is erased later");
        }
        Ok(answer)
    }

    /// The tenant `command` may create, while per-tenant keys are on: a
    /// put's, decided by the store as it applies it, so never from a
    /// snapshot a change ahead of it may outdate, or a new one's.
    pub fn creates(&self, command: &Command) -> Option<TenantId> {
        if self.encryption != Encryption::Tenant {
            return None;
        }
        match command {
            Command::ChangePolicy(Change::Tenant { id, .. } | Change::NewTenant { id, .. }) => {
                Some(*id)
            }
            _ => None,
        }
    }

    fn creating(&self) -> std::sync::MutexGuard<'_, BTreeSet<TenantId>> {
        self.creating.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Erases `tenant`'s key: its file goes, its directory synced, so what
    /// it sealed can never be opened again, then the store and the shell
    /// forget it. Until all of it is done, the shell holds the key, and it
    /// is tried again.
    pub async fn erase(&self, store: &Store, tenant: TenantId) -> Result<(), String> {
        self.unlink(tenant)?;
        let Some(Answer::Keyed(Ok(()))) = store.ask(Command::ForgetTenantKey(tenant)).await else {
            return Err("the store could not forget a tenant's key".to_owned());
        };
        self.forget(tenant);
        Ok(())
    }

    fn unlink(&self, tenant: TenantId) -> Result<(), String> {
        let path = self.path(tenant);
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("{}: {error}", path.display())),
        }
        sync_directory(&self.directory).map_err(|error| format!("{}: {error}", path.display()))
    }

    fn forget(&self, tenant: TenantId) {
        self.keys
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .forget_tenant(tenant.0.as_u64());
    }

    /// Brings tenants' keys in step with `present`, the tenants the store's
    /// policy holds as it opens, on its thread before recovery or any
    /// command reads or writes a record: a key whose tenant is not there, as
    /// one made for a creation that never committed or one whose removal a
    /// stop cut short, is erased; a tenant with none, as one made before
    /// per-tenant keys were on, is given one, with a warning. Gives every
    /// key, for the store. While a restore's fence holds, nothing is erased:
    /// a tenant the copy predates may still be needed by the store it
    /// replaced, until the operator settles the restore.
    pub fn settle(
        &self,
        present: &BTreeSet<TenantId>,
        fenced: bool,
    ) -> Result<Vec<(TenantId, DataKey)>, String> {
        let gone: Vec<TenantId> = self.keyed().difference(present).copied().collect();
        if fenced && !gone.is_empty() {
            tracing::warn!(
                keys = gone.len(),
                "keys whose tenants the restored copy does not hold are kept until its fence is released"
            );
        }
        for tenant in gone.iter().filter(|_| !fenced) {
            self.unlink(*tenant)?;
            self.forget(*tenant);
            tracing::info!(
                tenant = %crate::log::Hex(tenant.0),
                "a key whose tenant is gone is erased"
            );
        }
        if self.encryption == Encryption::Tenant {
            for tenant in present.difference(&self.keyed()) {
                warn_unkeyed(*tenant);
                self.make(*tenant)?;
            }
        }
        self.tenant_keys()
    }

    /// Keeps tenants' keys in step with policy after `settle`: a key whose
    /// tenant policy does not hold, but for one being created, is erased,
    /// and with it the tenant's mail, once no restore's fence holds.
    pub async fn watch(self: Arc<Self>, store: Store, policy: Arc<Current>) {
        let mut revision = Some(policy.load().policy().revision());
        let mut tick = tokio::time::interval(TICK);
        loop {
            tick.tick().await;
            // Decided, and done, with no creation beginning: one begun
            // before is in `creating`, and one finished before has its
            // change in the policy published, as every change is before
            // it is answered.
            let _deciding = self.deciding.lock().await;
            let creating = self.creating().clone();
            let current = policy.load().policy().revision();
            if revision == Some(current) && creating.is_empty() {
                continue;
            }
            let present = tenants_of(&policy);
            // Looked at again once no creation is under way, and once a
            // restore's fence is released, which keeps every key until then.
            let fenced = policy.load().policy().fence().is_some();
            let mut settled = creating.is_empty() && !fenced;
            let gone: Vec<TenantId> = self
                .keyed()
                .difference(&present)
                .filter(|tenant| !creating.contains(tenant) && !fenced)
                .copied()
                .collect();
            for tenant in gone {
                match self.erase(&store, tenant).await {
                    Ok(()) => tracing::info!(
                        tenant = %crate::log::Hex(tenant.0),
                        "a removed tenant's key is erased, and its mail with it"
                    ),
                    Err(why) => {
                        settled = false;
                        tracing::error!(why = %why, "a removed tenant's key could not be erased");
                    }
                }
            }
            if settled {
                revision = Some(current);
            }
        }
    }

    /// The tenants it holds a key of.
    fn keyed(&self) -> BTreeSet<TenantId> {
        self.keys
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .tenants()
            .filter_map(Id::from_u64)
            .map(TenantId)
            .collect()
    }

    fn path(&self, tenant: TenantId) -> PathBuf {
        self.directory.join(format!("{:016x}", tenant.0.as_u64()))
    }
}

/// A creation under way, until it is answered or given up.
struct Creation<'a>(&'a Sealer, TenantId);

impl Drop for Creation<'_> {
    fn drop(&mut self) {
        self.0.creating().remove(&self.1);
    }
}

fn warn_unkeyed(tenant: TenantId) {
    tracing::warn!(
        tenant = %crate::log::Hex(tenant.0),
        "a tenant had no key of its own; it is given one, and its mail from now on is sealed under it"
    );
}

/// Every tenant's key in `directory`, if it is there.
fn read_keys(directory: &Path) -> Result<Vec<(TenantId, DataKey)>, String> {
    let mut found = Vec::new();
    if !directory.exists() {
        return Ok(found);
    }
    let failed = |error: &dyn std::fmt::Display| {
        format!("tenants' keys at {}: {error}", directory.display())
    };
    for entry in std::fs::read_dir(directory).map_err(|error| failed(&error))? {
        let entry = entry.map_err(|error| failed(&error))?;
        let file_name = entry.file_name();
        let Some(tenant) = file_name
            .to_str()
            .and_then(|name| u64::from_str_radix(name, 16).ok())
            .and_then(Id::from_u64)
            .map(TenantId)
        else {
            continue;
        };
        found.push((tenant, read_key(&entry.path())?));
    }
    Ok(found)
}

/// The tenants `policy` holds now.
fn tenants_of(policy: &Current) -> BTreeSet<TenantId> {
    policy
        .load()
        .policy()
        .tenants()
        .map(|tenant| tenant.id)
        .collect()
}

/// The key in a tenant's key file, refused if anyone but its owner may read
/// it.
fn read_key(path: &Path) -> Result<DataKey, String> {
    let failed = |problem: &dyn std::fmt::Display| format!("{}: {problem}", path.display());
    let metadata = std::fs::symlink_metadata(path).map_err(|error| failed(&error))?;
    if !metadata.is_file() {
        return Err(failed(&"it is not a file"));
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(failed(
            &"anyone but its owner may read it; make it its owner's alone (mode 600)",
        ));
    }
    let text = std::fs::read_to_string(path).map_err(|error| failed(&error))?;
    let text = text.trim();
    let mut key = [0; 32];
    if text.len() != 64 {
        return Err(failed(&"it does not hold one key of 32 bytes in hex"));
    }
    for (byte, pair) in key.iter_mut().zip(text.as_bytes().chunks(2)) {
        let pair = std::str::from_utf8(pair).map_err(|_| failed(&"it is not hex"))?;
        *byte = u8::from_str_radix(pair, 16).map_err(|_| failed(&"it is not hex"))?;
    }
    Ok(DataKey(key))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn sync_directory(directory: &Path) -> std::io::Result<()> {
    std::fs::File::open(directory)?.sync_all()
}
