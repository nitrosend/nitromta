//! The installation's keys, which seal the secrets in policy:
//! access keys' secrets, DKIM private keys, subscriptions' signing secrets
//! and logins' password hashes. The keys are the shell's to read from a
//! file of their own, never from the store or its backups.
//!
//! A secret is sealed with AES-256-GCM-SIV in the record's envelope:
//! the key's ID, a nonce, and the ciphertext with its tag; never with no
//! key, the envelope's ID 0. The nonce is
//! derived from the record's ID and field, which are also its associated
//! data, so a sealed secret opens only in its own place. GCM-SIV keeps a
//! nonce used again for a new secret in the same place safe, at the cost
//! of showing whether two sealings there held the same secret.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use aws_lc_rs::aead::{AES_256_GCM_SIV, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use aws_lc_rs::hmac;

/// The envelope's ID for data sealed without a key, which no secret is.
pub const NO_KEY: u8 = 0;

/// The envelope's ID for data sealed under a tenant's key,
/// which the tenant's ID follows: no keys file may hold a key with it.
pub const TENANT: u8 = 255;

/// The installation's keys, by ID. Secrets are sealed under the newest,
/// and opened under whichever sealed them.
pub struct Keyring {
    keys: BTreeMap<u8, LessSafeKey>,
    /// Each key's index key, which searchable values are hashed under:
    /// derived from it, never the key itself.
    index: BTreeMap<u8, hmac::Key>,
    current: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyError {
    /// No key at all.
    Empty,
    /// An ID of 0, which marks data sealed without a key, or 255, which
    /// marks data sealed under a tenant's.
    Reserved,
    Repeated(u8),
}

impl fmt::Display for KeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(formatter, "it holds no key"),
            Self::Reserved => write!(formatter, "key IDs 0 and 255 are reserved"),
            Self::Repeated(id) => write!(formatter, "key {id} is there twice"),
        }
    }
}

impl fmt::Debug for Keyring {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ids: Vec<&u8> = self.keys.keys().collect();
        formatter
            .debug_struct("Keyring")
            .field("ids", &ids)
            .field("current", &self.current)
            .finish()
    }
}

impl Keyring {
    /// The keys, each its ID and its 32 bytes.
    pub fn new(keys: &[(u8, [u8; 32])]) -> Result<Self, KeyError> {
        let mut ring = BTreeMap::new();
        let mut index = BTreeMap::new();
        for (id, key) in keys {
            if *id == NO_KEY || *id == TENANT {
                return Err(KeyError::Reserved);
            }
            let sealing =
                UnboundKey::new(&AES_256_GCM_SIV, key).expect("32 bytes is its key's length");
            if ring.insert(*id, LessSafeKey::new(sealing)).is_some() {
                return Err(KeyError::Repeated(*id));
            }
            let derived = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), INDEX_LABEL);
            index.insert(*id, hmac::Key::new(hmac::HMAC_SHA256, derived.as_ref()));
        }
        let current = *ring.keys().next_back().ok_or(KeyError::Empty)?;
        Ok(Self {
            keys: ring,
            index,
            current,
        })
    }

    /// The ID of the key secrets are sealed under.
    pub fn current(&self) -> u8 {
        self.current
    }

    /// `value` hashed under the current key's index key, in hex: what a
    /// searchable value is found by while encryption is on.
    pub fn index(&self, value: &str) -> String {
        let tag = hmac::sign(&self.index[&self.current], value.as_bytes());
        tag.as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    /// `secret` sealed under the current key in `place`: the key's ID, the
    /// nonce and the ciphertext with its tag.
    pub fn seal(&self, place: [u8; NONCE_LEN], secret: &[u8]) -> Vec<u8> {
        let key = &self.keys[&self.current];
        let mut sealed = secret.to_vec();
        key.seal_in_place_append_tag(
            Nonce::assume_unique_for_key(place),
            Aad::from(place),
            &mut sealed,
        )
        .expect("sealing a secret this size cannot fail");
        let mut envelope = Vec::with_capacity(1 + NONCE_LEN + sealed.len());
        envelope.push(self.current);
        envelope.extend_from_slice(&place);
        envelope.extend_from_slice(&sealed);
        envelope
    }

    /// The secret `envelope` holds in `place`, and the key it was sealed
    /// under.
    pub fn open(&self, place: [u8; NONCE_LEN], envelope: &[u8]) -> Result<(Vec<u8>, u8), Unopened> {
        let Some((&id, rest)) = envelope.split_first() else {
            return Err(Unopened::Damaged);
        };
        if id == NO_KEY {
            return Err(Unopened::Damaged);
        }
        let key = self.keys.get(&id).ok_or(Unopened::NoKey(id))?;
        if rest.len() < NONCE_LEN || rest[..NONCE_LEN] != place {
            return Err(Unopened::Damaged);
        }
        let mut secret = rest[NONCE_LEN..].to_vec();
        let opened = key
            .open_in_place(
                Nonce::assume_unique_for_key(place),
                Aad::from(place),
                &mut secret,
            )
            .map_err(|_| Unopened::Damaged)?
            .len();
        secret.truncate(opened);
        Ok((secret, id))
    }
}

impl Keyring {
    /// `data` sealed under the current key in `place`, bound as
    /// well to `bound`, the rest of what names its record: the key's ID,
    /// then the ciphertext with its tag. Neither is kept, as the record it
    /// is in names both again when it is opened.
    pub fn seal_in(&self, place: [u8; NONCE_LEN], bound: &[u8], data: &[u8]) -> Vec<u8> {
        let key = &self.keys[&self.current];
        let mut sealed = Vec::with_capacity(1 + data.len() + AES_256_GCM_SIV.tag_len());
        sealed.push(self.current);
        sealed.extend_from_slice(data);
        let tag = seal(key, place, bound, &mut sealed[1..]);
        sealed.extend_from_slice(tag.as_ref());
        sealed
    }

    /// The data `envelope` holds in `place`, bound to `bound`, as `seal_in`
    /// sealed it.
    pub fn open_in(
        &self,
        place: [u8; NONCE_LEN],
        bound: &[u8],
        envelope: &[u8],
    ) -> Result<Vec<u8>, Unopened> {
        let Some((&id, sealed)) = envelope.split_first() else {
            return Err(Unopened::Damaged);
        };
        let key = self.keys.get(&id).ok_or(Unopened::NoKey(id))?;
        open(key, place, bound, sealed)
    }
}

/// Seals `data` in place under `key`, its nonce `place` and its associated
/// data `place` and then `bound`, and returns its tag.
fn seal(
    key: &LessSafeKey,
    place: [u8; NONCE_LEN],
    bound: &[u8],
    data: &mut [u8],
) -> aws_lc_rs::aead::Tag {
    key.seal_in_place_separate_tag(
        Nonce::assume_unique_for_key(place),
        Aad::from([&place[..], bound].concat()),
        data,
    )
    .expect("sealing data this size cannot fail")
}

/// What `seal` sealed, opened.
fn open(
    key: &LessSafeKey,
    place: [u8; NONCE_LEN],
    bound: &[u8],
    sealed: &[u8],
) -> Result<Vec<u8>, Unopened> {
    let mut data = sealed.to_vec();
    let opened = key
        .open_in_place(
            Nonce::assume_unique_for_key(place),
            Aad::from([&place[..], bound].concat()),
            &mut data,
        )
        .map_err(|_| Unopened::Damaged)?
        .len();
    data.truncate(opened);
    Ok(data)
}

/// A prepared message's content as the store keeps it, sealed in body
/// `body`'s place: a zero byte, which preparation refuses at a
/// message's start, then the envelope of the key it is under, the place,
/// and the ciphertext with its tag. Under a tenant with no key, as an
/// erased one, nothing of it is kept. It is sealed by the thread that
/// prepared it, and opened by whoever sends it, never on the store's
/// thread; the store checks its place is its own row's.
pub fn seal_body(keys: &Keys, tenant: Option<u64>, body: u64, content: &[u8]) -> Vec<u8> {
    seal_whole(keys, tenant, data_place(Kind::Body, body, 0), content)
}

/// A file capture mode writes, `file` of capture `capture`, sealed as a
/// body is, under the key its body was: erased with it.
pub fn seal_capture(
    keys: &Keys,
    tenant: Option<u64>,
    capture: u64,
    file: u32,
    content: &[u8],
) -> Vec<u8> {
    seal_whole(
        keys,
        tenant,
        data_place(Kind::Capture, capture, file),
        content,
    )
}

/// `content` sealed whole in `place`, its envelope before it.
fn seal_whole(keys: &Keys, tenant: Option<u64>, place: [u8; NONCE_LEN], content: &[u8]) -> Vec<u8> {
    let mut sealed = vec![0];
    let key = match tenant {
        Some(tenant) => {
            sealed.push(TENANT);
            sealed.extend_from_slice(&tenant.to_be_bytes());
            match keys.tenants.get(&tenant) {
                Some(ring) => {
                    sealed.extend_from_slice(&ring.print);
                    &ring.key
                }
                None => {
                    sealed.extend_from_slice(&ERASED_PRINT);
                    return sealed;
                }
            }
        }
        None => {
            let ring = &keys.installation;
            sealed.push(ring.current);
            &ring.keys[&ring.current]
        }
    };
    sealed.extend_from_slice(&place);
    let head = sealed.len();
    sealed.reserve(content.len() + AES_256_GCM_SIV.tag_len());
    sealed.extend_from_slice(content);
    let tag = seal(key, place, &[], &mut sealed[head..]);
    sealed.extend_from_slice(tag.as_ref());
    sealed
}

/// The key a stored body is sealed under: [`NO_KEY`] for one kept as it
/// is, [`TENANT`] for one under a tenant's.
pub fn body_key(stored: &[u8]) -> u8 {
    match stored {
        [0, key, ..] => *key,
        _ => NO_KEY,
    }
}

/// A stored body's parts: the key it is under and where, and what follows.
enum Stored<'a> {
    Plain,
    Installation(u8, [u8; NONCE_LEN], &'a [u8]),
    Tenant(u64, [u8; 4], Option<([u8; NONCE_LEN], &'a [u8])>),
}

/// The place at the front of `rest`, and what follows it.
fn placed(rest: &[u8]) -> Result<([u8; NONCE_LEN], &[u8]), Unopened> {
    let (place, sealed) = rest
        .split_first_chunk::<NONCE_LEN>()
        .ok_or(Unopened::Damaged)?;
    Ok((*place, sealed))
}

fn stored(bytes: &[u8]) -> Result<Stored<'_>, Unopened> {
    let [0, sealed @ ..] = bytes else {
        return Ok(Stored::Plain);
    };
    match sealed {
        [TENANT, rest @ ..] => {
            let (tenant, rest) = rest.split_first_chunk::<8>().ok_or(Unopened::Damaged)?;
            let (print, rest) = rest.split_first_chunk::<4>().ok_or(Unopened::Damaged)?;
            let placed = (!rest.is_empty()).then(|| placed(rest)).transpose()?;
            Ok(Stored::Tenant(u64::from_be_bytes(*tenant), *print, placed))
        }
        [id, rest @ ..] => {
            let (place, sealed) = placed(rest)?;
            Ok(Stored::Installation(*id, place, sealed))
        }
        [] => Err(Unopened::Damaged),
    }
}

/// Whose key a stored body is sealed under, if it is sealed at all: a
/// tenant's, or the installation's.
pub fn sealed_for(bytes: &[u8]) -> Option<Option<u64>> {
    match stored(bytes) {
        Ok(Stored::Plain) => None,
        Ok(Stored::Tenant(tenant, ..)) => Some(Some(tenant)),
        Ok(Stored::Installation(..)) | Err(_) => Some(None),
    }
}

/// Whether a stored body is sealed in body `body`'s place, if it is sealed
/// at all: one moved from another row's place never opens as this one's.
pub fn body_in_place(bytes: &[u8], body: u64) -> bool {
    in_place(bytes, data_place(Kind::Body, body, 0))
}

/// Whether a captured file is sealed as `file` of capture `capture`, if it
/// is sealed at all.
pub fn capture_in_place(bytes: &[u8], capture: u64, file: u32) -> bool {
    in_place(bytes, data_place(Kind::Capture, capture, file))
}

fn in_place(bytes: &[u8], own: [u8; NONCE_LEN]) -> bool {
    match stored(bytes) {
        Ok(Stored::Plain | Stored::Tenant(_, _, None)) => true,
        Ok(Stored::Installation(_, place, _) | Stored::Tenant(_, _, Some((place, _)))) => {
            place == own
        }
        Err(_) => false,
    }
}

/// A stored body's content: as it is, unless `seal_body` sealed it, when it
/// is opened under the key that did.
pub fn open_body(keys: &Keys, bytes: &[u8]) -> Result<Option<Vec<u8>>, Unopened> {
    open_whole(keys, bytes, Kind::Body)
}

/// A captured file's content: as it is, unless `seal_capture` sealed it.
pub fn open_capture(keys: &Keys, bytes: &[u8]) -> Result<Option<Vec<u8>>, Unopened> {
    open_whole(keys, bytes, Kind::Capture)
}

fn open_whole(keys: &Keys, bytes: &[u8], kind: Kind) -> Result<Option<Vec<u8>>, Unopened> {
    let (key, place, sealed) = match stored(bytes)? {
        Stored::Plain => return Ok(None),
        Stored::Installation(id, place, sealed) => (keys.installation_key(id)?, place, sealed),
        Stored::Tenant(tenant, print, placed) => {
            let ring = keys.tenants.get(&tenant).ok_or(Unopened::Erased)?;
            let Some((place, sealed)) = placed.filter(|_| print == ring.print) else {
                return Err(Unopened::Erased);
            };
            (&ring.key, place, sealed)
        }
    };
    if place[8] != kind as u8 {
        return Err(Unopened::Damaged);
    }
    open(key, place, &[], sealed).map(Some)
}

/// What an index key is derived under, from its key: so the two are never
/// the same.
const INDEX_LABEL: &[u8] = b"nitromta: the index key of searchable values";

/// What a tenant key's fingerprint is derived under.
const PRINT_LABEL: &[u8] = b"nitromta: a tenant key's fingerprint";

/// The fingerprint data sealed for a tenant with no key carries: it opens
/// under none, as nothing of it was kept.
const ERASED_PRINT: [u8; 4] = [0; 4];

/// The kinds of record personal data is sealed in, each its own
/// part of a place, so no two kinds' values share one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    Delivery = 1,
    Body = 2,
    Entry = 3,
    Message = 4,
    Suppression = 5,
    Report = 6,
    Cooldown = 7,
    /// Capture mode's files, beside the store.
    Capture = 8,
}

/// Where personal data is sealed: its record's kind and ID, and its field,
/// as the nonce and associated data take them. Policy's secrets are kind
/// 0's (`place`).
pub fn data_place(kind: Kind, record: u64, field: u32) -> [u8; NONCE_LEN] {
    debug_assert!(field < 1 << 24, "a field number fits three bytes");
    let mut place = place(record, field);
    place[8] = kind as u8;
    place
}

/// The keys personal data is sealed under: the installation's,
/// and, while per-tenant keys are on, each tenant's, whose data is sealed
/// under its own.
pub struct Keys {
    installation: Arc<Keyring>,
    tenants: BTreeMap<u64, TenantRing>,
    /// An installation key opened as if it were gone, by [`Keys::refusing`].
    refused: Option<u8>,
}

/// A tenant's key, and its fingerprint, which what it sealed carries: a
/// key made again for the tenant has another, so what the lost one sealed
/// reads as erased, never as damage.
struct TenantRing {
    key: LessSafeKey,
    print: [u8; 4],
}

impl fmt::Debug for Keys {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tenants: Vec<&u64> = self.tenants.keys().collect();
        formatter
            .debug_struct("Keys")
            .field("installation", &self.installation)
            .field("tenants", &tenants)
            .finish()
    }
}

/// A tenant's key.
pub use engine_core::command::DataKey as TenantKey;

impl Keys {
    pub fn new(installation: Arc<Keyring>) -> Self {
        Self {
            installation,
            tenants: BTreeMap::new(),
            refused: None,
        }
    }

    /// The installation's keys, `key` among them refused, and no tenant's:
    /// what still needs `key` fails to open as though it were gone, while
    /// what is under the others opens as ever, so a key's retirement is
    /// decided by what still needs it.
    pub fn refusing(&self, key: u8) -> Self {
        Self {
            installation: Arc::clone(&self.installation),
            tenants: BTreeMap::new(),
            refused: Some(key),
        }
    }

    /// The installation key `id`, unless it is refused.
    fn installation_key(&self, id: u8) -> Result<&LessSafeKey, Unopened> {
        match self.installation.keys.get(&id) {
            Some(key) if self.refused != Some(id) => Ok(key),
            _ => Err(Unopened::NoKey(id)),
        }
    }

    pub fn installation(&self) -> &Arc<Keyring> {
        &self.installation
    }

    /// Seals `tenant`'s data under `key` from now on, and opens what it
    /// sealed.
    pub fn add_tenant(&mut self, tenant: u64, key: &TenantKey) {
        let derived = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, &key.0), PRINT_LABEL);
        let mut print = [0; 4];
        print.copy_from_slice(&derived.as_ref()[..4]);
        // Never the erased print, which opens under nothing.
        if print == ERASED_PRINT {
            print[3] = 1;
        }
        let sealing =
            UnboundKey::new(&AES_256_GCM_SIV, &key.0).expect("32 bytes is its key's length");
        self.tenants.insert(
            tenant,
            TenantRing {
                key: LessSafeKey::new(sealing),
                print,
            },
        );
    }

    /// Forgets `tenant`'s key: what it sealed reads as erased.
    pub fn forget_tenant(&mut self, tenant: u64) {
        self.tenants.remove(&tenant);
    }

    pub fn has_tenant(&self, tenant: u64) -> bool {
        self.tenants.contains_key(&tenant)
    }

    /// The tenants it holds a key of.
    pub fn tenants(&self) -> impl Iterator<Item = u64> + '_ {
        self.tenants.keys().copied()
    }

    /// `data` sealed in `place`, bound to `bound`: as `tenant`'s, under its
    /// key, or, with none, as erased, nothing of it kept; or, as no
    /// tenant's, under the installation's. A tenant's envelope is
    /// [`TENANT`], its ID in 8 bytes, big-endian, its key's fingerprint,
    /// then the ciphertext with its tag.
    pub fn seal_in(
        &self,
        tenant: Option<u64>,
        place: [u8; NONCE_LEN],
        bound: &[u8],
        data: &[u8],
    ) -> Vec<u8> {
        let Some(tenant) = tenant else {
            return self.installation.seal_in(place, bound, data);
        };
        let mut sealed = Vec::with_capacity(13 + data.len() + AES_256_GCM_SIV.tag_len());
        sealed.push(TENANT);
        sealed.extend_from_slice(&tenant.to_be_bytes());
        let Some(ring) = self.tenants.get(&tenant) else {
            sealed.extend_from_slice(&ERASED_PRINT);
            return sealed;
        };
        sealed.extend_from_slice(&ring.print);
        let head = sealed.len();
        sealed.extend_from_slice(data);
        let tag = seal(&ring.key, place, bound, &mut sealed[head..]);
        sealed.extend_from_slice(tag.as_ref());
        sealed
    }

    /// The data `envelope` holds in `place`, bound to `bound`, under
    /// whichever key it says.
    pub fn open_in(
        &self,
        place: [u8; NONCE_LEN],
        bound: &[u8],
        envelope: &[u8],
    ) -> Result<Vec<u8>, Unopened> {
        match envelope.split_first() {
            Some((&TENANT, rest)) => {
                let (tenant, rest) = rest.split_first_chunk::<8>().ok_or(Unopened::Damaged)?;
                let (print, sealed) = rest.split_first_chunk::<4>().ok_or(Unopened::Damaged)?;
                let ring = self
                    .tenants
                    .get(&u64::from_be_bytes(*tenant))
                    .ok_or(Unopened::Erased)?;
                if *print != ring.print || sealed.is_empty() {
                    return Err(Unopened::Erased);
                }
                open(&ring.key, place, bound, sealed)
            }
            Some((&id, sealed)) => open(self.installation_key(id)?, place, bound, sealed),
            None => Err(Unopened::Damaged),
        }
    }
}

/// Why a sealed secret did not open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unopened {
    /// It is sealed under a key the keyring does not hold.
    NoKey(u8),
    /// It is sealed under a tenant's key, which is gone: it is erased.
    Erased,
    /// It is not what its key sealed in its place.
    Damaged,
}

/// Where a secret is sealed: its record's ID and its field, as the nonce
/// and associated data take them.
pub fn place(record: u64, field: u32) -> [u8; NONCE_LEN] {
    let mut place = [0; NONCE_LEN];
    place[..8].copy_from_slice(&record.to_be_bytes());
    place[8..].copy_from_slice(&field.to_be_bytes());
    place
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_secret_opens_only_in_its_place_under_the_key_that_sealed_it() {
        let ring = Keyring::new(&[(1, [7; 32]), (2, [8; 32])]).unwrap();
        assert_eq!(ring.current(), 2);
        let sealed = ring.seal(place(5, 13), b"the secret");
        assert_eq!(sealed[0], 2);
        assert!(!sealed.windows(10).any(|window| window == b"the secret"));
        assert_eq!(
            ring.open(place(5, 13), &sealed),
            Ok((b"the secret".to_vec(), 2))
        );
        assert_eq!(
            ring.open(place(6, 13), &sealed),
            Err(Unopened::Damaged),
            "another record"
        );
        assert_eq!(
            ring.open(place(5, 12), &sealed),
            Err(Unopened::Damaged),
            "another field"
        );
        let mut tampered = sealed.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert_eq!(ring.open(place(5, 13), &tampered), Err(Unopened::Damaged));
        // An older key still opens what it sealed; a key gone does not.
        let older = Keyring::new(&[(1, [7; 32])]).unwrap();
        let by_older = older.seal(place(5, 13), b"the secret");
        assert_eq!(
            ring.open(place(5, 13), &by_older),
            Ok((b"the secret".to_vec(), 1))
        );
        assert_eq!(older.open(place(5, 13), &sealed), Err(Unopened::NoKey(2)));
        // A secret is never kept unsealed.
        assert_eq!(ring.open(place(5, 13), b"\0plain"), Err(Unopened::Damaged));
        assert_eq!(Keyring::new(&[]).err(), Some(KeyError::Empty));
        assert_eq!(
            Keyring::new(&[(0, [1; 32])]).err(),
            Some(KeyError::Reserved)
        );
        assert_eq!(
            Keyring::new(&[(3, [1; 32]), (3, [2; 32])]).err(),
            Some(KeyError::Repeated(3))
        );
    }

    #[test]
    fn a_sealed_body_says_its_key_and_opens_under_it_and_a_plain_one_is_as_it_was() {
        let ring = Arc::new(Keyring::new(&[(1, [7; 32]), (3, [8; 32])]).unwrap());
        let keys = Keys::new(Arc::clone(&ring));
        let content = b"From: <a@example.test>\r\n\r\nhello\r\n";
        let sealed = seal_body(&keys, None, 42, content);
        assert_eq!(body_key(&sealed), 3);
        assert!(!sealed.windows(5).any(|window| window == b"hello"));
        assert_eq!(open_body(&keys, &sealed), Ok(Some(content.to_vec())));
        assert_eq!(body_key(content), NO_KEY);
        assert_eq!(open_body(&keys, content), Ok(None), "kept as it is");
        let mut tampered = sealed.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert_eq!(open_body(&keys, &tampered), Err(Unopened::Damaged));
        let older = Keys::new(Arc::new(Keyring::new(&[(1, [7; 32])]).unwrap()));
        assert_eq!(open_body(&older, &sealed), Err(Unopened::NoKey(3)));
    }

    #[test]
    fn a_tenants_data_is_sealed_under_its_own_key_and_erased_with_it() {
        let ring = Arc::new(Keyring::new(&[(1, [7; 32])]).unwrap());
        let mut keys = Keys::new(Arc::clone(&ring));
        let installation = Keys::new(Arc::clone(&ring));
        keys.add_tenant(9, &TenantKey([3; 32]));
        let here = data_place(Kind::Delivery, 5, 3);
        let sealed = keys.seal_in(Some(9), here, &[], b"ann@example.com");
        assert_eq!(sealed[0], TENANT, "it says whose it is");
        assert_eq!(
            keys.open_in(here, &[], &sealed),
            Ok(b"ann@example.com".to_vec())
        );
        assert_eq!(
            installation.open_in(here, &[], &sealed),
            Err(Unopened::Erased)
        );
        let body = seal_body(&keys, Some(9), 42, b"hello");
        assert_eq!(body_key(&body), TENANT);
        assert!(body_in_place(&body, 42) && !body_in_place(&body, 43));
        assert_eq!(open_body(&keys, &body), Ok(Some(b"hello".to_vec())));
        assert_eq!(sealed_for(&body), Some(Some(9)));
        // Its capture is sealed as it is, and each opens as its own kind
        // alone.
        let captured = seal_capture(&keys, Some(9), 42, 1, b"hello");
        assert!(capture_in_place(&captured, 42, 1) && !capture_in_place(&captured, 42, 0));
        assert_eq!(open_capture(&keys, &captured), Ok(Some(b"hello".to_vec())));
        assert_eq!(open_body(&keys, &captured), Err(Unopened::Damaged));
        assert_eq!(open_capture(&keys, &body), Err(Unopened::Damaged));
        // A tenant with no key keeps nothing: what is sealed for it is
        // erased as it is written.
        let keyless = keys.seal_in(Some(10), here, &[], b"bob@example.com");
        assert!(!keyless.windows(3).any(|window| window == b"bob"));
        assert_eq!(keys.open_in(here, &[], &keyless), Err(Unopened::Erased));
        assert_eq!(
            open_body(&keys, &seal_body(&keys, Some(10), 43, b"x")),
            Err(Unopened::Erased)
        );
        // Its key forgotten, what it sealed is erased; and a key made for it
        // again opens none of it, though new data opens under the new one.
        keys.forget_tenant(9);
        assert_eq!(keys.open_in(here, &[], &sealed), Err(Unopened::Erased));
        assert_eq!(open_body(&keys, &body), Err(Unopened::Erased));
        assert_eq!(open_capture(&keys, &captured), Err(Unopened::Erased));
        keys.add_tenant(9, &TenantKey([4; 32]));
        assert_eq!(keys.open_in(here, &[], &sealed), Err(Unopened::Erased));
        let again = keys.seal_in(Some(9), here, &[], b"carol@example.com");
        assert_eq!(
            keys.open_in(here, &[], &again),
            Ok(b"carol@example.com".to_vec())
        );
        // What is no tenant's is the installation's.
        let theirs = keys.seal_in(None, here, &[], b"dan@example.com");
        assert_eq!(
            installation.open_in(here, &[], &theirs),
            Ok(b"dan@example.com".to_vec())
        );
        // Bound to the rest of its row's key, it opens in that row alone.
        let bound = installation.seal_in(None, here, b"row a", b"eve@example.com");
        assert_eq!(
            installation.open_in(here, b"row a", &bound),
            Ok(b"eve@example.com".to_vec())
        );
        assert_eq!(
            installation.open_in(here, b"row b", &bound),
            Err(Unopened::Damaged)
        );
        assert_eq!(
            Keyring::new(&[(TENANT, [1; 32])]).err(),
            Some(KeyError::Reserved)
        );
    }

    #[test]
    fn data_opens_only_in_its_place_and_kind_under_the_key_that_sealed_it() {
        let ring = Keyring::new(&[(1, [7; 32]), (2, [8; 32])]).unwrap();
        let here = data_place(Kind::Delivery, 5, 3);
        let sealed = ring.seal_in(here, &[], b"ann@example.com");
        assert_eq!(sealed[0], 2);
        assert_eq!(sealed.len(), 1 + 15 + 16, "its key, the data and its tag");
        assert!(!sealed.windows(3).any(|window| window == b"ann"));
        assert_eq!(
            ring.open_in(here, &[], &sealed),
            Ok(b"ann@example.com".to_vec())
        );
        for elsewhere in [
            data_place(Kind::Report, 5, 3),
            data_place(Kind::Delivery, 6, 3),
            data_place(Kind::Delivery, 5, 4),
            place(5, 3),
        ] {
            assert_eq!(
                ring.open_in(elsewhere, &[], &sealed),
                Err(Unopened::Damaged)
            );
        }
        let older = Keyring::new(&[(1, [7; 32])]).unwrap();
        assert_eq!(
            ring.open_in(here, &[], &older.seal_in(here, &[], b"x")),
            Ok(b"x".to_vec())
        );
        assert_eq!(older.open_in(here, &[], &sealed), Err(Unopened::NoKey(2)));
        assert_eq!(ring.open_in(here, &[], &[]), Err(Unopened::Damaged));
    }
}
