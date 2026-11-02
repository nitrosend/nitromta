//! The record codec.
//!
//! A stored record is a version byte and then numbered fields in ascending
//! order, each a varint or a length-prefixed byte string. A field number is
//! never reused once retired. A reader accepts only the versions it knows
//! and refuses fields it does not, so a record is never guessed at, and
//! never rewritten without a field it carried.
//!
//! Fields holding personal data are sealed: a byte string holding the
//! encryption key ID, which is zero while encryption is off, then the data,
//! sealed in its place when there is a key: its record's kind and
//! ID and its field, which name the nonce, so none is kept. Turning
//! encryption on therefore changes no format, and data sealed before it
//! still reads.

use std::borrow::Cow;
use std::fmt;

use crate::keys::{self, Keys, Unopened};

const VARINT: u64 = 0;
const BYTES: u64 = 1;
/// The key ID of data sealed without encryption.
const NO_KEY: u8 = 0;

#[derive(Debug, PartialEq, Eq)]
pub enum CodecError {
    Truncated,
    Version(u8),
    /// A field out of ascending order, or repeated.
    Order(u32),
    WireType(u32),
    UnknownField(u32),
    Missing(&'static str),
    /// Sealed data under an encryption key, which this release cannot open.
    Encrypted,
    /// A secret sealed under a key the keyring does not hold.
    NoKey(u8),
    /// Data sealed under a tenant's key, which is gone.
    Erased,
    Invalid(&'static str),
}

impl fmt::Display for CodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => write!(formatter, "the record ends early"),
            Self::Version(version) => write!(
                formatter,
                "record version {version} is not one this release reads"
            ),
            Self::Order(field) => write!(formatter, "field {field} is out of order or repeated"),
            Self::WireType(field) => write!(formatter, "field {field} has the wrong type"),
            Self::UnknownField(field) => {
                write!(formatter, "field {field} is not one this release knows")
            }
            Self::Missing(name) => write!(formatter, "the {name} is missing"),
            Self::Encrypted => write!(
                formatter,
                "the record is encrypted, and no key is configured"
            ),
            Self::NoKey(id) => write!(
                formatter,
                "a secret is sealed under key {id}, which the keys' file does not hold"
            ),
            Self::Erased => write!(formatter, "it was sealed under a tenant's key, now gone"),
            Self::Invalid(name) => write!(formatter, "the {name} is invalid"),
        }
    }
}

/// Where a record's personal data is sealed: under `keys`, as
/// `tenant`'s, in a record of `kind` with ID `record`.
#[derive(Clone, Copy)]
pub struct Sealing<'k> {
    keys: &'k Keys,
    tenant: Option<u64>,
    kind: keys::Kind,
    record: u64,
    /// Added to a field's number in its place: a nested record's own.
    offset: u32,
    /// The rest of what names its record, where its ID alone does not: a
    /// suppression's key within its account, a cooldown's site.
    bound: &'k [u8],
}

impl<'k> Sealing<'k> {
    /// Sealing for a record of `kind` with ID `record`, while encryption is
    /// on: under `keys`, when there are any, `tenant`'s key if it is its
    /// tenant's and the keys hold one.
    pub fn of(
        keys: Option<&'k Keys>,
        tenant: Option<u64>,
        kind: keys::Kind,
        record: u64,
    ) -> Option<Self> {
        keys.map(|keys| Self {
            keys,
            tenant,
            kind,
            record,
            offset: 0,
            bound: &[],
        })
    }

    /// As it is, its values bound also to `bound`.
    pub fn bound(self, bound: &'k [u8]) -> Self {
        Self { bound, ..self }
    }

    /// Sealing for the `index`th record nested in this one, whose fields
    /// take places of their own, apart from the outer record's.
    pub fn nested(self, index: usize) -> Self {
        let index = u32::try_from(index).unwrap_or(u32::MAX).min(0xFFF);
        Self {
            offset: 0x1_0000 + (index << 4),
            ..self
        }
    }

    fn place(&self, field: u32) -> [u8; 12] {
        keys::data_place(self.kind, self.record, field + self.offset)
    }
}

/// Writes one record. Fields must be written in ascending order.
pub struct Writer {
    buffer: Vec<u8>,
    last_field: u32,
}

impl Writer {
    pub fn new(version: u8) -> Self {
        Self {
            buffer: vec![version],
            last_field: 0,
        }
    }

    pub fn uint(&mut self, field: u32, value: u64) {
        self.tag(field, VARINT);
        varint(&mut self.buffer, value);
    }

    pub fn bytes(&mut self, field: u32, value: &[u8]) {
        self.tag(field, BYTES);
        varint(&mut self.buffer, value.len() as u64);
        self.buffer.extend_from_slice(value);
    }

    /// Writes personal data, sealed in its place under `sealing`'s keys,
    /// or with no key while encryption is off.
    pub fn sealed(&mut self, field: u32, value: &[u8], sealing: Option<Sealing<'_>>) {
        match sealing {
            Some(sealing) => {
                let sealed = sealing.keys.seal_in(
                    sealing.tenant,
                    sealing.place(field),
                    sealing.bound,
                    value,
                );
                self.bytes(field, &sealed);
            }
            None => {
                self.tag(field, BYTES);
                varint(&mut self.buffer, value.len() as u64 + 1);
                self.buffer.push(NO_KEY);
                self.buffer.extend_from_slice(value);
            }
        }
    }

    pub fn finish(self) -> Vec<u8> {
        self.buffer
    }

    fn tag(&mut self, field: u32, wire_type: u64) {
        assert!(
            field > self.last_field,
            "fields are written in ascending order, once each"
        );
        self.last_field = field;
        varint(&mut self.buffer, (u64::from(field) << 1) | wire_type);
    }
}

/// One field's value, as read.
#[derive(Clone, Copy, Debug)]
pub enum Value<'a> {
    Uint(u64),
    Bytes(&'a [u8]),
}

impl<'a> Value<'a> {
    pub fn uint(self, field: u32) -> Result<u64, CodecError> {
        match self {
            Self::Uint(value) => Ok(value),
            Self::Bytes(_) => Err(CodecError::WireType(field)),
        }
    }

    pub fn bytes(self, field: u32) -> Result<&'a [u8], CodecError> {
        match self {
            Self::Bytes(value) => Ok(value),
            Self::Uint(_) => Err(CodecError::WireType(field)),
        }
    }

    /// Opens sealed personal data: as it is, sealed with no key, which it
    /// may be from before encryption was on; else under `sealing`'s keys.
    pub fn sealed(
        self,
        field: u32,
        sealing: Option<Sealing<'_>>,
    ) -> Result<Cow<'a, [u8]>, CodecError> {
        let bytes = self.bytes(field)?;
        match bytes.split_first() {
            Some((&NO_KEY, data)) => Ok(Cow::Borrowed(data)),
            Some(_) => {
                let sealing = sealing.ok_or(CodecError::Encrypted)?;
                sealing
                    .keys
                    .open_in(sealing.place(field), sealing.bound, bytes)
                    .map(Cow::Owned)
                    .map_err(|unopened| match unopened {
                        Unopened::NoKey(id) => CodecError::NoKey(id),
                        Unopened::Erased => CodecError::Erased,
                        Unopened::Damaged => CodecError::Invalid("sealed data"),
                    })
            }
            None => Err(CodecError::Truncated),
        }
    }
}

/// Reads one record's fields in order.
pub struct Reader<'a> {
    rest: &'a [u8],
    last_field: u32,
}

impl<'a> Reader<'a> {
    /// Starts reading `record`, which must be of `version`.
    pub fn new(record: &'a [u8], version: u8) -> Result<Self, CodecError> {
        match record.split_first() {
            Some((&found, rest)) if found == version => Ok(Self {
                rest,
                last_field: 0,
            }),
            Some((&found, _)) => Err(CodecError::Version(found)),
            None => Err(CodecError::Truncated),
        }
    }

    pub fn next(&mut self) -> Result<Option<(u32, Value<'a>)>, CodecError> {
        if self.rest.is_empty() {
            return Ok(None);
        }
        let tag = read_varint(&mut self.rest)?;
        let field = u32::try_from(tag >> 1).map_err(|_| CodecError::Invalid("field number"))?;
        if field <= self.last_field {
            return Err(CodecError::Order(field));
        }
        self.last_field = field;
        let value = if tag & 1 == VARINT {
            Value::Uint(read_varint(&mut self.rest)?)
        } else {
            let length =
                usize::try_from(read_varint(&mut self.rest)?).map_err(|_| CodecError::Truncated)?;
            if length > self.rest.len() {
                return Err(CodecError::Truncated);
            }
            let (bytes, rest) = self.rest.split_at(length);
            self.rest = rest;
            Value::Bytes(bytes)
        };
        Ok(Some((field, value)))
    }
}

/// Appends `value` as an unsigned LEB128 varint.
fn varint(buffer: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        buffer.push((value as u8) | 0x80);
        value >>= 7;
    }
    buffer.push(value as u8);
}

fn read_varint(rest: &mut &[u8]) -> Result<u64, CodecError> {
    let mut value: u64 = 0;
    for shift in (0..64).step_by(7) {
        let (&byte, tail) = rest.split_first().ok_or(CodecError::Truncated)?;
        *rest = tail;
        let bits = u64::from(byte & 0x7f);
        // The tenth byte may carry only the top bit of a 64-bit value.
        if shift == 63 && bits > 1 {
            return Err(CodecError::Invalid("varint"));
        }
        value |= bits << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(CodecError::Invalid("varint"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varints_round_trip_at_every_boundary() {
        for value in [
            0,
            1,
            127,
            128,
            16_383,
            16_384,
            u64::from(u32::MAX),
            u64::MAX - 1,
            u64::MAX,
        ] {
            let mut buffer = Vec::new();
            varint(&mut buffer, value);
            let mut rest = buffer.as_slice();
            assert_eq!(read_varint(&mut rest), Ok(value));
            assert!(rest.is_empty());
        }
        let mut overlong: &[u8] = &[0xff; 11];
        assert_eq!(
            read_varint(&mut overlong),
            Err(CodecError::Invalid("varint"))
        );
        let mut truncated: &[u8] = &[0x80];
        assert_eq!(read_varint(&mut truncated), Err(CodecError::Truncated));
    }

    #[test]
    fn fields_read_back_as_written() {
        let mut writer = Writer::new(3);
        writer.uint(1, 42);
        writer.sealed(5, b"personal", None);
        let record = writer.finish();

        let mut reader = Reader::new(&record, 3).expect("version 3");
        let (field, value) = reader.next().expect("readable").expect("a field");
        assert_eq!((field, value.uint(field)), (1, Ok(42)));
        let (field, value) = reader.next().expect("readable").expect("a field");
        assert_eq!(
            (field, value.sealed(field, None)),
            (5, Ok(Cow::Borrowed(&b"personal"[..])))
        );
        // The envelope is the key ID, zero, then the data.
        assert_eq!(value.bytes(field), Ok(&b"\0personal"[..]));
        assert_eq!(reader.next(), Ok(None));
    }

    #[test]
    fn sealed_fields_open_in_their_own_record_and_plain_ones_still_read() {
        use crate::keys::Keyring;
        use std::sync::Arc;
        let keys = Keys::new(Arc::new(Keyring::new(&[(4, [9; 32])]).unwrap()));
        let sealing = Sealing::of(Some(&keys), None, keys::Kind::Delivery, 77);
        let mut writer = Writer::new(1);
        writer.sealed(2, b"ann@example.com", sealing);
        let record = writer.finish();
        assert!(!record.windows(3).any(|window| window == b"ann"));
        let read = |sealing| {
            let mut reader = Reader::new(&record, 1).unwrap();
            let (field, value) = reader.next().unwrap().unwrap();
            value.sealed(field, sealing).map(Cow::into_owned)
        };
        assert_eq!(read(sealing), Ok(b"ann@example.com".to_vec()));
        assert_eq!(read(None), Err(CodecError::Encrypted), "no keys");
        let another = Sealing::of(Some(&keys), None, keys::Kind::Delivery, 78);
        assert_eq!(read(another), Err(CodecError::Invalid("sealed data")));
        let others = Keys::new(Arc::new(Keyring::new(&[(5, [9; 32])]).unwrap()));
        let theirs = Sealing::of(Some(&others), None, keys::Kind::Delivery, 77);
        assert_eq!(read(theirs), Err(CodecError::NoKey(4)));
        // Written before encryption was on, it reads as it was.
        let mut writer = Writer::new(1);
        writer.sealed(2, b"plain", None);
        let plain = writer.finish();
        let mut reader = Reader::new(&plain, 1).unwrap();
        let (field, value) = reader.next().unwrap().unwrap();
        assert_eq!(
            value.sealed(field, sealing),
            Ok(Cow::Borrowed(&b"plain"[..]))
        );
    }

    #[test]
    fn malformed_records_are_refused() {
        assert_eq!(Reader::new(&[], 1).err(), Some(CodecError::Truncated));
        assert_eq!(Reader::new(&[2], 1).err(), Some(CodecError::Version(2)));

        // Field 2, then field 1.
        let mut reader = Reader::new(&[1, 0b100, 7, 0b10, 7], 1).expect("version 1");
        assert!(reader.next().is_ok());
        assert_eq!(reader.next(), Err(CodecError::Order(1)));

        // A byte string longer than what follows.
        let mut reader = Reader::new(&[1, 0b11, 5, b'a'], 1).expect("version 1");
        assert_eq!(reader.next(), Err(CodecError::Truncated));

        // Sealed under key 9.
        let mut reader = Reader::new(&[1, 0b11, 2, 9, b'a'], 1).expect("version 1");
        let (field, value) = reader.next().expect("readable").expect("a field");
        assert_eq!(value.sealed(field, None), Err(CodecError::Encrypted));
        assert_eq!(value.uint(field), Err(CodecError::WireType(1)));
    }

    impl PartialEq for Value<'_> {
        fn eq(&self, other: &Self) -> bool {
            match (self, other) {
                (Self::Uint(a), Self::Uint(b)) => a == b,
                (Self::Bytes(a), Self::Bytes(b)) => a == b,
                _ => false,
            }
        }
    }
}
