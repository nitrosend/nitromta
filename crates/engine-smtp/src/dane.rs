//! DANE for SMTP (RFC 7672): which names' TLSA records may bind an
//! exchange's certificate, what the first secure answer among them asks of
//! a connection to it, and whether a certificate matches a record. The
//! driver performs the lookups, through a resolver that validates DNSSEC,
//! and says what each proved; what that means is decided here, so the
//! simulator decides the same.

use aws_lc_rs::digest;

use crate::route::Tls;

/// A TLSA record (RFC 6698, 2.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tlsa {
    pub usage: u8,
    pub selector: u8,
    pub matching: u8,
    pub data: Vec<u8>,
}

/// A trust anchor the server's chain must reach.
pub const DANE_TA: u8 = 2;
/// The server's own certificate.
pub const DANE_EE: u8 = 3;

impl Tlsa {
    /// Whether SMTP can use it (RFC 7672, 3.1; RFC 7671, 9): DANE-TA or
    /// DANE-EE, of the whole certificate or its public key, as it is or by
    /// a SHA-256 or SHA-512 digest of the digest's length.
    pub fn usable(&self) -> bool {
        let data = match self.matching {
            0 => !self.data.is_empty(),
            1 => self.data.len() == 32,
            2 => self.data.len() == 64,
            _ => false,
        };
        matches!(self.usage, DANE_TA | DANE_EE) && matches!(self.selector, 0 | 1) && data
    }

    /// Whether it matches `certificate`, in DER.
    pub fn matches(&self, certificate: &[u8]) -> bool {
        let selected = match self.selector {
            0 => certificate,
            1 => match public_key_info(certificate) {
                Some(info) => info,
                None => return false,
            },
            _ => return false,
        };
        match self.matching {
            0 => selected == self.data.as_slice(),
            1 => digest::digest(&digest::SHA256, selected).as_ref() == self.data.as_slice(),
            2 => digest::digest(&digest::SHA512, selected).as_ref() == self.data.as_slice(),
            _ => false,
        }
    }
}

/// What an exchange's address lookup proved (RFC 7672, 2.2.2).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Addresses {
    /// The CNAME chain it followed from the exchange's name: each alias's
    /// target, and whether its record was secure.
    pub aliases: Vec<(String, bool)>,
    /// Whether the address records it ended at were secure.
    pub secure: bool,
}

/// The names whose TLSA records may bind `host`'s certificate, in the
/// order they are tried (RFC 7672, 2.2.2 and 2.2.3): none unless the route
/// is DANE's and the host's own answer was secure; through a CNAME chain
/// secure to its addresses, the expanded name first, then the host's own.
pub fn candidates(host: &str, tls: Tls, addresses: &Addresses) -> Vec<String> {
    if !tls.dane {
        return Vec::new();
    }
    match addresses.aliases.split_first() {
        None if addresses.secure => vec![host.to_owned()],
        None => Vec::new(),
        // An insecure first answer: DANE does not apply.
        Some(((_, false), _)) => Vec::new(),
        Some(_) => {
            let chain = addresses.aliases.iter().all(|(_, secure)| *secure) && addresses.secure;
            let expanded = &addresses.aliases[addresses.aliases.len() - 1].0;
            if chain && expanded != host {
                vec![expanded.clone(), host.to_owned()]
            } else {
                vec![host.to_owned()]
            }
        }
    }
}

/// What a TLSA lookup at one candidate found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Lookup {
    /// Records proved secure, through every alias the lookup followed.
    Secure(Vec<Tlsa>),
    /// Records, or their absence, not proved secure: they bind nothing.
    Insecure,
    /// No records.
    Absent,
    /// The lookup failed, or its answer was bogus.
    Failed(String),
}

/// What TLS to one exchange must prove.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Requirement {
    /// Nothing: STARTTLS when offered, unverified, unless the
    /// configuration or the site's rules require TLS.
    Opportunistic,
    /// TLS, unverified: the exchange's TLSA records are all unusable (RFC
    /// 7672, 2.2).
    Required,
    /// A certificate the web PKI trusts for the exchange's name: MTA-STS.
    Verified,
    /// A certificate these records bind, found at `base`, the TLSA base
    /// domain; a DANE-TA certificate must be valid for one of `names`, its
    /// reference identifiers (RFC 7672, 3.2.2), the base among them.
    Dane {
        records: Vec<Tlsa>,
        base: String,
        names: Vec<String>,
    },
}

/// What a candidate's lookup decides, or `None` to try the next: the first
/// candidate with a secure RRset is the TLSA base domain, and a lookup that
/// fails leaves the exchange unusable, never unverified.
pub fn decide(tls: Tls, base: &str, lookup: Lookup) -> Option<Result<Requirement, String>> {
    match lookup {
        Lookup::Secure(records) if !records.is_empty() => {
            let usable: Vec<Tlsa> = records.into_iter().filter(Tlsa::usable).collect();
            Some(Ok(match (usable.is_empty(), tls.sts) {
                (true, true) => Requirement::Verified,
                (true, false) => Requirement::Required,
                (false, _) => Requirement::Dane {
                    records: usable,
                    base: base.to_owned(),
                    names: vec![base.to_owned()],
                },
            }))
        }
        Lookup::Secure(_) | Lookup::Insecure | Lookup::Absent => None,
        Lookup::Failed(why) => Some(Err(format!(
            "DANE: the TLSA lookup for {base} failed: {why}"
        ))),
    }
}

/// The names a DANE-TA certificate may be valid for (RFC 7672, 3.2.2): its
/// TLSA base domain first; then the domain the mail is for, its next hop,
/// and that domain as its aliases expand, each where it differs.
pub fn reference_identifiers(
    base: &str,
    next_hop: Option<&str>,
    expanded: Option<&str>,
) -> Vec<String> {
    let mut names = vec![base.to_owned()];
    for name in [next_hop, expanded].into_iter().flatten() {
        if !names.iter().any(|known| known.eq_ignore_ascii_case(name)) {
            names.push(name.to_ascii_lowercase());
        }
    }
    names
}

/// What TLS must prove when no candidate's records bind the exchange.
pub fn without_records(tls: Tls) -> Requirement {
    if tls.sts {
        Requirement::Verified
    } else {
        Requirement::Opportunistic
    }
}

/// A CA certificate's pathLenConstraint (RFC 5280, 4.2.1.9), if its basic
/// constraints give one: the most intermediate certificates that may follow
/// it in a path, which a DANE-TA anchor keeps (RFC 7672, 3.1.2).
pub fn path_length(certificate: &[u8]) -> Option<u64> {
    let certificate = element(certificate).filter(|element| element.tag == SEQUENCE)?;
    let mut signed = element(certificate.contents)
        .filter(|element| element.tag == SEQUENCE)?
        .contents;
    if signed.first() == Some(&VERSION) {
        signed = element(signed)?.rest;
    }
    // Its serial number, signature algorithm, issuer, validity, subject
    // and public key; then its unique IDs, if any, and its extensions.
    for _ in 0..6 {
        signed = element(signed)?.rest;
    }
    while let Some(field) = element(signed) {
        if field.tag == EXTENSIONS {
            let mut extensions = element(field.contents)
                .filter(|element| element.tag == SEQUENCE)?
                .contents;
            while let Some(extension) = element(extensions) {
                extensions = extension.rest;
                let id = element(extension.contents)?;
                if id.whole != BASIC_CONSTRAINTS {
                    continue;
                }
                let mut value = element(id.rest)?;
                if value.tag == BOOLEAN {
                    value = element(value.rest)?;
                }
                let mut constraints = element(value.contents)
                    .filter(|element| element.tag == SEQUENCE)?
                    .contents;
                if let Some(ca) = element(constraints).filter(|element| element.tag == BOOLEAN) {
                    constraints = ca.rest;
                }
                let length = element(constraints).filter(|element| element.tag == INTEGER)?;
                return length.contents.iter().try_fold(0u64, |value, &byte| {
                    value.checked_mul(256)?.checked_add(u64::from(byte))
                });
            }
            return None;
        }
        signed = field.rest;
    }
    None
}

/// The DER of a certificate's subjectPublicKeyInfo, which follows its
/// version, serial number, signature algorithm, issuer, validity and
/// subject in the certificate's signed part (RFC 5280, 4.1).
fn public_key_info(certificate: &[u8]) -> Option<&[u8]> {
    let certificate = element(certificate).filter(|element| element.tag == SEQUENCE)?;
    let mut signed = element(certificate.contents)
        .filter(|element| element.tag == SEQUENCE)?
        .contents;
    if signed.first() == Some(&VERSION) {
        signed = element(signed)?.rest;
    }
    for _ in 0..5 {
        signed = element(signed)?.rest;
    }
    let info = element(signed).filter(|element| element.tag == SEQUENCE)?;
    Some(info.whole)
}

const BOOLEAN: u8 = 0x01;
const INTEGER: u8 = 0x02;
const SEQUENCE: u8 = 0x30;
/// The signed part's explicitly tagged version.
const VERSION: u8 = 0xA0;
/// The signed part's explicitly tagged extensions.
const EXTENSIONS: u8 = 0xA3;
/// The basic constraints extension's ID, 2.5.29.19, as DER.
const BASIC_CONSTRAINTS: &[u8] = &[0x06, 0x03, 0x55, 0x1D, 0x13];

/// A DER element, and what follows it.
struct Element<'a> {
    tag: u8,
    /// Its whole encoding, tag and length included.
    whole: &'a [u8],
    contents: &'a [u8],
    rest: &'a [u8],
}

/// The DER element `der` starts with.
fn element(der: &[u8]) -> Option<Element<'_>> {
    let tag = *der.first()?;
    let first = *der.get(1)?;
    let (length, header) = if first < 0x80 {
        (usize::from(first), 2)
    } else {
        let count = usize::from(first & 0x7F);
        if !(1..=4).contains(&count) {
            return None;
        }
        let mut length = 0usize;
        for &byte in der.get(2..2 + count)? {
            length = length.checked_mul(256)?.checked_add(usize::from(byte))?;
        }
        (length, 2 + count)
    };
    let end = header.checked_add(length)?;
    let whole = der.get(..end)?;
    Some(Element {
        tag,
        whole,
        contents: &whole[header..],
        rest: &der[end..],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A self-signed certificate, and its subjectPublicKeyInfo, which rcgen
    /// builds the same way.
    fn generated() -> (Vec<u8>, Vec<u8>) {
        use rcgen::PublicKeyData as _;
        let certified = rcgen::generate_simple_self_signed(vec!["mx.example.test".to_owned()])
            .expect("a certificate");
        (
            certified.cert.der().to_vec(),
            certified.signing_key.subject_public_key_info(),
        )
    }

    fn record(usage: u8, selector: u8, matching: u8, data: Vec<u8>) -> Tlsa {
        Tlsa {
            usage,
            selector,
            matching,
            data,
        }
    }

    #[test]
    fn a_record_matches_the_certificate_or_its_key_as_it_is_or_by_its_digest() {
        let (certificate, key) = generated();
        assert_eq!(public_key_info(&certificate), Some(key.as_slice()));
        let sha256 = |bytes: &[u8]| digest::digest(&digest::SHA256, bytes).as_ref().to_vec();
        let sha512 = |bytes: &[u8]| digest::digest(&digest::SHA512, bytes).as_ref().to_vec();
        for record in [
            record(DANE_EE, 0, 0, certificate.clone()),
            record(DANE_EE, 0, 1, sha256(&certificate)),
            record(DANE_EE, 1, 1, sha256(&key)),
            record(DANE_EE, 1, 2, sha512(&key)),
            record(DANE_TA, 1, 0, key.clone()),
        ] {
            assert!(record.matches(&certificate), "{record:?}");
        }
        let (other, _) = generated();
        assert!(!record(DANE_EE, 1, 1, sha256(&key)).matches(&other));
        assert!(!record(DANE_EE, 1, 1, sha256(&key)).matches(b"not a certificate"));
    }

    #[test]
    fn only_dane_records_of_the_right_shape_bind_and_unusable_ones_still_require_tls() {
        let dane = Tls {
            dane: true,
            sts: false,
        };
        let usable = record(DANE_EE, 1, 1, vec![0; 32]);
        for unusable in [
            record(1, 1, 1, vec![0; 32]),
            record(DANE_EE, 1, 9, vec![0; 32]),
            record(DANE_EE, 1, 1, vec![0; 31]),
            record(DANE_EE, 1, 2, vec![0; 32]),
            record(DANE_EE, 0, 0, Vec::new()),
        ] {
            assert!(!unusable.usable(), "{unusable:?}");
            assert_eq!(
                decide(dane, "mx.test", Lookup::Secure(vec![unusable.clone()])),
                Some(Ok(Requirement::Required))
            );
        }
        assert_eq!(
            decide(
                dane,
                "mx.test",
                Lookup::Secure(vec![record(1, 1, 1, vec![0; 32]), usable.clone()])
            ),
            Some(Ok(Requirement::Dane {
                records: vec![usable],
                base: "mx.test".to_owned(),
                names: vec!["mx.test".to_owned()]
            }))
        );
        // Nothing secure binds; a failure leaves the exchange unused.
        assert_eq!(decide(dane, "mx.test", Lookup::Insecure), None);
        assert_eq!(decide(dane, "mx.test", Lookup::Absent), None);
        assert!(matches!(
            decide(dane, "mx.test", Lookup::Failed("bogus".to_owned())),
            Some(Err(_))
        ));
        let both = Tls {
            dane: true,
            sts: true,
        };
        assert_eq!(without_records(both), Requirement::Verified);
        assert_eq!(without_records(dane), Requirement::Opportunistic);
    }

    #[test]
    fn tlsa_records_are_looked_for_only_through_secure_answers() {
        let dane = Tls {
            dane: true,
            sts: false,
        };
        let alias = |target: &str, secure| (target.to_owned(), secure);
        let names = |aliases: Vec<(String, bool)>, secure| {
            candidates("mx.test", dane, &Addresses { aliases, secure })
        };
        assert_eq!(names(Vec::new(), true), ["mx.test"]);
        assert!(names(Vec::new(), false).is_empty());
        assert!(
            candidates("mx.test", Tls::default(), &Addresses::default()).is_empty(),
            "not a DANE route"
        );
        // A secure chain: the expanded name, then the host's own.
        assert_eq!(
            names(vec![alias("a.test", true), alias("b.test", true)], true),
            ["b.test", "mx.test"]
        );
        // Insecure past its first answer: only the host's own name.
        assert_eq!(names(vec![alias("b.test", true)], false), ["mx.test"]);
        assert_eq!(
            names(vec![alias("a.test", true), alias("b.test", false)], true),
            ["mx.test"]
        );
        // An insecure first answer: none.
        assert!(names(vec![alias("b.test", false)], true).is_empty());
    }

    #[test]
    fn a_dane_ta_certificate_may_name_its_base_its_next_hop_or_that_expanded() {
        assert_eq!(
            reference_identifiers(
                "mx.provider.test",
                Some("Example.Test"),
                Some("canonical.test")
            ),
            ["mx.provider.test", "example.test", "canonical.test"]
        );
        assert_eq!(
            reference_identifiers("example.test", Some("example.test"), None),
            ["example.test"],
            "a domain without MX records is its own base"
        );
        assert_eq!(reference_identifiers("mx.test", None, None), ["mx.test"]);
    }

    #[test]
    fn a_ca_certificates_path_length_is_read_from_its_basic_constraints() {
        let ca = |constraint| {
            let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
            params.is_ca = rcgen::IsCa::Ca(constraint);
            params
                .self_signed(&rcgen::KeyPair::generate().unwrap())
                .unwrap()
                .der()
                .to_vec()
        };
        assert_eq!(
            path_length(&ca(rcgen::BasicConstraints::Constrained(0))),
            Some(0)
        );
        assert_eq!(
            path_length(&ca(rcgen::BasicConstraints::Constrained(3))),
            Some(3)
        );
        assert_eq!(
            path_length(&ca(rcgen::BasicConstraints::Unconstrained)),
            None
        );
        assert_eq!(path_length(&generated().0), None);
    }
}
