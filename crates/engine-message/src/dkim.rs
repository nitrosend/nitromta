//! DKIM signing (RFC 6376): `rsa-sha256`, with relaxed canonicalization of
//! both the header and the body.
//!
//! The harness checks every signature the engine makes with a verifier
//! written separately from this one, so the two cannot share a mistake.

use aws_lc_rs::digest::{Context, Digest, SHA256};
use aws_lc_rs::signature::{RSA_PKCS1_SHA256, RsaKeyPair};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

pub struct Signer {
    key: RsaKeyPair,
    domain: String,
    selector: String,
    /// Lowercase field names, as configured, each with how often it was
    /// named before: the instance from the bottom it signs.
    headers: Vec<(String, usize)>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum KeyError {
    /// Not a PEM `PRIVATE KEY` (PKCS#8) or `RSA PRIVATE KEY` (PKCS#1).
    NotPem,
    /// Not an RSA key of 2048 to 8192 bits.
    Rejected,
}

/// The cryptographic library failed to sign.
#[derive(Debug, PartialEq, Eq)]
pub struct SigningFailed;

impl Signer {
    pub fn from_pem(
        pem: &str,
        domain: &str,
        selector: &str,
        headers: &[&str],
    ) -> Result<Self, KeyError> {
        let (label, der) = decode_pem(pem).ok_or(KeyError::NotPem)?;
        let key = match label {
            "PRIVATE KEY" => RsaKeyPair::from_pkcs8(&der),
            "RSA PRIVATE KEY" => RsaKeyPair::from_der(&der),
            _ => return Err(KeyError::NotPem),
        }
        .map_err(|_| KeyError::Rejected)?;
        Ok(Self {
            key,
            domain: domain.to_owned(),
            selector: selector.to_owned(),
            headers: headers
                .iter()
                .enumerate()
                .map(|(index, name)| {
                    let before = headers[..index]
                        .iter()
                        .filter(|earlier| earlier.eq_ignore_ascii_case(name))
                        .count();
                    (name.to_ascii_lowercase(), before)
                })
                .collect(),
        })
    }

    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// The public half of its key as its DNS record's `p=` publishes it: a
    /// SubjectPublicKeyInfo, in base64.
    pub fn public_key(&self) -> String {
        use aws_lc_rs::encoding::AsDer as _;
        use aws_lc_rs::signature::KeyPair as _;
        let der = self
            .key
            .public_key()
            .as_der()
            .expect("an RSA key's public half encodes");
        STANDARD.encode(der.as_ref())
    }

    /// The DKIM-Signature field, with its CRLF, to go before the header block
    /// of the message whose header block (every field with its CRLF) and body
    /// are given.
    pub fn sign(&self, header: &[u8], body: &[u8]) -> Result<Vec<u8>, SigningFailed> {
        // Each configured name signs the next instance of its field from
        // the bottom, as often as it is named (5.4.2). Named again with none
        // left, it is oversigned: in h= with nothing hashed, so an instance
        // added later breaks the signature. A name the message lacks
        // entirely is left out of h=.
        let fields = fields(header);
        let mut names = Vec::with_capacity(self.headers.len());
        let mut input = Vec::with_capacity(header.len() + 256);
        for (name, before) in &self.headers {
            let field = fields
                .iter()
                .rev()
                .filter(|field| name_of(field).eq_ignore_ascii_case(name.as_bytes()))
                .nth(*before);
            match field {
                Some(field) => {
                    relaxed_header(field, &mut input);
                    names.push(name.as_str());
                }
                None if *before > 0 => names.push(name.as_str()),
                None => {}
            }
        }
        let template = format!(
            "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d={}; s={};\r\n\th={};\r\n\tbh={};\r\n\tb=",
            self.domain,
            self.selector,
            names.join(":"),
            STANDARD.encode(body_hash(body)),
        );
        // The signature's own field ends the input, with b= empty and
        // without its final CRLF (3.7).
        relaxed_header(template.as_bytes(), &mut input);
        input.truncate(input.len() - 2);

        let mut signature = vec![0; self.key.public_modulus_len()];
        sign(&self.key, &input, &mut signature)?;
        let mut field = template.into_bytes();
        let encoded = STANDARD.encode(&signature);
        for (index, chunk) in encoded.as_bytes().chunks(72).enumerate() {
            if index > 0 {
                field.extend_from_slice(b"\r\n\t");
            }
            field.extend_from_slice(chunk);
        }
        field.extend_from_slice(b"\r\n");
        Ok(field)
    }
}

/// aws-lc-rs takes a generator for RSA signing and ignores it: PKCS#1 v1.5
/// signatures are deterministic, so nothing random reaches the output.
#[allow(clippy::disallowed_types)]
fn sign(key: &RsaKeyPair, input: &[u8], signature: &mut [u8]) -> Result<(), SigningFailed> {
    key.sign(
        &RSA_PKCS1_SHA256,
        &aws_lc_rs::rand::SystemRandom::new(),
        input,
        signature,
    )
    .map_err(|_| SigningFailed)
}

/// The header block's fields, each with its CRLF and folded lines.
pub(crate) fn fields(header: &[u8]) -> Vec<&[u8]> {
    let mut fields: Vec<&[u8]> = Vec::new();
    let mut rest = header;
    let mut start = header;
    let mut length = 0;
    while !rest.is_empty() {
        let line = rest
            .iter()
            .position(|&byte| byte == b'\n')
            .map_or(rest.len(), |at| at + 1);
        let folded = matches!(rest[0], b' ' | b'\t');
        if !folded && length > 0 {
            fields.push(&start[..length]);
            start = rest;
            length = 0;
        }
        length += line;
        rest = &rest[line..];
    }
    if length > 0 {
        fields.push(&start[..length]);
    }
    fields
}

/// The field's name, before its colon.
pub(crate) fn name_of(field: &[u8]) -> &[u8] {
    let colon = field
        .iter()
        .position(|&byte| byte == b':')
        .unwrap_or(field.len());
    field[..colon].trim_ascii_end()
}

/// Relaxed header canonicalization (3.4.2): the name in lowercase, then the
/// value unfolded, with runs of whitespace as one space and none at either
/// end.
fn relaxed_header(field: &[u8], out: &mut Vec<u8>) {
    let name = name_of(field);
    out.extend(name.iter().map(u8::to_ascii_lowercase));
    out.push(b':');
    let value = field
        .iter()
        .position(|&byte| byte == b':')
        .map_or(&[][..], |colon| &field[colon + 1..]);
    let mut space = false;
    let mut empty = true;
    for &byte in value {
        match byte {
            b'\r' | b'\n' => {}
            b' ' | b'\t' => space = true,
            _ => {
                if space && !empty {
                    out.push(b' ');
                }
                space = false;
                empty = false;
                out.push(byte);
            }
        }
    }
    out.extend_from_slice(b"\r\n");
}

/// The SHA-256 of the body in relaxed canonical form (3.4.4): runs of
/// whitespace as one space, none at the end of a line, every line ended by
/// CRLF, and no empty lines at the end.
fn body_hash(body: &[u8]) -> Digest {
    let mut hash = Context::new(&SHA256);
    let mut empty_lines = 0;
    let mut canonical = Vec::new();
    let mut rest = body;
    while !rest.is_empty() {
        let (line, next) = match rest.iter().position(|&byte| byte == b'\n') {
            Some(at) => (&rest[..at], &rest[at + 1..]),
            None => (rest, &[][..]),
        };
        rest = next;
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let line = if line.iter().any(|&byte| byte == b' ' || byte == b'\t') {
            canonical.clear();
            let mut space = false;
            for &byte in line {
                if byte == b' ' || byte == b'\t' {
                    space = true;
                } else {
                    if space {
                        canonical.push(b' ');
                    }
                    space = false;
                    canonical.push(byte);
                }
            }
            &canonical[..]
        } else {
            line
        };
        if line.is_empty() {
            empty_lines += 1;
            continue;
        }
        for _ in 0..empty_lines {
            hash.update(b"\r\n");
        }
        empty_lines = 0;
        hash.update(line);
        hash.update(b"\r\n");
    }
    hash.finish()
}

/// The label and contents of the first PEM block in `pem`.
fn decode_pem(pem: &str) -> Option<(&str, Vec<u8>)> {
    let rest = &pem[pem.find("-----BEGIN ")? + "-----BEGIN ".len()..];
    let label_end = rest.find("-----")?;
    let label = &rest[..label_end];
    let contents = &rest[label_end + "-----".len()..];
    let end = contents.find(&format!("-----END {label}-----"))?;
    let encoded: String = contents[..end]
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    STANDARD.decode(encoded).ok().map(|der| (label, der))
}

#[cfg(test)]
mod tests {
    use aws_lc_rs::encoding::AsDer;
    use aws_lc_rs::rsa::{KeyPair, KeySize};
    use aws_lc_rs::signature::{KeyPair as _, RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey};

    use super::*;

    fn pem(label: &str, der: &[u8]) -> String {
        let encoded = STANDARD.encode(der);
        let lines: Vec<&str> = encoded
            .as_bytes()
            .chunks(64)
            .map(|line| std::str::from_utf8(line).unwrap())
            .collect();
        format!(
            "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
            lines.join("\n")
        )
    }

    /// A fresh key, its signer, and its public key.
    fn signer(headers: &[&str]) -> (Signer, Vec<u8>) {
        let pair = KeyPair::generate(KeySize::Rsa2048).unwrap();
        let private = pem("PRIVATE KEY", pair.as_der().unwrap().as_ref());
        let public = pair.public_key().as_ref().to_vec();
        let signer = Signer::from_pem(&private, "bench.test", "s1", headers).unwrap();
        (signer, public)
    }

    #[test]
    fn the_body_hash_matches_rfc_8463() {
        let body = b"Hi.\r\n\r\nWe lost the game.  Are you hungry yet?\r\n\r\nJoe.\r\n\r\n";
        assert_eq!(
            STANDARD.encode(body_hash(body)),
            "2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8="
        );
    }

    /// The canonicalization example of RFC 6376, 3.4.5.
    #[test]
    fn canonicalization_matches_rfc_6376() {
        let mut header = Vec::new();
        for field in fields(b"A: X\r\nB : Y\t\r\n\tZ  \r\n") {
            relaxed_header(field, &mut header);
        }
        assert_eq!(header, b"a:X\r\nb:Y Z\r\n");

        let expected = aws_lc_rs::digest::digest(&SHA256, b" C\r\nD E\r\n");
        let hash = body_hash(b" C \r\nD \t E\r\n\r\n\r\n");
        assert_eq!(hash.as_ref(), expected.as_ref());
        let empty = aws_lc_rs::digest::digest(&SHA256, b"");
        assert_eq!(body_hash(b"\r\n\r\n").as_ref(), empty.as_ref());
        let unterminated = aws_lc_rs::digest::digest(&SHA256, b"end\r\n");
        assert_eq!(body_hash(b"end").as_ref(), unterminated.as_ref());
    }

    /// The signature covers the input RFC 6376 prescribes, written out here
    /// by hand rather than by the code under test.
    #[test]
    fn signatures_cover_the_canonical_header() {
        let (signer, public) = signer(&["From", "Subject", "Date"]);
        let header = b"Received: x\r\nFrom: Load <load@bench.test>\r\nSubject:  Hi \r\n there \r\nFrom: Late <late@bench.test>\r\n";
        let body = b"Body  text \r\n\r\n";
        let field = String::from_utf8(signer.sign(header, body).unwrap()).unwrap();

        let bh = STANDARD.encode(aws_lc_rs::digest::digest(&SHA256, b"Body text\r\n"));
        assert!(field.starts_with(&format!(
            "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=bench.test; s=s1;\r\n\th=from:subject;\r\n\tbh={bh};\r\n\tb="
        )));
        assert!(field.ends_with("\r\n") && field.lines().all(|line| line.len() <= 78));

        let b: String = field
            .split("b=")
            .last()
            .unwrap()
            .chars()
            .filter(|c| !c.is_ascii_whitespace())
            .collect();
        // The last From is the one signed; Date is absent, so unsigned.
        let input = format!(
            "from:Late <late@bench.test>\r\nsubject:Hi there\r\ndkim-signature:v=1; a=rsa-sha256; c=relaxed/relaxed; d=bench.test; s=s1; h=from:subject; bh={bh}; b="
        );
        UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, &public)
            .verify(input.as_bytes(), &STANDARD.decode(b).unwrap())
            .unwrap();
    }

    #[test]
    fn a_name_given_twice_signs_its_fields_from_the_bottom_and_oversigns_past_them() {
        // From twice for its two fields, the last first; Subject twice for
        // its one field, the second time oversigned; Cc, absent, left out.
        let (signer, public) = signer(&["From", "From", "Subject", "Subject", "Cc"]);
        let header =
            b"From: First <first@bench.test>\r\nSubject: Hi\r\nFrom: Last <last@bench.test>\r\n";
        let body = b"Body\r\n";
        let field = String::from_utf8(signer.sign(header, body).unwrap()).unwrap();
        let bh = STANDARD.encode(aws_lc_rs::digest::digest(&SHA256, b"Body\r\n"));
        assert!(field.contains("h=from:from:subject:subject;"), "{field}");
        let b: String = field
            .split("b=")
            .last()
            .unwrap()
            .chars()
            .filter(|c| !c.is_ascii_whitespace())
            .collect();
        // As a verifier takes them: each instance once, from the bottom.
        let input = format!(
            "from:Last <last@bench.test>\r\nfrom:First <first@bench.test>\r\nsubject:Hi\r\ndkim-signature:v=1; a=rsa-sha256; c=relaxed/relaxed; d=bench.test; s=s1; h=from:from:subject:subject; bh={bh}; b="
        );
        UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, &public)
            .verify(input.as_bytes(), &STANDARD.decode(b).unwrap())
            .unwrap();
    }

    #[test]
    fn keys_must_be_rsa_pem_of_2048_bits_or_more() {
        assert_eq!(
            Signer::from_pem("not a key", "d", "s", &[]).err(),
            Some(KeyError::NotPem)
        );
        let unknown = pem("CERTIFICATE", b"x");
        assert_eq!(
            Signer::from_pem(&unknown, "d", "s", &[]).err(),
            Some(KeyError::NotPem)
        );
        let garbage = pem("PRIVATE KEY", b"not der");
        assert_eq!(
            Signer::from_pem(&garbage, "d", "s", &[]).err(),
            Some(KeyError::Rejected)
        );
    }
}
