//! DKIM verification (RFC 6376), written for the sink independently of every
//! signer it judges: the engine signs through mail-auth, KumoMTA through its
//! own crate and Postfix through OpenDKIM. A verifier shared with a signer
//! could agree with that signer's mistakes.
//!
//! It verifies what the harness configures every system to produce:
//! `rsa-sha256` signatures by one domain and selector, checked against the key
//! the harness generated, in either canonicalization. A signature in any other
//! form is a failure, never a pass.

use std::collections::BTreeMap;

use aws_lc_rs::digest;
use aws_lc_rs::signature::{self, RsaParameters, UnparsedPublicKey};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

pub struct Verifier {
    key: UnparsedPublicKey<Vec<u8>>,
    domain: String,
    selector: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Failure {
    /// No signature by the expected domain and selector.
    Missing,
    /// A signature the verifier cannot read.
    Malformed(&'static str),
    /// A signature in a form the harness never configures.
    Unsupported(&'static str),
    BodyHash,
    Signature,
}

impl Verifier {
    /// `key` is the public key as DKIM publishes it: the decoded `p=` value,
    /// a DER SubjectPublicKeyInfo. Keys shorter than 2048 bits fail.
    pub fn new(key: Vec<u8>, domain: &str, selector: &str) -> Self {
        Self::with_algorithm(
            &signature::RSA_PKCS1_2048_8192_SHA256,
            key,
            domain,
            selector,
        )
    }

    fn with_algorithm(
        algorithm: &'static RsaParameters,
        key: Vec<u8>,
        domain: &str,
        selector: &str,
    ) -> Self {
        Self {
            key: UnparsedPublicKey::new(algorithm, key),
            domain: domain.to_owned(),
            selector: selector.to_owned(),
        }
    }

    /// Verifies a message given as its header fields (see [`fields`]) and
    /// its body. One valid signature by the expected signer is enough.
    pub fn verify(&self, fields: &[&[u8]], body: &[u8]) -> Result<(), Failure> {
        let mut outcome = Err(Failure::Missing);
        for (index, field) in fields.iter().enumerate() {
            if !named(field, "dkim-signature") {
                continue;
            }
            let tags = match tag_list(value(field)) {
                Ok(tags) => tags,
                Err(failure) => {
                    if outcome == Err(Failure::Missing) {
                        outcome = Err(failure);
                    }
                    continue;
                }
            };
            // Another signer's signature is no concern of the sink's, in
            // whatever form it takes.
            let is = |name: &str, expected: &str| {
                tags.get(name)
                    .is_some_and(|value| value.eq_ignore_ascii_case(expected))
            };
            if !is("d", &self.domain) || !is("s", &self.selector) {
                continue;
            }
            outcome = Signature::from_tags(&tags)
                .and_then(|signature| self.check(&signature, fields, index, body));
            if outcome.is_ok() {
                return outcome;
            }
        }
        outcome
    }

    fn check(
        &self,
        signature: &Signature,
        fields: &[&[u8]],
        index: usize,
        body: &[u8],
    ) -> Result<(), Failure> {
        let mut hash = digest::Context::new(&digest::SHA256);
        canonical_body(body, signature.body, |bytes| hash.update(bytes));
        if hash.finish().as_ref() != signature.body_hash.as_slice() {
            return Err(Failure::BodyHash);
        }

        // Each name in h= takes the last instance of that field not already
        // taken; a name with no instance left contributes nothing (5.4.2).
        let mut taken = vec![false; fields.len()];
        taken[index] = true;
        let mut input = Vec::with_capacity(1024);
        for name in &signature.headers {
            if let Some(chosen) = (0..fields.len())
                .rev()
                .find(|&at| !taken[at] && named(fields[at], name))
            {
                taken[chosen] = true;
                canonical_header(fields[chosen], signature.header, &mut input);
            }
        }
        // The signature's own field ends the input, with its b= value
        // removed and without its final CRLF (3.7).
        canonical_header(&without_b(fields[index]), signature.header, &mut input);
        if input.ends_with(b"\r\n") {
            input.truncate(input.len() - 2);
        }
        self.key
            .verify(&input, &signature.signature)
            .map_err(|_| Failure::Signature)
    }
}

/// Splits a header block into its fields, each with its terminating CRLF and
/// any folded continuation lines.
pub fn fields(header: &[u8]) -> Vec<&[u8]> {
    let mut fields = Vec::new();
    let mut start = 0;
    let mut at = 0;
    while at < header.len() {
        if at > start && !matches!(header[at], b' ' | b'\t') {
            fields.push(&header[start..at]);
            start = at;
        }
        at = header[at..]
            .iter()
            .position(|&byte| byte == b'\n')
            .map_or(header.len(), |end| at + end + 1);
    }
    if start < header.len() {
        fields.push(&header[start..]);
    }
    fields
}

/// Whether the field's name is `name`, ignoring case.
pub fn named(field: &[u8], name: &str) -> bool {
    let colon = field
        .iter()
        .position(|&byte| byte == b':')
        .unwrap_or(field.len());
    field[..colon]
        .trim_ascii()
        .eq_ignore_ascii_case(name.as_bytes())
}

/// The field's value: everything after its colon, CRLF included.
pub fn value(field: &[u8]) -> &[u8] {
    field
        .iter()
        .position(|&byte| byte == b':')
        .map_or(&[][..], |colon| &field[colon + 1..])
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Canonicalization {
    Simple,
    Relaxed,
}

struct Signature {
    header: Canonicalization,
    body: Canonicalization,
    /// Lowercase field names, in signing order.
    headers: Vec<String>,
    body_hash: Vec<u8>,
    signature: Vec<u8>,
}

/// Parses a DKIM-Signature tag list (3.2). Whitespace is removed from every
/// value, which none of the tags the verifier reads may contain.
fn tag_list(list: &[u8]) -> Result<BTreeMap<String, String>, Failure> {
    let mut tags = BTreeMap::new();
    for tag in list.split(|&byte| byte == b';') {
        let tag = tag.trim_ascii();
        if tag.is_empty() {
            continue;
        }
        let equals = tag
            .iter()
            .position(|&byte| byte == b'=')
            .ok_or(Failure::Malformed("a tag without a value"))?;
        let name = String::from_utf8_lossy(tag[..equals].trim_ascii()).into_owned();
        let value: String = String::from_utf8_lossy(&tag[equals + 1..])
            .chars()
            .filter(|c| !c.is_ascii_whitespace())
            .collect();
        if tags.insert(name, value).is_some() {
            return Err(Failure::Malformed("a repeated tag"));
        }
    }
    Ok(tags)
}

impl Signature {
    fn from_tags(tags: &BTreeMap<String, String>) -> Result<Self, Failure> {
        let tag = |name: &str| {
            tags.get(name)
                .map(String::as_str)
                .ok_or(Failure::Malformed("a required tag is missing"))
        };
        if tag("v")? != "1" {
            return Err(Failure::Malformed("v= is not 1"));
        }
        if !tag("a")?.eq_ignore_ascii_case("rsa-sha256") {
            return Err(Failure::Unsupported("an algorithm other than rsa-sha256"));
        }
        if tags.contains_key("l") {
            return Err(Failure::Unsupported("a body length limit"));
        }
        let (header, body) = match tags.get("c").map(|c| c.to_ascii_lowercase()).as_deref() {
            None | Some("simple" | "simple/simple") => {
                (Canonicalization::Simple, Canonicalization::Simple)
            }
            Some("simple/relaxed") => (Canonicalization::Simple, Canonicalization::Relaxed),
            Some("relaxed") | Some("relaxed/simple") => {
                (Canonicalization::Relaxed, Canonicalization::Simple)
            }
            Some("relaxed/relaxed") => (Canonicalization::Relaxed, Canonicalization::Relaxed),
            Some(_) => return Err(Failure::Malformed("an unknown canonicalization")),
        };
        let headers: Vec<String> = tag("h")?.split(':').map(str::to_ascii_lowercase).collect();
        if !headers.iter().any(|name| name == "from") {
            return Err(Failure::Malformed("h= does not sign From"));
        }
        let decode = |name: &str| {
            STANDARD
                .decode(tag(name)?)
                .map_err(|_| Failure::Malformed("a hash or signature is not base64"))
        };
        Ok(Self {
            header,
            body,
            headers,
            body_hash: decode("bh")?,
            signature: decode("b")?,
        })
    }
}

fn canonical_header(field: &[u8], canonicalization: Canonicalization, out: &mut Vec<u8>) {
    if canonicalization == Canonicalization::Simple {
        out.extend_from_slice(field);
        return;
    }
    // Relaxed (3.4.2): lowercase the name, unfold, reduce whitespace to
    // single spaces, and trim it around the colon and at the end.
    let colon = field
        .iter()
        .position(|&byte| byte == b':')
        .unwrap_or(field.len());
    out.extend(
        field[..colon]
            .trim_ascii()
            .iter()
            .map(u8::to_ascii_lowercase),
    );
    out.push(b':');
    let mut space = false;
    let mut started = false;
    for &byte in value(field) {
        match byte {
            b'\r' | b'\n' => {}
            b' ' | b'\t' => space = started,
            _ => {
                if space {
                    out.push(b' ');
                    space = false;
                }
                out.push(byte);
                started = true;
            }
        }
    }
    out.extend_from_slice(b"\r\n");
}

/// Feeds the canonical form of `body` to `sink` (3.4.3 and 3.4.4). Trailing
/// empty lines are dropped; every line kept ends with CRLF.
fn canonical_body(body: &[u8], canonicalization: Canonicalization, mut sink: impl FnMut(&[u8])) {
    let body = body.strip_suffix(b"\n").unwrap_or(body);
    let mut empty = 0;
    let mut wrote = false;
    let mut relaxed = Vec::new();
    for line in body.split(|&byte| byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let line = if canonicalization == Canonicalization::Relaxed
            && line.iter().any(|&byte| byte == b' ' || byte == b'\t')
        {
            relaxed.clear();
            let mut space = false;
            for &byte in line {
                if byte == b' ' || byte == b'\t' {
                    space = true;
                } else {
                    if space {
                        relaxed.push(b' ');
                        space = false;
                    }
                    relaxed.push(byte);
                }
            }
            &relaxed[..]
        } else {
            line
        };
        if line.is_empty() {
            empty += 1;
            continue;
        }
        for _ in 0..empty {
            sink(b"\r\n");
        }
        empty = 0;
        sink(line);
        sink(b"\r\n");
        wrote = true;
    }
    // The simple form of an empty body is one CRLF; the relaxed form is
    // empty.
    if !wrote && canonicalization == Canonicalization::Simple {
        sink(b"\r\n");
    }
}

/// The signature's own field with the value of its `b=` tag deleted,
/// surrounding whitespace included (3.7).
fn without_b(field: &[u8]) -> Vec<u8> {
    let end =
        field.len() - usize::from(field.ends_with(b"\n")) - usize::from(field.ends_with(b"\r\n"));
    let mut start = field
        .iter()
        .position(|&byte| byte == b':')
        .map_or(field.len(), |colon| colon + 1);
    while start < end {
        let stop = field[start..end]
            .iter()
            .position(|&byte| byte == b';')
            .map_or(end, |at| start + at);
        let tag = &field[start..stop];
        if let Some(equals) = tag.iter().position(|&byte| byte == b'=')
            && tag[..equals].trim_ascii() == b"b"
        {
            let mut out = field[..start + equals + 1].to_vec();
            out.extend_from_slice(&field[stop..]);
            return out;
        }
        start = stop + 1;
    }
    field.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The signed message of RFC 8463, Appendix A.3. It carries an Ed25519
    /// signature (selector `brisbane`) and an RSA one (selector `test`), both
    /// over-signing From, Subject and Date.
    const RFC_8463: &str = "DKIM-Signature: v=1; a=ed25519-sha256; c=relaxed/relaxed;\r
 d=football.example.com; i=@football.example.com;\r
 q=dns/txt; s=brisbane; t=1528637909; h=from : to :\r
 subject : date : message-id : from : subject : date;\r
 bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;\r
 b=/gCrinpcQOoIfuHNQIbq4pgh9kyIK3AQUdt9OdqQehSwhEIug4D11Bus\r
 Fa3bT3FY5OsU7ZbnKELq+eXdp1Q1Dw==\r
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;\r
 d=football.example.com; i=@football.example.com;\r
 q=dns/txt; s=test; t=1528637909; h=from : to : subject :\r
 date : message-id : from : subject : date;\r
 bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;\r
 b=F45dVWDfMbQDGHJFlXUNB2HKfbCeLRyhDXgFpEL8GwpsRe0IeIixNTe3\r
 DhCVlUrSjV4BwcVcOF6+FF3Zo9Rpo1tFOeS9mPYQTnGdaSGsgeefOsk2Jz\r
 dA+L10TeYt9BgDfQNZtKdN1WO//KgIqXP7OdEFE4LjFYNcUxZQ4FADY+8=\r
From: Joe SixPack <joe@football.example.com>\r
To: Suzie Q <suzie@shopping.example.net>\r
Subject: Is dinner ready?\r
Date: Fri, 11 Jul 2003 21:00:37 -0700 (PDT)\r
Message-ID: <20030712040037.46341.5F8J@football.example.com>\r
\r
Hi.\r
\r
We lost the game.  Are you hungry yet?\r
\r
Joe.\r
\r
";

    /// The `p=` value of `test._domainkey.football.example.com` (A.2), a
    /// 1024-bit key.
    const RFC_8463_KEY: &str = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDkHlOQoBTzWRiGs5V6NpP3idY6Wk08a5qhdR6wy5bdOKb2jLQiY/J16JYi0Qvx/byYzCNb3W91y3FutACDfzwQ/BC/e/8uBsCR+yz1Lxj+PL6lHvqMKrM3rG4hstT5QjvHO9PzoxZyVYLzBfO2EeC3Ip3G+2kryOTIKT+l/K4w3QIDAQAB";

    fn verifier(selector: &str) -> Verifier {
        Verifier::with_algorithm(
            &signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
            STANDARD.decode(RFC_8463_KEY).unwrap(),
            "football.example.com",
            selector,
        )
    }

    fn verify(verifier: &Verifier, message: &str) -> Result<(), Failure> {
        let split = message.find("\r\n\r\n").unwrap();
        let (header, body) = (
            &message.as_bytes()[..split + 2],
            &message.as_bytes()[split + 4..],
        );
        verifier.verify(&fields(header), body)
    }

    #[test]
    fn the_rfc_8463_rsa_signature_verifies() {
        assert_eq!(verify(&verifier("test"), RFC_8463), Ok(()));
    }

    #[test]
    fn changes_to_signed_content_fail_and_unsigned_ones_do_not() {
        let verifier = verifier("test");
        let body = RFC_8463.replace("hungry", "thirsty");
        assert_eq!(verify(&verifier, &body), Err(Failure::BodyHash));
        let subject = RFC_8463.replace("dinner ready", "lunch ready");
        assert_eq!(verify(&verifier, &subject), Err(Failure::Signature));
        // A second Subject is taken by the over-signed name, which the
        // signer saw as absent.
        let added = RFC_8463.replace("Subject: Is", "Subject: Extra\r\nSubject: Is");
        assert_eq!(verify(&verifier, &added), Err(Failure::Signature));
        let unsigned = RFC_8463.replace("From: Joe", "X-Extra: yes\r\nFrom: Joe");
        assert_eq!(verify(&verifier, &unsigned), Ok(()));
        // Relaxed canonicalization ignores changes to whitespace.
        let spaced = RFC_8463.replace("game.  Are", "game. \t Are");
        assert_eq!(verify(&verifier, &spaced), Ok(()));
    }

    #[test]
    fn only_the_expected_signer_counts() {
        assert_eq!(
            verify(&verifier("brisbane"), RFC_8463),
            Err(Failure::Unsupported("an algorithm other than rsa-sha256"))
        );
        assert_eq!(verify(&verifier("other"), RFC_8463), Err(Failure::Missing));
        // The production verifier refuses the RFC's 1024-bit key.
        let strict = Verifier::new(
            STANDARD.decode(RFC_8463_KEY).unwrap(),
            "football.example.com",
            "test",
        );
        assert_eq!(verify(&strict, RFC_8463), Err(Failure::Signature));
    }

    /// The canonicalization example of RFC 6376, 3.4.5.
    #[test]
    fn canonicalization_matches_rfc_6376() {
        let header = b"A: X\r\nB : Y\t\r\n\tZ  \r\n";
        let mut relaxed = Vec::new();
        for field in fields(header) {
            canonical_header(field, Canonicalization::Relaxed, &mut relaxed);
        }
        assert_eq!(relaxed, b"a:X\r\nb:Y Z\r\n");

        let body = b" C \r\nD \t E\r\n\r\n\r\n";
        let collect = |canonicalization| {
            let mut out = Vec::new();
            canonical_body(body, canonicalization, |bytes| out.extend_from_slice(bytes));
            out
        };
        assert_eq!(collect(Canonicalization::Relaxed), b" C\r\nD E\r\n");
        assert_eq!(collect(Canonicalization::Simple), b" C \r\nD \t E\r\n");

        let empty = |canonicalization, body: &[u8]| {
            let mut out = Vec::new();
            canonical_body(body, canonicalization, |bytes| out.extend_from_slice(bytes));
            out
        };
        assert_eq!(empty(Canonicalization::Simple, b""), b"\r\n");
        assert_eq!(empty(Canonicalization::Simple, b"\r\n\r\n"), b"\r\n");
        assert_eq!(empty(Canonicalization::Relaxed, b"\r\n"), b"");
        assert_eq!(
            empty(Canonicalization::Relaxed, b"no newline"),
            b"no newline\r\n"
        );
    }

    #[test]
    fn the_signature_value_is_removed_wherever_it_sits() {
        assert_eq!(
            without_b(b"DKIM-Signature: a=x; b=abc\r\n def; bh=q\r\n"),
            b"DKIM-Signature: a=x; b=; bh=q\r\n"
        );
        assert_eq!(
            without_b(b"DKIM-Signature: a=x; bh=q; b = abc \r\n"),
            b"DKIM-Signature: a=x; bh=q; b =\r\n"
        );
        assert_eq!(
            without_b(b"DKIM-Signature: bh=q\r\n"),
            b"DKIM-Signature: bh=q\r\n"
        );
    }
}
