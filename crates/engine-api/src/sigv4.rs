//! SigV4 verification, against the original request bytes: the
//! canonical request is rebuilt from the method, path, query, headers and
//! body exactly as they arrived, never from a reserialised request.
//!
//! It verifies what SES's clients send: header signatures, `AWS4-HMAC-SHA256`,
//! with the path normalised and double-encoded as for every service but S3.
//! The engine issues long-term keys only, so a request with a session token
//! is refused.

use std::time::Duration;

use aws_lc_rs::constant_time::verify_slices_are_equal;
use aws_lc_rs::digest::{SHA256, digest};
use aws_lc_rs::hmac;
use engine_core::time::Timestamp;

/// How far a request's time may be from the engine's, as AWS allows.
const SKEW: Duration = Duration::from_secs(15 * 60);

/// A request as it arrived.
pub struct Request<'a> {
    pub method: &'a str,
    /// The path as sent, percent-encoded.
    pub path: &'a str,
    /// The query as sent, without its `?`.
    pub query: &'a str,
    /// Every header, by name in any case; a repeated header appears once
    /// per value.
    pub headers: &'a [(&'a str, &'a [u8])],
    pub body: &'a [u8],
}

/// Where the engine serves, which a signature's scope must name.
pub struct Scope<'a> {
    pub region: &'a str,
    pub service: &'a str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Failure {
    /// No Authorization header.
    Missing,
    Malformed(&'static str),
    /// The access key is not one the engine issued.
    UnknownKey,
    /// The request's time is too far from the engine's.
    Skewed,
    /// The scope names another date, region or service.
    WrongScope,
    /// The signature does not match.
    Signature,
}

impl Failure {
    /// The HTTP status AWS answers with.
    pub fn status(&self) -> u16 {
        match self {
            Failure::Malformed(_) => 400,
            _ => 403,
        }
    }

    /// The error code AWS answers with, which SDKs act on: a clock-skew
    /// code makes them correct their clock from the response's Date and
    /// sign again.
    pub fn code(&self) -> &'static str {
        match self {
            Failure::Missing => "MissingAuthenticationTokenException",
            Failure::Malformed(_) => "IncompleteSignatureException",
            Failure::UnknownKey => "UnrecognizedClientException",
            Failure::Skewed | Failure::WrongScope | Failure::Signature => {
                "InvalidSignatureException"
            }
        }
    }

    pub fn message(&self) -> &'static str {
        match self {
            Failure::Missing => "Missing Authentication Token",
            Failure::Malformed(problem) => problem,
            Failure::UnknownKey => "The security token included in the request is invalid.",
            Failure::Skewed => {
                "Signature expired: the request's time is more than 15 minutes from the server's."
            }
            Failure::WrongScope => {
                "Credential should be scoped to today's date, and to this endpoint's region and service."
            }
            Failure::Signature => {
                "The request signature we calculated does not match the signature you provided. Check your AWS Secret Access Key and signing method."
            }
        }
    }
}

/// Verifies the request's signature, and returns the access key ID it was
/// signed with. `secret` looks up an access key's secret.
pub fn verify<'s>(
    request: &Request<'_>,
    scope: &Scope<'_>,
    now: Timestamp,
    secret: impl FnOnce(&str) -> Option<&'s str>,
) -> Result<String, Failure> {
    let header = |name: &str| {
        let mut values = request
            .headers
            .iter()
            .filter(|(header, _)| header.eq_ignore_ascii_case(name))
            .map(|(_, value)| *value);
        values.next()
    };
    let authorization = header("authorization").ok_or(Failure::Missing)?;
    let authorization = std::str::from_utf8(authorization)
        .map_err(|_| Failure::Malformed("Authorization is not text"))?;
    let parsed = Authorization::parse(authorization)?;
    if header("x-amz-security-token").is_some() {
        return Err(Failure::UnknownKey);
    }
    let date = header("x-amz-date").ok_or(Failure::Malformed("no X-Amz-Date"))?;
    let date =
        std::str::from_utf8(date).map_err(|_| Failure::Malformed("X-Amz-Date is not text"))?;
    let at = parse_time(date).ok_or(Failure::Malformed(
        "X-Amz-Date is not a basic ISO 8601 time",
    ))?;
    let gap = if at > now {
        at.saturating_duration_since(now)
    } else {
        now.saturating_duration_since(at)
    };
    if gap > SKEW {
        return Err(Failure::Skewed);
    }
    if parsed.date != &date[..8] || parsed.region != scope.region || parsed.service != scope.service
    {
        return Err(Failure::WrongScope);
    }
    if !parsed.signed.contains(&"host") {
        return Err(Failure::Malformed("Host is not signed"));
    }
    let secret = secret(parsed.key).ok_or(Failure::UnknownKey)?;

    let canonical = canonical_request(request, &parsed.signed)?;
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{date}\n{}/{}/{}/aws4_request\n{}",
        parsed.date,
        parsed.region,
        parsed.service,
        hex(digest(&SHA256, canonical.as_bytes()).as_ref())
    );
    let mut key = hmac::sign(
        &hmac::Key::new(hmac::HMAC_SHA256, format!("AWS4{secret}").as_bytes()),
        parsed.date.as_bytes(),
    );
    for part in [parsed.region, parsed.service, "aws4_request"] {
        key = hmac::sign(
            &hmac::Key::new(hmac::HMAC_SHA256, key.as_ref()),
            part.as_bytes(),
        );
    }
    let expected = hmac::sign(
        &hmac::Key::new(hmac::HMAC_SHA256, key.as_ref()),
        string_to_sign.as_bytes(),
    );
    verify_slices_are_equal(
        hex(expected.as_ref()).as_bytes(),
        parsed.signature.as_bytes(),
    )
    .map_err(|_| Failure::Signature)?;
    Ok(parsed.key.to_owned())
}

/// `AWS4-HMAC-SHA256 Credential=<key>/<date>/<region>/<service>/aws4_request,
/// SignedHeaders=<names>, Signature=<hex>`.
struct Authorization<'a> {
    key: &'a str,
    date: &'a str,
    region: &'a str,
    service: &'a str,
    signed: Vec<&'a str>,
    signature: &'a str,
}

impl<'a> Authorization<'a> {
    fn parse(text: &'a str) -> Result<Self, Failure> {
        let rest = text
            .strip_prefix("AWS4-HMAC-SHA256 ")
            .ok_or(Failure::Malformed("not AWS4-HMAC-SHA256"))?;
        let (mut credential, mut signed, mut signature) = (None, None, None);
        for part in rest.split(',') {
            let (name, value) = part
                .trim()
                .split_once('=')
                .ok_or(Failure::Malformed("a part without a value"))?;
            match name {
                "Credential" => credential = Some(value),
                "SignedHeaders" => signed = Some(value),
                "Signature" => signature = Some(value),
                _ => return Err(Failure::Malformed("an unknown part")),
            }
        }
        let (Some(credential), Some(signed), Some(signature)) = (credential, signed, signature)
        else {
            return Err(Failure::Malformed("a missing part"));
        };
        let parts: Vec<&str> = credential.split('/').collect();
        let [key, date, region, service, "aws4_request"] = parts[..] else {
            return Err(Failure::Malformed(
                "a credential that is not key/date/region/service/aws4_request",
            ));
        };
        let signed: Vec<&str> = signed.split(';').collect();
        let sorted = signed.windows(2).all(|pair| pair[0] < pair[1]);
        if !sorted
            || signed
                .iter()
                .any(|name| name.is_empty() || name.bytes().any(|byte| byte.is_ascii_uppercase()))
        {
            return Err(Failure::Malformed(
                "SignedHeaders is not sorted lowercase names",
            ));
        }
        if date.len() != 8 || signature.len() != 64 {
            return Err(Failure::Malformed("a malformed date or signature"));
        }
        Ok(Self {
            key,
            date,
            region,
            service,
            signed,
            signature,
        })
    }
}

/// The canonical request (AWS's SigV4 documentation, task 1) for the
/// headers named in `signed`.
fn canonical_request(request: &Request<'_>, signed: &[&str]) -> Result<String, Failure> {
    let mut canonical = String::with_capacity(512);
    canonical.push_str(request.method);
    canonical.push('\n');
    canonical.push_str(&encode(&normalize(request.path), false));
    canonical.push('\n');
    canonical.push_str(&canonical_query(request.query));
    canonical.push('\n');
    for name in signed {
        let values: Vec<String> = request
            .headers
            .iter()
            .filter(|(header, _)| header.eq_ignore_ascii_case(name))
            .map(|(_, value)| {
                let value = String::from_utf8_lossy(value);
                value.split_whitespace().collect::<Vec<_>>().join(" ")
            })
            .collect();
        if values.is_empty() {
            return Err(Failure::Malformed("a signed header is missing"));
        }
        canonical.push_str(name);
        canonical.push(':');
        canonical.push_str(&values.join(","));
        canonical.push('\n');
    }
    canonical.push('\n');
    canonical.push_str(&signed.join(";"));
    canonical.push('\n');
    let payload = hex(digest(&SHA256, request.body).as_ref());
    // A signed payload hash must be the body's.
    if let Some((_, claimed)) = request
        .headers
        .iter()
        .find(|(header, _)| header.eq_ignore_ascii_case("x-amz-content-sha256"))
        && *claimed != payload.as_bytes()
    {
        return Err(Failure::Signature);
    }
    canonical.push_str(&payload);
    Ok(canonical)
}

/// Removes dot segments and empty segments (RFC 3986, 5.2.4), keeping a
/// trailing slash, as every service but S3 does.
fn normalize(path: &str) -> String {
    let mut segments: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            segment => segments.push(segment),
        }
    }
    let mut normalized = format!("/{}", segments.join("/"));
    if path.ends_with('/') && normalized.len() > 1 {
        normalized.push('/');
    }
    normalized
}

/// Percent-encodes everything but unreserved characters (RFC 3986, 2.3),
/// and `/` unless `slash` is set. A path is encoded as sent, so its escapes
/// are encoded again: the double encoding of every service but S3.
fn encode(text: &str, slash: bool) -> String {
    let mut out = String::with_capacity(text.len());
    for &byte in text.as_bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) || byte == b'/' && !slash {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// The query's parameters decoded, encoded canonically, and sorted.
fn canonical_query(query: &str) -> String {
    let mut parameters: Vec<(String, String)> = query
        .split('&')
        .filter(|parameter| !parameter.is_empty())
        .map(|parameter| {
            let (name, value) = parameter.split_once('=').unwrap_or((parameter, ""));
            (encode(&decode(name), true), encode(&decode(value), true))
        })
        .collect();
    parameters.sort();
    parameters
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// Percent-decoding, leaving a malformed escape as it is.
pub(crate) fn decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        let escaped = (bytes[at] == b'%')
            .then(|| bytes.get(at + 1..at + 3))
            .flatten()
            .and_then(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok());
        match escaped {
            Some(byte) => {
                out.push(byte);
                at += 3;
            }
            None => {
                out.push(bytes[at]);
                at += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `20150830T123600Z`.
fn parse_time(text: &str) -> Option<Timestamp> {
    let digits = |range: std::ops::Range<usize>| text.get(range)?.parse::<u64>().ok();
    // ASCII alone, so every byte is a character and slicing never splits one.
    if text.len() != 16 || !text.is_ascii() || &text[8..9] != "T" || &text[15..] != "Z" {
        return None;
    }
    let (year, month, day) = (digits(0..4)?, digits(4..6)?, digits(6..8)?);
    let (hour, minute, second) = (digits(9..11)?, digits(11..13)?, digits(13..15)?);
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    // Howard Hinnant's days_from_civil.
    let year = if month <= 2 {
        year.checked_sub(1)?
    } else {
        year
    };
    let era = year / 400;
    let yoe = year - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = (era * 146_097 + doe).checked_sub(719_468)?;
    let seconds = days * 86_400 + hour * 3600 + minute * 60 + second;
    Some(Timestamp::from_micros(seconds.checked_mul(1_000_000)?))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A request in the suite's text form: request line, headers, a blank
    /// line, and the body.
    struct Parsed {
        method: String,
        path: String,
        query: String,
        headers: Vec<(String, Vec<u8>)>,
        body: Vec<u8>,
    }

    fn parse(text: &str) -> Parsed {
        let (head, body) = text.split_once("\n\n").unwrap_or((text, ""));
        let mut lines = head.lines();
        let mut request_line = lines.next().unwrap().splitn(3, ' ');
        let (method, target) = (request_line.next().unwrap(), request_line.next().unwrap());
        let (path, query) = target.split_once('?').unwrap_or((target, ""));
        let mut headers: Vec<(String, Vec<u8>)> = Vec::new();
        for line in lines {
            if line.starts_with([' ', '\t']) {
                // A folded continuation of the previous header.
                let last = headers.last_mut().unwrap();
                last.1.extend_from_slice(b" ");
                last.1.extend_from_slice(line.trim().as_bytes());
                continue;
            }
            let (name, value) = line.split_once(':').unwrap();
            // A server hands on a value without the optional whitespace
            // after the colon.
            headers.push((name.to_owned(), value.trim_start().as_bytes().to_vec()));
        }
        Parsed {
            method: method.to_owned(),
            path: path.to_owned(),
            query: query.to_owned(),
            headers,
            body: body.as_bytes().to_vec(),
        }
    }

    /// One case of AWS's suite, embedded when the tests are built.
    struct Case {
        name: &'static str,
        /// Empty for the two older cases, which have none.
        context: &'static str,
        signed: &'static str,
        canonical: &'static str,
    }

    macro_rules! case {
        (@file $name:literal, $file:literal) => {
            include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures/aws-signing-test-suite/v4/", $name, "/", $file))
        };
        ($name:literal) => {
            Case {
                name: $name,
                context: case!(@file $name, "context.json"),
                signed: case!(@file $name, "header-signed-request.txt"),
                canonical: case!(@file $name, "header-canonical-request.txt"),
            }
        };
        (legacy $name:literal) => {
            Case {
                name: $name,
                context: "",
                signed: case!(@file $name, "header-signed-request.txt"),
                canonical: case!(@file $name, "header-canonical-request.txt"),
            }
        };
    }

    const CASES: [Case; 40] = [
        case!(legacy "double-encode-path"),
        case!(legacy "double-url-encode"),
        case!("get-header-key-duplicate"),
        case!("get-header-value-multiline"),
        case!("get-header-value-order"),
        case!("get-header-value-trim"),
        case!("get-relative-normalized"),
        case!("get-relative-relative-normalized"),
        case!("get-relative-relative-unnormalized"),
        case!("get-relative-unnormalized"),
        case!("get-slash-dot-slash-normalized"),
        case!("get-slash-dot-slash-unnormalized"),
        case!("get-slash-normalized"),
        case!("get-slash-pointless-dot-normalized"),
        case!("get-slash-pointless-dot-unnormalized"),
        case!("get-slash-unnormalized"),
        case!("get-slashes-normalized"),
        case!("get-slashes-unnormalized"),
        case!("get-space-normalized"),
        case!("get-space-unnormalized"),
        case!("get-unreserved"),
        case!("get-utf8"),
        case!("get-vanilla"),
        case!("get-vanilla-empty-query-key"),
        case!("get-vanilla-query"),
        case!("get-vanilla-query-order-encoded"),
        case!("get-vanilla-query-order-key-case"),
        case!("get-vanilla-query-unreserved"),
        case!("get-vanilla-utf8-query"),
        case!("get-vanilla-with-session-token"),
        case!("post-header-key-case"),
        case!("post-header-key-sort"),
        case!("post-header-value-case"),
        case!("post-sts-header-after"),
        case!("post-sts-header-before"),
        case!("post-vanilla"),
        case!("post-vanilla-empty-query-value"),
        case!("post-vanilla-query"),
        case!("post-x-www-form-urlencoded"),
        case!("post-x-www-form-urlencoded-parameters"),
    ];

    fn json_field<'a>(json: &'a str, name: &str) -> Option<&'a str> {
        let start = json.find(&format!("\"{name}\""))? + name.len() + 2;
        let rest = json[start..].trim_start().strip_prefix(':')?.trim_start();
        Some(rest.strip_prefix('"').map_or_else(
            || rest.split([',', '\n', '}']).next().unwrap_or("").trim(),
            |quoted| &quoted[..quoted.find('"').unwrap_or(0)],
        ))
    }

    /// Cases that model something SES's signing never does. The first three
    /// assume single path encoding, or a path with raw characters an HTTP
    /// server never passes on, as smithy-rs also skips them; the
    /// `unnormalized` cases model S3; and the session-token cases use
    /// temporary credentials, which the engine never issues.
    fn skipped(case: &str, context: &str) -> Option<&'static str> {
        if ["get-space-normalized", "get-space-unnormalized", "get-utf8"].contains(&case) {
            return Some("single encoding or a raw path");
        }
        if json_field(context, "normalize") == Some("false") {
            return Some("S3's unnormalized paths");
        }
        if context.contains("\"token\"") {
            return Some("temporary credentials");
        }
        None
    }

    #[test]
    fn every_applicable_case_of_the_aws_suite_verifies() {
        let mut verified = 0;
        for &Case {
            name: case,
            context,
            signed,
            canonical: expected,
        } in &CASES
        {
            if skipped(case, context).is_some() {
                continue;
            }
            let signed = parse(signed);
            let headers: Vec<(&str, &[u8])> = signed
                .headers
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_slice()))
                .collect();
            let request = Request {
                method: &signed.method,
                path: &signed.path,
                query: &signed.query,
                headers: &headers,
                body: &signed.body,
            };
            let authorization = Authorization::parse(
                std::str::from_utf8(
                    headers
                        .iter()
                        .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
                        .unwrap()
                        .1,
                )
                .unwrap(),
            )
            .unwrap();
            // The two older cases have no context, and their canonical
            // requests carry another date: they test the path's encoding.
            if context.is_empty() {
                let canonical = canonical_request(&request, &authorization.signed).unwrap();
                assert_eq!(canonical.lines().nth(1), expected.lines().nth(1), "{case}");
                verified += 1;
                continue;
            }
            assert_eq!(
                canonical_request(&request, &authorization.signed).unwrap(),
                expected,
                "{case}"
            );

            let secret = json_field(context, "secret_access_key")
                .unwrap_or("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY");
            let region = json_field(context, "region").unwrap_or(authorization.region);
            let service = json_field(context, "service").unwrap_or(authorization.service);
            let date = std::str::from_utf8(
                headers
                    .iter()
                    .find(|(name, _)| name.eq_ignore_ascii_case("x-amz-date"))
                    .unwrap()
                    .1,
            )
            .unwrap();
            let now = parse_time(date).unwrap();
            let scope = Scope { region, service };
            assert_eq!(
                verify(&request, &scope, now, |_| Some(secret)),
                Ok(authorization.key.to_owned()),
                "{case}"
            );
            verified += 1;
        }
        assert!(verified >= 20, "only {verified} cases verified");
    }

    #[test]
    fn changes_to_what_was_signed_fail() {
        let case = CASES
            .iter()
            .find(|case| case.name == "post-vanilla-query")
            .unwrap();
        let signed = parse(case.signed);
        let headers: Vec<(&str, &[u8])> = signed
            .headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_slice()))
            .collect();
        let now = parse_time("20150830T123600Z").unwrap();
        let scope = Scope {
            region: "us-east-1",
            service: "service",
        };
        let secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
        let check = |query: &str,
                     body: &[u8],
                     headers: &[(&str, &[u8])],
                     now,
                     scope: &Scope<'_>,
                     secret: Option<&'static str>| {
            let request = Request {
                method: "POST",
                path: "/",
                query,
                headers,
                body,
            };
            verify(&request, scope, now, |_| secret)
        };
        assert!(check("Param1=value1", b"", &headers, now, &scope, Some(secret)).is_ok());
        assert_eq!(
            check("Param1=value2", b"", &headers, now, &scope, Some(secret)),
            Err(Failure::Signature)
        );
        assert_eq!(
            check(
                "Param1=value1",
                b"body",
                &headers,
                now,
                &scope,
                Some(secret)
            ),
            Err(Failure::Signature)
        );
        assert_eq!(
            check("Param1=value1", b"", &headers, now, &scope, Some("wrong")),
            Err(Failure::Signature)
        );
        assert_eq!(
            check("Param1=value1", b"", &headers, now, &scope, None),
            Err(Failure::UnknownKey)
        );
        let late = now.saturating_add(Duration::from_secs(16 * 60));
        assert_eq!(
            check("Param1=value1", b"", &headers, late, &scope, Some(secret)),
            Err(Failure::Skewed)
        );
        let other = Scope {
            region: "eu-west-1",
            service: "service",
        };
        assert_eq!(
            check("Param1=value1", b"", &headers, now, &other, Some(secret)),
            Err(Failure::WrongScope)
        );
        assert_eq!(
            check("Param1=value1", b"", &[], now, &scope, Some(secret)),
            Err(Failure::Missing)
        );
    }

    #[test]
    fn times_parse_as_utc() {
        assert_eq!(
            parse_time("20150830T123600Z"),
            Some(Timestamp::from_micros(1_440_938_160_000_000))
        );
        assert_eq!(
            parse_time("19700101T000000Z"),
            Some(Timestamp::from_micros(0))
        );
        assert_eq!(parse_time("20150830 123600Z"), None);
        assert_eq!(parse_time("20151330T123600Z"), None);
        // Refused, never a panic: a character of two bytes where the `T`
        // is, and the year 0's first months.
        assert_eq!(parse_time("1234567\u{e9}123456Z"), None);
        assert_eq!(parse_time("00000115T000000Z"), None);
    }
}
