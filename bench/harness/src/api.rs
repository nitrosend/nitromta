//! The API ingress clients, for the separately labelled API-ingress
//! comparison: SES v2 `SendEmail` with raw content, signed with
//! SigV4, and KumoMTA's HTTP injection with Basic authentication. Each runs
//! over one kept-alive HTTPS connection and carries exactly the message the
//! SMTP path sends, so the sink checks the same bytes however they came in.
//!
//! The SigV4 signer is the harness's own, written from AWS's specification,
//! so it shares no code with the verifier it is measured against.

use std::io;

use aws_lc_rs::digest::{SHA256, digest};
use aws_lc_rs::hmac;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt};

use crate::clock;

/// The region the engine is configured to serve, which every signature
/// names.
pub const REGION: &str = "us-east-1";
const SES_PATH: &str = "/v2/email/outbound-emails";
const INJECT_PATH: &str = "/api/inject/v1";

/// How messages reach a system under test.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Ingress {
    /// Authenticated submission over STARTTLS.
    #[default]
    Smtp,
    /// SES v2 `SendEmail` over HTTPS.
    Ses,
    /// KumoMTA's HTTP injection API over HTTPS.
    Kumomta,
}

impl Ingress {
    pub fn parse(text: &str) -> Result<Self, String> {
        match text {
            "smtp" => Ok(Self::Smtp),
            "ses" => Ok(Self::Ses),
            "kumomta" => Ok(Self::Kumomta),
            _ => Err(format!("no ingress `{text}`: smtp, ses or kumomta")),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Smtp => "smtp",
            Self::Ses => "ses",
            Self::Kumomta => "kumomta",
        }
    }
}

/// One message's request, for `host` (the Host header, with its port).
/// `user` and `password` are the SES access key and secret, or KumoMTA's
/// Basic credentials.
pub struct Submission<'a> {
    pub host: &'a str,
    pub user: &'a str,
    pub password: &'a str,
    pub sender: &'a str,
    pub recipients: &'a [String],
    pub message: &'a [u8],
}

/// The whole HTTP request that submits a message through `ingress`.
pub fn request(ingress: Ingress, submission: &Submission<'_>) -> Result<Vec<u8>, String> {
    match ingress {
        Ingress::Smtp => Err("SMTP is not an HTTP ingress".to_owned()),
        Ingress::Ses => Ok(send_email(submission, clock::now_micros())),
        Ingress::Kumomta => inject(submission),
    }
}

/// The SMTP-style code an answer earns: 250 when it accepted the message,
/// its HTTP status when it failed, and 554 when it answered 200 but
/// accepted nothing.
pub fn code(ingress: Ingress, status: u16, body: &[u8]) -> u16 {
    #[derive(Deserialize)]
    struct Sent {
        #[serde(rename = "MessageId")]
        message_id: String,
    }
    #[derive(Deserialize)]
    struct Injected {
        success_count: u64,
        fail_count: u64,
    }
    if status != 200 {
        return status;
    }
    let accepted = match ingress {
        Ingress::Smtp => false,
        Ingress::Ses => {
            serde_json::from_slice::<Sent>(body).is_ok_and(|sent| !sent.message_id.is_empty())
        }
        Ingress::Kumomta => serde_json::from_slice::<Injected>(body)
            .is_ok_and(|injected| injected.success_count > 0 && injected.fail_count == 0),
    };
    if accepted { 250 } else { 554 }
}

/// Reads one response: its status and body, which must carry a length.
pub async fn response<R: AsyncBufRead + Unpin>(
    stream: &mut R,
    line: &mut Vec<u8>,
) -> io::Result<(u16, Vec<u8>)> {
    let malformed = |what: &str| io::Error::new(io::ErrorKind::InvalidData, what.to_owned());
    let mut read_line = async |line: &mut Vec<u8>| {
        line.clear();
        if stream.read_until(b'\n', line).await? == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        Ok::<_, io::Error>(String::from_utf8_lossy(line).trim_end().to_owned())
    };
    let status_line = read_line(line).await?;
    let status = status_line
        .split(' ')
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| malformed("no HTTP status line"))?;
    let mut length = None;
    loop {
        let header = read_line(line).await?;
        if header.is_empty() {
            break;
        }
        let Some((name, value)) = header.split_once(':') else {
            return Err(malformed("a header without a colon"));
        };
        if name.eq_ignore_ascii_case("content-length") {
            length = value.trim().parse::<usize>().ok();
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(malformed("chunked responses are not read"));
        }
    }
    let mut body = vec![0; length.ok_or_else(|| malformed("no Content-Length"))?];
    stream.read_exact(&mut body).await?;
    Ok((status, body))
}

/// SES v2 `SendEmail` with the message as raw content and its recipients
/// as To addresses, signed at `now` with SigV4 over Content-Type, Host and
/// X-Amz-Date.
fn send_email(submission: &Submission<'_>, now: i64) -> Vec<u8> {
    let body = serde_json::json!({
        "FromEmailAddress": submission.sender,
        "Destination": { "ToAddresses": submission.recipients },
        "Content": { "Raw": { "Data": STANDARD.encode(submission.message) } },
    })
    .to_string();
    let time = clock::compact_utc(now);
    let date = &time[..8];
    let canonical = format!(
        "POST\n{SES_PATH}\n\ncontent-type:application/json\nhost:{}\nx-amz-date:{time}\n\ncontent-type;host;x-amz-date\n{}",
        submission.host,
        crate::hex(digest(&SHA256, body.as_bytes()).as_ref())
    );
    let scope = format!("{date}/{REGION}/ses/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{time}\n{scope}\n{}",
        crate::hex(digest(&SHA256, canonical.as_bytes()).as_ref())
    );
    let key = signing_key(submission.password, date, REGION, "ses");
    let signature = hmac::sign(
        &hmac::Key::new(hmac::HMAC_SHA256, &key),
        string_to_sign.as_bytes(),
    );
    let mut request = format!(
        "POST {SES_PATH} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {length}\r\n\
         X-Amz-Date: {time}\r\n\
         Authorization: AWS4-HMAC-SHA256 Credential={user}/{scope}, SignedHeaders=content-type;host;x-amz-date, Signature={signature}\r\n\
         \r\n",
        host = submission.host,
        length = body.len(),
        user = submission.user,
        signature = crate::hex(signature.as_ref()),
    )
    .into_bytes();
    request.extend_from_slice(body.as_bytes());
    request
}

/// SigV4's signing key: the secret, then the date, region, service and
/// terminator, each the HMAC key of the next.
fn signing_key(secret: &str, date: &str, region: &str, service: &str) -> Vec<u8> {
    let mut key = format!("AWS4{secret}").into_bytes();
    for part in [date, region, service, "aws4_request"] {
        key = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, &key), part.as_bytes())
            .as_ref()
            .to_vec();
    }
    key
}

/// KumoMTA's injection of the message, whole, to its recipients.
fn inject(submission: &Submission<'_>) -> Result<Vec<u8>, String> {
    let content = std::str::from_utf8(submission.message)
        .map_err(|_| "the message is not text".to_owned())?;
    let body = serde_json::json!({
        "envelope_sender": submission.sender,
        "content": content,
        "recipients": submission
            .recipients
            .iter()
            .map(|email| serde_json::json!({ "email": email }))
            .collect::<Vec<_>>(),
    })
    .to_string();
    let credentials = STANDARD.encode(format!("{}:{}", submission.user, submission.password));
    let mut request = format!(
        "POST {INJECT_PATH} HTTP/1.1\r\n\
         Host: {}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Authorization: Basic {credentials}\r\n\
         \r\n",
        submission.host,
        body.len(),
    )
    .into_bytes();
    request.extend_from_slice(body.as_bytes());
    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn submission<'a>(message: &'a [u8], recipients: &'a [String]) -> Submission<'a> {
        Submission {
            host: "sut.bench.test:8443",
            user: "AKIDBENCH",
            password: "secret",
            sender: "load@bench.test",
            recipients,
            message,
        }
    }

    /// AWS's published example of a signing key's derivation: the secret
    /// `wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY`, 20150830, us-east-1, iam.
    #[test]
    fn the_signing_key_derives_as_aws_documents() {
        let key = signing_key(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20150830",
            "us-east-1",
            "iam",
        );
        assert_eq!(
            crate::hex(&key),
            "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
        );
    }

    #[test]
    fn a_send_email_request_is_signed_over_its_body() {
        let recipients = ["r1@sink.test".to_owned(), "r2@sink.test".to_owned()];
        let request = send_email(
            &submission(b"From: a\r\n\r\nbody\r\n", &recipients),
            1_800_000_000_000_000,
        );
        let text = String::from_utf8(request).unwrap();
        let (head, body) = text.split_once("\r\n\r\n").unwrap();
        assert!(head.starts_with("POST /v2/email/outbound-emails HTTP/1.1\r\n"));
        assert!(head.contains(&format!("Content-Length: {}\r\n", body.len())));
        assert!(head.contains("X-Amz-Date: 20270115T080000Z\r\n"));
        assert!(head.contains(
            "Credential=AKIDBENCH/20270115/us-east-1/ses/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature="
        ));
        let sent: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(
            sent["Destination"]["ToAddresses"],
            serde_json::json!(["r1@sink.test", "r2@sink.test"])
        );
        assert_eq!(
            STANDARD
                .decode(sent["Content"]["Raw"]["Data"].as_str().unwrap())
                .unwrap(),
            b"From: a\r\n\r\nbody\r\n"
        );
    }

    #[test]
    fn answers_earn_their_codes() {
        assert_eq!(code(Ingress::Ses, 200, br#"{"MessageId":"0a"}"#), 250);
        assert_eq!(code(Ingress::Ses, 200, b"{}"), 554);
        assert_eq!(code(Ingress::Ses, 429, b"{}"), 429);
        let injected = br#"{"success_count":1,"fail_count":0,"failed_recipients":[],"errors":[]}"#;
        assert_eq!(code(Ingress::Kumomta, 200, injected), 250);
        let failed = br#"{"success_count":0,"fail_count":1,"failed_recipients":["r1@sink.test"],"errors":[]}"#;
        assert_eq!(code(Ingress::Kumomta, 200, failed), 554);
    }

    #[tokio::test]
    async fn a_response_is_read_by_its_length() {
        let bytes = b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 2\r\n\r\n{}HTTP/1.1";
        let mut stream = tokio::io::BufReader::new(&bytes[..]);
        let mut line = Vec::new();
        assert_eq!(
            response(&mut stream, &mut line).await.unwrap(),
            (200, b"{}".to_vec())
        );
    }
}
