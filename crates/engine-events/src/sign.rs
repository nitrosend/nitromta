//! Signing, as Standard Webhooks does it: an HMAC-SHA256 over the batch's
//! ID, the time it was signed and its exact bytes, so a receiver can check
//! it with any of that specification's libraries.

use aws_lc_rs::hmac;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

/// A subscription's secret as receivers are given it.
pub fn secret_text(secret: &[u8; 32]) -> String {
    format!("whsec_{}", STANDARD.encode(secret))
}

/// The headers a batch with `id`, signed at `timestamp` (seconds since the
/// Unix epoch), is posted with.
pub fn headers(
    secret: &[u8],
    id: &str,
    timestamp: u64,
    body: &[u8],
) -> Vec<(&'static str, String)> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    let mut context = hmac::Context::with_key(&key);
    context.update(format!("{id}.{timestamp}.").as_bytes());
    context.update(body);
    let signature = STANDARD.encode(context.sign().as_ref());
    vec![
        ("webhook-id", id.to_owned()),
        ("webhook-timestamp", timestamp.to_string()),
        ("webhook-signature", format!("v1,{signature}")),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Standard Webhooks' own example: its secret, ID, timestamp and body,
    /// and the signature it gives for them.
    #[test]
    fn signatures_match_the_specifications_example() {
        let secret = STANDARD.decode("MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw").unwrap();
        let headers = headers(
            &secret,
            "msg_p5jXN8AQM9LWM0D4loKWxJek",
            1_614_265_330,
            br#"{"test": 2432232314}"#,
        );
        assert_eq!(
            headers[2],
            (
                "webhook-signature",
                "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=".to_owned()
            )
        );
        assert_eq!(secret_text(&[0; 32]).len(), "whsec_".len() + 44);
    }
}
