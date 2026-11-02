# AWS SigV4 signing test suite

The SigV4 cases of the AWS signing test suite, unmodified, as smithy-rs
carries them at `aws/rust-runtime/aws-sigv4/aws-signing-test-suite/v4`
(release-2026-10-21). They come from the CRT test suite in
[awslabs/aws-c-auth](https://github.com/awslabs/aws-c-auth/tree/v0.9.0/tests/aws-signing-test-suite),
under the Apache-2.0 license; `double-url-encode` and `double-encode-path`
were added by smithy-rs in the older format, without a `context.json`.

Each case holds the request, its signing context, and the canonical request,
string to sign and signature AWS expects. `engine-api` verifies its SigV4
check against them.
