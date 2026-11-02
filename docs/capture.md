# Try it in capture mode

Capture mode runs the whole engine on your own machine, with no IP address,
DNS records or certificate authority. Every message is accepted, signed,
scheduled and recorded exactly as it would be for real delivery, then
written to a directory instead of being sent, and shown in a browser.

You need the `nitromta` binary on your path (see [installation](install.md),
or build it with `cargo build --release`) and a directory to work in.

## 1. Write an installation

```sh
nitromta setup --config config.toml --capture
```

This writes `config.toml`, the installation's keys, a certificate of its own
for `127.0.0.1`, `::1`, `localhost` and your host name, and a capture
directory, all beside the configuration. It listens on this host's own
unprivileged ports: SMTP submission on `127.0.0.1:2587`, the SES v2 API on
`https://127.0.0.1:4443`, and health, metrics and the capture inspector on
`http://127.0.0.1:9090`.

## 2. Start the engine

```sh
nitromta run --config config.toml
```

## 3. Give it an account, an identity and credentials

In another terminal, in the same directory:

```sh
nitromta admin --config config.toml <<'END'
{"op":"put_account","account":1}
{"op":"put_identity","account":1,"name":"example.test"}
{"op":"create_login","account":1,"user":"app"}
END
nitromta access-key create --config config.toml --account 1
```

The login is for SMTP clients: its password is printed once. The access key
is for SES SDKs: its ID and secret are printed once too.

## 4. Send

With any SES v2 SDK, pointed at the engine and trusting its certificate:

```sh
export AWS_ACCESS_KEY_ID=<the access key's ID>
export AWS_SECRET_ACCESS_KEY=<its secret>
export AWS_CA_BUNDLE=./tls.crt
```

```python
import boto3

# Your SES code as it is, pointed at the engine: only the endpoint and the keys change.
ses = boto3.client("sesv2", endpoint_url="https://127.0.0.1:4443", region_name="us-east-1")
sent = ses.send_email(
    FromEmailAddress="app@example.test",
    Destination={"ToAddresses": ["someone@example.com"]},
    Content={"Simple": {"Subject": {"Data": "from the quickstart"}, "Body": {"Text": {"Data": "hello"}}}},
)
print(sent["MessageId"])
```

Or through SMTP, at `127.0.0.1:2587` with STARTTLS and the login, from any
client that can trust `./tls.crt`.

## 5. Look at what was captured

Open `http://127.0.0.1:9090/capture`. Each transaction is shown newest
first, as the receiver would have been given it: its headers, its text, and
its message's lifecycle. The quickstart's identity has no DKIM key, so its
mail is unsigned; one given a key, as [installation](install.md) shows, is
signed before it is captured. The capture directory keeps each one as two
files: `<name>.eml`, the content exactly as it would have gone, and
`<name>.json`, its envelope (the return path, the recipients and the
deliveries).

`nitromta queue --config config.toml` and
`nitromta explain --config config.toml --message <id>` show what the engine
holds and why, as they do in production (see [operations](operations.md)).

The test `the_capture_quickstart_as_setup_prints_it` in
`crates/engine/tests/sdk.rs` follows these steps with the Python example
above, read from this page, and checks that the README shows the same.
