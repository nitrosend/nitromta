//! `nitromta setup`: a new installation's files, never written
//! over ones already there. It writes a commented configuration, its own
//! owner's alone as it holds the return path's key, with the hostname,
//! return path domain and paths given, and the installation's keys, and
//! says what is left to do: the certificate, the start, policy, and
//! `doctor`.
//!
//! With `--capture`, it writes an installation to try the engine with, in
//! capture mode: everything beside its configuration, a certificate of its
//! own for its hostname, listeners on this host's own unprivileged ports,
//! and the inspector on the operator endpoint. Mail is captured, never sent,
//! and nothing needs an IP address or DNS.

use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

use crate::keys;

/// Where a new installation's files go, as the package lays them out.
pub struct Layout {
    pub config: PathBuf,
    pub hostname: String,
    pub return_path_domain: String,
    pub store: PathBuf,
    pub keys: PathBuf,
    pub certificate: PathBuf,
    pub key: PathBuf,
    pub socket: PathBuf,
    /// Capture mode's directory, for an installation to try the engine
    /// with.
    pub capture: Option<PathBuf>,
}

/// Writes the configuration and the keys `layout` names, and says what is
/// left to do.
pub fn run(layout: &Layout) -> Result<(), String> {
    if layout.config.exists() {
        return Err(format!(
            "{} is there already: setup writes over nothing; move it aside to start again",
            layout.config.display()
        ));
    }
    let mut return_path_key = [0u8; 32];
    aws_lc_rs::rand::fill(&mut return_path_key)
        .map_err(|_| "no randomness for the return path's key".to_owned())?;
    if layout.capture.is_some() {
        self_signed(layout)?;
    }
    let text = template(layout, &hex(&return_path_key));
    // Its owner's alone: it holds the key return paths are made with.
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&layout.config)
        .map_err(|error| format!("{}: {error}", layout.config.display()))?;
    file.write_all(text.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("{}: {error}", layout.config.display()))?;
    println!("wrote {}", layout.config.display());
    match keys::create(&layout.keys)? {
        Some(id) => println!("wrote {}, with key {id}", layout.keys.display()),
        None => println!("kept {}, the keys already there", layout.keys.display()),
    }
    let config = layout.config.display();
    if let Some(capture) = &layout.capture {
        println!(
            "\nIn capture mode: mail is captured into {capture}, never sent.
  1. Start the engine: nitromta run --config {config}
  2. Give it an account, an identity to send as and a login, through its admin socket:
       nitromta admin --config {config} <<'END'
       {{\"op\":\"put_account\",\"account\":1}}
       {{\"op\":\"put_identity\",\"account\":1,\"name\":\"example.test\"}}
       {{\"op\":\"create_login\",\"account\":1,\"user\":\"app\"}}
       END
     and an access key for SES SDKs: nitromta access-key create --config {config} --account 1
  3. Send through SMTP at 127.0.0.1:2587 with STARTTLS and that login, or the SES API at https://127.0.0.1:4443, trusting {certificate}.
  4. Look at what was captured: http://127.0.0.1:9090/capture",
            capture = capture.display(),
            certificate = layout.certificate.display(),
        );
        return Ok(());
    }
    println!(
        "\nLeft to do:
  1. A certificate for {hostname}, from a certificate authority, at {certificate}, and its key at {key}.
  2. The configuration, the keys with the .lock and .engine files beside them, and the store's directory the engine's own user's: run setup as that user, or chown them to it.
  3. Start the engine: systemctl start nitromta, or nitromta run --config {config}.
  4. Its policy, through the admin socket: an identity for each domain mail is sent as, an egress for each address it goes out from, and a login or access key for each application.
  5. The MX of {return_path_domain} pointed at this host, and port 25 open to it: bounces and complaints arrive there.
  6. nitromta doctor --config {config}, which checks it all and says which DNS records to publish.",
        hostname = layout.hostname,
        certificate = layout.certificate.display(),
        key = layout.key.display(),
        return_path_domain = layout.return_path_domain,
    );
    Ok(())
}

/// The configuration's text: what `layout` names, the return path's key,
/// and every other setting as a comment, at its default.
fn template(layout: &Layout, return_path_key: &str) -> String {
    let path = |path: &Path| toml_string(&path.display().to_string());
    // To try the engine, in capture mode: this host's own unprivileged
    // ports, the SES API and the operator endpoint on, and the capture
    // directory.
    let capturing = layout.capture.is_some();
    let on = |setting: &str| {
        if capturing {
            setting.to_owned()
        } else {
            format!("# {setting}")
        }
    };
    // And what a real installation needs that capture mode does not:
    // bounces and complaints arriving at the return path's MX.
    let off = |setting: &str| {
        if capturing {
            format!("# {setting}")
        } else {
            setting.to_owned()
        }
    };
    let submission = if capturing {
        "127.0.0.1:2587"
    } else {
        "0.0.0.0:587"
    };
    let ses = if capturing {
        "127.0.0.1:4443"
    } else {
        "0.0.0.0:443"
    };
    let capture = match &layout.capture {
        Some(directory) => format!(
            "\n# Capture mode: every delivery is written here in place of being sent,\n# and the operator endpoint's /capture shows it.\n[capture]\ndirectory = {}\n",
            path(directory)
        ),
        None => String::new(),
    };
    format!(
        r#"# NitroMTA's configuration, as `nitromta setup` wrote it. Each commented
# setting is at its default.

[store]
# The SQLite database; its directory holds its write-ahead log too.
path = {store}
# The installation's keys, which seal the secrets in policy: a file of its
# own, apart from the store and its backups, which only its owner may read.
keys = {keys}
# Free space kept on the store's disk; new mail is refused below it.
# reserve_mib = 1024
# Bytes of mail waiting for their commit before new mail is refused.
# pending_mib = 512
# How long finished mail is kept, for bounces and complaints that come
# after it.
# feedback_window_seconds = 604800

[submission]
# SMTP submission, for applications, with STARTTLS and a login.
listen = "{submission}"
hostname = {hostname}
certificate = {certificate}
key = {key}
# max_message_bytes = 40000000
# max_recipients = 50
# How long mail is tried before it expires.
# lifetime_seconds = 259200

# The SES v2 API, for applications that call it, on its own certificate.
{ses_table}
{ses_listen}
{ses_certificate}
{ses_key}
{ses_region}

[admin]
# The native API, for the CLI: the engine's own user, or root, alone.
socket = {socket}

# Bounces and complaints, at the return path's domain's MX.
{feedback_table}
{feedback_listen}
{feedback_hostname}
{feedback_certificate}
{feedback_key}

[delivery]
# The name an egress greets with when it names none.
helo = {hostname}
# Return paths are made under this domain, which bounces go to.
return_path_domain = {return_path_domain}
# The key return paths are made with: this installation's own.
return_path_key = "{return_path_key}"
# Keys from before a rotation: bounces to return paths made with them are
# still taken, for as long as their mail may still bounce.
# previous_return_path_keys = []
# Mail goes only over TLS: a receiver that does not offer STARTTLS is
# tried again until the mail expires. False lets it go in the clear to
# such a receiver.
# require_tls = true
# The port every receiver is reached on: SMTP's 25. Another suits only a
# receiver that listens on it, such as a test's, as all mail goes there.
# port = 25
# The resolver lookups go through, as an address and port; the system's
# when absent. DANE is in effect only through one on this host that
# validates DNSSEC itself, such as unbound, whose word is taken: never a
# forwarder that passes on another's. Through any other, mail goes as it
# would without DANE.
# resolver = "127.0.0.1:53"
# mta_sts = true
# dane = true

{operator_table}
# Health and metrics, in Prometheus's text format.
{operator_listen}

# [log]
# level = "info"
# format = "json"

# [scheduler]
# How long a stop waits for attempts under way.
# drain_seconds = 20
# retry_first_seconds = 60
# retry_max_seconds = 3600
{capture}"#,
        store = path(&layout.store),
        keys = path(&layout.keys),
        hostname = toml_string(&layout.hostname),
        certificate = path(&layout.certificate),
        key = path(&layout.key),
        socket = path(&layout.socket),
        return_path_domain = toml_string(&layout.return_path_domain),
        feedback_table = off("[feedback]"),
        feedback_listen = off("listen = \"0.0.0.0:25\""),
        feedback_hostname = off(&format!("hostname = {}", toml_string(&layout.hostname))),
        feedback_certificate = off(&format!("certificate = {}", path(&layout.certificate))),
        feedback_key = off(&format!("key = {}", path(&layout.key))),
        ses_table = on("[ses]"),
        ses_listen = on(&format!("listen = \"{ses}\"")),
        ses_certificate = on(&format!("certificate = {}", path(&layout.certificate))),
        ses_key = on(&format!("key = {}", path(&layout.key))),
        ses_region = on("region = \"us-east-1\""),
        operator_table = on("[operator]"),
        operator_listen = on("listen = \"127.0.0.1:9090\""),
    )
}

/// A certificate of its own, and its key, for capture mode's listeners,
/// which no client outside this host needs to trust: for this host's own
/// addresses, which its instructions send clients to, and the hostname.
fn self_signed(layout: &Layout) -> Result<(), String> {
    // Valid for the addresses its listeners are on, which its instructions
    // name, and for its host name.
    let mut names = vec![
        "127.0.0.1".to_owned(),
        "::1".to_owned(),
        "localhost".to_owned(),
    ];
    if !names.contains(&layout.hostname) {
        names.push(layout.hostname.clone());
    }
    let certified = rcgen::generate_simple_self_signed(names)
        .map_err(|error| format!("a certificate for {}: {error}", layout.hostname))?;
    for (path, text, mode) in [
        (&layout.certificate, certified.cert.pem(), 0o644),
        (&layout.key, certified.signing_key.serialize_pem(), 0o600),
    ] {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(path)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        file.write_all(text.as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|error| format!("{}: {error}", path.display()))?;
        println!("wrote {}", path.display());
    }
    Ok(())
}

/// `text` as a TOML string.
fn toml_string(text: &str) -> String {
    toml::Value::String(text.to_owned()).to_string()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_configuration_written_is_one_the_engine_reads() {
        let layout = Layout {
            config: PathBuf::from("/etc/nitromta/config.toml"),
            hostname: "mail.example.test".to_owned(),
            return_path_domain: "bounces.example.test".to_owned(),
            store: PathBuf::from("/var/lib/nitromta/store.db"),
            keys: PathBuf::from("/etc/nitromta/keys"),
            certificate: PathBuf::from("/etc/nitromta/tls.crt"),
            key: PathBuf::from("/etc/nitromta/tls.key"),
            socket: PathBuf::from("/run/nitromta/admin.sock"),
            capture: None,
        };
        let text = template(&layout, &"ab".repeat(32));
        let config: crate::config::Config = toml::from_str(&text).unwrap();
        assert_eq!(config.submission.hostname, "mail.example.test");
        assert_eq!(config.delivery.return_path_domain, "bounces.example.test");
        assert_eq!(config.delivery.return_path_key, "ab".repeat(32));
        assert_eq!(config.store.keys, layout.keys);
        assert!(config.ses.is_none() && config.operator.is_none());
        // Bounces and complaints are taken at the return path's MX.
        assert_eq!(
            config.feedback.map(|feedback| feedback.listen),
            Some("0.0.0.0:25".to_owned())
        );
        assert!(config.delivery.require_tls);
        // Each commented setting, uncommented, is one it reads too.
        let uncommented: String = text
            .lines()
            .map(|line| match line.strip_prefix("# ") {
                Some(setting) if setting.contains(" = ") || setting.starts_with('[') => setting,
                _ => line,
            })
            .collect::<Vec<_>>()
            .join("\n");
        let config: crate::config::Config = toml::from_str(&uncommented).unwrap();
        assert!(config.ses.is_some() && config.feedback.is_some() && config.operator.is_some());
        // To try the engine: capture mode, with the SES API and the
        // inspector on, on this host's own ports.
        let capturing = Layout {
            capture: Some(PathBuf::from("capture")),
            ..layout
        };
        let config: crate::config::Config =
            toml::from_str(&template(&capturing, &"ab".repeat(32))).unwrap();
        assert_eq!(config.submission.listen, "127.0.0.1:2587");
        assert_eq!(
            config.ses.map(|ses| ses.listen),
            Some("127.0.0.1:4443".to_owned())
        );
        assert_eq!(
            config.operator.map(|operator| operator.listen),
            Some("127.0.0.1:9090".to_owned())
        );
        assert_eq!(
            config.capture.map(|capture| capture.directory),
            Some(PathBuf::from("capture"))
        );
    }
}
