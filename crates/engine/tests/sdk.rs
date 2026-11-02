//! The official SES v2 SDKs, and two applications built on them, against
//! the release binary: JavaScript with Nodemailer, Python
//! with django-ses, and Ruby at the version Nitrosend sends with, each
//! pinned in `sdk/` and run through the same scenario, which `sdk/README.md`
//! gives. They need their runtimes and packages, which `cargo xtask sdk`
//! installs before it runs these, so the gate leaves them out.

mod support;

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;
use support::{Dns, Engine, Receiver, Script};

const SES: &str = "[ses]\nlisten = \"127.0.0.1:0\"\ncertificate = \"tls.crt\"\nkey = \"tls.key\"\nregion = \"us-east-1\"\n\n[capture]\ndirectory = \"capture\"";

/// The address the scenario suppresses, and takes off the list again.
const SUPPRESS: &str = "bounced@plain.test";

fn sdk(language: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../sdk")
        .join(language)
}

/// Runs `program` with `arguments` in `language`'s directory against a new
/// engine capturing what it sends, and returns each step's line, by step,
/// and the subjects captured.
fn scenario(language: &str, program: &str, arguments: &[&str]) -> (Vec<Value>, Vec<String>) {
    let dns = Dns::start(&[]);
    let receiver = Receiver::start(Script::default());
    let mut engine = Engine::start(
        &format!("sdk-{language}"),
        &dns,
        &receiver,
        "dane = false",
        SES,
    );
    let ses = engine.ses_permitted(&["send", "manage"]);
    let directory = sdk(language);
    let output = Command::new(program)
        .args(arguments)
        .current_dir(&directory)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", std::env::var_os("HOME").unwrap_or_default())
        .env("SES_ENDPOINT", format!("https://localhost:{}", ses.port))
        .env("AWS_ACCESS_KEY_ID", &ses.access_key)
        .env("AWS_SECRET_ACCESS_KEY", &ses.secret)
        .env("AWS_REGION", "us-east-1")
        .env("AWS_CA_BUNDLE", engine.dir.join("tls.crt"))
        .env("NODE_EXTRA_CA_CERTS", engine.dir.join("tls.crt"))
        .env("BUNDLE_GEMFILE", directory.join("Gemfile"))
        .env("BUNDLE_PATH", directory.join("vendor/bundle"))
        .env("FROM", "app@sender.test")
        .env("TO", "reader@plain.test")
        .env("DOMAIN", "sender.test")
        .env("SUPPRESS", SUPPRESS)
        .output()
        .unwrap_or_else(|error| panic!("{program} runs: {error}; `cargo xtask sdk` installs it"));
    let said = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        output.status.success(),
        "{language}: {}\n{said}{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let steps: Vec<Value> = said
        .lines()
        .map(|line| serde_json::from_str(line).unwrap_or_else(|_| panic!("a step: {line}")))
        .collect();
    // Every message the scenario sent, captured whole.
    let capture = engine.dir.join("capture");
    let sent = steps
        .iter()
        .filter(|step| step["message_id"].is_string())
        .count()
        + 1;
    let subjects = || -> Vec<String> {
        let mut subjects: Vec<String> = std::fs::read_dir(&capture)
            .map(|entries| {
                entries
                    .flatten()
                    .filter(|entry| entry.file_name().to_string_lossy().ends_with(".eml"))
                    .filter_map(|entry| std::fs::read_to_string(entry.path()).ok())
                    .filter_map(|content| {
                        content
                            .lines()
                            .find_map(|line| line.strip_prefix("Subject: ").map(str::to_owned))
                    })
                    .collect()
            })
            .unwrap_or_default();
        subjects.sort();
        subjects
    };
    let deadline = std::time::Instant::now() + support::PATIENCE;
    while subjects().len() < sent && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let captured = subjects();
    assert_eq!(
        captured.len(),
        sent,
        "{language}: captured {captured:?}, steps {steps:?}"
    );
    (steps, captured)
}

/// The step named `name`.
fn step<'a>(steps: &'a [Value], name: &str) -> &'a Value {
    steps
        .iter()
        .find(|step| step["step"] == name)
        .unwrap_or_else(|| panic!("no step {name}: {steps:?}"))
}

/// What every SDK's scenario must show, as SES would answer it.
fn judged(language: &str, steps: &[Value]) {
    for sent in ["send_simple", "send_raw"] {
        assert!(
            step(steps, sent)["message_id"]
                .as_str()
                .is_some_and(|id| !id.is_empty()),
            "{language}: {steps:?}"
        );
    }
    assert_eq!(
        step(steps, "send_bulk")["statuses"],
        serde_json::json!(["SUCCESS", "MESSAGE_REJECTED"]),
        "{language}"
    );
    let account = step(steps, "account");
    assert_eq!(account["sending_enabled"], true, "{language}: {account}");
    assert!(
        account["max_24_hour_send"].is_number(),
        "{language}: {account}"
    );
    let rejected = step(steps, "rejected");
    assert_eq!(
        rejected["error"], "MessageRejected",
        "{language}: {rejected}"
    );
    assert_eq!(
        step(steps, "identity")["verified"],
        true,
        "{language}: {steps:?}"
    );
    let identities = step(steps, "identities");
    assert!(
        identities["names"]
            .as_array()
            .is_some_and(|names| names.iter().any(|name| name == "sender.test")),
        "{language}: {identities}"
    );
    let sets = step(steps, "configuration_sets");
    assert_eq!(
        (&sets["pages"], &sets["names"]),
        (&Value::from(2), &serde_json::json!(["first", "second"])),
        "{language}: {sets}"
    );
    let templates = step(steps, "templates");
    assert_eq!(
        (
            &templates["subject"],
            &templates["names"],
            &templates["gone"]
        ),
        (
            &Value::from("template from {{name}}"),
            &serde_json::json!(["welcome"]),
            &Value::from("NotFoundException")
        ),
        "{language}: {templates}"
    );
    let suppression = step(steps, "suppression");
    assert_eq!(
        (
            &suppression["reason"],
            &suppression["address"],
            &suppression["gone"]
        ),
        (
            &Value::from("BOUNCE"),
            &Value::from(SUPPRESS),
            &Value::from("NotFoundException")
        ),
        "{language}: {suppression}"
    );
    // Refused for good: an SDK neither retries it nor takes it for success.
    let unimplemented = step(steps, "unimplemented");
    assert_eq!(
        (&unimplemented["error"], &unimplemented["attempts"]),
        (&Value::from("BadRequestException"), &Value::from(1)),
        "{language}: {unimplemented}"
    );
}

#[test]
#[ignore = "needs the SDKs `cargo xtask sdk` installs"]
fn javascript_and_nodemailer() {
    let (steps, subjects) = scenario("javascript", "node", &["check.mjs"]);
    judged("javascript", &steps);
    let nodemailer = step(&steps, "nodemailer");
    assert_eq!(nodemailer["verified"], true, "{nodemailer}");
    assert_eq!(
        subjects,
        [
            "bulk for javascript",
            "from nodemailer",
            "raw from javascript",
            "simple from javascript",
            "template from javascript"
        ]
    );
}

#[test]
#[ignore = "needs the SDKs `cargo xtask sdk` installs"]
fn python_and_django_ses() {
    let (steps, subjects) = scenario("python", ".venv/bin/python", &["check.py"]);
    judged("python", &steps);
    assert_eq!(step(&steps, "django_ses")["sent"], 1, "{steps:?}");
    assert_eq!(
        subjects,
        [
            "bulk for python",
            "from django-ses",
            "raw from python",
            "simple from python",
            "template from python"
        ]
    );
}

#[test]
#[ignore = "needs the SDKs `cargo xtask sdk` installs"]
fn ruby_at_nitrosends_version() {
    let (steps, subjects) = scenario("ruby", "bundle", &["exec", "ruby", "check.rb"]);
    judged("ruby", &steps);
    assert_eq!(
        subjects,
        [
            "bulk for ruby",
            "raw from ruby",
            "simple from ruby",
            "template from ruby"
        ]
    );
}

/// What `setup --capture` tells a newcomer to do, done as it says, with an
/// unchanged official SDK: the engine run, its policy given through
/// the admin socket, an access key made, a message sent to the SES API it
/// names, trusting the certificate it made, and found in the inspector.
#[test]
#[ignore = "needs the SDKs `cargo xtask sdk` installs"]
fn the_capture_quickstart_as_setup_prints_it() {
    let dir = std::env::temp_dir().join(format!("nitromta-quickstart-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let nitromta = |arguments: &[&str], input: Option<&str>| {
        let mut child = Command::new(env!("CARGO_BIN_EXE_nitromta"))
            .args(arguments)
            .current_dir(&dir)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("the binary runs");
        let stdin = child.stdin.take().expect("its input");
        if let Some(input) = input {
            std::io::Write::write_all(&mut { stdin }, input.as_bytes()).unwrap();
        }
        let output = child.wait_with_output().unwrap();
        let mut said = String::from_utf8_lossy(&output.stdout).into_owned();
        said.push_str(&String::from_utf8_lossy(&output.stderr));
        assert!(output.status.success(), "nitromta {arguments:?}: {said}");
        said
    };
    let said = nitromta(&["setup", "--config", "config.toml", "--capture"], None);
    let api = "https://127.0.0.1:4443";
    assert!(
        said.contains(&format!("the SES API at {api}, trusting ./tls.crt")),
        "{said}"
    );
    // 1. Started.
    let log = std::fs::File::create(dir.join("engine.log")).unwrap();
    let mut engine = Command::new(env!("CARGO_BIN_EXE_nitromta"))
        .args(["run", "--config", "config.toml"])
        .current_dir(&dir)
        .stdout(log.try_clone().unwrap())
        .stderr(log)
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + support::PATIENCE;
    while !std::fs::read_to_string(dir.join("engine.log"))
        .unwrap_or_default()
        .contains("serving health and metrics")
    {
        assert!(
            std::time::Instant::now() < deadline,
            "the engine did not start"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    // 2. Its policy, and an access key.
    nitromta(
        &["admin", "--config", "config.toml"],
        Some(concat!(
            "{\"op\":\"put_account\",\"account\":1}\n",
            "{\"op\":\"put_identity\",\"account\":1,\"name\":\"example.test\"}\n",
            "{\"op\":\"create_login\",\"account\":1,\"user\":\"app\"}\n",
        )),
    );
    let created = nitromta(
        &[
            "access-key",
            "create",
            "--config",
            "config.toml",
            "--account",
            "1",
        ],
        None,
    );
    let (id, secret) = created
        .split_once("access key ")
        .and_then(|(_, rest)| rest.split_once(" created; its secret, shown this once: "))
        .map(|(id, secret)| (id.trim().to_owned(), secret.trim().to_owned()))
        .unwrap_or_else(|| panic!("an access key: {created}"));
    // 3. Sent through the SES API it names, trusting its certificate, as
    // the quickstart's page does.
    let python = sdk("python").join(".venv/bin/python");
    let page = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/capture.md"),
    )
    .unwrap();
    let send = page
        .split_once("```python\n")
        .and_then(|(_, rest)| rest.split_once("```"))
        .map(|(code, _)| code)
        .expect("the quickstart's Python");
    assert!(send.contains(&format!("endpoint_url=\"{api}\"")), "{send}");
    let readme =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../README.md"))
            .unwrap();
    assert!(
        readme.contains(&format!("```python\n{send}```")),
        "the README shows the quickstart's Python as it is"
    );
    let output = Command::new(python)
        .args(["-c", send])
        .env_clear()
        .env("AWS_ACCESS_KEY_ID", &id)
        .env("AWS_SECRET_ACCESS_KEY", &secret)
        .env("AWS_CA_BUNDLE", dir.join("tls.crt"))
        .output()
        .unwrap();
    let sent = String::from_utf8_lossy(&output.stdout).into_owned();
    let failed = String::from_utf8_lossy(&output.stderr).into_owned();
    // 4. In the inspector.
    let inspected = || {
        let mut stream = std::net::TcpStream::connect("127.0.0.1:9090").ok()?;
        std::io::Write::write_all(
            &mut stream,
            b"GET /capture HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n\r\n",
        )
        .ok()?;
        let mut page = String::new();
        std::io::Read::read_to_string(&mut stream, &mut page).ok()?;
        Some(page)
    };
    let mut page = String::new();
    let deadline = std::time::Instant::now() + support::PATIENCE;
    while output.status.success() && std::time::Instant::now() < deadline {
        page = inspected().unwrap_or_default();
        if page.contains("from the quickstart") {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let _ = engine.kill();
    let _ = engine.wait();
    assert!(output.status.success(), "the SDK's send: {sent}{failed}");
    assert!(page.contains("from the quickstart"), "{page}");
    let _ = std::fs::remove_dir_all(&dir);
}
