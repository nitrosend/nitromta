//! A renewed certificate through the release binary: served from the
//! next connection once the engine is told to read it again, with SIGHUP,
//! as `systemctl reload` tells it; one that cannot be served is not taken.
//! And signals as the engine starts, which it takes as it would later.

mod support;

use support::{Dns, Engine, Receiver, Script, wait_for};

#[test]
fn a_renewed_certificate_is_served_once_the_engine_reads_it_again() {
    let dns = Dns::start(&[]);
    let receiver = Receiver::start(Script::default());
    let engine = Engine::start("reload", &dns, &receiver, "dane = false", "");
    // The renewal writes its new certificate and key in place.
    let renewed = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    std::fs::write(engine.dir.join("tls.crt"), renewed.cert.pem()).unwrap();
    std::fs::write(
        engine.dir.join("tls.key"),
        renewed.signing_key.serialize_pem(),
    )
    .unwrap();
    let root = renewed.cert.der().clone();
    // Until it is told, the engine serves the certificate it read.
    assert!(!engine.serves(&root));
    engine.signal("HUP");
    wait_for("the renewed certificate", || engine.serves(&root));
    // A certificate whose key is not its own is not taken: it serves the one
    // it had, and says why.
    let other = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    std::fs::write(
        engine.dir.join("tls.key"),
        other.signing_key.serialize_pem(),
    )
    .unwrap();
    engine.signal("HUP");
    wait_for("the refusal in the log", || {
        engine.log().contains("kept the certificate it had")
    });
    assert!(engine.serves(&root));
}

#[test]
fn a_stop_sent_as_the_engine_starts_is_a_graceful_stop() {
    let dns = Dns::start(&[]);
    let receiver = Receiver::start(Script::default());
    let mut engine = Engine::start("signalled", &dns, &receiver, "dane = false", "");
    engine.stop();
    // Started again, and stopped the moment it says it serves anything,
    // before it takes mail: the stop is taken, never the signal's default
    // end.
    let _ = std::fs::remove_file(engine.dir.join("admin.sock"));
    let mut child = engine.spawn(&["run", "--config", "config.toml"]);
    let (lines, read) = std::sync::mpsc::channel();
    let outputs: [Box<dyn std::io::Read + Send>; 2] = [
        Box::new(child.stdout.take().expect("its output")),
        Box::new(child.stderr.take().expect("its errors")),
    ];
    for output in outputs {
        let lines = lines.clone();
        std::thread::spawn(move || {
            for line in
                std::io::BufRead::lines(std::io::BufReader::new(output)).map_while(Result::ok)
            {
                let _ = lines.send(line);
            }
        });
    }
    loop {
        let line = read
            .recv_timeout(support::PATIENCE)
            .expect("it logs as it starts");
        if line.contains("\"serving admin\"") {
            break;
        }
    }
    let signalled = std::process::Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .expect("kill runs");
    assert!(signalled.success());
    let status = child.wait().expect("it stops");
    assert!(status.success(), "it stopped with {status}");
}
