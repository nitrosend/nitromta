//! Verified delivery TLS through the release binary.
//!
//! MTA-STS: a domain's policy, fetched from its policy host over HTTPS the
//! test's authority verifies, keeps its mail to the exchanges it names,
//! over TLS that authority verifies for each exchange's name; a policy
//! outlives its record's withdrawal, its host's silence and a restart; and
//! an exchange that fails verification gives way to the next.
//!
//! DANE: in a DNSSEC-signed zone the engine validates with the test's
//! trust anchor, an exchange's TLSA records bind its certificate whatever
//! authority signed it; one that does not match holds the mail; a bogus
//! TLSA answer leaves the exchange unused; unusable records still require
//! TLS; and a secure exchange without records is delivered to as before.

mod support;

use aws_lc_rs::digest;
use hickory_resolver::proto::rr::RecordType;
use support::dns::Dns;
use support::pki::{Authority, Certified, PolicyHost, by_name};
use support::{Engine, Receiver, Script, wait_for};

/// What `explain` says of the message's one delivery's last reply.
fn last_reply(engine: &Engine, message: &str) -> String {
    let deliveries = engine.explain(message);
    deliveries
        .first()
        .and_then(|delivery| delivery["last_reply"]["reply"].as_str())
        .unwrap_or_default()
        .to_owned()
}

/// Waits until `explain` gives the message's delivery a last reply, and
/// returns it.
fn failure(engine: &Engine, message: &str) -> String {
    let mut reply = String::new();
    wait_for("the attempt's failure", || {
        reply = last_reply(engine, message);
        !reply.is_empty()
    });
    reply
}

fn sha256(bytes: &[u8]) -> Vec<u8> {
    digest::digest(&digest::SHA256, bytes).as_ref().to_vec()
}

/// A domain, s.test, whose policy enforces, its policy host and its one
/// exchange, mx.s.test, which presents a certificate the test's authority
/// issued for its name, and an engine that trusts that authority.
struct Sts {
    authority: Authority,
    dns: Dns,
    host: PolicyHost,
    receiver: Receiver,
    engine: Engine,
}

const POLICY: &str = "version: STSv1\nmode: enforce\nmx: mx.s.test\nmax_age: 86400\n";

fn sts(name: &str, policy: &str) -> Sts {
    let authority = Authority::new();
    let dns = Dns::start(&[("s.test", "mx.s.test")]);
    dns.txt("_mta-sts.s.test", "v=STSv1; id=1;");
    dns.address_of("mta-sts.s.test");
    let host = PolicyHost::start(&authority.issue(&["mta-sts.s.test"]), policy);
    let receiver = Receiver::start(Script::default());
    receiver.present(Some(authority.issue(&["mx.s.test"]).server()));
    // Connections and routes last a second, so each step meets the
    // exchange and the policy as the step leaves them.
    let engine = Engine::start_with(
        name,
        &dns,
        &receiver,
        &format!(
            "mta_sts_port = {}\nidle_seconds = 1\n# The stub DNS signs nothing.\ndane = false",
            host.port
        ),
        "[tls]\nauthorities = \"authority.pem\"\n\n[scheduler]\nroute_ttl_seconds = 1",
        &[("authority.pem", &authority.pem())],
    );
    Sts {
        authority,
        dns,
        host,
        receiver,
        engine,
    }
}

#[test]
fn an_enforced_policy_delivers_over_tls_the_web_pki_verifies() {
    let mut sts = sts("sts-verified", POLICY);
    sts.engine.submit(&["one@s.test"]);
    wait_for("the delivery", || sts.receiver.delivered().len() == 1);
    let connections = sts.receiver.connections();
    assert_eq!(connections[0].tls.as_deref(), Some("mx.s.test"));
    assert_eq!(*sts.host.fetched.lock().unwrap(), 1, "fetched once");
}

#[test]
fn a_certificate_the_policy_cannot_verify_holds_the_mail() {
    let mut sts = sts("sts-unverified", POLICY);
    // Issued by the authority, for another name.
    let elsewhere = sts.authority.issue(&["elsewhere.test"]);
    sts.receiver.present(Some(elsewhere.server()));
    let message = sts.engine.submit(&["one@s.test"]).remove(0);
    let reply = failure(&sts.engine, &message);
    assert!(
        reply.starts_with("MTA-STS: the TLS handshake with mx.s.test failed"),
        "{reply}"
    );
    assert!(sts.receiver.delivered().is_empty());
    // For its name, and issued by no authority.
    sts.receiver
        .present(Some(Certified::self_signed(&["mx.s.test"]).server()));
    let message = sts.engine.submit(&["two@s.test"]).remove(0);
    let reply = failure(&sts.engine, &message);
    assert!(reply.starts_with("MTA-STS:"), "{reply}");
    assert!(sts.receiver.delivered().is_empty());
}

#[test]
fn a_kept_policy_outlives_a_failed_fetch_its_record_its_host_and_a_restart() {
    let mut sts = sts("sts-kept", POLICY);
    sts.engine.submit(&["one@s.test"]);
    wait_for("the first delivery", || sts.receiver.delivered().len() == 1);
    wait_for("its connection to close", || {
        sts.receiver
            .connections()
            .iter()
            .all(|connection| connection.closed.is_some())
    });
    std::thread::sleep(std::time::Duration::from_millis(1_100));
    // An attacker announces a new policy and silences the host, and the
    // exchange presents a certificate no authority issued: the fetch fails,
    // and the policy kept stands.
    sts.dns.remove("_mta-sts.s.test", RecordType::TXT);
    sts.dns.txt("_mta-sts.s.test", "v=STSv1; id=2;");
    sts.host.serve(None);
    sts.receiver
        .present(Some(Certified::self_signed(&["mx.s.test"]).server()));
    let message = sts.engine.submit(&["two@s.test"]).remove(0);
    let reply = failure(&sts.engine, &message);
    assert!(reply.starts_with("MTA-STS:"), "{reply}");
    assert_eq!(
        *sts.host.fetched.lock().unwrap(),
        2,
        "the new policy was asked for"
    );
    // Then removes the record, and the engine restarts.
    sts.dns.remove("_mta-sts.s.test", RecordType::TXT);
    sts.engine.restart();
    let message = sts.engine.submit(&["three@s.test"]).remove(0);
    let reply = failure(&sts.engine, &message);
    assert!(reply.starts_with("MTA-STS:"), "{reply}");
    assert_eq!(sts.receiver.delivered(), ["one@s.test"]);
}

#[test]
fn a_policy_that_names_none_of_the_exchanges_withholds_the_mail() {
    let mut sts = sts(
        "sts-withheld",
        "version: STSv1\nmode: enforce\nmx: mx.elsewhere.test\nmax_age: 86400\n",
    );
    let message = sts.engine.submit(&["one@s.test"]).remove(0);
    let reply = failure(&sts.engine, &message);
    assert_eq!(
        reply,
        "MTA-STS: the policy of s.test permits none of its exchanges"
    );
    assert!(sts.receiver.connections().is_empty());
}

#[test]
fn an_exchange_that_fails_verification_gives_way_to_the_next() {
    let mut sts = sts(
        "sts-next",
        "version: STSv1\nmode: enforce\nmx: *.s.test\nmax_age: 86400\n",
    );
    sts.dns.mx("s.test", 20, "mx2.s.test");
    let first = sts.authority.issue(&["elsewhere.test"]);
    let second = sts.authority.issue(&["mx2.s.test"]);
    sts.receiver.present(Some(by_name(&[
        ("mx.s.test", &first),
        ("mx2.s.test", &second),
    ])));
    sts.engine.submit(&["one@s.test"]);
    wait_for("the delivery", || sts.receiver.delivered().len() == 1);
    let delivered: Vec<_> = sts
        .receiver
        .connections()
        .into_iter()
        .filter(|connection| !connection.delivered.is_empty())
        .collect();
    assert_eq!(delivered[0].tls.as_deref(), Some("mx2.s.test"));
}

/// A signed zone with one domain, d.test, whose exchange is mx.d.test, and
/// an engine that validates it with the zone's trust anchor.
fn dane(name: &str, receiver: &Receiver, tlsa: impl FnOnce(&Dns, u16)) -> (Dns, Engine) {
    let dns = Dns::signed(&[("d.test", "mx.d.test")]);
    tlsa(&dns, receiver.port);
    let anchor = dns.trust_anchor();
    let engine = Engine::start_with(
        name,
        &dns,
        receiver,
        "trust_anchor = \"anchor.key\"",
        "",
        &[("anchor.key", &anchor)],
    );
    (dns, engine)
}

#[test]
fn tlsa_records_bind_the_exchanges_certificate_whoever_signed_it() {
    let receiver = Receiver::start(Script::default());
    let certified = Certified::self_signed(&["anything.test"]);
    receiver.present(Some(certified.server()));
    let key = sha256(&certified.public_key);
    let (_dns, mut engine) = dane("dane-bound", &receiver, |dns, port| {
        dns.tlsa("mx.d.test", port, 3, 1, 1, key);
    });
    engine.submit(&["one@d.test"]);
    wait_for("the delivery", || receiver.delivered().len() == 1);
    assert_eq!(receiver.connections()[0].tls.as_deref(), Some("mx.d.test"));
}

#[test]
fn a_certificate_its_tlsa_records_do_not_bind_holds_the_mail() {
    let receiver = Receiver::start(Script::default());
    receiver.present(Some(Certified::self_signed(&["mx.d.test"]).server()));
    let other = sha256(&Certified::self_signed(&["mx.d.test"]).public_key);
    let (_dns, mut engine) = dane("dane-unbound", &receiver, |dns, port| {
        dns.tlsa("mx.d.test", port, 3, 1, 1, other);
    });
    let message = engine.submit(&["one@d.test"]).remove(0);
    let reply = failure(&engine, &message);
    assert!(
        reply.starts_with("DANE: the TLS handshake with mx.d.test failed"),
        "{reply}"
    );
    assert!(receiver.delivered().is_empty());
}

#[test]
fn a_bogus_tlsa_answer_leaves_the_exchange_unused() {
    let receiver = Receiver::start(Script::default());
    let certified = Certified::self_signed(&["mx.d.test"]);
    receiver.present(Some(certified.server()));
    let key = sha256(&certified.public_key);
    let (_dns, mut engine) = dane("dane-bogus", &receiver, |dns, port| {
        dns.tlsa("mx.d.test", port, 3, 1, 1, key);
        dns.forge(&format!("_{port}._tcp.mx.d.test"), RecordType::TLSA);
    });
    let message = engine.submit(&["one@d.test"]).remove(0);
    let reply = failure(&engine, &message);
    assert!(
        reply.starts_with("DANE: the TLSA lookup for mx.d.test failed"),
        "{reply}"
    );
    assert!(receiver.connections().is_empty());
}

#[test]
fn unusable_tlsa_records_still_require_tls() {
    let receiver = Receiver::start(Script::default());
    let (_dns, mut engine) = dane("dane-unusable", &receiver, |dns, port| {
        // PKIX-EE, which SMTP cannot use.
        dns.tlsa("mx.d.test", port, 1, 1, 1, vec![0; 32]);
    });
    let message = engine.submit(&["one@d.test"]).remove(0);
    let reply = failure(&engine, &message);
    assert_eq!(
        reply,
        "TLS is required, and mx.d.test does not offer STARTTLS"
    );
    receiver.present(Some(Certified::self_signed(&["anything.test"]).server()));
    engine.submit(&["two@d.test"]);
    wait_for("the delivery over unverified TLS", || {
        receiver.delivered() == ["two@d.test"]
    });
}

#[test]
fn a_secure_exchange_without_tlsa_records_is_delivered_to_as_before() {
    // The zone proves the exchange has no TLSA records, so nothing binds it
    // and nothing requires TLS: the receiver offers none.
    let receiver = Receiver::start(Script::default());
    let (_dns, mut engine) = dane("dane-none", &receiver, |_, _| {});
    engine.submit(&["one@d.test"]);
    wait_for("the delivery", || receiver.delivered().len() == 1);
    assert_eq!(receiver.connections()[0].tls, None);
}

#[test]
fn a_domain_proved_to_have_no_mx_records_is_bound_by_its_own_tlsa_records() {
    let receiver = Receiver::start(Script::default());
    receiver.present(Some(Certified::self_signed(&["n.test"]).server()));
    let other = sha256(&Certified::self_signed(&["n.test"]).public_key);
    let (_dns, mut engine) = dane("dane-mx-less", &receiver, |dns, port| {
        dns.address_of("n.test");
        dns.tlsa("n.test", port, 3, 1, 1, other);
    });
    let message = engine.submit(&["one@n.test"]).remove(0);
    let reply = failure(&engine, &message);
    assert!(
        reply.starts_with("DANE: the TLS handshake with n.test failed"),
        "{reply}"
    );
    assert!(receiver.delivered().is_empty());
}

#[test]
fn a_dane_ta_anchor_binds_the_chains_below_it_within_its_path_length() {
    // d.test's exchange chains through a subordinate to a root that allows
    // none; e.test's through one to a root that allows any.
    let narrow = Authority::constrained(Some(0));
    let wide = Authority::new();
    let receiver = Receiver::start(Script::default());
    let below_narrow = narrow.subordinate().issue(&["mx.d.test"]);
    let below_wide = wide.subordinate().issue(&["mx.e.test"]);
    receiver.present(Some(by_name(&[
        ("mx.d.test", &below_narrow),
        ("mx.e.test", &below_wide),
    ])));
    let (_dns, mut engine) = dane("dane-anchor", &receiver, |dns, port| {
        dns.route("e.test", "mx.e.test");
        dns.tlsa("mx.d.test", port, 2, 0, 1, sha256(&narrow.certificate()));
        dns.tlsa("mx.e.test", port, 2, 0, 1, sha256(&wide.certificate()));
    });
    let held = engine.submit(&["one@d.test"]).remove(0);
    engine.submit(&["one@e.test"]);
    wait_for("the delivery within its path length", || {
        receiver.delivered() == ["one@e.test"]
    });
    let reply = failure(&engine, &held);
    assert!(
        reply.starts_with("DANE: the TLS handshake with mx.d.test failed"),
        "{reply}"
    );
}

#[test]
fn a_dane_ta_certificate_may_name_the_domain_the_mail_is_for() {
    // The exchange presents a certificate naming d.test, not itself: d.test's
    // mail may go, and f.test's, at the same exchange, may not; each
    // domain's mail goes on its own connections, which check its names.
    let authority = Authority::new();
    let receiver = Receiver::start(Script::default());
    receiver.present(Some(authority.issue(&["d.test"]).server()));
    let (_dns, mut engine) = dane("dane-next-hop", &receiver, |dns, port| {
        dns.mx_only("f.test", 10, "mx.d.test");
        dns.tlsa("mx.d.test", port, 2, 0, 1, sha256(&authority.certificate()));
    });
    let held = engine.submit(&["one@f.test"]).remove(0);
    engine.submit(&["one@d.test"]);
    wait_for("d.test's delivery", || {
        receiver.delivered() == ["one@d.test"]
    });
    let reply = failure(&engine, &held);
    assert!(
        reply.starts_with("DANE: the TLS handshake with mx.d.test failed"),
        "{reply}"
    );
}

#[test]
fn an_exchange_reached_through_a_secure_alias_is_bound_at_its_expanded_name() {
    // c.test's exchange is an alias; the TLSA records are at its target
    // alone, and bind another certificate than the one it presents.
    let receiver = Receiver::start(Script::default());
    receiver.present(Some(Certified::self_signed(&["real.c.test"]).server()));
    let other = sha256(&Certified::self_signed(&["real.c.test"]).public_key);
    let (_dns, mut engine) = dane("dane-alias", &receiver, |dns, port| {
        dns.mx_only("c.test", 10, "mx.c.test");
        dns.alias("mx.c.test", "real.c.test");
        dns.address_of("real.c.test");
        dns.tlsa("real.c.test", port, 3, 1, 1, other);
    });
    let message = engine.submit(&["one@c.test"]).remove(0);
    let reply = failure(&engine, &message);
    assert!(
        reply.starts_with("DANE: the TLS handshake with mx.c.test failed"),
        "{reply}"
    );
    assert!(receiver.delivered().is_empty());
}

#[test]
fn an_exchange_whose_certificate_names_none_of_its_names_gives_way_to_the_next() {
    let authority = Authority::new();
    let receiver = Receiver::start(Script::default());
    let elsewhere = authority.issue(&["elsewhere.test"]);
    let second = authority.issue(&["mx2.g.test"]);
    receiver.present(Some(by_name(&[
        ("mx1.g.test", &elsewhere),
        ("mx2.g.test", &second),
    ])));
    let anchor = sha256(&authority.certificate());
    let (_dns, mut engine) = dane("dane-next-exchange", &receiver, |dns, port| {
        dns.mx("g.test", 10, "mx1.g.test");
        dns.mx("g.test", 20, "mx2.g.test");
        dns.tlsa("mx1.g.test", port, 2, 0, 1, anchor.clone());
        dns.tlsa("mx2.g.test", port, 2, 0, 1, anchor);
    });
    engine.submit(&["one@g.test"]);
    wait_for("the delivery through the second", || {
        receiver.delivered() == ["one@g.test"]
    });
    let delivered: Vec<_> = receiver
        .connections()
        .into_iter()
        .filter(|connection| !connection.delivered.is_empty())
        .collect();
    assert_eq!(delivered[0].tls.as_deref(), Some("mx2.g.test"));
}

#[test]
fn tlsa_aliases_that_loop_hold_the_mail() {
    let receiver = Receiver::start(Script::default());
    receiver.present(Some(Certified::self_signed(&["mx.d.test"]).server()));
    let (_dns, mut engine) = dane("dane-alias-loop", &receiver, |dns, port| {
        let name = format!("_{port}._tcp.mx.d.test");
        dns.alias(&name, "a.loop.test");
        dns.alias("a.loop.test", &name);
    });
    let message = engine.submit(&["one@d.test"]).remove(0);
    let reply = failure(&engine, &message);
    assert!(reply.contains("aliases loop"), "{reply}");
    assert!(receiver.connections().is_empty());
}

#[test]
fn a_self_issued_authority_does_not_count_against_an_anchors_path_length() {
    // The anchor allows no intermediate below it; its key's rollover, under
    // its own name, is none.
    let anchor = Authority::constrained(Some(0));
    let receiver = Receiver::start(Script::default());
    receiver.present(Some(anchor.rollover().issue(&["mx.d.test"]).server()));
    let (_dns, mut engine) = dane("dane-rollover", &receiver, |dns, port| {
        dns.tlsa("mx.d.test", port, 2, 0, 1, sha256(&anchor.certificate()));
    });
    engine.submit(&["one@d.test"]);
    wait_for("the delivery", || receiver.delivered() == ["one@d.test"]);
}

#[test]
fn a_dane_ta_certificate_may_name_the_domain_its_aliases_expand_to() {
    // alias.test is canonical.test's alias, whose exchange presents a
    // certificate naming canonical.test.
    let authority = Authority::new();
    let receiver = Receiver::start(Script::default());
    receiver.present(Some(authority.issue(&["canonical.test"]).server()));
    let (_dns, mut engine) = dane("dane-expanded", &receiver, |dns, port| {
        dns.alias("alias.test", "canonical.test");
        dns.mx("canonical.test", 10, "mx.canonical.test");
        dns.tlsa(
            "mx.canonical.test",
            port,
            2,
            0,
            1,
            sha256(&authority.certificate()),
        );
    });
    engine.submit(&["one@alias.test"]);
    wait_for("the delivery", || {
        receiver.delivered() == ["one@alias.test"]
    });
}
