//! SES's tenants, configuration sets and account through the release binary,
//! as Nitrosend provisions and checks them: a
//! tenant and a configuration set with their tags, resources associated by
//! the ARNs Nitrosend builds from its account ID, statuses rendered from
//! holds, and the account's quota; and a tenant's login sending over SMTP
//! for the tenant its `X-SES-TENANT` field names.

mod support;

use std::os::unix::fs::PermissionsExt as _;

use serde_json::{Value, json};
use support::{Dns, Engine, Receiver, Script};

const SES: &str = "[ses]\nlisten = \"127.0.0.1:0\"\ncertificate = \"tls.crt\"\nkey = \"tls.key\"\nregion = \"us-east-1\"";

/// The engine account's resources, as Nitrosend names them from
/// `AWS_ACCOUNT_ID`: the account in twelve digits.
const ARN: &str = "arn:aws:ses:us-east-1:000000000001";

/// A path's label, percent-encoded as SDKs encode one.
fn label(text: &str) -> String {
    text.bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                char::from(byte).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

#[test]
fn a_tenant_and_its_configuration_set_are_provisioned_associated_and_held_as_nitrosend_does() {
    let dns = Dns::start(&[("plain.test", "mx.plain.test")]);
    let receiver = Receiver::start(Script::default());
    let sections = format!("{SES}\n\n[capture]\ndirectory = \"capture\"");
    let mut engine = Engine::start("tenant", &dns, &receiver, "dane = false", &sections);
    let ses = engine.ses_permitted(&["send", "manage"]);
    let post = |path: &str, body: Value| ses.send("POST", path, "", &body.to_string());
    let errortype = |answer: &support::ses::Answer| {
        answer
            .header("x-amzn-errortype")
            .unwrap_or_default()
            .to_owned()
    };
    let tags = json!([
        {"Key": "Application", "Value": "nitrosend"},
        {"Key": "DeliverabilityCohort", "Value": "a"},
    ]);

    // Provisioned as `ses_tenant_provisioner.rb` provisions a cohort.
    let created = post(
        "/v2/email/tenants",
        json!({"TenantName": "cohort-a", "Tags": tags}),
    );
    assert_eq!(created.status, 200, "{}", created.body);
    let tenant = created.json();
    let id = tenant["TenantId"].as_str().unwrap().to_owned();
    assert!(id.starts_with("tn-"), "{tenant}");
    let tenant_arn = format!("{ARN}:tenant/cohort-a/{id}");
    assert_eq!(tenant["TenantArn"], tenant_arn.as_str());
    assert_eq!(tenant["SendingStatus"], "ENABLED");
    assert_eq!(tenant["Tags"], tags);
    assert!(tenant["CreatedTimestamp"].is_number(), "{tenant}");
    let again = post("/v2/email/tenants", json!({"TenantName": "cohort-a"}));
    assert_eq!(errortype(&again), "AlreadyExistsException");
    let configuration = json!({
        "ConfigurationSetName": "cohort-a-events",
        "ReputationOptions": {"ReputationMetricsEnabled": true},
        "Tags": tags,
    });
    let created = post("/v2/email/configuration-sets", configuration.clone());
    assert_eq!(created.status, 200, "{}", created.body);
    let again = post("/v2/email/configuration-sets", configuration);
    assert_eq!(errortype(&again), "AlreadyExistsException");
    let fresh = post(
        "/v2/email/configuration-sets",
        json!({"ConfigurationSetName": "fresh", "ReputationOptions": {"ReputationMetricsEnabled": true, "LastFreshStart": 1_800_000_000}}),
    );
    assert_eq!(errortype(&fresh), "BadRequestException", "{}", fresh.body);
    let tracked = post(
        "/v2/email/configuration-sets",
        json!({"ConfigurationSetName": "tracked", "TrackingOptions": {"CustomRedirectDomain": "t.test"}}),
    );
    assert_eq!(
        errortype(&tracked),
        "BadRequestException",
        "{}",
        tracked.body
    );
    let put = ses.send(
        "PUT",
        "/v2/email/configuration-sets/cohort-a-events/reputation-options",
        "",
        &json!({"ReputationMetricsEnabled": false}).to_string(),
    );
    assert_eq!(put.status, 200, "{}", put.body);
    let got = ses
        .send(
            "GET",
            "/v2/email/configuration-sets/cohort-a-events",
            "",
            "",
        )
        .json();
    assert_eq!(
        got["ReputationOptions"]["ReputationMetricsEnabled"], false,
        "{got}"
    );
    assert_eq!(got["SendingOptions"]["SendingEnabled"], true, "{got}");
    assert_eq!(got["Tags"], tags);
    // Listed a page at a time in the order of their names: with a GET, as
    // Nitrosend's SDK lists, and with the POST of the engine's model, as
    // later SDKs do.
    let other = post(
        "/v2/email/configuration-sets",
        json!({"ConfigurationSetName": "cohort-b-events"}),
    );
    assert_eq!(other.status, 200, "{}", other.body);
    let mut names = Vec::new();
    let mut query = "PageSize=1".to_owned();
    loop {
        let page = ses.send("GET", "/v2/email/configuration-sets", &query, "");
        assert_eq!(page.status, 200, "{}", page.body);
        let page = page.json();
        let sets = page["ConfigurationSets"].as_array().unwrap().clone();
        assert_eq!(sets.len(), 1, "{page}");
        names.extend(sets);
        match page["NextToken"].as_str() {
            Some(token) => query = format!("NextToken={token}&PageSize=1"),
            None => break,
        }
    }
    assert_eq!(names, ["cohort-a-events", "cohort-b-events"]);
    let posted = post("/v2/email/list-configuration-sets", json!({}));
    assert_eq!(posted.status, 200, "{}", posted.body);
    assert_eq!(posted.json()["ConfigurationSets"], json!(names));

    // Associated by ARN, as the provisioner and `tenant_identity_associator.rb`
    // associate them, once each.
    let configuration_arn = format!("{ARN}:configuration-set/cohort-a-events");
    let identity_arn = format!("{ARN}:identity/sender.test");
    let associate = |arn: &str| {
        post(
            "/v2/email/tenants/resources",
            json!({"TenantName": "cohort-a", "ResourceArn": arn}),
        )
    };
    for arn in [&configuration_arn, &identity_arn] {
        assert_eq!(associate(arn).status, 200);
        assert_eq!(errortype(&associate(arn)), "AlreadyExistsException");
    }
    let elsewhere = associate("arn:aws:ses:us-east-1:999999999999:identity/sender.test");
    assert_eq!(errortype(&elsewhere), "NotFoundException");
    let tenants_of = |arn: &str| {
        post(
            "/v2/email/resources/tenants/list",
            json!({"ResourceArn": arn, "PageSize": 100}),
        )
        .json()["ResourceTenants"]
            .as_array()
            .unwrap()
            .iter()
            .map(|tenant| tenant["TenantName"].as_str().unwrap().to_owned())
            .collect::<Vec<_>>()
    };
    assert_eq!(tenants_of(&identity_arn), ["cohort-a"]);
    let resources = post(
        "/v2/email/tenants/resources/list",
        json!({"TenantName": "cohort-a", "PageSize": 1}),
    )
    .json();
    assert_eq!(
        resources["TenantResources"],
        json!([{"ResourceType": "CONFIGURATION_SET", "ResourceArn": configuration_arn}])
    );
    let token = resources["NextToken"].as_str().unwrap();
    let rest = post(
        "/v2/email/tenants/resources/list",
        json!({"TenantName": "cohort-a", "PageSize": 1, "NextToken": token}),
    )
    .json();
    assert_eq!(
        rest["TenantResources"],
        json!([{"ResourceType": "EMAIL_IDENTITY", "ResourceArn": identity_arn}])
    );
    assert!(rest["NextToken"].is_null(), "{rest}");
    let listed = post("/v2/email/tenants/list", json!({})).json();
    assert_eq!(listed["Tenants"][0]["TenantArn"], tenant_arn.as_str());

    // Sent for the tenant, under its configuration set.
    let send = || {
        post(
            "/v2/email/outbound-emails",
            json!({
                "FromEmailAddress": "app@sender.test",
                "Destination": {"ToAddresses": ["one@plain.test"]},
                "Content": {"Simple": {"Subject": {"Data": "a test"}, "Body": {"Text": {"Data": "hello"}}}},
                "TenantName": "cohort-a",
                "ConfigurationSetName": "cohort-a-events",
            }),
        )
    };
    let sent = send();
    assert_eq!(sent.status, 200, "{}", sent.body);

    // Disabled through its reputation entity, its status and its mail say
    // so, and enabled again, they do not.
    let entity = format!(
        "/v2/email/reputation/entities/RESOURCE/{}",
        label(&tenant_arn)
    );
    let reputation = || ses.send("GET", &entity, "", "").json()["ReputationEntity"].clone();
    let shown = reputation();
    assert_eq!(shown["SendingStatusAggregate"], "ENABLED", "{shown}");
    assert_eq!(shown["CustomerManagedStatus"]["Status"], "ENABLED");
    assert_eq!(shown["AwsSesManagedStatus"]["Status"], "ENABLED");
    assert_eq!(shown["ReputationImpact"], "LOW");
    let status = |status: &str| {
        ses.send(
            "PUT",
            &format!("{entity}/customer-managed-status"),
            "",
            &json!({"SendingStatus": status}).to_string(),
        )
    };
    assert_eq!(status("DISABLED").status, 200);
    let shown = reputation();
    assert_eq!(shown["SendingStatusAggregate"], "DISABLED", "{shown}");
    assert!(
        shown["CustomerManagedStatus"]["Cause"].is_string(),
        "{shown}"
    );
    let tenant = post("/v2/email/tenants/get", json!({"TenantName": "cohort-a"})).json();
    assert_eq!(tenant["Tenant"]["SendingStatus"], "DISABLED", "{tenant}");
    assert_eq!(errortype(&send()), "SendingPausedException");
    assert_eq!(status("ENABLED").status, 200);
    assert_eq!(status("ENABLED").status, 200, "enabling twice is enabled");
    assert_eq!(reputation()["SendingStatusAggregate"], "ENABLED");

    // Dissociated, its mail is refused in the words Nitrosend repairs by.
    let dissociate = || {
        post(
            "/v2/email/tenants/resources/delete",
            json!({"TenantName": "cohort-a", "ResourceArn": identity_arn}),
        )
    };
    assert_eq!(dissociate().status, 200);
    assert_eq!(errortype(&dissociate()), "NotFoundException");
    let refused = send();
    assert_eq!(errortype(&refused), "BadRequestException");
    assert!(
        refused
            .body
            .contains("Tenant not associated with resources"),
        "{}",
        refused.body
    );

    // The account, as `ses_tenant_readiness_checker.rb` reads it.
    let account = ses.send("GET", "/v2/email/account", "", "").json();
    assert_eq!(account["SendingEnabled"], true, "{account}");
    assert_eq!(account["EnforcementStatus"], "HEALTHY");
    assert_eq!(account["SendQuota"]["Max24HourSend"], -1.0);
    assert_eq!(account["SendQuota"]["SentLast24Hours"], 1.0);
}

#[test]
fn a_tenants_login_sends_over_smtp_for_the_tenant_its_field_names() {
    let dns = Dns::start(&[("plain.test", "mx.plain.test")]);
    let receiver = Receiver::start(Script::default());
    let sections = "[capture]\ndirectory = \"capture\"";
    let engine = Engine::start("smtp-tenant", &dns, &receiver, "dane = false", sections);
    let answers = engine.admin(&[
        json!({"op": "put_account", "account": 1}),
        json!({"op": "put_identity", "account": 1, "name": "sender.test"}),
        json!({"op": "put_tenant", "account": 1, "name": "acme", "identities": ["sender.test"]}),
        json!({"op": "create_login", "account": 1, "user": "acme", "tenants": ["acme"]}),
    ]);
    let password = answers[3]["ok"]["password"]
        .as_str()
        .unwrap_or_else(|| panic!("a login: {answers:?}"));
    let mut session = engine.session_as("acme", password);
    let mut send = |fields: &str| {
        session.send("MAIL FROM:<app@sender.test>", 250);
        session.send("RCPT TO:<one@plain.test>", 250);
        session.send("DATA", 354);
        session.ask(&format!(
            "{fields}From: app@sender.test\r\nTo: one@plain.test\r\nSubject: a test\r\n\r\nhello\r\n."
        ))
    };
    // Naming no tenant, it may not send; naming its own, it does.
    let unnamed = send("");
    assert!(unnamed.starts_with("550 5.7.1"), "{unnamed}");
    let accepted = send("X-SES-TENANT: acme\r\n");
    assert!(accepted.starts_with("250"), "{accepted}");
    // Sent without the field, as SES takes it out.
    let directory = engine.dir.join("capture");
    let mut sent = Vec::new();
    support::wait_for("its capture", || {
        sent = std::fs::read_dir(&directory)
            .into_iter()
            .flatten()
            .flatten()
            .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "eml"))
            .filter_map(|entry| std::fs::read_to_string(entry.path()).ok())
            .collect();
        sent.len() == 1
    });
    assert!(sent[0].contains("Subject: a test"), "{}", sent[0]);
    assert!(
        !sent[0].to_ascii_lowercase().contains("x-ses-tenant"),
        "{}",
        sent[0]
    );
}

#[test]
fn the_suppression_list_is_read_as_nitrosends_preflight_reads_it_and_managed_through_ses() {
    let dns = Dns::start(&[("plain.test", "mx.plain.test")]);
    let receiver = Receiver::start(Script::default());
    let sections = format!("{SES}\n\n[capture]\ndirectory = \"capture\"");
    let mut engine = Engine::start("suppression", &dns, &receiver, "dane = false", &sections);
    let ses = engine.ses_permitted(&["send", "manage"]);
    let errortype = |answer: &support::ses::Answer| {
        answer
            .header("x-amzn-errortype")
            .unwrap_or_default()
            .to_owned()
    };
    let address = |text: &str| format!("/v2/email/suppression/addresses/{}", label(text));
    let get = |text: &str| ses.send("GET", &address(text), "", "");
    let put = |text: &str, reason: &str| {
        ses.send(
            "PUT",
            "/v2/email/suppression/addresses",
            "",
            &json!({"EmailAddress": text, "Reason": reason}).to_string(),
        )
    };
    // Not on the list, as the preflight reads it.
    assert_eq!(errortype(&get("one@plain.test")), "NotFoundException");
    assert_eq!(put("One@plain.test", "BOUNCE").status, 200);
    let found = get("ONE@plain.test");
    assert_eq!(found.status, 200, "{}", found.body);
    let destination = &found.json()["SuppressedDestination"];
    assert_eq!(
        destination["EmailAddress"], "One@plain.test",
        "as it was given"
    );
    assert_eq!(destination["Reason"], "BOUNCE");
    assert!(destination["LastUpdateTime"].is_number(), "{destination}");
    assert_eq!(put("two@plain.test", "COMPLAINT").status, 200);
    // One the operator suppressed is shown as a bounce.
    let answers = engine.admin(&[json!({
        "op": "suppress", "account": 1, "addresses": ["three@plain.test"], "reason": "operator"
    })]);
    assert!(answers[0]["ok"].is_object(), "{answers:?}");
    let list = |query: &str| ses.send("GET", "/v2/email/suppression/addresses", query, "");
    let listed = |query: &str| -> Vec<(String, String)> {
        list(query).json()["SuppressedDestinationSummaries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|summary| {
                (
                    summary["EmailAddress"].as_str().unwrap().to_owned(),
                    summary["Reason"].as_str().unwrap().to_owned(),
                )
            })
            .collect()
    };
    let pair = |address: &str, reason: &str| (address.to_owned(), reason.to_owned());
    assert_eq!(
        listed("Reason=BOUNCE"),
        [
            pair("One@plain.test", "BOUNCE"),
            pair("three@plain.test", "BOUNCE")
        ]
    );
    assert_eq!(
        listed("Reason=COMPLAINT"),
        [pair("two@plain.test", "COMPLAINT")]
    );
    let first = list("PageSize=1").json();
    let token = first["NextToken"].as_str().unwrap().to_owned();
    assert_eq!(
        listed(&format!("NextToken={token}&PageSize=2")),
        [
            pair("three@plain.test", "BOUNCE"),
            pair("two@plain.test", "COMPLAINT")
        ]
    );
    assert_eq!(
        errortype(&list("NextToken=nonsense")),
        "InvalidNextTokenException"
    );
    // A tenant's own list is not kept.
    let tenant = ses.send(
        "PUT",
        "/v2/email/suppression/addresses",
        "",
        &json!({"EmailAddress": "four@plain.test", "Reason": "BOUNCE", "TenantName": "cohort-a"})
            .to_string(),
    );
    assert_eq!(errortype(&tenant), "BadRequestException");
    // Taken off, it is not on the list, and taking it off again finds
    // nothing.
    let delete = || ses.send("DELETE", &address("one@plain.test"), "", "");
    assert_eq!(delete().status, 200);
    assert_eq!(errortype(&delete()), "NotFoundException");
    assert_eq!(errortype(&get("one@plain.test")), "NotFoundException");
}

#[test]
fn dedicated_ip_pools_are_the_accounts_pools_of_its_egresses() {
    let dns = Dns::start(&[("plain.test", "mx.plain.test")]);
    let receiver = Receiver::start(Script::default());
    let sections = format!("{SES}\n\n[capture]\ndirectory = \"capture\"");
    let mut engine = Engine::start("pools", &dns, &receiver, "dane = false", &sections);
    let ses = engine.ses_permitted(&["send", "manage"]);
    let errortype = |answer: &support::ses::Answer| {
        answer
            .header("x-amzn-errortype")
            .unwrap_or_default()
            .to_owned()
    };
    let answers = engine.admin(&[json!({
        "op": "put_egress", "account": 1, "address": "192.0.2.10", "helo": "mta1.sender.test"
    })]);
    assert!(answers[0]["ok"].is_object(), "{answers:?}");
    let pool = |body: Value| {
        ses.send(
            "POST",
            "/v2/email/dedicated-ip-pools",
            "",
            &body.to_string(),
        )
    };
    assert_eq!(pool(json!({"PoolName": "transactional"})).status, 200);
    assert_eq!(
        errortype(&pool(json!({"PoolName": "transactional"}))),
        "AlreadyExistsException"
    );
    let managed = pool(json!({"PoolName": "managed", "ScalingMode": "MANAGED"}));
    assert_eq!(errortype(&managed), "BadRequestException");
    let into = |ip: &str, pool: &str| {
        ses.send(
            "PUT",
            &format!("/v2/email/dedicated-ips/{ip}/pool"),
            "",
            &json!({"DestinationPoolName": pool}).to_string(),
        )
    };
    assert_eq!(into("192.0.2.10", "transactional").status, 200);
    assert_eq!(
        errortype(&into("192.0.2.99", "transactional")),
        "NotFoundException"
    );
    assert_eq!(
        errortype(&into("192.0.2.10", "nowhere")),
        "NotFoundException"
    );
    let created = ses.send(
        "POST",
        "/v2/email/configuration-sets",
        "",
        &json!({"ConfigurationSetName": "receipts"}).to_string(),
    );
    assert_eq!(created.status, 200, "{}", created.body);
    let delivery = |body: Value| {
        ses.send(
            "PUT",
            "/v2/email/configuration-sets/receipts/delivery-options",
            "",
            &body.to_string(),
        )
    };
    assert_eq!(
        delivery(json!({"SendingPoolName": "transactional"})).status,
        200
    );
    let required = delivery(json!({"SendingPoolName": "transactional", "TlsPolicy": "REQUIRE"}));
    assert_eq!(errortype(&required), "BadRequestException");
    let got = ses
        .send("GET", "/v2/email/configuration-sets/receipts", "", "")
        .json();
    assert_eq!(
        got["DeliveryOptions"]["SendingPoolName"], "transactional",
        "{got}"
    );
    let egresses = engine.admin(&[json!({"op": "list", "kind": "egresses"})]);
    assert_eq!(
        egresses[0]["ok"]["egresses"][0]["pool"], "transactional",
        "{egresses:?}"
    );

    // Its warmup: an egress with no cap is done; one capped at
    // its ladder's third rung is in progress, as far up the bundle's ladder
    // as its own cap, and one capped at a site alone as far as that.
    let answers = engine.admin(&[
        json!({"op": "put_egress", "account": 1, "address": "192.0.2.11",
               "helo": "mta2.sender.test", "daily_cap": 200}),
        json!({"op": "put_egress", "account": 1, "address": "192.0.2.12",
               "helo": "mta3.sender.test"}),
        json!({"op": "put_cap", "account": 1, "address": "192.0.2.12",
               "site": "Google", "daily_cap": 50}),
        json!({"op": "put_cap", "account": 1, "address": "192.0.2.99", "daily_cap": 50}),
    ]);
    assert!(
        answers[..3].iter().all(|answer| answer["ok"].is_object()),
        "{answers:?}"
    );
    assert!(
        answers[3]["error"]["code"] == "unknown",
        "an address it has not: {answers:?}"
    );
    let dedicated = |ip: &str| ses.send("GET", &format!("/v2/email/dedicated-ips/{ip}"), "", "");
    let warmup = |ip: &str| {
        let got = dedicated(ip).json();
        let ip = &got["DedicatedIp"];
        (
            ip["WarmupStatus"].as_str().unwrap_or_default().to_owned(),
            ip["WarmupPercentage"].as_i64().unwrap_or(-2),
        )
    };
    assert_eq!(warmup("192.0.2.10"), ("DONE".to_owned(), 100));
    // 17 rungs, two below 200.
    assert_eq!(warmup("192.0.2.11"), ("IN_PROGRESS".to_owned(), 11));
    assert_eq!(warmup("192.0.2.12"), ("IN_PROGRESS".to_owned(), 0));
    assert_eq!(
        dedicated("192.0.2.10").json()["DedicatedIp"]["PoolName"],
        "transactional"
    );
    assert_eq!(errortype(&dedicated("192.0.2.99")), "NotFoundException");
    let listed = |query: &str| {
        let got = ses.send("GET", "/v2/email/dedicated-ips", query, "").json();
        let ips: Vec<String> = got["DedicatedIps"]
            .as_array()
            .map(|ips| {
                ips.iter()
                    .map(|ip| ip["Ip"].as_str().unwrap_or_default().to_owned())
                    .collect()
            })
            .unwrap_or_default();
        (ips, got["NextToken"].as_str().map(str::to_owned))
    };
    let (first, token) = listed("PageSize=2");
    assert_eq!(first, ["192.0.2.10", "192.0.2.11"]);
    let token = token.expect("one more");
    let (rest, last) = listed(&format!("NextToken={token}&PageSize=2"));
    assert_eq!((rest, last), (vec!["192.0.2.12".to_owned()], None));
    assert_eq!(listed("PoolName=transactional").0, ["192.0.2.10"]);
    let unknown = ses.send("GET", "/v2/email/dedicated-ips", "PoolName=nowhere", "");
    assert_eq!(errortype(&unknown), "NotFoundException");
    let egresses = engine.admin(&[json!({"op": "list", "kind": "egresses"})]);
    let third = egresses[0]["ok"]["egresses"]
        .as_array()
        .and_then(|egresses| {
            egresses
                .iter()
                .find(|egress| egress["address"] == "192.0.2.12")
        })
        .cloned()
        .unwrap_or_default();
    assert_eq!(third["site_caps"], json!({"Google": 50}), "{egresses:?}");
    assert_eq!(third["daily_cap"], Value::Null);
    // Warmup judges only a day this run of the engine saw end, and only
    // minutes past its midnight: started today, it has judged none, though
    // the day before is over, and the caps stand as they were put, even if
    // this wait crosses midnight.
    std::thread::sleep(std::time::Duration::from_secs(2));
    let egresses = engine.admin(&[json!({"op": "list", "kind": "egresses"})]);
    let second = egresses[0]["ok"]["egresses"]
        .as_array()
        .and_then(|egresses| {
            egresses
                .iter()
                .find(|egress| egress["address"] == "192.0.2.11")
        })
        .cloned()
        .unwrap_or_default();
    assert!(second["warmup"].is_null(), "{second}");
    assert_eq!(second["daily_cap"], 200);
}

#[test]
fn a_tenants_mail_is_sealed_under_its_own_key_and_removing_the_tenant_erases_it() {
    let dns = Dns::start(&[("plain.test", "mx.plain.test")]);
    let receiver = Receiver::start(Script::default());
    let sections = format!(
        "{SES}\n\n[operator]\nlisten = \"127.0.0.1:0\"\n\n[capture]\ndirectory = \"capture\""
    );
    let mut engine = Engine::start("tenant-keys", &dns, &receiver, "dane = false", &sections);
    let config = engine.dir.join("config.toml");
    let text = std::fs::read_to_string(&config).unwrap();
    std::fs::write(
        &config,
        text.replace(
            "keys = \"keys\"",
            "keys = \"keys\"\nencryption = \"tenant\"",
        ),
    )
    .unwrap();
    engine.restart();
    let ses = engine.ses_permitted(&["send", "manage"]);
    let keys = engine.dir.join("keys.tenants");
    let kept = || -> Vec<String> {
        std::fs::read_dir(&keys)
            .map(|entries| {
                entries
                    .flatten()
                    .map(|entry| entry.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default()
    };
    assert!(kept().is_empty(), "no tenant, no key");
    // Its key is made, its owner's alone, before the tenant is.
    let answers = engine.admin(&[
        json!({"op": "put_identity", "account": 1, "name": "brand.test"}),
        json!({"op": "put_tenant", "account": 1, "name": "acme", "identities": ["brand.test"]}),
        json!({"op": "hold", "account": 1, "tenant": "acme", "accepting": true, "reason": "a look"}),
    ]);
    assert!(
        answers.iter().all(|answer| answer["ok"].is_object()),
        "{answers:?}"
    );
    let files = kept();
    assert_eq!(files.len(), 1, "{files:?}");
    let mode = std::fs::metadata(keys.join(&files[0]))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
    let body = json!({
        "FromEmailAddress": "news@brand.test",
        "Destination": {"ToAddresses": ["tenant.reader@plain.test"]},
        "Content": {"Simple": {"Subject": {"Data": "for acme"}, "Body": {"Text": {"Data": "hello"}}}},
        "TenantName": "acme",
    });
    let sent = ses.send("POST", "/v2/email/outbound-emails", "", &body.to_string());
    assert_eq!(sent.status, 200, "{}", sent.body);
    let message = sent.json()["MessageId"].as_str().unwrap().to_owned();
    support::wait_for("its delivery paused", || {
        engine.explain(&message)[0]["state"] == "paused"
    });
    let in_the_clear = |needle: &[u8]| {
        ["store.db", "store.db-wal"].iter().any(|file| {
            std::fs::read(engine.dir.join(file))
                .is_ok_and(|bytes| bytes.windows(needle.len()).any(|window| window == needle))
        })
    };
    assert!(!in_the_clear(b"tenant.reader"));
    assert_eq!(
        engine.explain(&message)[0]["recipient"],
        "tenant.reader@plain.test"
    );
    // Released, it is captured, sealed under its key as its body is, and
    // the inspector opens it.
    let answers = engine.admin(&[json!({"op": "release", "account": 1, "tenant": "acme"})]);
    assert!(answers[0]["ok"].is_object(), "{answers:?}");
    support::wait_for("its delivery captured", || {
        engine.explain(&message)[0]["state"] == "finished"
    });
    let capture = engine.dir.join("capture");
    let captured: Vec<Vec<u8>> = std::fs::read_dir(&capture)
        .unwrap()
        .flatten()
        .map(|entry| std::fs::read(entry.path()).unwrap())
        .collect();
    assert_eq!(captured.len(), 2, "its content and its envelope");
    for needle in [&b"tenant.reader"[..], b"for acme", b"hello"] {
        assert!(
            !captured
                .iter()
                .any(|bytes| bytes.windows(needle.len()).any(|window| window == needle)),
            "{} is captured in the clear",
            String::from_utf8_lossy(needle)
        );
    }
    let (status, index) = engine.operator("/capture");
    assert_eq!(status, 200);
    assert!(
        index.contains("1 captured") && index.contains("tenant.reader@plain.test"),
        "{index}"
    );
    // Removed, its key goes, and its mail reads as erased: in the store and
    // in its capture, which the inspector no longer has.
    let answers = engine.admin(&[json!({"op": "remove_tenant", "account": 1, "name": "acme"})]);
    assert!(answers[0]["ok"].is_object(), "{answers:?}");
    // Its file goes first, then the engine forgets it.
    support::wait_for("its key erased", || {
        kept().is_empty() && engine.explain(&message)[0]["recipient"] == "erased@erased.invalid"
    });
    let (status, index) = engine.operator("/capture");
    assert_eq!(status, 200);
    assert!(index.contains("Nothing captured yet"), "{index}");
    // One created through SES's API is given its key as well.
    let created = ses.send(
        "POST",
        "/v2/email/tenants",
        "",
        &json!({"TenantName": "beta"}).to_string(),
    );
    assert_eq!(created.status, 200, "{}", created.body);
    assert_eq!(kept().len(), 1);
    // Removed and put again together, beta is a new tenant, created with a
    // key of its own whatever the policy the put was asked under held, and
    // the old one's goes; its mail is kept, sealed.
    let before = kept();
    let answers = engine.admin(&[
        json!({"op": "remove_tenant", "account": 1, "name": "beta"}),
        json!({"op": "put_tenant", "account": 1, "name": "beta", "identities": ["brand.test"]}),
    ]);
    assert!(
        answers.iter().all(|answer| answer["ok"].is_object()),
        "{answers:?}"
    );
    support::wait_for("the old beta's key erased", || {
        let now = kept();
        now.len() == 1 && now != before
    });
    let body = json!({
        "FromEmailAddress": "news@brand.test",
        "Destination": {"ToAddresses": ["beta.reader@plain.test"]},
        "Content": {"Simple": {"Subject": {"Data": "for beta"}, "Body": {"Text": {"Data": "hello"}}}},
        "TenantName": "beta",
    });
    let sent = ses.send("POST", "/v2/email/outbound-emails", "", &body.to_string());
    assert_eq!(sent.status, 200, "{}", sent.body);
    let theirs = sent.json()["MessageId"].as_str().unwrap().to_owned();
    support::wait_for("beta's mail captured", || {
        engine.explain(&theirs)[0]["state"] == "finished"
    });
    assert_eq!(
        engine.explain(&theirs)[0]["recipient"],
        "beta.reader@plain.test"
    );
    // A restart finds nothing to give back, and keeps beta's; a key file a
    // stop left in part, never published, is cleared away.
    std::fs::write(keys.join("00000000000000ab.making"), "0123").unwrap();
    engine.restart();
    assert_eq!(
        engine.explain(&message)[0]["recipient"],
        "erased@erased.invalid"
    );
    let files = kept();
    assert!(
        files.len() == 1 && !files[0].ends_with(".making"),
        "{files:?}"
    );
    // With a tenant's key kept, no other mode starts: beta's mail would
    // outlive its key.
    engine.stop();
    for mode in ["installation", "off"] {
        let text = std::fs::read_to_string(&config).unwrap();
        let text = text.replace(
            "encryption = \"tenant\"",
            &format!("encryption = \"{mode}\""),
        );
        std::fs::write(&config, &text).unwrap();
        let refused = engine.start_again().expect_err("refused");
        assert!(
            refused.contains("encryption stays `tenant` until every tenant with a key is removed"),
            "{refused}"
        );
        std::fs::write(
            &config,
            text.replace(
                &format!("encryption = \"{mode}\""),
                "encryption = \"tenant\"",
            ),
        )
        .unwrap();
    }
}
