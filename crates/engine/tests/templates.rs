//! SES's email templates through the release binary: created, read,
//! listed, updated and deleted as SDKs call them, and mail sent by a
//! template's name, its parts filled from the request's data.

mod support;

use serde_json::{Value, json};
use support::{Dns, Engine, Receiver, Script};

/// The account's resources, as SDKs name them.
const ARN: &str = "arn:aws:ses:us-east-1:000000000001";

const SES: &str = "[ses]\nlisten = \"127.0.0.1:0\"\ncertificate = \"tls.crt\"\nkey = \"tls.key\"\nregion = \"us-east-1\"";

#[test]
fn a_kept_template_is_managed_and_mail_is_sent_by_its_name() {
    let dns = Dns::start(&[("plain.test", "mx.plain.test")]);
    let receiver = Receiver::start(Script::default());
    let sections = format!("{SES}\n\n[capture]\ndirectory = \"capture\"");
    let mut engine = Engine::start("templates", &dns, &receiver, "dane = false", &sections);
    let ses = engine.ses_permitted(&["send", "manage"]);
    let call = |method: &str, path: &str, body: Value| {
        let body = if body.is_null() {
            String::new()
        } else {
            body.to_string()
        };
        ses.send(method, path, "", &body)
    };
    let errortype = |answer: &support::ses::Answer| {
        answer
            .header("x-amzn-errortype")
            .unwrap_or_default()
            .to_owned()
    };

    // Created, and again refused as existing.
    let template = json!({
        "TemplateName": "welcome",
        "TemplateContent": {"Subject": "Welcome, {{name}}", "Text": "Hello {{name}}"},
    });
    let created = call("POST", "/v2/email/templates", template.clone());
    assert_eq!(created.status, 200, "{}", created.body);
    let again = call("POST", "/v2/email/templates", template);
    assert_eq!(
        errortype(&again),
        "AlreadyExistsException",
        "{}",
        again.body
    );

    // One the engine cannot render is refused as it is kept, not when mail
    // is sent by it.
    let blocked = call(
        "POST",
        "/v2/email/templates",
        json!({
            "TemplateName": "blocked",
            "TemplateContent": {"Subject": "Hi", "Text": "{{#if name}}Hello{{/if}}"},
        }),
    );
    assert_eq!(
        errortype(&blocked),
        "BadRequestException",
        "{}",
        blocked.body
    );
    // A page is 1 to 100 templates.
    for size in ["PageSize=0", "PageSize=101"] {
        let refused = ses.send("GET", "/v2/email/templates", size, "");
        assert_eq!(
            errortype(&refused),
            "BadRequestException",
            "{size}: {}",
            refused.body
        );
    }

    // Updated, then read and listed as it now is.
    let updated = call(
        "PUT",
        "/v2/email/templates/welcome",
        json!({"TemplateContent": {"Subject": "Welcome back, {{name}}", "Text": "Hello again, {{name}}"}}),
    );
    assert_eq!(updated.status, 200, "{}", updated.body);
    let got = call("GET", "/v2/email/templates/welcome", Value::Null).json();
    assert_eq!(got["TemplateName"], "welcome");
    assert_eq!(
        got["TemplateContent"]["Subject"], "Welcome back, {{name}}",
        "{got}"
    );
    let listed = ses
        .send("GET", "/v2/email/templates", "PageSize=10", "")
        .json();
    assert_eq!(
        listed["TemplatesMetadata"][0]["TemplateName"], "welcome",
        "{listed}"
    );
    assert!(
        listed["TemplatesMetadata"][0]["CreatedTimestamp"].is_number(),
        "{listed}"
    );

    // Mail sent by its name, its parts filled.
    let by_name = |name: &str| {
        call(
            "POST",
            "/v2/email/outbound-emails",
            json!({
                "FromEmailAddress": "app@sender.test",
                "Destination": {"ToAddresses": ["one@plain.test"]},
                "Content": {"Template": {"TemplateName": name, "TemplateData": "{\"name\":\"Ann\"}"}},
            }),
        )
    };
    let sent = by_name("welcome");
    assert_eq!(sent.status, 200, "{}", sent.body);
    let directory = engine.dir.join("capture");
    let mut captured = Vec::new();
    support::wait_for("its capture", || {
        captured = std::fs::read_dir(&directory)
            .into_iter()
            .flatten()
            .flatten()
            .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "eml"))
            .filter_map(|entry| std::fs::read_to_string(entry.path()).ok())
            .collect();
        captured.len() == 1
    });
    assert!(
        captured[0].contains("Subject: Welcome back, Ann"),
        "{}",
        captured[0]
    );
    assert!(captured[0].contains("Hello again, Ann"), "{}", captured[0]);

    // Sent in bulk by its name and by its ARN, each entry filled from its
    // own data over the default's.
    for template in [
        json!({"TemplateName": "welcome", "TemplateData": "{\"name\":\"nobody\"}"}),
        json!({"TemplateArn": format!("{ARN}:template/welcome"), "TemplateData": "{\"name\":\"nobody\"}"}),
    ] {
        let bulk = call(
            "POST",
            "/v2/email/outbound-bulk-emails",
            json!({
                "FromEmailAddress": "app@sender.test",
                "DefaultContent": {"Template": template},
                "BulkEmailEntries": [
                    {"Destination": {"ToAddresses": ["two@plain.test"]},
                     "ReplacementEmailContent": {"ReplacementTemplate": {"ReplacementTemplateData": "{\"name\":\"Bo\"}"}}},
                    {"Destination": {"ToAddresses": ["three@plain.test"]},
                     "ReplacementEmailContent": {"ReplacementTemplate": {"ReplacementTemplateData": "{\"name\":\"Di\"}"}}},
                ],
            }),
        );
        assert_eq!(bulk.status, 200, "{}", bulk.body);
        let results = bulk.json()["BulkEmailEntryResults"].clone();
        assert_eq!(results[0]["Status"], "SUCCESS", "{results}");
        assert_eq!(results[1]["Status"], "SUCCESS", "{results}");
    }
    let mut subjects: Vec<String> = Vec::new();
    support::wait_for("the bulk entries' captures", || {
        subjects = std::fs::read_dir(&directory)
            .into_iter()
            .flatten()
            .flatten()
            .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "eml"))
            .filter_map(|entry| std::fs::read_to_string(entry.path()).ok())
            .filter_map(|content| {
                content
                    .lines()
                    .find_map(|line| line.strip_prefix("Subject: ").map(str::to_owned))
            })
            .collect();
        subjects.len() == 5
    });
    subjects.sort();
    assert_eq!(
        subjects,
        [
            "Welcome back, Ann",
            "Welcome back, Bo",
            "Welcome back, Bo",
            "Welcome back, Di",
            "Welcome back, Di"
        ]
    );

    // Sent for a tenant, only once it is associated with the tenant.
    let created = call(
        "POST",
        "/v2/email/tenants",
        json!({"TenantName": "cohort-a"}),
    );
    assert_eq!(created.status, 200, "{}", created.body);
    let associate = |arn: &str| {
        call(
            "POST",
            "/v2/email/tenants/resources",
            json!({"TenantName": "cohort-a", "ResourceArn": arn}),
        )
    };
    for arn in [
        format!("{ARN}:identity/sender.test"),
        format!("{ARN}:template/welcome"),
    ] {
        if arn.ends_with("template/welcome") {
            let refused = call(
                "POST",
                "/v2/email/outbound-emails",
                json!({
                    "FromEmailAddress": "app@sender.test",
                    "Destination": {"ToAddresses": ["one@plain.test"]},
                    "Content": {"Template": {"TemplateName": "welcome", "TemplateData": "{\"name\":\"Cy\"}"}},
                    "TenantName": "cohort-a",
                }),
            );
            assert_eq!(
                errortype(&refused),
                "BadRequestException",
                "{}",
                refused.body
            );
            // Refused for the template, its identity now associated.
            assert!(
                refused
                    .body
                    .contains("Tenant not associated with resources")
                    && refused.body.contains(":template/welcome"),
                "{}",
                refused.body
            );
        }
        let associated = associate(&arn);
        assert_eq!(associated.status, 200, "{arn}: {}", associated.body);
    }
    let for_tenant = call(
        "POST",
        "/v2/email/outbound-emails",
        json!({
            "FromEmailAddress": "app@sender.test",
            "Destination": {"ToAddresses": ["one@plain.test"]},
            "Content": {"Template": {"TemplateName": "welcome", "TemplateData": "{\"name\":\"Cy\"}"}},
            "TenantName": "cohort-a",
        }),
    );
    assert_eq!(for_tenant.status, 200, "{}", for_tenant.body);
    let resources = call(
        "POST",
        "/v2/email/tenants/resources/list",
        json!({"TenantName": "cohort-a"}),
    )
    .json();
    assert!(
        resources["TenantResources"]
            .as_array()
            .is_some_and(|resources| resources.iter().any(|resource| {
                resource["ResourceType"] == "EMAIL_TEMPLATE"
                    && resource["ResourceArn"] == format!("{ARN}:template/welcome").as_str()
            })),
        "{resources}"
    );

    // Deleted, it is neither read nor sent by.
    let deleted = call("DELETE", "/v2/email/templates/welcome", Value::Null);
    assert_eq!(deleted.status, 200, "{}", deleted.body);
    let gone = call("GET", "/v2/email/templates/welcome", Value::Null);
    assert_eq!(errortype(&gone), "NotFoundException", "{}", gone.body);
    let refused = by_name("welcome");
    assert_eq!(errortype(&refused), "NotFoundException", "{}", refused.body);
}
