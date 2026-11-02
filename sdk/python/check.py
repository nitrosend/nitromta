"""The SDK scenario (sdk/README.md) through the official SES v2 SDK for
Python, then django-ses. Each step prints one line of JSON, which
crates/engine/tests/sdk.rs judges."""

import json
import os

import boto3
import botocore.exceptions

ENDPOINT = os.environ["SES_ENDPOINT"]
FROM, TO, DOMAIN, SUPPRESS = (
    os.environ[name] for name in ("FROM", "TO", "DOMAIN", "SUPPRESS")
)
ses = boto3.client("sesv2", endpoint_url=ENDPOINT, region_name="us-east-1")


def show(step, **fields):
    print(json.dumps({"step": step, **fields}), flush=True)


def failure(call):
    try:
        call()
        return {"error": None}
    except botocore.exceptions.ClientError as error:
        return {
            "error": error.response["Error"]["Code"],
            "message": error.response["Error"]["Message"],
            "attempts": error.response["ResponseMetadata"].get("RetryAttempts", 0) + 1,
        }


sent = ses.send_email(
    FromEmailAddress=FROM,
    Destination={"ToAddresses": [TO]},
    Content={
        "Simple": {
            "Subject": {"Data": "simple from python"},
            "Body": {"Text": {"Data": "hello"}, "Html": {"Data": "<p>hello</p>"}},
        }
    },
)
show("send_simple", message_id=sent["MessageId"])

raw = f"From: {FROM}\r\nTo: {TO}\r\nSubject: raw from python\r\n\r\nhello\r\n"
sent = ses.send_email(Content={"Raw": {"Data": raw.encode()}})
show("send_raw", message_id=sent["MessageId"])

bulk = ses.send_bulk_email(
    FromEmailAddress=FROM,
    DefaultContent={
        "Template": {
            "TemplateContent": {"Subject": "bulk for {{name}}", "Text": "hello {{name}}"},
            "TemplateData": json.dumps({}),
        }
    },
    BulkEmailEntries=[
        {
            "Destination": {"ToAddresses": [TO]},
            "ReplacementEmailContent": {
                "ReplacementTemplate": {"ReplacementTemplateData": json.dumps({"name": "python"})}
            },
        },
        {
            "Destination": {"ToAddresses": [TO]},
            "ReplacementEmailContent": {
                "ReplacementTemplate": {"ReplacementTemplateData": json.dumps({"other": 1})}
            },
        },
    ],
)
show("send_bulk", statuses=[result["Status"] for result in bulk["BulkEmailEntryResults"]])

account = ses.get_account()
show(
    "account",
    sending_enabled=account["SendingEnabled"],
    max_24_hour_send=account["SendQuota"]["Max24HourSend"],
)

show(
    "rejected",
    **failure(
        lambda: ses.send_email(
            FromEmailAddress="app@unverified.test",
            Destination={"ToAddresses": [TO]},
            Content={"Simple": {"Subject": {"Data": "x"}, "Body": {"Text": {"Data": "x"}}}},
        )
    ),
)

identity = ses.get_email_identity(EmailIdentity=DOMAIN)
show("identity", verified=identity["VerifiedForSendingStatus"])

names, pages, token = [], 0, None
while True:
    page = ses.list_email_identities(PageSize=1, **({"NextToken": token} if token else {}))
    names += [identity["IdentityName"] for identity in page["EmailIdentities"]]
    pages += 1
    token = page.get("NextToken")
    if not token:
        break
show("identities", pages=pages, names=names)

for name in ["first", "second"]:
    ses.create_configuration_set(ConfigurationSetName=name)
names, pages, token = [], 0, None
while True:
    page = ses.list_configuration_sets(PageSize=1, **({"NextToken": token} if token else {}))
    names += page["ConfigurationSets"]
    pages += 1
    token = page.get("NextToken")
    if not token:
        break
show("configuration_sets", pages=pages, names=names)

ses.put_suppressed_destination(EmailAddress=SUPPRESS, Reason="BOUNCE")
suppressed = ses.get_suppressed_destination(EmailAddress=SUPPRESS)["SuppressedDestination"]
ses.delete_suppressed_destination(EmailAddress=SUPPRESS)
gone = failure(lambda: ses.get_suppressed_destination(EmailAddress=SUPPRESS))
show(
    "suppression",
    reason=suppressed["Reason"],
    address=suppressed["EmailAddress"],
    gone=gone["error"],
)

ses.create_email_template(
    TemplateName="welcome",
    TemplateContent={"Subject": "Welcome, {{name}}", "Text": "Hello {{name}}"},
)
ses.update_email_template(
    TemplateName="welcome",
    TemplateContent={"Subject": "template from {{name}}", "Text": "Hello again, {{name}}"},
)
subject = ses.get_email_template(TemplateName="welcome")["TemplateContent"]["Subject"]
listed = ses.list_email_templates(PageSize=10)["TemplatesMetadata"]
sent = ses.send_email(
    FromEmailAddress=FROM,
    Destination={"ToAddresses": [TO]},
    Content={"Template": {"TemplateName": "welcome", "TemplateData": '{"name": "python"}'}},
)
ses.delete_email_template(TemplateName="welcome")
gone = failure(lambda: ses.get_email_template(TemplateName="welcome"))
show(
    "templates",
    subject=subject,
    names=[template["TemplateName"] for template in listed],
    message_id=sent["MessageId"],
    gone=gone["error"],
)

show("unimplemented", **failure(lambda: ses.list_contact_lists()))

# django-ses, an application of its own on the same SDK.
import django  # noqa: E402
from django.conf import settings  # noqa: E402

settings.configure(
    EMAIL_BACKEND="django_ses.SESBackend",
    USE_SES_V2=True,
    AWS_SES_REGION_NAME="us-east-1",
    AWS_SES_REGION_ENDPOINT_URL=ENDPOINT,
)
django.setup()
from django.core.mail import EmailMultiAlternatives  # noqa: E402

message = EmailMultiAlternatives(
    subject="from django-ses",
    body="hello",
    from_email=f"The App <{FROM}>",
    to=[TO],
)
message.attach_alternative("<p>hello</p>", "text/html")
message.attach("note.txt", "an attachment", "text/plain")
show("django_ses", sent=message.send(), message_id=message.extra_headers.get("message_id"))
