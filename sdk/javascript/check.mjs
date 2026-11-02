// The SDK scenario (sdk/README.md) through the official SES v2 SDK for
// JavaScript, then Nodemailer's SES transport. Each step prints one line
// of JSON, which crates/engine/tests/sdk.rs judges.

import {
  CreateConfigurationSetCommand,
  CreateEmailTemplateCommand,
  DeleteEmailTemplateCommand,
  GetEmailTemplateCommand,
  ListEmailTemplatesCommand,
  UpdateEmailTemplateCommand,
  DeleteSuppressedDestinationCommand,
  GetAccountCommand,
  GetEmailIdentityCommand,
  GetSuppressedDestinationCommand,
  ListConfigurationSetsCommand,
  ListContactListsCommand,
  ListEmailIdentitiesCommand,
  PutSuppressedDestinationCommand,
  SESv2Client,
  SendBulkEmailCommand,
  SendEmailCommand,
} from "@aws-sdk/client-sesv2";
import nodemailer from "nodemailer";

const { SES_ENDPOINT, FROM, TO, DOMAIN, SUPPRESS } = process.env;
const ses = new SESv2Client({ endpoint: SES_ENDPOINT, region: "us-east-1" });
const print = (step, fields) => console.log(JSON.stringify({ step, ...fields }));
const failure = async (call) => {
  try {
    await call();
    return { error: null };
  } catch (error) {
    return { error: error.name, message: error.message, attempts: error.$metadata?.attempts };
  }
};

let sent = await ses.send(
  new SendEmailCommand({
    FromEmailAddress: FROM,
    Destination: { ToAddresses: [TO] },
    Content: {
      Simple: {
        Subject: { Data: "simple from javascript" },
        Body: { Text: { Data: "hello" }, Html: { Data: "<p>hello</p>" } },
      },
    },
  }),
);
print("send_simple", { message_id: sent.MessageId });

const raw = `From: ${FROM}\r\nTo: ${TO}\r\nSubject: raw from javascript\r\n\r\nhello\r\n`;
sent = await ses.send(
  new SendEmailCommand({ Content: { Raw: { Data: new TextEncoder().encode(raw) } } }),
);
print("send_raw", { message_id: sent.MessageId });

const bulk = await ses.send(
  new SendBulkEmailCommand({
    FromEmailAddress: FROM,
    DefaultContent: {
      Template: {
        TemplateContent: { Subject: "bulk for {{name}}", Text: "hello {{name}}" },
        TemplateData: JSON.stringify({}),
      },
    },
    BulkEmailEntries: [
      {
        Destination: { ToAddresses: [TO] },
        ReplacementEmailContent: {
          ReplacementTemplate: { ReplacementTemplateData: JSON.stringify({ name: "javascript" }) },
        },
      },
      {
        Destination: { ToAddresses: [TO] },
        ReplacementEmailContent: {
          ReplacementTemplate: { ReplacementTemplateData: JSON.stringify({ other: 1 }) },
        },
      },
    ],
  }),
);
print("send_bulk", { statuses: bulk.BulkEmailEntryResults.map((result) => result.Status) });

const account = await ses.send(new GetAccountCommand({}));
print("account", {
  sending_enabled: account.SendingEnabled,
  max_24_hour_send: account.SendQuota?.Max24HourSend,
});

print(
  "rejected",
  await failure(() =>
    ses.send(
      new SendEmailCommand({
        FromEmailAddress: "app@unverified.test",
        Destination: { ToAddresses: [TO] },
        Content: { Simple: { Subject: { Data: "x" }, Body: { Text: { Data: "x" } } } },
      }),
    ),
  ),
);

const identity = await ses.send(new GetEmailIdentityCommand({ EmailIdentity: DOMAIN }));
print("identity", { verified: identity.VerifiedForSendingStatus });

const names = [];
let pages = 0;
let token;
do {
  const page = await ses.send(new ListEmailIdentitiesCommand({ PageSize: 1, NextToken: token }));
  names.push(...page.EmailIdentities.map((identity) => identity.IdentityName));
  pages += 1;
  token = page.NextToken;
} while (token);
print("identities", { pages, names });

for (const name of ["first", "second"]) {
  await ses.send(new CreateConfigurationSetCommand({ ConfigurationSetName: name }));
}
const sets = [];
pages = 0;
token = undefined;
do {
  const page = await ses.send(new ListConfigurationSetsCommand({ PageSize: 1, NextToken: token }));
  sets.push(...page.ConfigurationSets);
  pages += 1;
  token = page.NextToken;
} while (token);
print("configuration_sets", { pages, names: sets });

await ses.send(
  new PutSuppressedDestinationCommand({ EmailAddress: SUPPRESS, Reason: "BOUNCE" }),
);
const suppressed = await ses.send(
  new GetSuppressedDestinationCommand({ EmailAddress: SUPPRESS }),
);
await ses.send(new DeleteSuppressedDestinationCommand({ EmailAddress: SUPPRESS }));
const gone = await failure(() =>
  ses.send(new GetSuppressedDestinationCommand({ EmailAddress: SUPPRESS })),
);
print("suppression", {
  reason: suppressed.SuppressedDestination.Reason,
  address: suppressed.SuppressedDestination.EmailAddress,
  gone: gone.error,
});

await ses.send(
  new CreateEmailTemplateCommand({
    TemplateName: "welcome",
    TemplateContent: { Subject: "Welcome, {{name}}", Text: "Hello {{name}}" },
  }),
);
await ses.send(
  new UpdateEmailTemplateCommand({
    TemplateName: "welcome",
    TemplateContent: { Subject: "template from {{name}}", Text: "Hello again, {{name}}" },
  }),
);
const template = await ses.send(new GetEmailTemplateCommand({ TemplateName: "welcome" }));
const listed = await ses.send(new ListEmailTemplatesCommand({ PageSize: 10 }));
sent = await ses.send(
  new SendEmailCommand({
    FromEmailAddress: FROM,
    Destination: { ToAddresses: [TO] },
    Content: { Template: { TemplateName: "welcome", TemplateData: '{"name": "javascript"}' } },
  }),
);
await ses.send(new DeleteEmailTemplateCommand({ TemplateName: "welcome" }));
const removed = await failure(() =>
  ses.send(new GetEmailTemplateCommand({ TemplateName: "welcome" })),
);
print("templates", {
  subject: template.TemplateContent.Subject,
  names: listed.TemplatesMetadata.map((metadata) => metadata.TemplateName),
  message_id: sent.MessageId,
  gone: removed.error,
});

print("unimplemented", await failure(() => ses.send(new ListContactListsCommand({}))));

// Nodemailer, an application of its own on the same SDK.
const transport = nodemailer.createTransport({ SES: { sesClient: ses, SendEmailCommand } });
const verified = await transport.verify();
const info = await transport.sendMail({
  from: `"The App" <${FROM}>`,
  to: TO,
  subject: "from nodemailer",
  text: "hello",
  html: "<p>hello</p>",
  attachments: [{ filename: "note.txt", content: "an attachment" }],
});
print("nodemailer", { verified, message_id: info.messageId });
