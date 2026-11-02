# The SDK scenario (sdk/README.md) through the official SES v2 SDK for Ruby,
# at the version Nitrosend sends with. Each step prints one line of JSON,
# which crates/engine/tests/sdk.rs judges.

require "json"
require "aws-sdk-sesv2"

from, to, domain, suppress = %w[FROM TO DOMAIN SUPPRESS].map { |name| ENV.fetch(name) }
ses = Aws::SESV2::Client.new(
  endpoint: ENV.fetch("SES_ENDPOINT"),
  region: "us-east-1",
  ssl_ca_bundle: ENV.fetch("AWS_CA_BUNDLE")
)

def show(step, **fields)
  puts JSON.generate({ step: step, **fields })
  $stdout.flush
end

def failure
  yield
  { error: nil }
rescue Aws::SESV2::Errors::ServiceError => e
  { error: e.code, message: e.message, attempts: e.context.retries + 1 }
end

sent = ses.send_email(
  from_email_address: from,
  destination: { to_addresses: [to] },
  content: {
    simple: {
      subject: { data: "simple from ruby" },
      body: { text: { data: "hello" }, html: { data: "<p>hello</p>" } }
    }
  }
)
show("send_simple", message_id: sent.message_id)

raw = "From: #{from}\r\nTo: #{to}\r\nSubject: raw from ruby\r\n\r\nhello\r\n"
sent = ses.send_email(content: { raw: { data: raw } })
show("send_raw", message_id: sent.message_id)

bulk = ses.send_bulk_email(
  from_email_address: from,
  default_content: {
    template: {
      template_content: { subject: "bulk for {{name}}", text: "hello {{name}}" },
      template_data: JSON.generate({})
    }
  },
  bulk_email_entries: [
    {
      destination: { to_addresses: [to] },
      replacement_email_content: {
        replacement_template: { replacement_template_data: JSON.generate({ name: "ruby" }) }
      }
    },
    {
      destination: { to_addresses: [to] },
      replacement_email_content: {
        replacement_template: { replacement_template_data: JSON.generate({ other: 1 }) }
      }
    }
  ]
)
show("send_bulk", statuses: bulk.bulk_email_entry_results.map(&:status))

account = ses.get_account
show(
  "account",
  sending_enabled: account.sending_enabled,
  max_24_hour_send: account.send_quota.max_24_hour_send
)

show("rejected", **failure {
  ses.send_email(
    from_email_address: "app@unverified.test",
    destination: { to_addresses: [to] },
    content: { simple: { subject: { data: "x" }, body: { text: { data: "x" } } } }
  )
})

identity = ses.get_email_identity(email_identity: domain)
show("identity", verified: identity.verified_for_sending_status)

names = []
pages = 0
token = nil
loop do
  page = ses.list_email_identities(page_size: 1, next_token: token)
  names.concat(page.email_identities.map(&:identity_name))
  pages += 1
  token = page.next_token
  break unless token
end
show("identities", pages: pages, names: names)

%w[first second].each { |name| ses.create_configuration_set(configuration_set_name: name) }
names = []
pages = 0
token = nil
loop do
  page = ses.list_configuration_sets(page_size: 1, next_token: token)
  names.concat(page.configuration_sets)
  pages += 1
  token = page.next_token
  break unless token
end
show("configuration_sets", pages: pages, names: names)

ses.put_suppressed_destination(email_address: suppress, reason: "BOUNCE")
suppressed = ses.get_suppressed_destination(email_address: suppress).suppressed_destination
ses.delete_suppressed_destination(email_address: suppress)
gone = failure { ses.get_suppressed_destination(email_address: suppress) }
show(
  "suppression",
  reason: suppressed.reason,
  address: suppressed.email_address,
  gone: gone[:error]
)

ses.create_email_template(
  template_name: "welcome",
  template_content: { subject: "Welcome, {{name}}", text: "Hello {{name}}" }
)
ses.update_email_template(
  template_name: "welcome",
  template_content: { subject: "template from {{name}}", text: "Hello again, {{name}}" }
)
subject = ses.get_email_template(template_name: "welcome").template_content.subject
listed = ses.list_email_templates(page_size: 10).templates_metadata
sent = ses.send_email(
  from_email_address: from,
  destination: { to_addresses: [to] },
  content: { template: { template_name: "welcome", template_data: '{"name": "ruby"}' } }
)
ses.delete_email_template(template_name: "welcome")
gone = failure { ses.get_email_template(template_name: "welcome") }
show(
  "templates",
  subject: subject,
  names: listed.map(&:template_name),
  message_id: sent.message_id,
  gone: gone[:error]
)

show("unimplemented", **failure { ses.list_contact_lists })
