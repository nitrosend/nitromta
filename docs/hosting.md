# Choosing a host

NitroMTA runs on an x86_64 or arm64 Linux host with systemd and glibc 2.34
or later, as [installation](install.md) says. What decides where it can
send from is the network: mail goes out on port 25, straight to each recipient's mail
server, and many providers block that port until asked.

## What a sending host needs

- **Outbound port 25,** to reach recipients' mail servers.
- **Inbound port 25,** where bounces and complaints arrive at the return
  path's domain.
- **A static public address for each IP mail goes out from,** whose
  reverse DNS (PTR) you can set to a name that resolves back to it.
- **An address with a clean history.** One a previous tenant spammed from
  is on blocklists that receivers consult.

## Checking a server

Before installing anything, see whether port 25 reaches a large receiver.
An open port prints the receiver's `220` greeting; a blocked one times out:

```sh
timeout 10 bash -c 'exec 3<>/dev/tcp/gmail-smtp-in.l.google.com/25 && head -n1 <&3'
```

Once the engine is installed, `nitromta doctor` checks the same and more:
each egress's reverse DNS and that it resolves back, its HELO name, port 25
from its own address, the blocklists it is on, and the SPF, DKIM and DMARC
records it depends on, and what to publish for any that is missing.

Set the reverse DNS in the provider's panel or API, naming the host name
given to `nitromta setup`, with an A record for that name pointing back. A
changed PTR takes hours to reach every receiver's resolver, so set it a day
before the first mail goes out.

A host with several sending addresses gives each its own egress, with its
own reverse DNS. The engine sends from an egress's address alone, in its
address family, so a host with an IPv6 address it has not prepared still
sends over IPv4 from an IPv4 egress.

## Providers

What each provider's own documentation says. Policies change; the check above
is the one to trust.

| Provider | Outbound port 25 | To send |
|---|---|---|
| [Hostinger](https://www.hostinger.com/support/7854530-is-smtp-port-25-blocked-on-vps/) (VPS) | Open, limited to 5 messages a minute | Nothing to ask. Reverse DNS is set in its panel. Outlook.com has refused an address here, naming the network as on its block list (S3150) |
| [OVHcloud](https://docs.ovhcloud.com/en/guides/bare-metal-cloud/dedicated-servers/mail-sending-optimization) | Not blocked on VPS and dedicated servers, its mail guide says, though its anti-spam monitoring can block an address; its US VPS FAQ says blocked by default | Check from the server; ask support if blocked |
| [Amazon EC2](https://repost.aws/knowledge-center/ec2-port-25-throttle) | Blocked | Submit the "Request to remove email sending limitations" form. An Elastic IP's reverse DNS is set by its owner, once its forward record points at it |
| [Microsoft Azure](https://learn.microsoft.com/en-us/azure/virtual-network/troubleshoot-outbound-smtp-connectivity) | Open on Enterprise Agreement and MCA-E subscriptions; blocked on others | Enterprise Dev/Test: run the portal's port 25 diagnostic. Others: no route |
| [Google Compute Engine](https://docs.cloud.google.com/compute/docs/tutorials/sending-mail) | Blocked on most projects | No route published |
| [Hetzner Cloud](https://docs.hetzner.com/cloud/servers/faq/) | Blocked, with 465 | A limit request, after a month as a customer and the first invoice paid, decided case by case |
| [DigitalOcean](https://docs.digitalocean.com/support/why-is-smtp-blocked/) | Blocked, with 465 and 587 | No route published |
| [Vultr](https://docs.vultr.com/support/products/compute/why-is-smtp-blocked) | Blocked on new instances | A support ticket with the use case, protections and volume, decided case by case |
| [Akamai (Linode)](https://techdocs.akamai.com/cloud-computing/docs/send-email) | Restricted on some new accounts | A support request with the use case and sending domains |

## A new address

An address with no sending history starts with none of the reputation
receivers judge mail by, however well its mail is authenticated. Give each
new egress a starting cap, and warmup raises it receiver by receiver as the
receivers accept its mail
([deliverability](deliverability.md#warming-up-a-new-address)).
