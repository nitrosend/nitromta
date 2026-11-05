# Deliverability

Receivers decide whether mail reaches the inbox, and they judge each sending
address and domain by its history with them. NitroMTA cannot give an address
a history. It can pace a new one at each receiver, back off when a receiver
pushes back, and stop mailing anyone who complains or no longer exists.

This page covers how warmup works, how provider defaults and your own
configuration fit together, what each provider tells you, and how to configure
warmup for any provider.

## Warming up a new address

Warmup is optional, and a daily cap is what turns it on. An egress with no cap
sends as much as it is given, which suits an address that already has a
sending history. A new address has none, so start it with a cap, as
[installation](install.md#5-give-it-its-policy) does, or afterwards:

```sh
echo '{"op":"put_cap","account":1,"address":"203.0.113.10","daily_cap":50}' | \
  sudo -u nitromta nitromta admin --config /etc/nitromta/config.toml
```

The egress then sends at most 50 messages a day to each receiver. Once each
UTC day, the engine judges every capped egress on what its receivers replied
the day before:

- a cap rises one rung after a day under every threshold below, on which
  replies reached half of it;
- a signal over its threshold to hold keeps the cap where it is;
- a signal over its threshold to lower takes the cap down a rung, and never
  below the first;
- past the last rung there is no cap at that receiver, and warmup is done
  there.

These are the default thresholds:

| Signal | Measured against | Holds the cap at | Lowers the cap at |
|---|---|---|---|
| Complaints | Deliveries | 0.1% | 0.3% |
| Permanent failures | Replies | 2% | 5% |
| Deferrals | Replies | 5% | 20% |
| Throttles | Replies | Any | 1% |

A throttle is a 421, or a reply the receiver rules know as a receiver refusing
an address for now. A deferral is any other temporary failure. A provider's
entry can set its own, as [`Outlook`'s does](#how-provider-settings-work).

Each receiver climbs on its own. A receiver gets a cap of its own once its
replies in a day reach 100 or half its cap, whichever is fewer. Until then it
shares the egress's own cap with the other small receivers, and they are
judged together on the defaults.

A cap with no room puts mail off in the store, so a warming address never
delays mail to other receivers. That mail still expires when its lifetime ends
(`[submission] lifetime_seconds`, three days by default), so send a warming
address no more than its caps allow, and keep the rest on the sender you have.

A `put_egress` line can start warmup on an egress with no cap, and never
changes it after that: running one again, to change a HELO name, leaves the
caps where warmup has taken them. `put_cap` changes a cap, and warmup's next
judgment starts from what you set. `nitromta list --config <file> egresses`
shows each egress's caps and last judgment. A small receiver may never send
enough to test its cap, so when you judge an address warm, end its warmup with
`put_cap` and no `daily_cap`.

With `[warmup] automatic = false`, the engine judges nothing and caps change
only by `put_cap`, by hand or from a system of your own.

## How provider settings work

The engine groups the exchanges a provider runs into one receiver. Its settings
come from three layers, and the first that gives a field wins:

1. your configuration, under `[receivers.<Provider>]`;
2. the provider's entry in the rules the engine ships,
   [`rules/receivers.toml`](../rules/receivers.toml);
3. the `[defaults]` entry in those rules, which every provider falls through to,
   and which applies as it is to any receiver with no entry of its own.

Any field of any provider can be configured, and a new name adds a provider, if
it lists its exchanges. The shipped provider entries set connection limits,
TLS and throttle rules, and differ by provider.

For warmup, every receiver falls through to the default ladder, 50, 100, 200,
500, 1,000, 2,000, 5,000, 10,000 a day and on to 1,000,000, past which there is
no cap. The exception is the shipped `Outlook` entry, because its replies are
most of what warmup can hear from it, as the next section explains. Its ladder
takes 14 clean days to reach 10,000, where the default takes 7, and a deferral
holds it from 0.5%, not 5%. Both are defaults, which your configuration
overrides like any other.

These are the receivers the rules ship, by the names `queue`, `explain`,
`put_cap` and your configuration use:

| Receiver | Covers | Complaints the engine can count |
|---|---|---|
| `Google` | Gmail and Google Workspace | None: Gmail sends no per-recipient reports |
| `Outlook` | Outlook.com and Hotmail | Few: its reports can lack what names their message |
| `Office365`, `Office365Dane` | Microsoft 365 | None known: operators report Microsoft's program covering its consumer mail |
| `Yahoo` | Yahoo Mail and AOL | Yes, once your DKIM domain is enrolled |
| `Apple` | iCloud Mail | None: Apple offers no feedback loop |
| `Comcast`, `Orange` | Their own mail | See [Comcast's](https://spa.xfinity.com/help/postmaster) and [Orange's](https://messagerie.orange.fr/postmaster.html) postmaster pages |

A receiver is defined by its exchanges, so settings cannot split one: Gmail and
Google Workspace share a cap, as they share exchanges, and Microsoft's consumer
mail and Microsoft 365 are configured separately, as they do not.

## What each provider tells you

What each provider's own documentation said on 6 November 2026, except where
this says otherwise. Policies change.

### Gmail and Google Workspace

Gmail sends no complaint report for a message. Its
[feedback loop](https://support.google.com/mail/answer/6254652) is aggregate
and shown in Postmaster Tools, so the engine never counts a complaint at
`Google`, and warmup there runs on deferrals, throttles and failures alone.

[Postmaster Tools](https://support.google.com/mail/answer/14668346) shows the
spam rate of DKIM-authenticated mail to Gmail accounts, for domains you verify.
[Google asks](https://support.google.com/mail/answer/81126) for a rate below
0.1%, and never reaching 0.3%. Its data is typically "updated within 24 hours
but can take longer", and may be incomplete on days of low volume, so a quiet
dashboard on a new address does not mean no complaints.

When it shows complaints, lower the cap yourself, one rung down from the one
`nitromta list` shows:

```sh
echo '{"op":"put_cap","account":1,"address":"203.0.113.10","site":"Google","daily_cap":500}' | \
  sudo -u nitromta nitromta admin --config /etc/nitromta/config.toml
```

The engine cannot see what Postmaster Tools shows, so a clean day raises the
cap again. Set it again each day until the rate falls, by hand or from a script
of your own.

### Outlook.com and Hotmail

Microsoft's Junk Mail Reporting Program (JMRP) sends a report when a user marks
a message as junk, to an address you set in
[SNDS](https://substrate.office.com/ip-domain-management-snds/SNDS), once you
have registered your addresses there.

Microsoft's SNDS pages do not say what those reports contain. Operators report
that since June 2026 they carry
[no recipient and no body](https://emailexpert.com/microsoft-redacts-jmrp-the-end-of-unblinded-feedback-loops/),
and [in some samples no return path](https://www.suped.com/learn/email-deliverability/did-microsoft-change-the-jmrp-spam-complaint-report-format),
while the Message-ID and custom headers remain. The engine finds a complaint's
message by its return path, so a report without one neither suppresses its
recipient, nor counts toward warmup, nor makes an event.

Enrol anyway, and check what your reports do
([below](#receiving-complaint-reports)), but treat Outlook's replies as your
warning signs, and lower its cap by `put_cap` when SNDS shows a problem.

Operators report JMRP covering Microsoft's consumer mail, so expect no complaint
reports for Microsoft 365.

### Yahoo Mail and AOL

Yahoo's [Complaint Feedback Loop](https://senders.yahooinc.com/faqs/) sends a
report in the standard format when a user marks a message as spam. The domain in
your DKIM signature's `d=` must be enrolled through Sender Hub, and reports go to
an address you verify there. Yahoo
[asks for a spam rate below 0.3%](https://senders.yahooinc.com/best-practices/),
measured on mail delivered to the inbox, so its figure can differ from yours.

### Apple iCloud Mail

[Apple says](https://support.apple.com/en-us/102322) "We don't offer a feedback
loop (FBL)", so no complaint reaches the engine. That is not the same as no
complaints: Apple counts user feedback in its reputation of a sender, and you
hear of it only through its replies.

## Receiving complaint reports

A provider sends its reports to an address you choose. Point it at an address
on your return path's domain, whose MX is already this host, and name that
address in the configuration, then restart the engine:

```toml
[feedback]
# As setup wrote it, and:
loops = ["complaints@bounces.example.com"]
```

A report finds its message by the `Original-Mail-From` field, or the
`Return-Path` of the copy it carries. Found, it suppresses its recipient, makes
a `Complaint` event, and counts toward warmup at the receiver that message was
delivered to. A report that names no recipient is taken to be about its
message's only delivery, so on a message sent to several recipients it does none
of these. A report that names no message is set aside as evidence and does
nothing else.

The listener answers each of these the same way, so check a provider's reports
in the metrics after your first few. `reports_unmatched_total` counts the
reports that found none of your deliveries, and a provider whose reports raise
it is not reaching suppression, events or warmup.

By default any report that finds its mail counts. To count only reports signed
by providers you enrolled with, see
[`[feedback] trusted`](compatibility.md#smtp).

## Configuring warmup for a provider

Warmup is configured under `[receivers.<Provider>.warmup]`, and under
`[receivers.defaults.warmup]` for everything that falls through. Each field
replaces the one below it and leaves the rest:

| Field | What it sets |
|---|---|
| `ladder` | The daily caps, each above the one before |
| `sample` | The replies in a day that give a receiver a cap of its own, if fewer than half its cap |
| `complaints`, `failures`, `deferrals`, `throttles` | `[hold, lower]`, in basis points, where 100 is 1% and a hold of 0 means any |

Gmail and Outlook throttle differently, so one ladder rarely suits both. This
example starts Outlook lower, holds it on any deferral, and lets Gmail climb
faster:

```toml
# Outlook starts lower, and any deferral holds it.
[receivers.Outlook.warmup]
ladder = [
  20, 40, 60, 100, 150, 200, 300, 500, 750, 1000, 1500,
  2000, 3000, 5000, 7500, 10000, 20000, 40000, 70000,
  100000, 150000, 250000, 400000, 600000, 1000000,
]
deferrals = [0, 2000]

# Gmail climbs faster than the default.
[receivers.Google.warmup]
ladder = [
  50, 150, 500, 1500, 5000, 15000, 40000, 70000, 100000,
  150000, 250000, 400000, 600000, 1000000,
]
```

Against the default, for a receiver with a clean day each day and replies
reaching half its cap:

| Clean days | Default | This Outlook | This Gmail |
|---|---|---|---|
| 0 | 50 | 20 | 50 |
| 1 | 100 | 40 | 150 |
| 2 | 200 | 60 | 500 |
| 3 | 500 | 100 | 1,500 |
| 4 | 1,000 | 150 | 5,000 |
| 5 | 2,000 | 200 | 15,000 |
| 6 | 5,000 | 300 | 40,000 |
| 7 | 10,000 | 500 | 70,000 |

A ladder says where a cap goes next, not where it starts. A receiver starts on
the egress's own cap, and until it has a cap of its own it is judged on the
defaults. Give it one as you start warmup, and it starts there and is judged on
its own settings from the first day:

```sh
sudo -u nitromta nitromta admin --config /etc/nitromta/config.toml <<END
{"op":"put_cap","account":1,"address":"203.0.113.10","daily_cap":50}
{"op":"put_cap","account":1,"address":"203.0.113.10","site":"Outlook","daily_cap":20}
END
```

The engine reads these settings as it starts. An egress already warming moves
to the new ladder at its next judgment, at the next rung above its cap.

These numbers are an example, and yours should follow what your own receivers
reply. Google asks you to
[start low and increase slowly](https://support.google.com/mail/answer/81126),
and gives no schedule. Three things to weigh:

- **Any deferral.** At higher caps, one temporary failure a day is likely, so
  `deferrals = [0, 2000]` can stop a cap rising at all. The shipped Outlook
  setting, `[50, 2000]`, does the same as any deferral up to 200 replies a day,
  and is a rate of 0.5% above that.
- **A faster Gmail.** Gmail's complaints reach you a day or more late, and may
  not show at low volume, so a fast ladder climbs furthest while it can least
  see them.
- **A slower Outlook.** More of your Outlook mail waits behind its cap, and it
  still expires at the end of its lifetime.
