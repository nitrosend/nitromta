# Installation

NitroMTA runs on one Linux host with systemd, on x86_64 or arm64, with glibc
2.34 or later (Debian 12, Ubuntu 22.04, RHEL 9, or newer). It delivers mail
directly, so the host needs what any sending host needs:

- outbound TCP to port 25 (many cloud providers block it until asked), and
  inbound to port 25, where bounces and complaints arrive;
- a public address for each IP it sends from, each with reverse DNS (PTR)
  naming a host name that resolves back to it;
- a domain for return paths, whose MX points at this host, so bounces reach
  it;
- for each domain mail is sent as, SPF, DKIM and DMARC records, which
  `nitromta doctor` writes out for you;
- a synchronised clock (NTP), and, for DANE, a resolver on this host that
  validates DNSSEC, such as unbound; without one, mail goes as it would
  without DANE.

To try the engine first, without any of this, use
[capture mode](capture.md).

## 1. Install the release

On Debian or Ubuntu, and on RHEL or Fedora, install the release's package,
after checking its build provenance, signed by GitHub:

```sh
gh attestation verify nitromta_<version>_amd64.deb --repo nitrosend/nitromta
sudo apt install ./nitromta_<version>_amd64.deb
```

```sh
gh attestation verify nitromta-<version>-1.x86_64.rpm --repo nitrosend/nitromta
sudo dnf install ./nitromta-<version>-1.x86_64.rpm
```

On arm64 they are `nitromta_<version>_arm64.deb` and
`nitromta-<version>-1.aarch64.rpm`. On Arch, `nitromta-bin` from the AUR. The
package installs the binary, the systemd unit and the engine's system user,
and starts nothing. Then go on to [step 2](#2-write-the-configuration).

On any other Linux, each release also publishes an archive for each
architecture,
`nitromta-<version>-x86_64-linux.tar.gz` and
`nitromta-<version>-aarch64-linux.tar.gz`, with build provenance signed by
GitHub. Check it before installing:

```sh
gh attestation verify nitromta-<version>-x86_64-linux.tar.gz --repo nitrosend/nitromta
tar -xzf nitromta-<version>-x86_64-linux.tar.gz
cd nitromta-<version>-x86_64-linux
sudo install -m 0755 nitromta /usr/bin/nitromta
sudo install -m 0644 nitromta.service /usr/lib/systemd/system/nitromta.service
sudo install -m 0644 nitromta.sysusers /usr/lib/sysusers.d/nitromta.conf
sudo systemd-sysusers
sudo systemctl daemon-reload
```

The unit runs the engine as its own user, `nitromta`, with
`CAP_NET_BIND_SERVICE` alone, so it can listen on ports below 1024. The
engine refuses to start as root or with any other capability. It keeps its
store in `/var/lib/nitromta`, its admin socket in `/run/nitromta`, and reads
its configuration, certificates and keys from `/etc/nitromta`.

### Or run the container image

Each release publishes an image for both architectures,
`ghcr.io/nitrosend/nitromta:<version>`, built from the same binaries, with
its provenance signed by GitHub. It holds the binary alone, on glibc and the
certificate authorities, and runs as its own user, uid 65532, with its store
in `/var/lib/nitromta` and its configuration in `/etc/nitromta`, each a
volume of its own. The steps below are the same, run in it:

```sh
gh attestation verify oci://ghcr.io/nitrosend/nitromta:<version> --repo nitrosend/nitromta
docker volume create nitromta-etc
docker volume create nitromta-store
docker run --rm -v nitromta-etc:/etc/nitromta ghcr.io/nitrosend/nitromta:<version> \
  setup --config /etc/nitromta/config.toml \
  --hostname mta.example.com --return-path-domain bounces.example.com
docker run -d --name nitromta -p 25:25 -p 443:443 -p 587:587 \
  -v nitromta-etc:/etc/nitromta -v nitromta-store:/var/lib/nitromta \
  ghcr.io/nitrosend/nitromta:<version>
```

In Docker's own network the engine listens on the usual ports as its own
user, and its mail leaves from the host's address, so the image suits a
host that sends from one address: give it no egresses, and it sends as the
host. A host with an address for each egress installs the package above.
The admin commands run in the container:
`docker exec -i nitromta nitromta admin --config /etc/nitromta/config.toml`.

## 2. Write the configuration

As the engine's user, so everything it writes is that user's:

```sh
sudo install -d -o nitromta -g nitromta /etc/nitromta
sudo -u nitromta nitromta setup --config /etc/nitromta/config.toml \
  --hostname mta.example.com --return-path-domain bounces.example.com
```

`setup` writes a commented configuration, with every other setting at its
default: submission on 587, bounces and complaints taken on 25 for the
return path domain (`[feedback]`), and delivery only over TLS (`[delivery]
require_tls`). It writes the installation's keys too, which seal the secrets
the store keeps. It never writes over a file already there. Keep a copy of
the configuration and the keys away from the host: a backup of the store can
be restored only with them.

For DANE, run a resolver that validates DNSSEC on this host and name it as
`[delivery] resolver`: on Debian or Ubuntu, `sudo apt install unbound`, then
`resolver = "127.0.0.1:53"`. The engine takes that resolver's word that it
validated an answer, so it must validate DNSSEC itself: never name a
forwarder that passes on another resolver's word, such as dnsmasq with
`proxy-dnssec` or systemd-resolved's 127.0.0.54. Through a resolver
elsewhere, or one that does not validate, mail goes as it would without
DANE.

The engine reads its resolver when it starts, so restart it after changing
`[delivery] resolver` or the system's nameservers. `doctor` says whether
DANE is in effect with the resolver a start would use.

## 3. Give it a certificate

Submission, the SES API and the feedback listener serve TLS with the
certificate at `/etc/nitromta/tls.crt` and its key at
`/etc/nitromta/tls.key`, which must be for the host name given to `setup`,
from a certificate authority your clients trust. A renewal's hook runs
`systemctl reload nitromta`, and the engine reads the new certificate
without a restart.

The SES API is off until its `[ses]` table is uncommented. It listens on
443 by default.

## 4. Start it

```sh
sudo systemctl enable --now nitromta
```

A stop waits for attempts under way, up to `[scheduler] drain_seconds` (20
by default).

## 5. Give it its policy

Through the admin socket, with one JSON line for each change. An account,
an egress for each address mail goes out from, an identity for each domain
mail is sent as, with its DKIM key, and a login for an SMTP client:

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out dkim.pem
key=$(jq -Rs . dkim.pem)
sudo -u nitromta nitromta admin --config /etc/nitromta/config.toml <<END
{"op":"put_account","account":1}
{"op":"put_egress","account":1,"address":"203.0.113.10","helo":"mta.example.com","daily_cap":50}
{"op":"put_identity","account":1,"name":"example.com","selector":"s1","private_key":$key}
{"op":"create_login","account":1,"user":"app"}
END
```

And an access key for an application that calls the SES API:

```sh
sudo -u nitromta nitromta access-key create --config /etc/nitromta/config.toml --account 1
```

`daily_cap` is what turns warmup on, and a new address needs it, having no
reputation with receivers yet. The egress sends at most 50 messages a day to
each receiver, and the engine raises or lowers that once a day from how each
receiver replied ([deliverability](deliverability.md#warming-up-a-new-address)
says how, and how each provider is treated). Leave it out for an address that
already has a sending history: with no cap, an egress sends as much as it is
given, and warmup takes no part.

This line can start warmup on an egress with no cap, and never changes it after
that: running it again, to change the HELO name, leaves the caps where warmup
has taken them. `put_cap` changes a cap.

[Operations](operations.md) has the rest of policy: pools, configurations,
tenants, holds and subscriptions.

## 6. Check it

```sh
sudo -u nitromta nitromta doctor --config /etc/nitromta/config.toml
```

`doctor` checks the installation with what the engine itself uses: its
configuration, store and certificates, its clock, its resolver, and,
through the running engine, each egress's reverse DNS, port 25 from it, its
blocklist listings and the return path's SPF record covering it, and each
identity's DKIM and DMARC records. Each check prints
`ok`, `warn` or `fail` with what it found, and a failure says what to
change: for a missing SPF, DKIM or DMARC record, the exact record to
publish. It changes nothing.

A record just published may not show at once: a resolver keeps the answer
it had, even that there was none, for as long as that answer's TTL, so
`doctor` can report a record missing for a while after it went in. A
changed PTR takes hours to reach every receiver's resolver, which until
then see the provider's name for the address: publish the records, the PTR
first, a day before the first mail goes out.

An identity put through the admin socket is the operator's word, and sends
at once; `doctor` is how it is checked. One an application creates through
the SES API is checked as SES checks it, by its DKIM records, and mail sent
as it is refused until they check out.

## Upgrading

Stop the engine, install the new binary and start it again. An upgrade
keeps the store: a release that changes it brings it up to date as it
opens, one step in one transaction at a time, so a step cut short leaves it
as it was. `nitromta migrate --config /etc/nitromta/config.toml` does the
same without starting the engine, and says from which version to which. A
store written by a newer release is refused, never read, so going back to
an older release means restoring a backup taken before the upgrade.

Before 1.0, a minor release (0.1 to 0.2) may change a configuration key, a
command or an admin operation; its changelog says exactly what to edit. A
patch release (0.1.0 to 0.1.1) changes none of them.
