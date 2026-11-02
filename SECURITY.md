# Security

Report a vulnerability privately, by email to security@nitrosend.com, never
in a public issue. Say what is affected, how to reproduce it, and what it
lets an attacker do. We will confirm we have it, keep you told as we work
on it, and credit you in the release that fixes it unless you would rather
we did not.

Fixes go into the latest release. The engine runs as an unprivileged user
under its systemd unit's hardening, and seals the secrets it stores under
keys kept apart from its store; [installation](docs/install.md) and
[durability](docs/durability.md) say how.
