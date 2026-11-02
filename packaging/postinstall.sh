#!/bin/sh
# After the package installs: the engine's system user, and systemd told of
# its unit. Neither starts the engine, which waits for `nitromta setup`.
set -e
if command -v systemd-sysusers >/dev/null 2>&1; then
  systemd-sysusers nitromta.conf
elif ! getent passwd nitromta >/dev/null; then
  # A host without systemd, such as a container: the same user, as
  # nitromta.sysusers describes it.
  getent group nitromta >/dev/null || groupadd --system nitromta
  useradd --system --gid nitromta --home-dir /var/lib/nitromta --no-create-home \
    --shell "$(command -v nologin || echo /usr/sbin/nologin)" \
    --comment "NitroMTA mail engine" nitromta
fi
if [ -d /run/systemd/system ]; then
  systemctl daemon-reload
fi
