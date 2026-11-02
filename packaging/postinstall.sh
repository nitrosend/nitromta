#!/bin/sh
# After the package installs: the engine's system user, and systemd told of
# its unit. Neither starts the engine, which waits for `nitromta setup`.
set -e
if command -v systemd-sysusers >/dev/null 2>&1; then
  systemd-sysusers nitromta.conf
fi
if [ -d /run/systemd/system ]; then
  systemctl daemon-reload
fi
