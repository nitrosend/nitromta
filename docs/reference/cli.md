# Command line

`nitromta --help` prints every command and its options:

```text
usage: nitromta <command> [--option value ...] | nitromta --version | nitromta --help

  run --config <file>             serve
  check --config <file>           check a stopped engine's store
  key --to <file>                 write the installation's next key
  key list --config <file>        the installation's keys, by ID, and which seals
  key retire --config <file> --id <id>   take an older key out, once no secret uses it
  migrate --config <file>         bring a stopped engine's store up to date
  backup --config <file> --to <file>      copy the store, while the engine runs or not
  restore --config <file> --from <file>   put a copy in place of a stopped engine's store, fenced
  fence --config <file> [release | discard]   a restored store's fence, and the decision on it
  setup --config <file> --hostname <name> --return-path-domain <domain>
        [--store <path>] [--keys <path>] [--certificate <path>] [--key <path>]
        [--admin-socket <path>]   write a new installation's configuration and keys
  setup --config <file> --capture [--hostname <name>]
                                  write one to try the engine with: capture mode, beside it
  doctor --config <file> [--time-server <host:port>] [--port25 <host:port>]
                                  check the installation, and what to change
  admin --config <file>           send native API lines from standard input

  queue --config <file> [--most <n>]
  explain --config <file> (--message <id> | --delivery <id>)
  list --config <file> <kind> [--account <id>]
      kinds: accounts identities tenants configurations pools egresses
             logins access_keys subscriptions holds
  pause --config <file> --account <id> [--tenant <name> | --configuration <name>
        | --identity <name> | --egress <address>] --reason <text> [--accepting]
  resume --config <file> --account <id> [the same target]
  drain --config <file> [--wait]  take no new mail while the queue is delivered
  undrain --config <file>         take new mail again
  parked --config <file> --account <id> --subscription <name> [--from <batch>]
  replay --config <file> --account <id> --subscription <name> [--batch <batch>]
  login create --config <file> --account <id> --user <name> [--identity <name> ...]
  login remove --config <file> --user <name>
  access-key create --config <file> --account <id> [--identity <name> ...]
        [--manage | --manage-only]  manage the account through SES's API too, or only
  access-key revoke --config <file> --access-key-id <id>

  Each command about a running engine takes --json for the API's own lines.
```

[Installation](../install.md) shows the commands that set up an
installation at work, and [operations](../operations.md) those about a
running engine.
