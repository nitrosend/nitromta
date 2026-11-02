# NitroMTA documentation

NitroMTA is a self-hosted mail delivery engine that speaks the Amazon SES v2
API. These guides take it from your own machine to your own servers.

## Start

- [Try it in capture mode](capture.md): the whole engine on your machine,
  each message shown in a browser instead of sent.
- [Installation](install.md): from a bare Linux host to the first delivered
  message.
- [Choosing a host](hosting.md): what a sending server needs, and which
  providers allow it.

## Move from SES

- [Migrating from SES](migrate-from-ses.md): your application, domains,
  events, suppression list and mail, moved one at a time.
- [Compatibility](compatibility.md): the SES operations, SMTP and events,
  and where the engine differs from SES.

## Run it

- [Operations](operations.md): why a message is waiting, the queue,
  metrics, holds, warmup and keys.
- [Durability](durability.md): what an acceptance promises.
- [Benchmarks](benchmarks.md): NitroMTA, KumoMTA and Postfix on the same
  machine, and how to run it yourself.

## Reference

- [Command line](reference/cli.md): every command and its options.
- [Configuration](reference/configuration.md): what `nitromta setup`
  writes, every setting explained.
