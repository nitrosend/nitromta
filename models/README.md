# Models

`sesv2-2019-09-27.json` is the Amazon SES v2 Smithy model, unmodified, from
[aws/api-models-aws](https://github.com/aws/api-models-aws) at commit
`bac79d18c4d60f6ed14002e09caadd1c871f09cc`
(`models/sesv2/service/2019-09-27/sesv2-2019-09-27.json`), under the
Apache-2.0 license.

`crates/engine-ses-v2` is generated from it by smithy-rs's server generator,
at the release named in `generate/Dockerfile`, and is never edited by hand:

```sh
cargo xtask generate          # regenerate the crate
cargo xtask check generated   # fail if the committed crate differs
```

Both need a container runtime with the `docker` command; no contributor needs
Java. Updating the model or the generator is a commit of its own, with the
regenerated crate.
