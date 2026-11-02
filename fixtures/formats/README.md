# Persisted formats

The golden fixtures of the store's formats: the schema each step makes
(`schema-<version>.sql`), and rows of each record's layout
(`<record>-<version>-<case>.hex`), as the release that added each case
wrote them.

They are generated, never edited. `cargo xtask fixtures` writes those of a
new case or schema step and never rewrites one that exists. The gate reads
every one with the current build: each row must still read as the value it
was written from, and the steps up to each version must still make that
version's schema.

So the formats only grow. A record may gain an optional field, since a row
written before it reads as not having it, and the schema may gain a step.
A field whose number or meaning changes, or a published step edited, fails
the gate: that change is a one-time rewrite of the store, in the release
that needs it.
