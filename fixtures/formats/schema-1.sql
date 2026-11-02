CREATE TABLE bodies (
         id INTEGER PRIMARY KEY,
         -- The encryption envelope: key 0 and no nonce while encryption is off.
         key INTEGER NOT NULL,
         nonce BLOB,
         content BLOB NOT NULL
     ) STRICT;

CREATE TABLE cooldowns (
         egress INTEGER NOT NULL,
         site TEXT NOT NULL,
         until INTEGER NOT NULL,
         record BLOB NOT NULL,
         PRIMARY KEY (egress, site)
     ) STRICT, WITHOUT ROWID;

CREATE TABLE copied (taken_at INTEGER NOT NULL) STRICT;

CREATE TABLE cursors (
         subscription INTEGER PRIMARY KEY,
         position INTEGER NOT NULL,
         skipped INTEGER NOT NULL DEFAULT 0,
         failing_since INTEGER,
         failing_first INTEGER
     ) STRICT, WITHOUT ROWID;

CREATE TABLE deliveries (
         id INTEGER PRIMARY KEY,
         -- Index keys derived from the record: 0 waiting, 1 in flight, 2
         -- finished, 3 held, which expires as waiting does. A
         -- finished delivery's expires_at holds when it finished instead,
         -- since only a waiting or held one's expiry is indexed.
         state INTEGER NOT NULL,
         due_at INTEGER,
         expires_at INTEGER NOT NULL,
         record BLOB NOT NULL,
         -- The site a recipient was delivered at from a capped egress, which
         -- a report about it counts toward warmup at.
         site TEXT
     ) STRICT;

CREATE TABLE dispatched (
         egress INTEGER NOT NULL,
         site TEXT NOT NULL,
         record BLOB NOT NULL,
         PRIMARY KEY (egress, site)
     ) STRICT, WITHOUT ROWID;

CREATE TABLE feedback (
         id INTEGER PRIMARY KEY,
         identity BLOB NOT NULL UNIQUE,
         record BLOB NOT NULL,
         quarantined INTEGER NOT NULL
     ) STRICT;

CREATE TABLE feedback_effects (
         delivery INTEGER NOT NULL,
         report BLOB NOT NULL,
         trusted INTEGER NOT NULL,
         PRIMARY KEY (delivery, report)
     ) STRICT, WITHOUT ROWID;

CREATE TABLE fence (
         below INTEGER NOT NULL,
         taken_at INTEGER NOT NULL,
         restored_at INTEGER NOT NULL,
         discarding INTEGER NOT NULL
     ) STRICT;

CREATE TABLE highest_id (
         only INTEGER PRIMARY KEY CHECK (only = 0),
         id INTEGER NOT NULL
     ) STRICT;

CREATE TABLE journal (
         position INTEGER PRIMARY KEY,
         record BLOB NOT NULL,
         topics BLOB
     ) STRICT;

CREATE TABLE messages (
         id INTEGER PRIMARY KEY,
         unfinished INTEGER NOT NULL,
         record BLOB NOT NULL,
         finished_at INTEGER,
         mail BLOB
     ) STRICT;

CREATE TABLE parked_events (
         subscription INTEGER NOT NULL,
         first INTEGER NOT NULL,
         through INTEGER NOT NULL,
         parked_at INTEGER NOT NULL,
         attempts INTEGER NOT NULL,
         failure TEXT NOT NULL,
         PRIMARY KEY (subscription, first)
     ) STRICT, WITHOUT ROWID;

CREATE TABLE policy (
         id INTEGER PRIMARY KEY,
         record BLOB NOT NULL
     ) STRICT;

CREATE TABLE policy_revision (
         only INTEGER PRIMARY KEY CHECK (only = 0),
         revision INTEGER NOT NULL
     ) STRICT;

CREATE TABLE sent (
         account INTEGER NOT NULL,
         minute INTEGER NOT NULL,
         recipients INTEGER NOT NULL,
         PRIMARY KEY (account, minute)
     ) STRICT, WITHOUT ROWID;

CREATE TABLE sts_policies (
         domain TEXT PRIMARY KEY,
         fetched_at INTEGER NOT NULL,
         expires_at INTEGER NOT NULL,
         record BLOB NOT NULL
     ) STRICT, WITHOUT ROWID;

CREATE TABLE suppression_index (key INTEGER NOT NULL) STRICT;

CREATE TABLE suppressions (
         account INTEGER NOT NULL,
         key BLOB NOT NULL,
         record BLOB NOT NULL,
         PRIMARY KEY (account, key)
     ) STRICT, WITHOUT ROWID;

CREATE INDEX deliveries_due ON deliveries (due_at) WHERE state = 0;

CREATE INDEX deliveries_expiring ON deliveries (expires_at) WHERE state IN (0, 3);

CREATE INDEX deliveries_held ON deliveries (id) WHERE state = 3;

CREATE INDEX deliveries_in_flight ON deliveries (state) WHERE state = 1;

CREATE INDEX feedback_quarantined ON feedback (id) WHERE quarantined = 1;

CREATE INDEX parked_events_through ON parked_events (through);

CREATE INDEX sts_policies_expiring ON sts_policies (expires_at);

