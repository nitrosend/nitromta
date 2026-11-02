//! The store's schema, and the migrations that create and evolve it.
//!
//! Migrations only move forward. Each runs once, in order, in the
//! transaction that records it in `user_version`, so one cut short by a
//! crash leaves the store at the version before it. A store at a version
//! newer than this release knows is refused.

use rusqlite::Connection;

use crate::store::StoreError;

/// Each published version of the schema, the first the release's.
/// A published step never changes: a change is a step after it, with
/// its fixture (`fixtures/formats`).
const MIGRATIONS: &[&str] = &[
    // Version 1.
    "-- Each message's record, and how many of its deliveries are not yet
     -- finished: its body is deleted when that is zero. When its deliveries
     -- last finished, in seconds, and what SES-shaped events say
     -- of it, kept only when its configuration publishes them.
     CREATE TABLE messages (
         id INTEGER PRIMARY KEY,
         unfinished INTEGER NOT NULL,
         record BLOB NOT NULL,
         finished_at INTEGER,
         mail BLOB
     ) STRICT;
     -- Written once, deleted once, never rewritten.
     CREATE TABLE bodies (
         id INTEGER PRIMARY KEY,
         -- The encryption envelope: key 0 and no nonce while encryption is off.
         key INTEGER NOT NULL,
         nonce BLOB,
         content BLOB NOT NULL
     ) STRICT;
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
     CREATE INDEX deliveries_due ON deliveries (due_at) WHERE state = 0;
     CREATE INDEX deliveries_in_flight ON deliveries (state) WHERE state = 1;
     CREATE INDEX deliveries_expiring ON deliveries (expires_at) WHERE state IN (0, 3);
     CREATE INDEX deliveries_held ON deliveries (id) WHERE state = 3;
     -- Every ID the shard has stored is at or below this, even after the
     -- row holding it is deleted, so generators never reissue one.
     CREATE TABLE highest_id (
         only INTEGER PRIMARY KEY CHECK (only = 0),
         id INTEGER NOT NULL
     ) STRICT;
     INSERT INTO highest_id (only, id) VALUES (0, 0);
     -- The transition journal: an attempt's evidence is its
     -- outcome's entry. A row's key is its position, given as it is
     -- appended, so rows are in commit order, and the oldest are the ones
     -- trimmed. The topics each event is published to are decided as it is
     -- written: null for none.
     CREATE TABLE journal (
         position INTEGER PRIMARY KEY,
         record BLOB NOT NULL,
         topics BLOB
     ) STRICT;
     -- Each account's suppression list, keyed by the address's
     -- matching key, which a reservation looks up.
     CREATE TABLE suppressions (
         account INTEGER NOT NULL,
         key BLOB NOT NULL,
         record BLOB NOT NULL,
         PRIMARY KEY (account, key)
     ) STRICT, WITHOUT ROWID;
     -- The key the suppression list's keys are hashed under, 0
     -- for none, when they are the addresses in lowercase: a start under
     -- another rewrites the list.
     CREATE TABLE suppression_index (key INTEGER NOT NULL) STRICT;
     INSERT INTO suppression_index (key) VALUES (0);
     -- Policy, read whole at start, and the revision it is
     -- at.
     CREATE TABLE policy (
         id INTEGER PRIMARY KEY,
         record BLOB NOT NULL
     ) STRICT;
     CREATE TABLE policy_revision (
         only INTEGER PRIMARY KEY CHECK (only = 0),
         revision INTEGER NOT NULL
     ) STRICT;
     INSERT INTO policy_revision (only, revision) VALUES (0, 0);
     -- The acceptance quota's ledger: the recipients each
     -- account accepted in each minute of the last 24 hours.
     CREATE TABLE sent (
         account INTEGER NOT NULL,
         minute INTEGER NOT NULL,
         recipients INTEGER NOT NULL,
         PRIMARY KEY (account, minute)
     ) STRICT, WITHOUT ROWID;
     -- Each subscription's cursor over the journal: every event
     -- it owed up to this position was delivered. The positions it skipped
     -- because they were trimmed before it was given them; when the batch
     -- at its cursor first failed, so its budget runs on across restarts,
     -- and that batch's first position, null while none fails.
     CREATE TABLE cursors (
         subscription INTEGER PRIMARY KEY,
         position INTEGER NOT NULL,
         skipped INTEGER NOT NULL DEFAULT 0,
         failing_since INTEGER,
         failing_first INTEGER
     ) STRICT, WITHOUT ROWID;
     -- Each subscription's parked batches of events: the span of
     -- journal positions each covers, when it was parked, its posts and why
     -- the last failed. Trimmed with the journal.
     CREATE TABLE parked_events (
         subscription INTEGER NOT NULL,
         first INTEGER NOT NULL,
         through INTEGER NOT NULL,
         parked_at INTEGER NOT NULL,
         attempts INTEGER NOT NULL,
         failure TEXT NOT NULL,
         PRIMARY KEY (subscription, first)
     ) STRICT, WITHOUT ROWID;
     CREATE INDEX parked_events_through ON parked_events (through);
     -- The dispatch ledger: each (egress, site)'s reservations
     -- over the last 24 hours, as one window of ten-minute buckets.
     CREATE TABLE dispatched (
         egress INTEGER NOT NULL,
         site TEXT NOT NULL,
         record BLOB NOT NULL,
         PRIMARY KEY (egress, site)
     ) STRICT, WITHOUT ROWID;
     -- Each site's cooldown from each source: the egress,
     -- or 0 for the host's own address, until a wall-clock time in
     -- microseconds, so a restart keeps it. A row goes when the scheduler
     -- says the cooldown has ended.
     CREATE TABLE cooldowns (
         egress INTEGER NOT NULL,
         site TEXT NOT NULL,
         until INTEGER NOT NULL,
         record BLOB NOT NULL,
         PRIMARY KEY (egress, site)
     ) STRICT, WITHOUT ROWID;
     -- Bounce and complaint reports, each under the identity
     -- that makes a report sent again the same report; 1 for one about
     -- none of the engine's deliveries, kept in quarantine, which holds a
     -- bounded number.
     CREATE TABLE feedback (
         id INTEGER PRIMARY KEY,
         identity BLOB NOT NULL UNIQUE,
         record BLOB NOT NULL,
         quarantined INTEGER NOT NULL
     ) STRICT;
     CREATE INDEX feedback_quarantined ON feedback (id) WHERE quarantined = 1;
     -- Each delivery a report has had its effect on, by the report's
     -- identity: the same report again has none. Whether its effect was
     -- applied, or only its event recorded, its report below the class the
     -- operator trusts, so a trusted copy after it applies once.
     CREATE TABLE feedback_effects (
         delivery INTEGER NOT NULL,
         report BLOB NOT NULL,
         trusted INTEGER NOT NULL,
         PRIMARY KEY (delivery, report)
     ) STRICT, WITHOUT ROWID;
     -- Each domain's MTA-STS policy, as delivery last fetched
     -- it, kept until it runs out so a restart keeps it: when it was
     -- fetched and when it expires, in microseconds.
     CREATE TABLE sts_policies (
         domain TEXT PRIMARY KEY,
         fetched_at INTEGER NOT NULL,
         expires_at INTEGER NOT NULL,
         record BLOB NOT NULL
     ) STRICT, WITHOUT ROWID;
     CREATE INDEX sts_policies_expiring ON sts_policies (expires_at);
     -- Backups and restores. A copy notes when it was taken, in
     -- microseconds; a store restored from one keeps its fence until the
     -- operator's decision lifts it: every delivery whose ID is at or below
     -- the copy's high-water mark is held, or, once the decision is to
     -- discard them, cancelled as it falls due.
     CREATE TABLE copied (taken_at INTEGER NOT NULL) STRICT;
     CREATE TABLE fence (
         below INTEGER NOT NULL,
         taken_at INTEGER NOT NULL,
         restored_at INTEGER NOT NULL,
         discarding INTEGER NOT NULL
     ) STRICT;",
];

pub fn migrate(db: &Connection) -> Result<(), StoreError> {
    let version: u32 = db.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    let known = u32::try_from(MIGRATIONS.len()).expect("a few migrations");
    if version > known {
        return Err(StoreError::Newer { version, known });
    }
    for (migration, target) in MIGRATIONS.iter().zip(1..).skip(version as usize) {
        let script = format!("BEGIN; {migration}; PRAGMA user_version = {target}; COMMIT;");
        if let Err(error) = db.execute_batch(&script) {
            // Leave the store at the version before this migration.
            let _ = db.execute_batch("ROLLBACK");
            return Err(error.into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_schema_each_version_makes_is_its_fixtures() {
        // The steps up to each version, run as a store at the one before
        // runs them, make the schema its fixture kept, so a published
        // step edited fails here.
        let db = Connection::open_in_memory().unwrap();
        for (step, version) in MIGRATIONS.iter().zip(1..) {
            db.execute_batch(&format!(
                "BEGIN; {step}; PRAGMA user_version = {version}; COMMIT;"
            ))
            .unwrap();
            let made: Vec<String> = db
                .prepare(
                    "SELECT sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY type DESC, name",
                )
                .unwrap()
                .query_map([], |row| row.get(0))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            let made: String = made.iter().map(|sql| format!("{sql};\n\n")).collect();
            let kept = crate::golden::text(&format!("schema-{version}.sql"), &made);
            assert!(
                kept == made,
                "fixtures/formats/schema-{version}.sql: a published step is changed; a change is a step after it, with its fixture"
            );
        }
        // And migrating a new store takes it to the last.
        let fresh = Connection::open_in_memory().unwrap();
        migrate(&fresh).unwrap();
        let version: u32 = fresh
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version as usize, MIGRATIONS.len());
    }
}
