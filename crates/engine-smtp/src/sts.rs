//! MTA-STS decisions (RFC 8461): what a domain's `_mta-sts` record names,
//! what its policy file says, and whether the policy kept for it serves or
//! a fetch is due. The driver performs the lookup and the fetch; what they
//! mean is decided here.

use std::time::Duration;

use engine_core::sts::{Mode, Policy};
use engine_core::time::Timestamp;

/// The most of a policy file read (RFC 8461, 3.3, suggests a bound).
pub const MAX_POLICY_BYTES: usize = 64 * 1024;

/// How long a fetched policy serves before it is fetched again, its
/// record's ID unchanged: a day, or half its `max_age` when that is
/// shorter, so a policy the domain still publishes never runs out between
/// fetches.
const REFRESH: Duration = Duration::from_secs(86_400);

/// How long after a failed fetch a domain's policy is fetched again, and
/// the least a route its policy shaped is kept, so a policy host that is
/// down costs a fetch every few minutes, never one per message.
pub const RETRY: Duration = Duration::from_secs(300);

/// What a domain's `_mta-sts` TXT lookup found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Record {
    /// One valid record, naming this policy ID.
    Id(String),
    /// No valid record, or more than one (section 3.1).
    Absent,
    /// The lookup failed, for now.
    Failed,
}

/// The record among `records`, each a TXT record's strings joined.
pub fn record(records: &[String]) -> Record {
    // Records whose first field is not exactly the version are not STS's.
    let mut ids = records
        .iter()
        .filter(|record| record.split(';').next().map(str::trim) == Some("v=STSv1"))
        .map(|record| id(record));
    match (ids.next(), ids.next()) {
        (Some(Some(id)), None) => Record::Id(id),
        _ => Record::Absent,
    }
}

/// A record's ID, if it is a valid record: `v=STSv1`, then fields
/// separated by semicolons, one of them `id=` and 1 to 32 letters and
/// digits.
fn id(record: &str) -> Option<String> {
    let mut fields = record.split(';').map(str::trim);
    if fields.next() != Some("v=STSv1") {
        return None;
    }
    let mut id = None;
    for field in fields.filter(|field| !field.is_empty()) {
        let (name, value) = field.split_once('=')?;
        if name == "id" && id.is_none() {
            let valid = (1..=32).contains(&value.len())
                && value.bytes().all(|byte| byte.is_ascii_alphanumeric());
            if !valid {
                return None;
            }
            id = Some(value.to_owned());
        }
    }
    id
}

/// The policy `text` states for `domain`, fetched at `now` while its record
/// named `id` (section 3.2). Fields it does not know are ignored; a field
/// but `mx` given twice counts the first time.
pub fn parse(domain: &str, id: &str, text: &str, now: Timestamp) -> Result<Policy, String> {
    let (mut version, mut mode, mut max_age) = (None, None, None);
    let mut mx = Vec::new();
    for line in text.lines() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.trim().is_empty() {
            continue;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| format!("{line:?} is not a field"))?;
        let value = value.trim();
        match name {
            "version" => {
                version.get_or_insert(value);
            }
            "mode" => {
                mode.get_or_insert(value);
            }
            "max_age" => {
                max_age.get_or_insert(value);
            }
            "mx" => mx.push(pattern(value)?),
            _ => {}
        }
    }
    if version != Some("STSv1") {
        return Err("its version is not STSv1".to_owned());
    }
    let mode = match mode {
        Some("enforce") => Mode::Enforce,
        Some("testing") => Mode::Testing,
        Some("none") => Mode::None,
        Some(other) => return Err(format!("its mode {other:?} is unknown")),
        None => return Err("it has no mode".to_owned()),
    };
    let max_age = max_age
        .filter(|age| {
            (1..=10).contains(&age.len()) && age.bytes().all(|byte| byte.is_ascii_digit())
        })
        .and_then(|age| age.parse().ok())
        .map(Duration::from_secs)
        .ok_or("its max_age is not a number of seconds")?
        .min(Policy::MAX_AGE);
    if mode != Mode::None && mx.is_empty() {
        return Err("it names no exchanges".to_owned());
    }
    Ok(Policy {
        domain: domain.into(),
        id: id.into(),
        mode,
        mx,
        max_age,
        fetched_at: now,
    })
}

/// An `mx` field's pattern, in lowercase: a name, or `*.` and a name.
fn pattern(value: &str) -> Result<Box<str>, String> {
    let pattern = value.trim_end_matches('.').to_ascii_lowercase();
    let name = pattern.strip_prefix("*.").unwrap_or(&pattern);
    let valid = !name.is_empty()
        && name.split('.').all(|label| {
            !label.is_empty()
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        });
    if valid {
        Ok(pattern.into())
    } else {
        Err(format!("{value:?} is not an exchange pattern"))
    }
}

/// What to do about a domain's policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Plan {
    /// The policy kept serves.
    Keep,
    /// Fetch the policy; if that fails, the policy kept serves while it
    /// holds.
    Fetch,
    /// The domain has no policy.
    None,
}

/// What `record` asks of the policy kept for the domain (section 5.1): a
/// policy that holds serves until it runs out, whatever its record says
/// meanwhile, unless the record names a new one, or it is due a refresh.
/// A domain whose fetch `failed` less than [`RETRY`] ago is not fetched
/// again yet.
pub fn plan(
    kept: Option<&Policy>,
    record: &Record,
    failed: Option<Timestamp>,
    now: Timestamp,
) -> Plan {
    let kept = kept.filter(|policy| policy.holds(now));
    let waiting = failed.is_some_and(|at| now.saturating_duration_since(at) < RETRY);
    match (kept, record) {
        (Some(policy), Record::Id(id)) if *policy.id == **id && !refresh_due(policy, now) => {
            Plan::Keep
        }
        (Some(_), Record::Id(_)) if waiting => Plan::Keep,
        (None, Record::Id(_)) if waiting => Plan::None,
        (_, Record::Id(_)) => Plan::Fetch,
        (Some(_), Record::Absent | Record::Failed) => Plan::Keep,
        (None, Record::Absent | Record::Failed) => Plan::None,
    }
}

fn refresh_due(policy: &Policy, now: Timestamp) -> bool {
    now.saturating_duration_since(policy.fetched_at) >= refresh_after(policy)
}

fn refresh_after(policy: &Policy) -> Duration {
    REFRESH.min(policy.max_age / 2)
}

/// How long a route that `policy` shaped may be kept before it is looked
/// up again: until the policy is due a refresh, so a new one is seen in
/// time, but at least [`RETRY`], and never past its end.
pub fn holds_for(policy: &Policy, now: Timestamp) -> Duration {
    let refresh = policy
        .fetched_at
        .saturating_add(refresh_after(policy))
        .saturating_duration_since(now);
    let end = policy.expires_at().saturating_duration_since(now);
    refresh.max(RETRY).min(end)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: Timestamp = Timestamp::from_micros(1_800_000_000_000_000);

    fn later(seconds: u64) -> Timestamp {
        NOW.saturating_add(Duration::from_secs(seconds))
    }

    #[test]
    fn a_record_names_its_id_and_only_one_record_counts() {
        let id = |records: &[&str]| {
            record(
                &records
                    .iter()
                    .map(|&record| record.to_owned())
                    .collect::<Vec<_>>(),
            )
        };
        assert_eq!(
            id(&["v=STSv1; id=20261029T01;"]),
            Record::Id("20261029T01".to_owned())
        );
        assert_eq!(
            id(&["v=spf1 -all", "v=STSv1;id=abc ; ext=1"]),
            Record::Id("abc".to_owned())
        );
        assert_eq!(id(&["v=STSv1; id=a", "v=STSv1; id=b"]), Record::Absent);
        assert_eq!(
            id(&["v=STSv1; id=a", "v=STSv10; id=b"]),
            Record::Id("a".to_owned()),
            "another version's record is not counted"
        );
        assert_eq!(id(&["v=STSv1; id=not-alphanumeric"]), Record::Absent);
        assert_eq!(
            id(&["v=STSv1; id=123456789012345678901234567890123"]),
            Record::Absent
        );
        assert_eq!(id(&["v=STSv1"]), Record::Absent);
        assert_eq!(id(&[]), Record::Absent);
    }

    #[test]
    fn a_policy_file_is_read_as_the_rfc_gives_it() {
        let text = "version: STSv1\r\nmode: enforce\r\nmx: MX1.Example.Test.\r\nmx: *.mail.example.test\r\nmax_age: 604800\r\nextension: ignored\r\n";
        let policy = parse("example.test", "1", text, NOW).unwrap();
        assert_eq!(policy.mode, Mode::Enforce);
        assert_eq!(
            policy.mx,
            vec![
                Box::from("mx1.example.test"),
                Box::from("*.mail.example.test")
            ]
        );
        assert_eq!(policy.max_age, Duration::from_secs(604_800));
        assert!(policy.permits("mx1.example.test") && policy.permits("b.mail.example.test"));
        // LF alone ends a line too, and an over-long max_age is cut to the
        // longest a policy may hold.
        let policy = parse(
            "example.test",
            "1",
            "version: STSv1\nmode: testing\nmx: mx.example.test\nmax_age: 9999999999\n",
            NOW,
        )
        .unwrap();
        assert_eq!(
            (policy.mode, policy.max_age),
            (Mode::Testing, Policy::MAX_AGE)
        );
        let none = parse(
            "example.test",
            "1",
            "version: STSv1\nmode: none\nmax_age: 1\n",
            NOW,
        );
        assert_eq!(none.unwrap().mode, Mode::None);
        for broken in [
            "mode: enforce\nmx: mx.example.test\nmax_age: 1\n",
            "version: STSv2\nmode: enforce\nmx: mx.example.test\nmax_age: 1\n",
            "version: STSv1\nmode: strict\nmx: mx.example.test\nmax_age: 1\n",
            "version: STSv1\nmode: enforce\nmax_age: 1\n",
            "version: STSv1\nmode: enforce\nmx: mx.example.test\nmax_age: soon\n",
            "version: STSv1\nmode: enforce\nmx: mx..example.test\nmax_age: 1\n",
            "<html>not a policy</html>",
        ] {
            assert!(
                parse("example.test", "1", broken, NOW).is_err(),
                "{broken:?}"
            );
        }
    }

    #[test]
    fn a_kept_policy_serves_until_it_runs_out_unless_its_record_names_another() {
        let kept = parse(
            "example.test",
            "1",
            "version: STSv1\nmode: enforce\nmx: mx.example.test\nmax_age: 604800\n",
            NOW,
        )
        .unwrap();
        let same = Record::Id("1".to_owned());
        let other = Record::Id("2".to_owned());
        assert_eq!(plan(Some(&kept), &same, None, later(60)), Plan::Keep);
        assert_eq!(plan(Some(&kept), &other, None, later(60)), Plan::Fetch);
        // A record withdrawn, or a lookup failing, never takes away a
        // policy that holds: an attacker could do either.
        assert_eq!(
            plan(Some(&kept), &Record::Absent, None, later(60)),
            Plan::Keep
        );
        assert_eq!(
            plan(Some(&kept), &Record::Failed, None, later(60)),
            Plan::Keep
        );
        // A day on, it is fetched again; once it has run out, it is gone.
        assert_eq!(plan(Some(&kept), &same, None, later(86_400)), Plan::Fetch);
        assert_eq!(
            plan(Some(&kept), &Record::Absent, None, later(604_800)),
            Plan::None
        );
        assert_eq!(plan(None, &same, None, NOW), Plan::Fetch);
        assert_eq!(plan(None, &Record::Failed, None, NOW), Plan::None);
        // A fetch that failed is not tried again for a while, policy or
        // none.
        let failed = Some(later(86_400));
        assert_eq!(plan(Some(&kept), &other, failed, later(86_460)), Plan::Keep);
        assert_eq!(plan(None, &other, failed, later(86_460)), Plan::None);
        assert_eq!(
            plan(Some(&kept), &other, failed, later(86_700)),
            Plan::Fetch
        );
        // A route it shaped is kept until its refresh is due, a few
        // minutes at least, and never past its end.
        assert_eq!(holds_for(&kept, later(60)), Duration::from_secs(86_340));
        assert_eq!(holds_for(&kept, later(90_000)), RETRY);
        let short = Policy {
            max_age: Duration::from_secs(60),
            ..kept
        };
        assert_eq!(holds_for(&short, later(10)), Duration::from_secs(50));
        assert_eq!(holds_for(&short, later(100)), Duration::ZERO);
    }
}
