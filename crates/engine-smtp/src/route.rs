//! Route resolution decisions (RFC 5321, 5.1; RFC 7505): where a domain's
//! mail goes, given what its MX lookup found, and what its connections' TLS
//! must prove there: its MTA-STS policy, when one enforces,
//! permits only the exchanges it names (RFC 8461, 4.1), and DNSSEC-secure
//! MX records let each exchange's TLSA records bind its certificate (RFC
//! 7672, 2.2). The driver performs the lookups; the decision is made here,
//! so the simulator makes the same one.

use engine_core::sts::Policy;

/// What a domain's MX lookup found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Answer {
    /// Its MX records: each preference and exchange.
    Records(Vec<(u16, String)>),
    /// The domain exists, and has no MX records.
    NoRecords,
    /// The domain does not exist.
    NoSuchDomain,
    /// The lookup failed, for now, for this reason.
    Failed(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Route {
    /// Its exchanges, in lowercase, most preferred first, and what TLS to
    /// them must prove.
    Exchanges(Vec<String>, Tls),
    /// It accepts no mail: it has a null MX, or does not exist.
    Refused,
    /// Not usable for now: its lookup failed, or its MTA-STS policy permits
    /// none of its exchanges. Its mail waits, for this reason.
    Unresolved(String),
}

/// What a route's connections must prove of their TLS beyond encrypting.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Tls {
    /// Its MX records are DNSSEC-secure, so an exchange's own secure TLSA
    /// records bind its certificate (RFC 7672).
    pub dane: bool,
    /// Its MTA-STS policy enforces: an exchange without TLSA records that
    /// bind it must present a certificate the web PKI trusts for its name
    /// (RFC 8461).
    pub sts: bool,
}

impl Tls {
    /// What its queues' names carry after their exchanges', so connections
    /// that must prove different things never carry each other's mail.
    pub fn suffix(self) -> &'static str {
        match (self.dane, self.sts) {
            (false, false) => "",
            (true, false) => " dane",
            (false, true) => " sts",
            (true, true) => " dane sts",
        }
    }
}

/// Where `domain`'s mail goes. A domain with no MX records is its own
/// exchange (5.1); a lone exchange of `.` is a null MX, which refuses mail.
/// `secure` says DNSSEC proved its MX records, or proved it has none, which
/// DANE applies to. `policy` is its MTA-STS policy, if it has one that
/// holds.
pub fn route(domain: &str, answer: Answer, secure: bool, policy: Option<&Policy>) -> Route {
    let (exchanges, dane) = match answer {
        Answer::Records(mut records) => {
            records.sort_by_key(|(preference, _)| *preference);
            let exchanges: Vec<String> = records
                .into_iter()
                .map(|(_, exchange)| exchange.trim_end_matches('.').to_ascii_lowercase())
                .filter(|exchange| !exchange.is_empty())
                .collect();
            if exchanges.is_empty() {
                return Route::Refused;
            }
            (exchanges, secure)
        }
        // A domain proved to have no MX records is its own exchange, and
        // its own name its TLSA base (RFC 7672, 2.2.2).
        Answer::NoRecords => (vec![domain.to_ascii_lowercase()], secure),
        Answer::NoSuchDomain => return Route::Refused,
        Answer::Failed(reason) => {
            return Route::Unresolved(format!("the MX lookup for {domain} failed: {reason}"));
        }
    };
    let Some(policy) = policy.filter(|policy| policy.enforces()) else {
        return Route::Exchanges(exchanges, Tls { dane, sts: false });
    };
    let permitted: Vec<String> = exchanges
        .into_iter()
        .filter(|exchange| policy.permits(exchange))
        .collect();
    if permitted.is_empty() {
        return Route::Unresolved(format!(
            "MTA-STS: the policy of {} permits none of its exchanges",
            policy.domain
        ));
    }
    Route::Exchanges(permitted, Tls { dane, sts: true })
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Duration;

    use engine_core::sts::Mode;
    use engine_core::time::Timestamp;

    fn exchanges(names: &[&str]) -> Vec<String> {
        names.iter().map(|&name| name.to_owned()).collect()
    }

    #[test]
    fn exchanges_come_in_order_of_preference() {
        let answer = Answer::Records(vec![
            (20, "MX2.Example.Test.".to_owned()),
            (10, "mx1.example.test.".to_owned()),
        ]);
        assert_eq!(
            route("example.test", answer, false, None),
            Route::Exchanges(
                exchanges(&["mx1.example.test", "mx2.example.test"]),
                Tls::default()
            )
        );
    }

    #[test]
    fn a_domain_without_records_is_its_own_exchange_and_a_null_mx_refuses() {
        assert_eq!(
            route("Example.Test", Answer::NoRecords, false, None),
            Route::Exchanges(exchanges(&["example.test"]), Tls::default())
        );
        assert_eq!(
            route("example.test", Answer::NoRecords, true, None),
            Route::Exchanges(
                exchanges(&["example.test"]),
                Tls {
                    dane: true,
                    sts: false
                }
            ),
            "proved to have no MX records: DANE applies to its own name"
        );
        assert_eq!(
            route(
                "example.test",
                Answer::Records(vec![(0, ".".to_owned())]),
                false,
                None
            ),
            Route::Refused
        );
        assert_eq!(
            route("example.test", Answer::NoSuchDomain, false, None),
            Route::Refused
        );
        assert_eq!(
            route(
                "example.test",
                Answer::Failed("timed out".to_owned()),
                false,
                None
            ),
            Route::Unresolved("the MX lookup for example.test failed: timed out".to_owned())
        );
    }

    #[test]
    fn an_enforced_policy_keeps_mail_to_the_exchanges_it_names() {
        let policy = |mode| Policy {
            domain: "example.test".into(),
            id: "1".into(),
            mode,
            mx: vec!["mx1.example.test".into()],
            max_age: Duration::from_secs(86_400),
            fetched_at: Timestamp::from_micros(0),
        };
        let answer = || {
            Answer::Records(vec![
                (10, "mx1.example.test".to_owned()),
                (20, "backup.elsewhere.test".to_owned()),
            ])
        };
        let enforced = policy(Mode::Enforce);
        assert_eq!(
            route("example.test", answer(), true, Some(&enforced)),
            Route::Exchanges(
                exchanges(&["mx1.example.test"]),
                Tls {
                    dane: true,
                    sts: true
                }
            )
        );
        // A policy in testing changes nothing.
        assert_eq!(
            route(
                "example.test",
                answer(),
                false,
                Some(&policy(Mode::Testing))
            ),
            Route::Exchanges(
                exchanges(&["mx1.example.test", "backup.elsewhere.test"]),
                Tls::default()
            )
        );
        let elsewhere = Answer::Records(vec![(10, "backup.elsewhere.test".to_owned())]);
        assert_eq!(
            route("example.test", elsewhere, false, Some(&enforced)),
            Route::Unresolved(
                "MTA-STS: the policy of example.test permits none of its exchanges".to_owned()
            )
        );
    }
}
