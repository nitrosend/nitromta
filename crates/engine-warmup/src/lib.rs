//! Warmup's schedule and promotion: once a UTC day is over,
//! every capped egress is judged on that day's evidence, and the caps it
//! earns are set in one policy change. Enforcement is the scheduler's and
//! the counts are the store's; this crate only judges.
//!
//! A site with a cap of its own is judged on its own, on whatever it saw
//! that day, nothing included. One without is judged on its own once its
//! replies reach the bundle's sample or half the cap it takes, whichever is
//! fewer, and given a cap of its own from then. A provider whose promotion
//! is held gets its own cap even with no traffic, so the pool cannot raise
//! its inherited cap. The rest are pooled, and the
//! pool is judged against the egress's own cap on the bundle's default
//! ladder. A judgment over a signal's threshold to lower takes the cap down
//! a rung, never below the first; over its threshold to hold, it stays;
//! otherwise it rises a rung, but only if the day had replies reaching half
//! the cap. Past the last rung there is no cap.

use std::collections::BTreeMap;
use std::sync::Arc;

use engine_core::budget::{Counts, Signal};
use engine_core::id::EgressId;
use engine_core::policy::{Capping, Caps, Egress, Judgment, Policy, Verdict, Warmed};
use engine_rules::{Reached, Rules, Warmup};

/// The caps every capped egress not yet judged on `day` earns from its
/// evidence that day, as `Change::Caps` takes them: none if every one has
/// been judged on it, or on a later day, already.
pub fn judge(
    policy: &Policy,
    rules: &Rules,
    day: u64,
    evidence: &[(EgressId, Arc<str>, Counts)],
) -> Vec<Capping> {
    let mut by_egress: BTreeMap<EgressId, Vec<(&Arc<str>, &Counts)>> = BTreeMap::new();
    for (egress, site, counts) in evidence {
        by_egress.entry(*egress).or_default().push((site, counts));
    }
    policy
        .egresses()
        .filter(|egress| egress.caps.any())
        .filter(|egress| {
            egress
                .caps
                .warmed
                .as_ref()
                .is_none_or(|warmed| warmed.day < day)
        })
        .map(|egress| {
            let sites = by_egress.get(&egress.id).map_or(&[][..], Vec::as_slice);
            Capping {
                egress: egress.id,
                from: egress.caps.clone(),
                to: judged(egress, rules, day, sites),
                evidence: sites
                    .iter()
                    .map(|(site, counts)| (Arc::clone(site), **counts))
                    .collect(),
            }
        })
        .collect()
}

/// `egress`'s caps once judged on `day`, on its sites' counts: every site
/// with a cap of its own, and every other that saw anything.
fn judged(egress: &Egress, rules: &Rules, day: u64, sites: &[(&Arc<str>, &Counts)]) -> Caps {
    let caps = &egress.caps;
    let mut to = caps.clone();
    let mut pooled = Counts::default();
    let mut judgments = BTreeMap::new();
    let none = Counts::default();
    let mut every: BTreeMap<&Arc<str>, &Counts> =
        caps.sites.keys().map(|site| (site, &none)).collect();
    every.extend(
        rules
            .provider_warmups()
            .filter(|(_, warmup)| !warmup.promote)
            .map(|(site, _)| (site, &none)),
    );
    every.extend(sites.iter().copied());
    for (site, counts) in every {
        // Done there: nothing is counted, nothing to judge.
        let Some(cap) = caps.at(site) else {
            continue;
        };
        let warmup = rules.warmup_of(site);
        let own = caps.sites.contains_key(site);
        if !own && warmup.promote && counts.replies() < needed(warmup, cap) {
            pooled.add(counts);
            continue;
        }
        let (judgment, next) = judge_one(warmup, counts, cap);
        to.sites.insert(Arc::clone(site), next);
        judgments.insert(Arc::clone(site), judgment);
    }
    let pool = match caps.daily {
        Some(cap) => {
            let (judgment, next) = judge_one(rules.default_warmup(), &pooled, cap);
            to.daily = next;
            judgment
        }
        // Its own cap is done, so nothing is pooled under it.
        None => Judgment {
            counts: pooled,
            verdict: Verdict::Untested,
        },
    };
    to.tidy();
    to.warmed = Some(Warmed {
        day,
        pool,
        sites: judgments,
    });
    to
}

/// The replies that test a cap: the bundle's sample, or half the cap,
/// whichever is fewer.
fn needed(warmup: &Warmup, cap: u64) -> u64 {
    warmup.sample.min(cap.div_ceil(2))
}

/// The judgment of one day's `counts` against `cap`, and the cap it earns.
/// A signal over a threshold says so however few the replies; a raise needs
/// replies reaching half the cap, and a cap of none, which sends nothing,
/// never has them.
fn judge_one(warmup: &Warmup, counts: &Counts, cap: u64) -> (Judgment, Option<u64>) {
    let judgment = |verdict| Judgment {
        counts: *counts,
        verdict,
    };
    let replies = counts.replies();
    let signals = [
        (
            Signal::Complained,
            warmup
                .complaints
                .reached(counts.complained, u64::from(counts.delivered)),
        ),
        (
            Signal::Failed,
            warmup.failures.reached(counts.failed, replies),
        ),
        (
            Signal::Deferred,
            warmup.deferrals.reached(counts.deferred, replies),
        ),
        (
            Signal::Throttled,
            warmup.throttles.reached(counts.throttled, replies),
        ),
    ];
    // The furthest reached, the first of those in this order.
    let worst = signals
        .into_iter()
        .filter_map(|(signal, reached)| Some((reached?, signal)))
        .fold(None, |worst: Option<(Reached, Signal)>, next| match worst {
            Some(worst) if worst.0 >= next.0 => Some(worst),
            _ => Some(next),
        });
    match worst {
        Some((Reached::Lower, signal)) => {
            let lower = warmup
                .ladder
                .iter()
                .rev()
                .find(|rung| **rung < cap)
                .copied()
                .unwrap_or(cap);
            (judgment(Verdict::Lowered(signal)), Some(lower))
        }
        Some((Reached::Hold, signal)) => (judgment(Verdict::Held(signal)), Some(cap)),
        None if !warmup.promote => (judgment(Verdict::PromotionHeld), Some(cap)),
        None if replies > 0 && replies.saturating_mul(2) >= cap => {
            let next = warmup.ladder.iter().find(|rung| **rung > cap).copied();
            (judgment(Verdict::Raised), next)
        }
        None => (judgment(Verdict::Untested), Some(cap)),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use engine_core::id::{AccountId, Id};
    use engine_core::policy::Change;

    use super::*;

    const ACCOUNT: AccountId = AccountId(Id::from_u64(1).unwrap());
    const DAY: u64 = 20_391;

    fn egress(policy: &mut Policy, value: u64, address: &str, cap: Option<u64>) -> EgressId {
        policy
            .apply(Change::Egress {
                id: EgressId(Id::from_u64(value).unwrap()),
                account: ACCOUNT,
                address: address.parse().unwrap(),
                helo: format!("mta{value}.example.test"),
                pool: None,
                daily_cap: cap,
            })
            .unwrap();
        policy
            .egresses()
            .find(|egress| egress.address.to_string() == address)
            .unwrap()
            .id
    }

    fn rules() -> Rules {
        Rules::new(&BTreeMap::new()).unwrap()
    }

    fn delivered(delivered: u32) -> Counts {
        Counts {
            delivered,
            ..Counts::default()
        }
    }

    /// Applies `cappings`, as the store does, and returns the egress's caps.
    fn applied(policy: &mut Policy, cappings: Vec<Capping>, egress: EgressId) -> Caps {
        policy.apply(Change::Caps(cappings)).unwrap();
        policy.egress(egress).unwrap().caps.clone()
    }

    #[test]
    fn a_tested_clean_day_raises_a_cap_one_rung_and_an_untested_one_keeps_it() {
        let mut policy = Policy::default();
        let id = egress(&mut policy, 10, "203.0.113.1", Some(50));
        let rules = rules();
        // Google tested its cap: it is judged on its own, and rises. The
        // others are too few to judge alone, and pooled.
        let google: Arc<str> = Arc::from("Google");
        let small: Arc<str> = Arc::from("mx.small.test");
        let evidence = vec![
            (id, Arc::clone(&google), delivered(50)),
            (id, Arc::clone(&small), delivered(10)),
        ];
        let cappings = judge(&policy, &rules, DAY, &evidence);
        // Each carries the evidence it was judged on, which the store
        // checks is still the day's.
        assert_eq!(
            cappings[0].evidence,
            [
                (Arc::clone(&google), delivered(50)),
                (Arc::clone(&small), delivered(10))
            ]
        );
        let caps = applied(&mut policy, cappings, id);
        assert_eq!(caps.at("Google"), Some(100));
        let warmed = caps.warmed.as_ref().unwrap();
        assert_eq!(warmed.sites["Google"].verdict, Verdict::Raised);
        // The pool's 10 replies are under half its cap of 50: untested.
        assert_eq!(warmed.pool.verdict, Verdict::Untested);
        assert_eq!(warmed.pool.counts, delivered(10));
        assert_eq!((caps.daily, caps.at("mx.small.test")), (Some(50), Some(50)));
        // Judged once a day: the same day again is nothing to do.
        assert!(judge(&policy, &rules, DAY, &evidence).is_empty());
        // A day with too few replies at Google keeps its cap; three small
        // sites, each too few to judge alone, test the pool's cap together.
        let next = vec![
            (id, google, delivered(20)),
            (id, small, delivered(10)),
            (id, Arc::from("mx.second.test"), delivered(10)),
            (id, Arc::from("mx.third.test"), delivered(10)),
        ];
        let cappings = judge(&policy, &rules, DAY + 1, &next);
        let caps = applied(&mut policy, cappings, id);
        let warmed = caps.warmed.as_ref().unwrap();
        assert_eq!(warmed.sites["Google"].verdict, Verdict::Untested);
        assert_eq!(caps.at("Google"), Some(100));
        assert_eq!(
            (warmed.pool.verdict, caps.daily),
            (Verdict::Raised, Some(100))
        );
        assert_eq!(warmed.pool.counts, delivered(30));
        assert_eq!(caps.at("mx.second.test"), Some(100), "the pool's cap");
        // A day with no mail at all is judged too, and changes nothing:
        // the site with a cap of its own is judged on nothing, untested.
        let cappings = judge(&policy, &rules, DAY + 2, &[]);
        let caps = applied(&mut policy, cappings, id);
        assert_eq!((caps.daily, caps.at("Google")), (Some(100), Some(100)));
        let warmed = caps.warmed.as_ref().unwrap();
        assert_eq!(warmed.day, DAY + 2);
        assert_eq!(
            warmed.sites["Google"],
            Judgment {
                counts: Counts::default(),
                verdict: Verdict::Untested
            }
        );
    }

    #[test]
    fn a_signal_says_so_however_few_the_replies_and_a_cap_of_none_never_rises() {
        let mut policy = Policy::default();
        let id = egress(&mut policy, 10, "203.0.113.1", Some(1_000));
        let rules = rules();
        // A site with a cap of its own, all of its few replies failures:
        // lowered, though they are under the sample.
        policy
            .apply(Change::Cap {
                account: ACCOUNT,
                address: "203.0.113.1".parse().unwrap(),
                site: Some("Google".to_owned()),
                cap: Some(1_000),
            })
            .unwrap();
        let failing = vec![(
            id,
            Arc::from("Google"),
            Counts {
                failed: 99,
                ..Counts::default()
            },
        )];
        let cappings = judge(&policy, &rules, DAY, &failing);
        let caps = applied(&mut policy, cappings, id);
        assert_eq!(caps.at("Google"), Some(500));
        assert_eq!(
            caps.warmed.unwrap().sites["Google"].verdict,
            Verdict::Lowered(Signal::Failed)
        );
        // The pool's one complaint of a few deliveries, under the sample,
        // still lowers its cap.
        let complained = vec![(
            id,
            Arc::from("mx.small.test"),
            Counts {
                delivered: 5,
                complained: 1,
                ..Counts::default()
            },
        )];
        let cappings = judge(&policy, &rules, DAY + 1, &complained);
        let caps = applied(&mut policy, cappings, id);
        assert_eq!(caps.daily, Some(500));
        // An operator's cap of none sends nothing, and no judgment raises
        // it.
        let mut policy = Policy::default();
        let id = egress(&mut policy, 11, "203.0.113.2", Some(0));
        let cappings = judge(&policy, &rules, DAY, &[]);
        let caps = applied(&mut policy, cappings, id);
        assert_eq!(caps.daily, Some(0));
        assert_eq!(caps.warmed.unwrap().pool.verdict, Verdict::Untested);
    }

    #[test]
    fn signals_over_their_thresholds_hold_or_lower_a_cap_and_never_below_the_first_rung() {
        let mut policy = Policy::default();
        let id = egress(&mut policy, 10, "203.0.113.1", Some(1_000));
        let rules = rules();
        let site = |name: &str, counts| (id, Arc::<str>::from(name), counts);
        let evidence = vec![
            // One throttle holds.
            site(
                "Yahoo",
                Counts {
                    delivered: 900,
                    throttled: 1,
                    ..Counts::default()
                },
            ),
            // Complaints at 0.3% of deliveries lower.
            site(
                "Google",
                Counts {
                    delivered: 1_000,
                    complained: 3,
                    ..Counts::default()
                },
            ),
            // Deferrals at 5% hold, failures at 5% lower: the furthest wins.
            site(
                "Outlook",
                Counts {
                    delivered: 900,
                    deferred: 50,
                    failed: 50,
                    ..Counts::default()
                },
            ),
        ];
        let cappings = judge(&policy, &rules, DAY, &evidence);
        let caps = applied(&mut policy, cappings, id);
        let warmed = caps.warmed.clone().unwrap();
        assert_eq!(
            warmed.sites["Yahoo"].verdict,
            Verdict::Held(Signal::Throttled)
        );
        assert_eq!(caps.at("Yahoo"), Some(1_000));
        assert_eq!(
            warmed.sites["Google"].verdict,
            Verdict::Lowered(Signal::Complained)
        );
        assert_eq!(caps.at("Google"), Some(500));
        assert_eq!(
            warmed.sites["Outlook"].verdict,
            Verdict::Lowered(Signal::Failed)
        );
        assert_eq!(caps.at("Outlook"), Some(750), "down its own ladder");

        // On the same clean day each climbs its own ladder, and one deferral
        // holds Outlook's where it leaves Google's to rise.
        let mut policy = Policy::default();
        let id = egress(&mut policy, 12, "203.0.113.3", Some(200));
        let clean = vec![
            (id, Arc::<str>::from("Google"), delivered(200)),
            (id, Arc::<str>::from("Outlook"), delivered(200)),
        ];
        let cappings = judge(&policy, &rules, DAY, &clean);
        let caps = applied(&mut policy, cappings, id);
        assert_eq!(
            (caps.at("Google"), caps.at("Outlook")),
            (Some(500), Some(300))
        );
        let mut policy = Policy::default();
        let id = egress(&mut policy, 13, "203.0.113.4", Some(200));
        let one_deferred = Counts {
            delivered: 199,
            deferred: 1,
            ..Counts::default()
        };
        let deferred = vec![
            (id, Arc::<str>::from("Google"), one_deferred),
            (id, Arc::<str>::from("Outlook"), one_deferred),
        ];
        let cappings = judge(&policy, &rules, DAY, &deferred);
        let caps = applied(&mut policy, cappings, id);
        assert_eq!(
            (caps.at("Google"), caps.at("Outlook")),
            (Some(500), Some(200))
        );
        assert_eq!(
            caps.warmed.unwrap().sites["Outlook"].verdict,
            Verdict::Held(Signal::Deferred)
        );

        // At the first rung, a lowering keeps it there.
        let mut policy = Policy::default();
        let id = egress(&mut policy, 11, "203.0.113.2", Some(50));
        let bounced = vec![(
            id,
            Arc::from("Google"),
            Counts {
                delivered: 40,
                failed: 10,
                ..Counts::default()
            },
        )];
        let cappings = judge(&policy, &rules, DAY, &bounced);
        let caps = applied(&mut policy, cappings, id);
        assert_eq!(caps.at("Google"), Some(50));
        assert_eq!(
            caps.warmed.unwrap().sites["Google"].verdict,
            Verdict::Lowered(Signal::Failed)
        );
    }

    #[test]
    fn past_the_last_rung_there_is_no_cap_and_the_egress_is_done_once_no_site_has_one() {
        let short = engine_rules::Entry {
            warmup: Some(engine_rules::WarmupEntry {
                ladder: Some(vec![50, 100]),
                ..Default::default()
            }),
            ..Default::default()
        };
        let overrides = BTreeMap::from([(engine_rules::DEFAULTS.to_owned(), short)]);
        let rules = Rules::new(&overrides).unwrap();
        let mut policy = Policy::default();
        let id = egress(&mut policy, 10, "203.0.113.1", Some(100));
        // One site tests the egress's last rung on its own and takes a cap
        // of its own: none. Twenty small ones, each too few to judge alone,
        // test it together.
        let mut evidence = vec![(id, Arc::<str>::from("mx.one.test"), delivered(60))];
        for index in 0..20 {
            evidence.push((id, Arc::from(format!("mx{index}.pool.test")), delivered(30)));
        }
        let cappings = judge(&policy, &rules, DAY, &evidence);
        let caps = applied(&mut policy, cappings, id);
        let warmed = caps.warmed.as_ref().unwrap();
        assert_eq!(warmed.sites["mx.one.test"].verdict, Verdict::Raised);
        assert_eq!(warmed.pool.verdict, Verdict::Raised);
        assert_eq!(warmed.pool.counts, delivered(600));
        // With no cap of its own, a site's cap of none needs no entry.
        assert_eq!(caps.daily, None);
        assert!(caps.sites.is_empty(), "{:?}", caps.sites);
        assert!(!caps.any(), "done");
        assert!(judge(&policy, &rules, DAY + 1, &[]).is_empty());
    }
    #[test]
    fn a_provider_promotion_hold_survives_clean_days_and_still_lowers_on_bad_signals() {
        let mut policy = Policy::default();
        let id = egress(&mut policy, 10, "203.0.113.1", Some(500));
        let override_entry = engine_rules::Entry {
            warmup: Some(engine_rules::WarmupEntry {
                promote: Some(false),
                ..Default::default()
            }),
            ..Default::default()
        };
        let rules = Rules::new(&BTreeMap::from([("Google".to_owned(), override_entry)])).unwrap();
        let site = |name: &str, counts| (id, Arc::<str>::from(name), counts);
        // Even a small sample gets its own held cap, rather than pooling
        // into an automatic increase from other sites' traffic.
        let counts = [site("Google", delivered(10)), site("Yahoo", delivered(500))];
        let changes = judge(&policy, &rules, DAY, &counts);
        let caps = applied(&mut policy, changes, id);
        assert_eq!(caps.at("Google"), Some(500));
        assert_eq!(caps.at("Yahoo"), Some(1000));
        assert_eq!(
            caps.warmed.unwrap().sites["Google"].verdict,
            Verdict::PromotionHeld
        );
        let counts = [site("Google", delivered(500))];
        let changes = judge(&policy, &rules, DAY + 1, &counts);
        assert_eq!(applied(&mut policy, changes, id).at("Google"), Some(500));
        let counts = [site(
            "Google",
            Counts {
                delivered: 500,
                complained: 5,
                ..Counts::default()
            },
        )];
        let changes = judge(&policy, &rules, DAY + 2, &counts);
        assert_eq!(applied(&mut policy, changes, id).at("Google"), Some(200));
        // Explicitly re-enable promotion; the existing cap becomes the
        // starting point, without resetting progress or adding new state.
        let changes = judge(
            &policy,
            &self::rules(),
            DAY + 3,
            &[site("Google", delivered(200))],
        );
        assert_eq!(applied(&mut policy, changes, id).at("Google"), Some(500));
    }

    #[test]
    fn an_idle_held_provider_does_not_inherit_the_pools_increase() {
        let mut policy = Policy::default();
        let id = egress(&mut policy, 10, "203.0.113.1", Some(500));
        let rules = Rules::new(&BTreeMap::from([(
            "Google".to_owned(),
            engine_rules::Entry {
                warmup: Some(engine_rules::WarmupEntry {
                    promote: Some(false),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )]))
        .unwrap();
        let counts: Vec<_> = (0..5)
            .map(|n| (id, Arc::<str>::from(format!("mx{n}.test")), delivered(50)))
            .collect();
        let changes = judge(&policy, &rules, DAY, &counts);
        let caps = applied(&mut policy, changes, id);
        assert_eq!(caps.daily, Some(1000), "small sites promote the pool");
        assert_eq!(caps.at("Google"), Some(500), "the idle provider stays held");
        assert_eq!(
            caps.warmed.unwrap().sites["Google"].verdict,
            Verdict::PromotionHeld
        );
    }
}
