//! What the scheduler can say about the mail it holds in memory, for the
//! operator's `explain` and `queue`: where each delivery waits and
//! why, and how each queue stands. It reads what the scheduler holds and
//! changes nothing.

use std::sync::Arc;

use engine_core::attempt::Evidence;
use engine_core::id::{DeliveryId, EgressId};
use engine_core::policy::Judgment;
use engine_core::time::{Now, Timestamp};

use crate::{Domain, Flight, Path, Scheduler, Site, SiteKey, Waiting};

/// What an inspection asks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Inspection {
    /// Where each of these deliveries waits, if the scheduler holds it.
    Explain(Vec<DeliveryId>),
    /// The queues, those with the most waiting first, at most this many.
    Queues { most: usize },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Report {
    /// Each delivery asked about that the scheduler holds, and where. One
    /// it does not hold waits in the store for its due time.
    Holds(Vec<(DeliveryId, Hold)>),
    Queues(Vec<QueueReport>),
}

/// Where a delivery waits, and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Hold {
    /// Its domain's route is being looked up.
    Routing { domain: Box<str> },
    /// It waits to be placed on an egress: its pool has none, the dispatch
    /// ledger is not read yet, or no policy has been given.
    Unplaced,
    /// It waits in its queue behind `ahead` others.
    Queued {
        site: Arc<str>,
        /// Its queue: the exchanges its domain names.
        queue: Arc<str>,
        egress: Option<EgressId>,
        ahead: usize,
        cooling: Option<Cooling>,
        /// When its egress has budget for the site again, if it has none.
        budget_frees: Option<Timestamp>,
        warmup: Option<Capped>,
    },
    /// The dispatch hook is deciding it.
    Consulting {
        site: Arc<str>,
        egress: Option<EgressId>,
    },
    /// Its reservation, or its body, is being read.
    Starting {
        site: Arc<str>,
        egress: Option<EgressId>,
    },
    /// An attempt is under way.
    InFlight {
        site: Arc<str>,
        egress: Option<EgressId>,
    },
}

/// A queue's cooldown: its receiver throttled it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cooling {
    pub until: Timestamp,
    /// Throttles since the site last took mail.
    pub throttles: u32,
    /// What the receiver said when it began.
    pub reply: Option<Evidence>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueueReport {
    pub site: Arc<str>,
    /// The exchanges whose queue it is.
    pub queue: Arc<str>,
    pub egress: Option<EgressId>,
    pub waiting: usize,
    /// Transactions under way at its site, from any of the site's queues.
    pub active: usize,
    pub cooling: Option<Cooling>,
    pub budget_frees: Option<Timestamp>,
    pub warmup: Option<Capped>,
    /// Deliveries put off in the store until the egress's cap has room for
    /// them at the site, still to come due: those put off since
    /// the engine started. A site's are shown on its own row, the queue
    /// named for the site, which shows them alone when none of its queues
    /// is so named.
    pub put_off: u64,
}

/// The cap an egress has at a site, and warmup's last judgment
/// of what it applies to there, if it judged that: the site, judged on its
/// own, or the egress's pool, whose cap a site without its own takes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capped {
    pub cap: u64,
    /// The UTC day judged, days since the Unix epoch, and the judgment.
    pub judged: Option<(u64, Judgment)>,
}

impl Scheduler {
    pub(crate) fn inspect(&self, now: Now, inspection: &Inspection) -> Report {
        match inspection {
            Inspection::Explain(deliveries) => Report::Holds(
                deliveries
                    .iter()
                    .filter_map(|&delivery| Some((delivery, self.hold(now, delivery)?)))
                    .collect(),
            ),
            Inspection::Queues { most } => {
                let mut queues: Vec<QueueReport> = self
                    .queues
                    .iter()
                    .map(|(queue, line)| {
                        let key = (queue.0, Arc::clone(line.destination.site.name()));
                        let site = self.sites.get(&key);
                        QueueReport {
                            site: Arc::clone(&key.1),
                            queue: Arc::clone(&queue.1),
                            egress: queue.0,
                            waiting: line.ready.len(),
                            active: site.map_or(0, |site| site.active),
                            cooling: site.and_then(|site| cooling(now, site)),
                            budget_frees: self.budget_frees(now, &key),
                            warmup: self.capped(&key),
                            put_off: 0,
                        }
                    })
                    .collect();
                for ((egress, name), put_off) in &self.put_off {
                    let put_off = put_off.to_come(now.wall);
                    if put_off == 0 {
                        continue;
                    }
                    let own = queues.iter_mut().find(|queue| {
                        queue.egress == Some(*egress) && queue.site == *name && queue.queue == *name
                    });
                    if let Some(queue) = own {
                        queue.put_off = put_off;
                        continue;
                    }
                    let key = (Some(*egress), Arc::clone(name));
                    let site = self.sites.get(&key);
                    queues.push(QueueReport {
                        site: Arc::clone(name),
                        queue: Arc::clone(name),
                        egress: Some(*egress),
                        waiting: 0,
                        active: site.map_or(0, |site| site.active),
                        cooling: site.and_then(|site| cooling(now, site)),
                        budget_frees: self.budget_frees(now, &key),
                        warmup: self.capped(&key),
                        put_off,
                    });
                }
                let most_first = |queue: &QueueReport| queue.waiting as u64 + queue.put_off;
                queues.sort_by(|a, b| most_first(b).cmp(&most_first(a)).then(a.site.cmp(&b.site)));
                queues.truncate(*most);
                Report::Queues(queues)
            }
        }
    }

    fn hold(&self, now: Now, delivery: DeliveryId) -> Option<Hold> {
        if !self.held.contains(&delivery) {
            return None;
        }
        if let Some(Flight { path, .. }) = self.flights.get(&delivery) {
            return Some(Hold::InFlight {
                site: Arc::clone(path.destination.site.name()),
                egress: path.source,
            });
        }
        for (queue, line) in &self.queues {
            if let Some(ahead) = line
                .ready
                .iter()
                .position(|item| item.delivery.id() == delivery)
            {
                let key = (queue.0, Arc::clone(line.destination.site.name()));
                return Some(Hold::Queued {
                    site: Arc::clone(&key.1),
                    queue: Arc::clone(&queue.1),
                    egress: queue.0,
                    ahead,
                    cooling: self.sites.get(&key).and_then(|site| cooling(now, site)),
                    budget_frees: self.budget_frees(now, &key),
                    warmup: self.capped(&key),
                });
            }
        }
        for waiting in self.waiting.values() {
            let starting = |path: &Path| Hold::Starting {
                site: Arc::clone(path.destination.site.name()),
                egress: path.source,
            };
            match waiting {
                Waiting::Content(path, items)
                    if items.iter().any(|item| item.delivery.id() == delivery) =>
                {
                    return Some(starting(path));
                }
                Waiting::Consult(path, items)
                    if items.iter().any(|item| item.delivery.id() == delivery) =>
                {
                    return Some(Hold::Consulting {
                        site: Arc::clone(path.destination.site.name()),
                        egress: path.source,
                    });
                }
                Waiting::Reserve(number, item) if item.delivery.id() == delivery => {
                    return self.groups.get(number).map(|group| starting(&group.path));
                }
                _ => {}
            }
        }
        for (domain, state) in &self.domains {
            if let Domain::Resolving(items) = state
                && items.iter().any(|item| item.delivery.id() == delivery)
            {
                return Some(Hold::Routing {
                    domain: domain.clone(),
                });
            }
        }
        self.unplaced
            .iter()
            .any(|(_, item)| item.delivery.id() == delivery)
            .then_some(Hold::Unplaced)
    }

    /// `site`'s cap at its egress, if it has one.
    fn capped(&self, site: &SiteKey) -> Option<Capped> {
        let caps = &self.policy.egress(site.0?)?.caps;
        let cap = caps.at(&site.1)?;
        let judged = caps.warmed.as_ref().and_then(|warmed| {
            let judgment = if caps.sites.contains_key(&site.1) {
                warmed.sites.get(&site.1)?
            } else {
                &warmed.pool
            };
            Some((warmed.day, *judgment))
        });
        Some(Capped { cap, judged })
    }

    /// When `site`'s egress has budget for it again, if it has none.
    fn budget_frees(&self, now: Now, site: &SiteKey) -> Option<Timestamp> {
        if self.site_budget(now.wall, site) > 0 {
            return None;
        }
        let egress = site.0?;
        self.budgets
            .get(&(egress, Arc::clone(&site.1)))?
            .frees_at(now.wall)
    }
}

fn cooling(now: Now, site: &Site) -> Option<Cooling> {
    let cooldown = site.cooldown.as_ref()?;
    (cooldown.until > now.monotonic).then(|| Cooling {
        until: cooldown.until_wall,
        throttles: cooldown.throttles,
        reply: cooldown.reply.clone(),
    })
}
