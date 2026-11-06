//! The command line: `nitromta <command>`, each command's options
//! as `--name value`, or a bare `--name` for a switch.
//!
//! A command about a running engine speaks the native API to its admin
//! socket, which `--config` names, so the store, which the engine holds
//! alone, is never opened twice. Each prints plain text for a person, and
//! with `--json` the API's own answer lines, for a script. An answer that
//! is an error ends the command with its code and message.

use std::collections::BTreeMap;
use std::path::Path;

use serde_json::{Value, json};

use crate::{admin, backup, clock, config, doctor, keys, setup, store};

/// Every command, for the usage line.
const USAGE: &str =
    "usage: nitromta <command> [--option value ...] | nitromta --version | nitromta --help

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

  Each command about a running engine takes --json for the API's own lines.";

/// How to run the command `words` name: each of its forms, as the usage
/// gives them, or the whole usage when they name no command. Words past a
/// command's own, as in `fence release`, name the command they follow.
fn usage(words: &[&str]) -> String {
    if words.is_empty() {
        return USAGE.to_owned();
    }
    // Each form: the command's words it opens with, and its lines.
    let mut forms: Vec<(Vec<&str>, Vec<&str>)> = Vec::new();
    for line in USAGE.lines().skip(1) {
        let Some(form) = line.strip_prefix("  ") else {
            continue;
        };
        if form.starts_with(' ') {
            // A line indented further goes on with the form above it.
            if let Some((_, lines)) = forms.last_mut() {
                lines.push(line);
            }
        } else {
            let named = form
                .split(' ')
                .take_while(|word| word.starts_with(|c: char| c.is_ascii_lowercase()))
                .collect();
            forms.push((named, vec![line]));
        }
    }
    let chosen = |fits: &dyn Fn(&[&str]) -> bool| -> Vec<&str> {
        forms
            .iter()
            .filter(|(named, _)| !named.is_empty() && fits(named))
            .flat_map(|(_, lines)| lines.iter().copied())
            .collect()
    };
    let mut lines = chosen(&|named| named.starts_with(words));
    if lines.is_empty() {
        lines = chosen(&|named| words.starts_with(named));
    }
    if lines.is_empty() {
        return USAGE.to_owned();
    }
    format!("usage:\n{}", lines.join("\n"))
}

/// A command's words and options, as given.
pub struct Options {
    words: Vec<String>,
    values: BTreeMap<String, Vec<String>>,
    switches: Vec<String>,
}

/// The options that are switches, with no value.
const SWITCHES: [&str; 8] = [
    "help",
    "version",
    "json",
    "accepting",
    "wait",
    "capture",
    "manage",
    "manage-only",
];

impl Options {
    pub fn parse(argv: &[String]) -> Result<Self, String> {
        let mut options = Self {
            words: Vec::new(),
            values: BTreeMap::new(),
            switches: Vec::new(),
        };
        let mut arguments = argv.iter();
        while let Some(argument) = arguments.next() {
            match argument.strip_prefix("--") {
                Some(name) if SWITCHES.contains(&name) => options.switches.push(name.to_owned()),
                Some(name) => {
                    // An option where its value should be is a value left
                    // out, never the value.
                    let value = arguments
                        .next()
                        .filter(|value| !value.starts_with("--"))
                        .ok_or_else(|| format!("--{name} needs a value"))?;
                    options
                        .values
                        .entry(name.to_owned())
                        .or_default()
                        .push(value.clone());
                }
                None => options.words.push(argument.clone()),
            }
        }
        Ok(options)
    }

    /// The command, and the words after it.
    pub fn words(&self) -> Vec<&str> {
        self.words.iter().map(String::as_str).collect()
    }

    pub fn value(&self, name: &str) -> Option<&str> {
        self.values.get(name)?.last().map(String::as_str)
    }

    fn all(&self, name: &str) -> Vec<String> {
        self.values.get(name).cloned().unwrap_or_default()
    }

    pub fn required(&self, name: &str) -> Result<&str, String> {
        self.value(name)
            .ok_or_else(|| format!("--{name} is needed\n\n{USAGE}"))
    }

    pub fn switch(&self, name: &str) -> bool {
        self.switches.iter().any(|switch| switch == name)
    }

    /// Refuses any option but `allowed`, and `--config` and `--json`.
    fn only(&self, allowed: &[&str]) -> Result<(), String> {
        let unknown = self.values.keys().chain(&self.switches).find(|name| {
            !matches!(name.as_str(), "config" | "json") && !allowed.contains(&name.as_str())
        });
        match unknown {
            Some(name) => Err(format!(
                "--{name} is not an option of this command\n\n{USAGE}"
            )),
            None => Ok(()),
        }
    }

    fn account(&self) -> Result<u64, String> {
        self.required("account")?
            .parse()
            .map_err(|_| "--account is a number".to_owned())
    }
}

/// Runs a command other than `run`, or says how to run any.
pub fn command(options: &Options) -> Result<(), String> {
    let words = options.words();
    if options.switch("help") {
        println!("{}", usage(&words));
        return Ok(());
    }
    match words.as_slice() {
        [] if options.switch("version") => {
            println!("nitromta {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        ["check"] => {
            options.only(&[])?;
            let config = config::load(Path::new(options.required("config")?))?;
            store::check(&config.store.path)
        }
        ["key", "list"] => {
            options.only(&[])?;
            let config = config::load(Path::new(options.required("config")?))?;
            let ids = keys::ids(&config.store.keys)?;
            let sealing = engine_keys(options).ok().map(|running| running.sealing);
            let newest = ids.last().copied();
            for id in &ids {
                let mut line = format!("key {id}");
                if Some(*id) == newest {
                    line.push_str(", the newest, which new secrets are sealed under");
                }
                if Some(*id) == sealing {
                    line.push_str(", which the running engine seals every secret under");
                }
                println!("{line}");
            }
            if sealing.is_none() {
                println!(
                    "the engine is not running: which key seals its secrets is known once it starts"
                );
            }
            Ok(())
        }
        ["key", "retire"] => {
            options.only(&["id"])?;
            let id: u8 = options
                .required("id")?
                .parse()
                .map_err(|_| "--id is a key's ID, 1 to 254".to_owned())?;
            let config = config::load(Path::new(options.required("config")?))?;
            // Only the running engine can say no secret is under it: the
            // engine holding these keys, sealing this store.
            let running = engine_keys(options)
                .map_err(|why| format!("{why}; a key retires only while the engine runs, which says what seals its secrets"))?;
            let full = |path: &Path| {
                std::fs::canonicalize(path)
                    .map(|path| path.display().to_string())
                    .map_err(|error| format!("{}: {error}", path.display()))
            };
            if running.keys != full(&config.store.keys)?
                || running.store != full(&config.store.path)?
            {
                return Err(format!(
                    "the engine on this configuration's admin socket holds the keys at {} and the store at {}, not this configuration's: retire a key through its own engine's configuration",
                    running.keys, running.store
                ));
            }
            let held = held_by(options, &config, id)?;
            if !held.is_empty() {
                return Err(format!(
                    "key {id} still seals {}: retire it once they are gone",
                    doctor::held(&held)
                ));
            }
            keys::retire(&config.store.keys, id, running.sealing)?;
            println!("key {id} retired from {}", config.store.keys.display());
            Ok(())
        }
        ["key"] => {
            options.only(&["to"])?;
            let path = options.required("to")?;
            let id = keys::generate(Path::new(path))?;
            println!(
                "key {id} written to {path}; a restart seals every secret under it, and older keys may then go, once mail sealed under them is gone (`key retire` says what still needs one)"
            );
            Ok(())
        }
        ["admin"] => {
            options.only(&[])?;
            admin::client(&socket(options)?)
        }
        ["setup"] => {
            options.only(&[
                "hostname",
                "return-path-domain",
                "store",
                "keys",
                "certificate",
                "key",
                "admin-socket",
                "capture",
            ])?;
            let config = std::path::PathBuf::from(options.required("config")?);
            let beside = |name: &str| {
                config
                    .parent()
                    .filter(|parent| !parent.as_os_str().is_empty())
                    .unwrap_or(Path::new("."))
                    .join(name)
            };
            let path = |option: &str, otherwise: std::path::PathBuf| {
                options
                    .value(option)
                    .map_or(otherwise, std::path::PathBuf::from)
            };
            // To try the engine, everything is beside the configuration,
            // and nothing needs a name of its own.
            let capturing = options.switch("capture");
            let named = |option: &str, trying: &str| match options.value(option) {
                Some(value) => Ok(value.to_owned()),
                None if capturing => Ok(trying.to_owned()),
                None => options.required(option).map(str::to_owned),
            };
            let (store, socket) = if capturing {
                (beside("store.db"), beside("admin.sock"))
            } else {
                (
                    "/var/lib/nitromta/store.db".into(),
                    "/run/nitromta/admin.sock".into(),
                )
            };
            let layout = setup::Layout {
                hostname: named("hostname", "localhost")?,
                return_path_domain: named("return-path-domain", "bounces.localhost")?,
                store: path("store", store),
                keys: path("keys", beside("keys")),
                certificate: path("certificate", beside("tls.crt")),
                key: path("key", beside("tls.key")),
                socket: path("admin-socket", socket),
                capture: capturing.then(|| beside("capture")),
                config,
            };
            setup::run(&layout)
        }
        ["doctor"] => {
            options.only(&["time-server", "port25"])?;
            let config = config::load(Path::new(options.required("config")?))?;
            let running = running(options, &config);
            let probes = doctor::Probes {
                time_server: options
                    .value("time-server")
                    .unwrap_or(doctor::TIME_SERVER)
                    .to_owned(),
                port25: options.value("port25").unwrap_or(doctor::PROBE).to_owned(),
            };
            if doctor::run(&config, running.as_ref(), &probes)? {
                Ok(())
            } else {
                Err("doctor found what to change, above".to_owned())
            }
        }
        ["migrate"] => {
            options.only(&[])?;
            let config = config::load(Path::new(options.required("config")?))?;
            store::migrate(&config.store.path)
        }
        ["backup"] => {
            options.only(&["to"])?;
            let config = config::load(Path::new(options.required("config")?))?;
            let to = full_path(Path::new(options.required("to")?))?;
            let now = || clock::SystemClock::new().now().wall;
            // Through the running engine, whose store thread copies it
            // between commits; or, stopped, directly.
            let running = config
                .admin
                .as_ref()
                .map(|admin| admin.socket.clone())
                .filter(|socket| std::os::unix::net::UnixStream::connect(socket).is_ok());
            match running {
                Some(socket) => {
                    let request = json!({"op": "backup", "to": to.display().to_string()});
                    let answer = admin::ask_backup(&socket, &request)?;
                    shown(options, &answer, |ok| {
                        format!(
                            "backed up to {}: {} bytes, the store as it was at {}",
                            text(&ok["to"]),
                            ok["bytes"],
                            text(&ok["taken"])
                        )
                    })?;
                }
                None => {
                    let copied = backup::stopped(&config.store.path, &to, now)?;
                    println!(
                        "backed up to {}: {} bytes, the stopped store as it was at {}",
                        to.display(),
                        copied.bytes,
                        engine_api::inspect::rfc3339(copied.taken)
                    );
                }
            }
            Ok(())
        }
        ["restore"] => {
            options.only(&["from"])?;
            let path = options.required("config")?;
            let config = config::load(Path::new(path))?;
            let from = Path::new(options.required("from")?);
            let now = clock::SystemClock::new().now().wall;
            let restored = backup::restore(&config, from, now)?;
            println!(
                "restored {} as the store at {}, fenced: the copy was taken at {}",
                from.display(),
                config.store.path.display(),
                engine_api::inspect::rfc3339(restored.fence.taken)
            );
            if let Some(aside) = &restored.aside {
                println!("the store that was there is at {}", aside.display());
            }
            if restored.unkeyed > 0 {
                println!(
                    "{} of its tenants have no key in {}.tenants: their mail in it reads as erased, unless their keys are put back before the engine starts",
                    restored.unkeyed,
                    config.store.keys.display()
                );
            }
            println!(
                "\n{} deliveries the copy held unfinished wait for a decision, once the engine starts; until then new mail is taken and sent as ever.
  nitromta fence release --config {path}   sends them: any may have been delivered after the copy was taken
  nitromta fence discard --config {path}   cancels each as it falls due, unsent
Suppressions and feedback recorded after the copy was taken are not in it.",
                restored.unfinished
            );
            Ok(())
        }
        ["fence"] => {
            options.only(&[])?;
            answer(options, &[json!({"op": "fence"})], fence)
        }
        ["fence", "release"] => {
            options.only(&[])?;
            answer(options, &[json!({"op": "fence_release"})], fence)
        }
        ["fence", "discard"] => {
            options.only(&[])?;
            answer(options, &[json!({"op": "fence_discard"})], fence)
        }
        ["queue"] => {
            options.only(&["most"])?;
            let mut request = json!({"op": "queue"});
            if let Some(most) = options.value("most") {
                request["most"] = json!(number(most, "most")?);
            }
            answer(options, &[request], queues)
        }
        ["explain"] => {
            options.only(&["message", "delivery"])?;
            let request = match (options.value("message"), options.value("delivery")) {
                (Some(message), None) => json!({"op": "explain", "message": message}),
                (None, Some(delivery)) => json!({"op": "explain", "delivery": delivery}),
                _ => return Err(format!("explain names --message or --delivery\n\n{USAGE}")),
            };
            answer(options, &[request], explained)
        }
        ["list", kind] => {
            options.only(&["account"])?;
            let mut request = json!({"op": "list", "kind": kind});
            if options.value("account").is_some() {
                request["account"] = json!(options.account()?);
            }
            answer(options, &[request], listed)
        }
        ["pause"] => {
            options.only(&target_and(&["reason", "accepting"]))?;
            let mut request = target(options, "hold")?;
            request["reason"] = json!(options.required("reason")?);
            request["accepting"] = json!(options.switch("accepting"));
            answer(options, &[request], |_| "paused".to_owned())
        }
        ["resume"] => {
            options.only(&target_and(&[]))?;
            let request = target(options, "release")?;
            answer(options, &[request], |_| "resumed".to_owned())
        }
        ["drain"] => {
            options.only(&["wait"])?;
            let socket = socket(options)?;
            loop {
                let answers = admin::ask(&socket, &[json!({"op": "drain"})])?;
                let ok = shown(options, &answers[0], outstanding)?;
                let done = ok["waiting"] == 0 && ok["in_flight"] == 0;
                if !options.switch("wait") || done {
                    return Ok(());
                }
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        }
        ["undrain"] => {
            options.only(&[])?;
            answer(options, &[json!({"op": "undrain"})], outstanding)
        }
        ["parked"] => {
            options.only(&["account", "subscription", "from"])?;
            let mut request = json!({
                "op": "parked",
                "account": options.account()?,
                "subscription": options.required("subscription")?,
            });
            if let Some(from) = options.value("from") {
                request["from"] = json!(number(from, "from")?);
            }
            answer(options, &[request], parked)
        }
        ["replay"] => {
            options.only(&["account", "subscription", "batch"])?;
            let mut request = json!({
                "op": "replay",
                "account": options.account()?,
                "subscription": options.required("subscription")?,
            });
            if let Some(batch) = options.value("batch") {
                request["batch"] = json!(number(batch, "batch")?);
            }
            answer(options, &[request], |ok| {
                format!("replaying {} parked batches", ok["replaying"])
            })
        }
        ["login", "create"] => {
            options.only(&["account", "user", "identity", "tenant"])?;
            let mut request = json!({
                "op": "create_login",
                "account": options.account()?,
                "user": options.required("user")?,
            });
            scope(options, &mut request);
            answer(options, &[request], |ok| {
                format!(
                    "login {} created; its password, shown this once: {}",
                    text(&ok["user"]),
                    text(&ok["password"])
                )
            })
        }
        ["login", "remove"] => {
            options.only(&["user"])?;
            let request = json!({"op": "remove_login", "user": options.required("user")?});
            answer(options, &[request], |_| "removed".to_owned())
        }
        ["access-key", "create"] => {
            options.only(&["account", "identity", "tenant", "manage", "manage-only"])?;
            let mut request = json!({"op": "create_access_key", "account": options.account()?});
            scope(options, &mut request);
            match (options.switch("manage"), options.switch("manage-only")) {
                (false, false) => {}
                (true, false) => request["permissions"] = json!(["send", "manage"]),
                (false, true) => request["permissions"] = json!(["manage"]),
                (true, true) => {
                    return Err(format!(
                        "give --manage or --manage-only, not both\n\n{USAGE}"
                    ));
                }
            }
            answer(options, &[request], |ok| {
                format!(
                    "access key {} created; its secret, shown this once: {}",
                    text(&ok["access_key_id"]),
                    text(&ok["secret_access_key"])
                )
            })
        }
        ["access-key", "revoke"] => {
            options.only(&["access-key-id"])?;
            let request = json!({
                "op": "remove_access_key",
                "access_key_id": options.required("access-key-id")?,
            });
            answer(options, &[request], |_| "revoked".to_owned())
        }
        _ => Err(USAGE.to_owned()),
    }
}

/// `path` as a full path, which the engine, in another directory, finds:
/// its directory's, with its name.
fn full_path(path: &Path) -> Result<std::path::PathBuf, String> {
    let name = path
        .file_name()
        .ok_or_else(|| format!("{} names no file", path.display()))?;
    let directory = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    Ok(std::fs::canonicalize(directory)
        .map_err(|error| format!("{}: {error}", directory.display()))?
        .join(name))
}

/// A restored store's fence, as a sentence.
fn fence(ok: &Value) -> String {
    let fence = &ok["fence"];
    if fence.is_null() {
        return "the store is not fenced".to_owned();
    }
    let since = format!(
        "restored at {} from a copy taken at {}",
        text(&fence["restored"]),
        text(&fence["taken"])
    );
    if fence["discarding"] == true {
        format!(
            "{since}, its deliveries discarded: {} left, each cancelled as it falls due",
            fence["unfinished"]
        )
    } else {
        format!(
            "fenced, {since}: {} deliveries it held unfinished wait; `fence release` sends them, any of which may have been delivered after the copy was taken, and `fence discard` cancels each as it falls due",
            fence["unfinished"]
        )
    }
}

/// The options that name what a hold is on, and `more`.
fn target_and<'a>(more: &[&'a str]) -> Vec<&'a str> {
    let mut allowed = vec!["account", "tenant", "configuration", "identity", "egress"];
    allowed.extend_from_slice(more);
    allowed
}

/// A hold's or release's request: its account, and at most one of what in
/// it.
fn target(options: &Options, op: &str) -> Result<Value, String> {
    let mut request = json!({"op": op, "account": options.account()?});
    let named: Vec<&str> = ["tenant", "configuration", "identity", "egress"]
        .into_iter()
        .filter(|name| options.value(name).is_some())
        .collect();
    match named.as_slice() {
        [] => {}
        [name] => request[*name] = json!(options.value(name)),
        _ => {
            return Err("name one of --tenant, --configuration, --identity or --egress".to_owned());
        }
    }
    Ok(request)
}

/// The identities and tenants a credential is limited to, if named.
fn scope(options: &Options, request: &mut Value) {
    for (option, field) in [("identity", "identities"), ("tenant", "tenants")] {
        let named = options.all(option);
        if !named.is_empty() {
            request[field] = json!(named);
        }
    }
}

fn number(value: &str, name: &str) -> Result<u64, String> {
    value.parse().map_err(|_| format!("--{name} is a number"))
}

/// What the running engine says of its policy and keys, for `doctor`:
/// `None` when it does not answer.
fn running(options: &Options, config: &config::Config) -> Option<doctor::Running> {
    let socket = socket(options).ok()?;
    let requests = [
        json!({"op": "list", "kind": "identities"}),
        json!({"op": "list", "kind": "egresses"}),
        json!({"op": "keys"}),
        json!({"op": "fence"}),
        json!({"op": "space"}),
    ];
    let answers = admin::ask(&socket, &requests).ok()?;
    let rows = |answer: &Value, kind: &str| -> Option<Vec<Value>> {
        ok(answer).ok()?[kind].as_array().cloned()
    };
    let sealing = ok(&answers[2]).ok()?["sealing"]
        .as_u64()
        .and_then(|id| u8::try_from(id).ok())?;
    // What each key older than the one sealing still seals, which says
    // whether it may go.
    let older = keys::ids(&config.store.keys)
        .unwrap_or_default()
        .into_iter()
        .filter(|id| *id < sealing)
        .map(|id| (id, held_by(options, config, id)))
        .collect();
    Some(doctor::Running {
        identities: rows(&answers[0], "identities")?,
        egresses: rows(&answers[1], "egresses")?,
        sealing,
        older,
        fence: ok(&answers[3]).ok()?["fence"].clone(),
        reusable: ok(&answers[4]).ok()?["reusable_bytes"].as_u64()?,
    })
}

/// What the running engine says of its keys.
struct EngineKeys {
    /// The key it seals every secret under.
    sealing: u8,
    /// The full paths of the keys file it holds and the store it seals.
    keys: String,
    store: String,
}

/// What still needs installation key `id`, by where it is kept, those
/// holding none left out: mail sealed under it needs it until
/// the last of it is gone, however long that is kept, so the running engine
/// reads every record of personal data, a page at a time, for those that
/// still need it, and capture's files are read here.
fn held_by(options: &Options, config: &config::Config, id: u8) -> Result<doctor::Kept, String> {
    let mut held = doctor::Kept::new();
    let mut from: Option<String> = None;
    loop {
        let request = json!({"op": "key_held", "key": id, "from": from});
        let answers = admin::ask(&socket(options)?, &[request])?;
        let page = ok(&answers[0])?;
        let said = || format!("the engine answered {page}");
        let table = page["table"].as_str().ok_or_else(said)?;
        let records = page["held"].as_u64().ok_or_else(said)?;
        match held.iter_mut().find(|(name, _)| name == table) {
            Some((_, count)) => *count += records,
            None if records > 0 => held.push((table.to_owned(), records)),
            None => {}
        }
        match page["next"].as_str() {
            Some(next) => from = Some(next.to_owned()),
            None => break,
        }
    }
    if let Some(capture) = &config.capture {
        let files = captured_under(&capture.directory, id)?;
        if files > 0 {
            held.push(("captured files".to_owned(), files));
        }
    }
    Ok(held)
}

/// How many of capture's files in `directory` are sealed under
/// installation key `id`.
fn captured_under(directory: &Path, id: u8) -> Result<u64, String> {
    let failed = |error: &dyn std::fmt::Display| format!("{}: {error}", directory.display());
    let mut files = 0;
    for entry in std::fs::read_dir(directory).map_err(|error| failed(&error))? {
        let path = entry.map_err(|error| failed(&error))?.path();
        let mut head = [0; 2];
        let read = std::fs::File::open(&path).and_then(|mut file| {
            use std::io::Read as _;
            file.read(&mut head)
        });
        if read.is_ok_and(|read| read == 2) && engine_store::keys::body_key(&head) == id {
            files += 1;
        }
    }
    Ok(files)
}

fn engine_keys(options: &Options) -> Result<EngineKeys, String> {
    let answers = admin::ask(&socket(options)?, &[json!({"op": "keys"})])?;
    let ok = ok(&answers[0])?;
    let said = || format!("the engine answered {ok}");
    Ok(EngineKeys {
        sealing: ok["sealing"]
            .as_u64()
            .and_then(|id| u8::try_from(id).ok())
            .ok_or_else(said)?,
        keys: ok["keys"].as_str().ok_or_else(said)?.to_owned(),
        store: ok["store"].as_str().ok_or_else(said)?.to_owned(),
    })
}

/// The admin socket the configuration names.
fn socket(options: &Options) -> Result<std::path::PathBuf, String> {
    let config = config::load(Path::new(options.required("config")?))?;
    Ok(config
        .admin
        .ok_or("the configuration names no admin socket")?
        .socket)
}

/// Sends `requests` and prints their answers, each as [`shown`] does. An
/// error answer ends the command.
fn answer(
    options: &Options,
    requests: &[Value],
    show: impl Fn(&Value) -> String,
) -> Result<(), String> {
    let answers = admin::ask(&socket(options)?, requests)?;
    for answer in &answers {
        shown(options, answer, &show)?;
    }
    Ok(())
}

/// Prints an answer: as it came with `--json`, an error's line too, for a
/// script to read; otherwise its `ok` as `show` writes it. An error answer
/// is the command's.
fn shown<'a>(
    options: &Options,
    answer: &'a Value,
    show: impl Fn(&Value) -> String,
) -> Result<&'a Value, String> {
    if options.switch("json") {
        println!("{answer}");
    }
    let ok = ok(answer)?;
    if !options.switch("json") {
        println!("{}", show(ok));
    }
    Ok(ok)
}

/// An answer's `ok`, or its error as the command's.
fn ok(answer: &Value) -> Result<&Value, String> {
    match answer.get("error") {
        Some(error) => Err(format!(
            "{}: {}",
            text(&error["code"]),
            text(&error["message"])
        )),
        None => Ok(&answer["ok"]),
    }
}

/// What a drain has outstanding, as a sentence.
fn outstanding(ok: &Value) -> String {
    let state = if ok["draining"] == true {
        "draining, no new mail taken"
    } else {
        "taking new mail"
    };
    let mut line = format!(
        "{state}: {} waiting, {} in flight, {} held; {} attempts uncertain since the start",
        ok["waiting"], ok["in_flight"], ok["held"], ok["uncertain_attempts"]
    );
    if ok["draining"] == true && ok["waiting"] == 0 && ok["in_flight"] == 0 {
        line.push_str(if ok["held"] == 0 {
            "; drained"
        } else {
            "; drained but for held mail, which waits on its holds"
        });
    }
    line
}

/// A JSON value as text: a string without its quotes, nothing for null.
fn text(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// Rows under their headings, each column as wide as its widest.
fn table(headings: &[&str], rows: &[Vec<String>]) -> String {
    let mut widths: Vec<usize> = headings.iter().map(|heading| heading.len()).collect();
    for row in rows {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.chars().count());
        }
    }
    let line = |cells: Vec<&str>| {
        cells
            .iter()
            .zip(&widths)
            .map(|(cell, width)| format!("{cell:width$}"))
            .collect::<Vec<_>>()
            .join("  ")
            .trim_end()
            .to_owned()
    };
    let mut lines = vec![line(headings.to_vec())];
    for row in rows {
        lines.push(line(row.iter().map(String::as_str).collect()));
    }
    lines.join("\n")
}

fn queues(ok: &Value) -> String {
    let rows: Vec<Vec<String>> = ok["queues"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .map(|queue| {
            let cooling = match &queue["cooling"] {
                Value::Null => String::new(),
                cooling => format!(
                    "until {} ({} throttles)",
                    text(&cooling["until"]),
                    cooling["throttles"]
                ),
            };
            vec![
                text(&queue["site"]),
                text(&queue["exchanges"]),
                text(&queue["egress"]),
                text(&queue["waiting"]),
                text(&queue["put_off"]),
                text(&queue["active"]),
                cooling,
                text(&queue["budget_frees"]),
            ]
        })
        .collect();
    let stored = &ok["stored"];
    let count = |state: &str| stored[state].as_u64().unwrap_or_default();
    let (waiting, in_flight, held) = (count("waiting"), count("in_flight"), count("held"));
    if waiting + in_flight + held == 0 && rows.is_empty() {
        return "no mail queued".to_owned();
    }
    // The store's counts first: the queues show what the scheduler holds in
    // memory, and mail due later, a retry's or a cap's, waits in the store.
    let summary = format!("in the store: {waiting} waiting, {in_flight} in flight, {held} held");
    if rows.is_empty() {
        return format!(
            "{summary}; the scheduler holds none in a queue (explain says where each waits)"
        );
    }
    let shown = table(
        &[
            "SITE",
            "EXCHANGES",
            "EGRESS",
            "WAITING",
            "PUT OFF",
            "ACTIVE",
            "COOLING",
            "BUDGET FREES",
        ],
        &rows,
    );
    format!("{summary}\n\n{shown}")
}

fn explained(ok: &Value) -> String {
    let deliveries = ok["deliveries"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default();
    if deliveries.is_empty() {
        return "no such message or delivery".to_owned();
    }
    let mut blocks = Vec::new();
    for delivery in deliveries {
        let mut lines = vec![format!(
            "delivery {} of message {} to {}",
            text(&delivery["delivery"]),
            text(&delivery["message"]),
            text(&delivery["recipient"])
        )];
        let mut field = |name: &str, value: String| {
            if !value.is_empty() {
                lines.push(format!("  {name:<10} {value}"));
            }
        };
        let state = text(&delivery["state"]);
        let completion = text(&delivery["completion"]);
        field(
            "state",
            if completion.is_empty() {
                format!("{state} since {}", text(&delivery["at"]))
            } else {
                format!("{state}, {completion}, at {}", text(&delivery["at"]))
            },
        );
        field("expires", text(&delivery["expires"]));
        field(
            "attempts",
            format!(
                "{}, {} of them uncertain",
                delivery["attempts"], delivery["uncertain_attempts"]
            ),
        );
        field("egress", text(&delivery["egress"]));
        if let Value::Object(reply) = &delivery["last_reply"] {
            let rules = reply
                .get("rules")
                .and_then(Value::as_array)
                .map(|rules| rules.iter().map(text).collect::<Vec<_>>().join(" "))
                .unwrap_or_default();
            let rules = if rules.is_empty() {
                String::new()
            } else {
                format!(" (rules: {rules})")
            };
            field("last reply", format!("{}{rules}", text(&reply["reply"])));
        }
        if let Value::Object(held) = &delivery["held"] {
            let mut place = text(&held["where"]);
            for (name, label) in [("site", "at"), ("egress", "from"), ("ahead", "behind")] {
                if let Some(value) = held.get(name) {
                    place.push_str(&format!(" {label} {}", text(value)));
                }
            }
            if let Some(cooling) = held.get("cooling") {
                place.push_str(&format!(", cooling until {}", text(&cooling["until"])));
            }
            if let Some(frees) = held.get("budget_frees") {
                place.push_str(&format!(", its budget frees at {}", text(frees)));
            }
            field("scheduler", place);
        }
        if let Value::Object(paused) = &delivery["paused"] {
            let on = ["tenant", "configuration", "identity", "egress"]
                .into_iter()
                .find_map(|name| {
                    paused
                        .get(name)
                        .map(|value| format!("{name} {}", text(value)))
                })
                .unwrap_or_else(|| format!("account {}", paused["account"]));
            let accepting = if paused["accepting"] == true {
                ", new mail accepted"
            } else {
                ", new mail refused"
            };
            field(
                "paused",
                format!(
                    "by the hold on {on}: {}{accepting}",
                    text(&paused["reason"])
                ),
            );
        }
        if let Value::Object(fenced) = &delivery["fenced"] {
            let decided = if fenced["discarding"] == true {
                "cancelled, unsent, as it falls due"
            } else {
                "it waits for `fence release` or `fence discard`"
            };
            lines.push(format!(
                "  {:<10} by the restore of a copy taken at {}: {decided}",
                "fenced",
                text(&fenced["taken"])
            ));
        }
        blocks.push(lines.join("\n"));
    }
    blocks.join("\n\n")
}

fn listed(ok: &Value) -> String {
    let Some((kind, rows)) = ok.as_object().and_then(|ok| ok.iter().next()) else {
        return String::new();
    };
    let rows = rows.as_array().map(Vec::as_slice).unwrap_or_default();
    if rows.is_empty() {
        return format!("no {}", kind.replace('_', " "));
    }
    // Every field the rows have, what names a record first.
    let mut headings: Vec<String> = Vec::new();
    for row in rows {
        for name in row.as_object().map(|row| row.keys()).into_iter().flatten() {
            if !headings.contains(name) {
                headings.push(name.clone());
            }
        }
    }
    let first = ["name", "user", "access_key_id", "address", "account"];
    headings.sort_by_key(|name| {
        first
            .iter()
            .position(|first| first == name)
            .unwrap_or(first.len())
    });
    // A DKIM key is too long for a column: it goes under its row.
    let long = |name: &str| name == "dkim_public_key";
    let columns: Vec<&str> = headings
        .iter()
        .map(String::as_str)
        .filter(|name| !long(name))
        .collect();
    let cell = |value: &Value| match value {
        Value::Array(items) => items.iter().map(text).collect::<Vec<_>>().join(","),
        other => text(other),
    };
    let cells: Vec<Vec<String>> = rows
        .iter()
        .map(|row| columns.iter().map(|name| cell(&row[*name])).collect())
        .collect();
    let upper: Vec<String> = columns
        .iter()
        .map(|name| name.to_uppercase().replace('_', " "))
        .collect();
    let mut out = table(
        &upper.iter().map(String::as_str).collect::<Vec<_>>(),
        &cells,
    );
    let keys: Vec<String> = rows
        .iter()
        .filter_map(|row| {
            let key = row.get("dkim_public_key")?.as_str()?;
            Some(format!(
                "{} {}._domainkey: v=DKIM1; k=rsa; p={key}",
                text(&row["name"]),
                text(&row["selector"])
            ))
        })
        .collect();
    if !keys.is_empty() {
        out.push_str("\n\nDKIM records to publish:\n");
        out.push_str(&keys.join("\n"));
    }
    out
}

fn parked(ok: &Value) -> String {
    let rows: Vec<Vec<String>> = ok["parked"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .map(|batch| {
            vec![
                text(&batch["batch"]),
                text(&batch["through"]),
                text(&batch["parked_at"]),
                text(&batch["attempts"]),
                text(&batch["failure"]),
            ]
        })
        .collect();
    let mut out = if rows.is_empty() {
        "no parked batches".to_owned()
    } else {
        table(
            &["BATCH", "THROUGH", "PARKED AT", "POSTS", "LAST FAILURE"],
            &rows,
        )
    };
    if let Some(next) = ok.get("next") {
        out.push_str(&format!("\nmore from --from {next}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_says_what_the_store_holds_when_nothing_is_due_yet() {
        let empty = serde_json::json!({
            "stored": {"waiting": 0, "in_flight": 0, "held": 0},
            "queues": [],
        });
        assert_eq!(queues(&empty), "no mail queued");
        // Put off for a cap, waiting for a retry, or for its route or an
        // egress, after a restart.
        let later = serde_json::json!({
            "stored": {"waiting": 40, "in_flight": 0, "held": 2},
            "queues": [],
        });
        assert_eq!(
            queues(&later),
            "in the store: 40 waiting, 0 in flight, 2 held; the scheduler holds none in a queue (explain says where each waits)"
        );
    }

    fn options(line: &str) -> Options {
        let argv: Vec<String> = line.split(' ').map(str::to_owned).collect();
        Options::parse(&argv).unwrap()
    }

    #[test]
    fn options_are_named_and_switches_take_no_value() {
        let parsed =
            options("pause --config c.toml --account 1 --tenant acme --accepting --reason why");
        assert_eq!(parsed.words(), ["pause"]);
        assert_eq!(parsed.value("tenant"), Some("acme"));
        assert!(parsed.switch("accepting"));
        assert_eq!(
            target(&parsed, "hold").unwrap(),
            json!({"op": "hold", "account": 1, "tenant": "acme"})
        );
        assert!(parsed.only(&target_and(&["reason", "accepting"])).is_ok());
        assert!(
            parsed
                .only(&["account"])
                .is_err_and(|why| why.contains("--tenant"))
        );
        let both = options("resume --account 1 --tenant a --identity b");
        assert!(target(&both, "release").is_err());
        assert!(Options::parse(&["queue".to_owned(), "--most".to_owned()]).is_err());
        let scoped =
            options("login create --account 1 --user u --identity a.test --identity b.test");
        let mut request = json!({});
        scope(&scoped, &mut request);
        assert_eq!(request, json!({"identities": ["a.test", "b.test"]}));
    }

    #[test]
    fn answers_are_shown_as_tables_with_dkim_records_under_them() {
        let listing = json!({"identities": [
            {"account": 1, "name": "a.test", "configuration": null, "selector": "s1", "dkim_public_key": "KEY"},
            {"account": 1, "name": "b.test", "configuration": "receipts"},
        ]});
        let shown = listed(&listing);
        assert!(
            shown.starts_with("NAME    ACCOUNT  CONFIGURATION  SELECTOR\n"),
            "{shown}"
        );
        assert!(shown.contains("\nb.test  1        receipts\n"), "{shown}");
        assert!(
            shown.ends_with("a.test s1._domainkey: v=DKIM1; k=rsa; p=KEY"),
            "{shown}"
        );
        assert_eq!(listed(&json!({"access_keys": []})), "no access keys");
        assert_eq!(queues(&json!({"queues": []})), "no mail queued");
        let page = parked(&json!({"parked": [], "next": 9}));
        assert_eq!(page, "no parked batches\nmore from --from 9");
    }
}
