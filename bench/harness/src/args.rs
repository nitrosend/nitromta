//! Command-line options: `--name value` pairs and positional arguments. Every
//! option a command accepts is named up front, so a misspelt option is an
//! error rather than a silent default.

use std::collections::BTreeMap;
use std::fmt::Display;
use std::str::FromStr;

pub struct Args {
    positional: Vec<String>,
    options: BTreeMap<String, String>,
}

impl Args {
    pub fn parse(argv: &[String], known: &[&str]) -> Result<Self, String> {
        let mut positional = Vec::new();
        let mut options = BTreeMap::new();
        let mut rest = argv.iter();
        while let Some(arg) = rest.next() {
            match arg.strip_prefix("--") {
                Some(name) => {
                    if !known.contains(&name) {
                        return Err(format!("unknown option `--{name}`"));
                    }
                    let value = rest
                        .next()
                        .ok_or_else(|| format!("`--{name}` needs a value"))?;
                    options.insert(name.to_owned(), value.clone());
                }
                None => positional.push(arg.clone()),
            }
        }
        Ok(Self {
            positional,
            options,
        })
    }

    pub fn positional(&self) -> &[String] {
        &self.positional
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.options.get(name).map(String::as_str)
    }

    pub fn required(&self, name: &str) -> Result<&str, String> {
        self.get(name)
            .ok_or_else(|| format!("`--{name}` is required"))
    }

    pub fn parse_or<T>(&self, name: &str, default: T) -> Result<T, String>
    where
        T: FromStr,
        T::Err: Display,
    {
        match self.get(name) {
            None => Ok(default),
            Some(value) => value
                .parse()
                .map_err(|error| format!("`--{name} {value}`: {error}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(words: &[&str]) -> Vec<String> {
        words.iter().map(|word| (*word).to_owned()).collect()
    }

    #[test]
    fn options_and_positionals_are_separated() {
        let args = Args::parse(&argv(&["quick", "--rate", "250"]), &["rate"]).unwrap();
        assert_eq!(args.positional(), ["quick"]);
        assert_eq!(args.parse_or("rate", 0.0).unwrap(), 250.0);
        assert_eq!(args.parse_or("rate-limit", 7).unwrap_or(0), 7);
    }

    #[test]
    fn unknown_and_incomplete_options_are_errors() {
        assert!(Args::parse(&argv(&["--rat", "1"]), &["rate"]).is_err());
        assert!(Args::parse(&argv(&["--rate"]), &["rate"]).is_err());
        let args = Args::parse(&argv(&["--rate", "fast"]), &["rate"]).unwrap();
        assert!(args.parse_or("rate", 0.0).is_err());
        assert!(args.required("seconds").is_err());
    }
}
