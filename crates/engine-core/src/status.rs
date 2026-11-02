//! Enhanced mail system status codes (RFC 3463): `class.subject.detail`, as
//! receivers give them in SMTP replies and in delivery status reports.

use std::fmt;

/// A status code, as in `5.1.1`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Status {
    /// 2 success, 4 a temporary failure, 5 a permanent one.
    pub class: u8,
    pub subject: u16,
    pub detail: u16,
}

impl Status {
    /// The code at the start of `text`, as a reply's text or a report's
    /// `Status` field gives it: `5.1.1`, perhaps followed by a comment.
    /// `None` unless it is one.
    pub fn parse(text: &str) -> Option<Self> {
        let code = text
            .trim_start()
            .split(|c: char| !(c.is_ascii_digit() || c == '.'))
            .next()?;
        let mut parts = code.split('.');
        let class = parts
            .next()?
            .parse()
            .ok()
            .filter(|class| matches!(class, 2 | 4 | 5))?;
        // Each of the last two is one to three digits.
        let mut number = || {
            let part = parts.next()?;
            (1..=3)
                .contains(&part.len())
                .then(|| part.parse().ok())
                .flatten()
        };
        let (subject, detail) = (number()?, number()?);
        parts.next().is_none().then_some(Self {
            class,
            subject,
            detail,
        })
    }

    pub fn is_permanent(self) -> bool {
        self.class == 5
    }
}

impl fmt::Display for Status {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.class, self.subject, self.detail)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(class: u8, subject: u16, detail: u16) -> Status {
        Status {
            class,
            subject,
            detail,
        }
    }

    #[test]
    fn a_code_is_read_from_the_start_of_its_text() {
        assert_eq!(Status::parse("5.1.1"), Some(status(5, 1, 1)));
        assert_eq!(
            Status::parse(" 4.7.0 (try again later)"),
            Some(status(4, 7, 0))
        );
        assert_eq!(Status::parse("5.1.10"), Some(status(5, 1, 10)));
        assert_eq!(
            Status::parse("5.1.1 no such user").unwrap().to_string(),
            "5.1.1"
        );
        for invalid in [
            "", "550", "3.1.1", "5.1", "5.1.1.1", "5..1", "5.1000.1", "x5.1.1",
        ] {
            assert_eq!(Status::parse(invalid), None, "{invalid:?}");
        }
    }
}
