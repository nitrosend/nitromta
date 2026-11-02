//! SES's email templates, as far as the engine renders them:
//! `{{name}}`, and `{{a.b}}` for a value inside an object, each replaced by
//! the value at that path in the template's data, as it is: unescaped, as
//! SES puts a whole HTML body in place of `{{html_body}}`. A name the data
//! does not hold fails the render, as SES fails one it cannot render, and
//! so does a value that is an object or a list. Handlebars' blocks and
//! partials (`{{#...}}`, `{{/...}}`, `{{else}}`, `{{>...}}`) are not
//! rendered, and a template that has one is refused, never sent half
//! rendered. A render is bounded: it fails once what it has rendered would
//! pass the bytes it is given, before it is allocated.

use serde_json::Value;

/// Why a template did not render.
#[derive(Debug, PartialEq, Eq)]
pub enum RenderError {
    /// It names a value the data does not hold.
    Missing(String),
    /// It names an object or a list, which is not one value.
    NotAValue(String),
    /// It uses a block, partial or comment the engine does not render.
    Unsupported(String),
    /// A `{{` with no `}}` after it.
    Unclosed,
    /// What it renders would pass the bytes it may come to.
    TooLarge,
}

impl std::fmt::Display for RenderError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing(name) => write!(
                formatter,
                "Attribute '{name}' is not present in the rendering data."
            ),
            Self::NotAValue(name) => {
                write!(formatter, "Attribute '{name}' is not a single value.")
            }
            Self::Unsupported(tag) => write!(
                formatter,
                "The template's {{{{{tag}}}}} is not supported: NitroMTA renders {{{{name}}}} alone."
            ),
            Self::Unclosed => formatter.write_str("The template has a {{ with no }} after it."),
            Self::TooLarge => formatter.write_str("The rendered template is too large."),
        }
    }
}

/// `template` with each `{{name}}` replaced by its value in `data`, in at
/// most `most` bytes.
pub fn render(template: &str, data: &Value, most: usize) -> Result<String, RenderError> {
    let mut rendered = String::with_capacity(template.len().min(most));
    let push = |rendered: &mut String, text: &str| {
        if rendered.len() + text.len() > most {
            return Err(RenderError::TooLarge);
        }
        rendered.push_str(text);
        Ok(())
    };
    walk(template, |piece| match piece {
        Piece::Text(text) => push(&mut rendered, text),
        Piece::Tag(tag) => {
            let value = tag
                .split('.')
                .try_fold(data, |value, key| value.get(key))
                .ok_or_else(|| RenderError::Missing(shown(tag)))?;
            match value {
                Value::String(text) => push(&mut rendered, text),
                Value::Number(number) => push(&mut rendered, &number.to_string()),
                Value::Bool(flag) => push(&mut rendered, if *flag { "true" } else { "false" }),
                Value::Null => Ok(()),
                Value::Object(_) | Value::Array(_) => Err(RenderError::NotAValue(shown(tag))),
            }
        }
    })?;
    Ok(rendered)
}

/// Whether `template` is one the engine renders, whatever its data: as a
/// template is checked when it is kept, so one it cannot send is refused
/// then.
pub fn checked(template: &str) -> Result<(), RenderError> {
    walk(template, |_| Ok(()))
}

/// A run of a template's text, or the name a `{{name}}` gives.
enum Piece<'a> {
    Text(&'a str),
    Tag(&'a str),
}

/// Gives `piece` each run of `template`'s text and each `{{name}}` it
/// names, in order; a block, partial or comment is refused.
fn walk<'a>(
    template: &'a str,
    mut piece: impl FnMut(Piece<'a>) -> Result<(), RenderError>,
) -> Result<(), RenderError> {
    let mut rest = template;
    while let Some(open) = rest.find("{{") {
        piece(Piece::Text(&rest[..open]))?;
        let after = &rest[open + 2..];
        // `{{{name}}}` is a value unescaped, as every value here is.
        let (triple, after) = match after.strip_prefix('{') {
            Some(after) => (true, after),
            None => (false, after),
        };
        let close = after.find("}}").ok_or(RenderError::Unclosed)?;
        let name = after[..close].trim();
        let mut next = &after[close + 2..];
        if triple {
            next = next.strip_prefix('}').unwrap_or(next);
        }
        if name.is_empty()
            || name.starts_with(['#', '/', '>', '!', '^', '&', '~'])
            || name.ends_with('~')
            || name == "else"
            || name.contains(char::is_whitespace)
        {
            return Err(RenderError::Unsupported(shown(name)));
        }
        piece(Piece::Tag(name))?;
        rest = next;
    }
    piece(Piece::Text(rest))
}

/// The most of a tag a refusal names.
const SHOWN: usize = 100;

/// A tag as a refusal names it: at most [`SHOWN`] bytes of it, cut at a
/// character, so a refusal repeated for every entry stays small however
/// large the tag.
fn shown(tag: &str) -> String {
    if tag.len() <= SHOWN {
        return tag.to_owned();
    }
    let mut end = SHOWN;
    while !tag.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &tag[..end])
}

/// A template's default data with an entry's own laid over it, name by
/// name: each is a JSON object, or absent.
pub fn data(default: Option<&str>, entry: Option<&str>) -> Result<Value, String> {
    let object =
        |text: Option<&str>, what: &str| -> Result<serde_json::Map<String, Value>, String> {
            match text {
                None => Ok(serde_json::Map::new()),
                Some(text) => match serde_json::from_str(text) {
                    Ok(Value::Object(object)) => Ok(object),
                    _ => Err(format!("{what} is not a JSON object")),
                },
            }
        };
    let mut merged = object(default, "TemplateData")?;
    merged.extend(object(entry, "ReplacementTemplateData")?);
    Ok(Value::Object(merged))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// As many bytes as a test's render needs.
    const ANY: usize = usize::MAX;

    #[test]
    fn names_are_replaced_by_their_values_as_they_are_and_anything_else_is_refused() {
        let data = json!({
            "subject": "Hello & welcome",
            "html_body": "<p>Hi <b>Ann</b></p>",
            "count": 3,
            "user": {"name": "Ann"},
            "none": null,
        });
        assert_eq!(
            render(
                "{{subject}}: {{ html_body }} ({{count}}) {{user.name}}{{none}}",
                &data,
                ANY
            ),
            Ok("Hello & welcome: <p>Hi <b>Ann</b></p> (3) Ann".to_owned())
        );
        assert_eq!(
            render("{{{html_body}}}", &data, ANY),
            Ok("<p>Hi <b>Ann</b></p>".to_owned())
        );
        assert_eq!(render("no tags", &data, ANY), Ok("no tags".to_owned()));
        assert_eq!(
            render("{{missing}}", &data, ANY),
            Err(RenderError::Missing("missing".to_owned()))
        );
        assert_eq!(
            render("{{user}}", &data, ANY),
            Err(RenderError::NotAValue("user".to_owned()))
        );
        for tag in ["#if user", "/if", "else", ">partial", "!comment"] {
            assert!(
                matches!(
                    render(&format!("{{{{{tag}}}}}"), &data, ANY),
                    Err(RenderError::Unsupported(_))
                ),
                "{tag}"
            );
        }
        assert_eq!(render("{{subject", &data, ANY), Err(RenderError::Unclosed));
    }

    #[test]
    fn a_template_the_engine_cannot_render_is_found_before_it_is_kept() {
        assert!(checked("Hello {{name}}, {{{user.name}}}").is_ok());
        for template in [
            "{{#if name}}x{{/if}}",
            "{{> partial}}",
            "{{! a comment}}",
            "{{~> partial}}",
            "{{~! a comment}}",
            "{{~name}}",
            "{{name~}}",
            "{{name",
        ] {
            assert!(checked(template).is_err(), "{template}");
        }
    }

    #[test]
    fn a_render_fails_before_it_passes_its_bytes() {
        let data = json!({"x": "a".repeat(1_000)});
        let template = "{{x}}".repeat(10_000);
        assert_eq!(
            render(&template, &data, 64 * 1_024),
            Err(RenderError::TooLarge)
        );
        assert_eq!(render("{{x}}!", &data, 1_000), Err(RenderError::TooLarge));
        assert_eq!(
            render("{{x}}", &data, 1_000).map(|text| text.len()),
            Ok(1_000)
        );
        // A refusal names a little of a large tag, never all of it.
        let large = format!("{{{{{}}}}}", "y".repeat(1 << 20));
        let Err(RenderError::Missing(named)) = render(&large, &data, ANY) else {
            panic!("refused");
        };
        assert_eq!(named.len(), SHOWN + 3);
    }

    #[test]
    fn an_entrys_data_is_laid_over_the_default_name_by_name() {
        let merged = data(
            Some(r#"{"a": "default", "b": "kept"}"#),
            Some(r#"{"a": "entry"}"#),
        )
        .unwrap();
        assert_eq!(merged, json!({"a": "entry", "b": "kept"}));
        assert_eq!(data(None, None).unwrap(), json!({}));
        assert!(data(Some("[1]"), None).is_err());
        assert!(data(None, Some("not json")).is_err());
    }
}
