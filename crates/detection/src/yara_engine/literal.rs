//! Deliberately restricted fallback, not a general YARA interpreter.
use super::{Result, SubstringRule, YaraError};

fn unsupported() -> YaraError {
    YaraError::Parse("substring backend supports only one ASCII literal at 0 and filesize <= 128; real YARA required".into())
}

pub(super) fn parse_rules(source: &str) -> Result<Vec<SubstringRule>> {
    let mut out = Vec::new();
    let (mut name, mut id, mut literal) = (None, None, None);
    let mut section = "";
    let mut condition = String::new();
    for line in source
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.starts_with("//"))
    {
        if name.is_none() {
            let header = line
                .strip_prefix("rule ")
                .and_then(|s| s.strip_suffix('{'))
                .ok_or_else(unsupported)?
                .trim();
            if !identifier(header) {
                return Err(unsupported());
            }
            name = Some(header.to_string());
            section = "";
            continue;
        }
        match line {
            "meta:" if section.is_empty() => section = "meta",
            "strings:" if section.is_empty() || section == "meta" => section = "strings",
            "condition:" if section == "strings" => section = "condition",
            "}" if section == "condition" => {
                let id = id.take().ok_or_else(unsupported)?;
                let expected = format!("${id} at 0 and filesize <= 128");
                if condition.split_whitespace().collect::<Vec<_>>()
                    != expected.split_whitespace().collect::<Vec<_>>()
                {
                    return Err(unsupported());
                }
                out.push(SubstringRule {
                    name: name.take().ok_or_else(unsupported)?,
                    literal: literal.take().ok_or_else(unsupported)?,
                });
                section = "";
                condition.clear();
            }
            _ if section == "meta" => {
                // Metadata is never executable or a source of scan literals.
                let (key, value) = line.split_once('=').ok_or_else(unsupported)?;
                if !identifier(key.trim()) || value.trim().is_empty() {
                    return Err(unsupported());
                }
            }
            _ if section == "strings" && id.is_none() => {
                let (key, value) = line.split_once('=').ok_or_else(unsupported)?;
                let key = key.trim().strip_prefix('$').ok_or_else(unsupported)?;
                if !identifier(key) {
                    return Err(unsupported());
                }
                id = Some(key.to_string());
                literal = Some(quoted_ascii(value.trim())?);
            }
            _ if section == "condition" => {
                condition.push_str(line);
                condition.push(' ');
            }
            _ => return Err(unsupported()),
        }
    }
    if name.is_some() || out.is_empty() {
        return Err(unsupported());
    }
    Ok(out)
}

fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .enumerate()
            .all(|(i, c)| c.is_ascii_alphabetic() || c == b'_' || (i > 0 && c.is_ascii_digit()))
}

fn quoted_ascii(value: &str) -> Result<Vec<u8>> {
    let mut bytes = value.as_bytes();
    if bytes.first() != Some(&b'"') {
        return Err(unsupported());
    }
    bytes = &bytes[1..];
    let mut out = Vec::new();
    while let Some((&c, rest)) = bytes.split_first() {
        bytes = rest;
        match c {
            b'"' => {
                // Only ASCII (the YARA default) is supported. No ignored modifiers.
                if !out.is_empty()
                    && matches!(
                        std::str::from_utf8(bytes).unwrap_or("").trim(),
                        "" | "ascii"
                    )
                {
                    return Ok(out);
                }
                return Err(unsupported());
            }
            b'\\' => {
                let (&escaped, rest) = bytes.split_first().ok_or_else(unsupported)?;
                bytes = rest;
                out.push(match escaped {
                    b'\\' => b'\\',
                    b'"' => b'"',
                    b'n' => b'\n',
                    b'r' => b'\r',
                    b't' => b'\t',
                    _ => return Err(unsupported()),
                });
            }
            c if c.is_ascii() && !c.is_ascii_control() => out.push(c),
            _ => return Err(unsupported()),
        }
    }
    Err(unsupported())
}
