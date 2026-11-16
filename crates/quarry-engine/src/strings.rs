//! String matching semantics — exact port of `quarry/engine/matchers.py`.
//!
//! Modifier order matches upstream: base64-encode first, then regex
//! passthrough, then fullword wrap. `nocase` applies at match time.

/// Declared-string modifiers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Modifiers {
    pub nocase: bool,
    pub fullword: bool,
    pub base64: bool,
    pub regex: bool,
}

impl Modifiers {
    pub fn from_slice(mods: &[quarry_dsl::StringModifier]) -> Self {
        let mut m = Self::default();
        for d in mods {
            match d {
                quarry_dsl::StringModifier::NoCase => m.nocase = true,
                quarry_dsl::StringModifier::FullWord => m.fullword = true,
                quarry_dsl::StringModifier::Base64 => m.base64 = true,
                quarry_dsl::StringModifier::Regex => m.regex = true,
            }
        }
        m
    }
}

/// `(effective_pattern, use_regex)` — the exact transform quarry applies.
pub fn apply_modifiers(pattern: &str, mods: &Modifiers) -> (String, bool) {
    let mut modified = pattern.to_string();
    if mods.base64 {
        modified = base64_encode(modified.as_bytes());
    }
    if mods.regex {
        return (modified, true);
    }
    if mods.fullword {
        return (format!(r"\b{}\b", regex::escape(&modified)), true);
    }
    (modified, false)
}

/// First match position, or `None`. Empty text or pattern is a non-match.
pub fn find_position(text: &str, pattern: &str, mods: &Modifiers) -> Result<Option<usize>, String> {
    if text.is_empty() || pattern.is_empty() {
        return Ok(None);
    }
    let (effective, use_regex) = apply_modifiers(pattern, mods);
    if use_regex {
        let re = compile_regex(&effective, mods.nocase)?;
        return Ok(re.find(text).map(|m| m.start()));
    }
    let (search_text, search_pat) = if mods.nocase {
        (text.to_lowercase(), effective.to_lowercase())
    } else {
        (text.to_string(), effective)
    };
    Ok(search_text.find(&search_pat))
}

/// Occurrence count. Literal path is non-overlapping (`str.count`).
pub fn count_occurrences(text: &str, pattern: &str, mods: &Modifiers) -> Result<usize, String> {
    if text.is_empty() || pattern.is_empty() {
        return Ok(0);
    }
    let (effective, use_regex) = apply_modifiers(pattern, mods);
    if use_regex {
        let re = compile_regex(&effective, mods.nocase)?;
        return Ok(re.find_iter(text).count());
    }
    let (search_text, search_pat) = if mods.nocase {
        (text.to_lowercase(), effective.to_lowercase())
    } else {
        (text.to_string(), effective)
    };
    if search_pat.is_empty() {
        return Ok(0);
    }
    Ok(search_text.matches(&search_pat).count())
}

/// Boolean regex search — the `~` operator semantics (search, not fullmatch).
pub fn match_regex(text: &str, pattern: &str, nocase: bool) -> Result<bool, String> {
    if text.is_empty() || pattern.is_empty() {
        return Ok(false);
    }
    let re = compile_regex(pattern, nocase)?;
    Ok(re.is_match(text))
}

/// `contains`: substring (modifiers applied for declared strings).
pub fn match_contains(text: &str, pattern: &str, mods: &Modifiers) -> Result<bool, String> {
    Ok(find_position(text, pattern, mods)?.is_some())
}

pub fn compile_regex(pattern: &str, nocase: bool) -> Result<regex::Regex, String> {
    let mut builder = regex::RegexBuilder::new(pattern);
    builder.case_insensitive(nocase);
    builder
        .build()
        .map_err(|e| format!("invalid regex `{pattern}`: {e}"))
}

/// Minimal standard base64 encoder (no padding tricks — exactly RFC 4648
/// with padding), so the crate avoids a dependency for one transform.
pub fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[(n >> 18) as usize & 63] as char);
        out.push(TABLE[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_standard() {
        assert_eq!(base64_encode(b"malware"), "bWFsd2FyZQ==");
        assert_eq!(base64_encode(b"ab"), "YWI=");
        assert_eq!(base64_encode(b"a"), "YQ==");
        assert_eq!(base64_encode(b""), "");
    }

    #[test]
    fn modifiers_order_matches_upstream() {
        // base64 + regex: encode first, then treat as regex.
        let (p, use_regex) = apply_modifiers("a.b", &Modifiers { base64: true, regex: true, ..Default::default() });
        assert!(use_regex);
        assert_eq!(p, base64_encode(b"a.b"));
        // fullword wraps escaped literal as regex.
        let (p, use_regex) = apply_modifiers("admin", &Modifiers { fullword: true, ..Default::default() });
        assert!(use_regex);
        assert_eq!(p, r"\badmin\b");
    }

    #[test]
    fn position_and_count() {
        let mods = Modifiers::default();
        assert_eq!(find_position("hello world", "world", &mods).unwrap(), Some(6));
        assert_eq!(find_position("hello", "x", &mods).unwrap(), None);
        assert_eq!(count_occurrences("aaa", "aa", &mods).unwrap(), 1); // non-overlapping
        assert_eq!(count_occurrences("aXaX", "ax", &Modifiers { nocase: true, ..Default::default() }).unwrap(), 2);
    }
}
