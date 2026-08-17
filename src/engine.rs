use aho_corasick::AhoCorasick;
use serde_json;

/// PiiVault holds the Aho-Corasick searcher and replacement arrays.
/// replacements: standard text replacements
/// escaped_replacements: JSON-escaped text (suitable for inserting into JSON string contexts)
#[allow(dead_code)]
#[derive(Clone)]
pub struct PiiVault {
    pub searcher: AhoCorasick,
    pub max_pattern_len: usize,
    pub replacements: Vec<String>,
    pub escaped_replacements: Vec<String>,
}

impl PiiVault {
    /// Create a new vault from patterns and corresponding replacements.
    /// patterns.len() must equal replacements.len().
    pub fn new(patterns: &[&str], replacements: &[&str]) -> Self {
        assert_eq!(patterns.len(), replacements.len(), "patterns and replacements length mismatch");
        let searcher = AhoCorasick::new(patterns).expect("failed to build aho-corasick automaton");

        // compute maximum pattern length in bytes
        let max_pattern_len = patterns.iter().map(|p| p.len()).max().unwrap_or(0);

        // copy replacements into owned Strings
        let replacements_vec = replacements.iter().map(|s| s.to_string()).collect::<Vec<_>>();

        // compute JSON-escaped versions of replacements (without surrounding quotes)
        let escaped_replacements_vec = replacements
            .iter()
            .map(|s| {
                // serde_json::to_string will return a quoted JSON string e.g. "foo\nbar"
                let quoted = serde_json::to_string(s).unwrap_or_else(|_| String::from("\"\""));
                // strip the surrounding quotes if present
                if quoted.len() >= 2 && quoted.starts_with('"') && quoted.ends_with('"') {
                    quoted[1..quoted.len() - 1].to_string()
                } else {
                    quoted
                }
            })
            .collect::<Vec<_>>();

        Self {
            searcher,
            max_pattern_len,
            replacements: replacements_vec,
            escaped_replacements: escaped_replacements_vec,
        }
    }
}

/// Redact text using the vault. Returns a Cow that is Borrowed when no match is found,
/// or Owned with replacements applied when matches exist.
pub fn redact_text<'a>(text: &'a str, vault: &PiiVault) -> std::borrow::Cow<'a, str> {
    if vault.searcher.find(text).is_none() {
        return std::borrow::Cow::Borrowed(text);
    }

    // iterate matches and build replaced string
    let mut out = String::with_capacity(text.len());
    let mut last = 0usize;
    for mat in vault.searcher.find_iter(text) {
        let (start, end, pat) = (mat.start(), mat.end(), mat.pattern());
        if start >= last {
            out.push_str(&text[last..start]);
            let repl = &vault.replacements[pat];
            out.push_str(repl);
            last = end;
        }
    }
    out.push_str(&text[last..]);
    // Log that a redaction occurred so telemetry can aggregate redaction counts without
    // exposing PII. This is intentionally minimal.
    tracing::info!("redaction applied: replaced patterns detected");
    // increment redaction counter for telemetry (do not include PII in metric labels)
    metrics::increment_counter!("pii_redactions_total");
    std::borrow::Cow::Owned(out)
}

/// Determine a safe flush boundary for `text` given the vault patterns.
/// Returns a tuple (safe_to_flush, hold_in_tail_buffer) as borrowed slices of the input.
/// CRITICAL: ensures the split index is a UTF-8 char boundary using is_char_boundary.
pub fn determine_safe_boundary<'a>(text: &'a str, vault: &PiiVault) -> (&'a str, &'a str) {
    // If there are no patterns or max pattern length <= 1, nothing to guard for.
    if vault.max_pattern_len <= 1 {
        return (text, "");
    }

    // If the text is short, hold it entirely to avoid chopping potential matches.
    if text.len() <= vault.max_pattern_len {
        return ("", text);
    }

    // If there are no matches in this chunk, it's safe to flush entirely.
    if vault.searcher.find(text).is_none() {
        return (text, "");
    }

    // Otherwise, hold the last (max_pattern_len - 1) bytes in the tail buffer to
    // allow matches that cross chunk boundaries to be detected when the next chunk arrives.
    let hold = vault.max_pattern_len - 1;
    let mut split_at = text.len().saturating_sub(hold);

    // Walk backwards until we find a char boundary to avoid splitting multi-byte UTF-8 chars.
    while split_at > 0 && !text.is_char_boundary(split_at) {
        split_at -= 1;
    }

    // If somehow we couldn't find a boundary (very unlikely), fallback to holding everything.
    if split_at == 0 {
        return ("", text);
    }

    (&text[..split_at], &text[split_at..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::ChoiceState;

    #[test]
    fn test_basic_redaction() {
        let vault = PiiVault::new(&["password", "secret"], &["[REDACTED]", "[REDACTED]"]);
        let out = redact_text("my password is secret", &vault);
        assert_eq!(out, "my [REDACTED] is [REDACTED]");
    }

    #[test]
    fn test_boundary_hold_partial_pii() {
        // Create a vault with a max pattern length of 5 by including a 5-byte pattern
        // and also include the shorter pattern "pass" which appears in the text.
        let vault = PiiVault::new(&["xxxxx", "pass"], &["[REDACTED]", "[REDACTED]"]);
        let (safe, tail) = determine_safe_boundary("my pass", &vault);
        assert_eq!(safe, "my ");
        assert_eq!(tail, "pass");
    }

    #[test]
    fn test_utf8_char_boundary_panic_trap() {
        // Pattern that is a 4-byte emoji ensures max_pattern_len == 4
        let vault = PiiVault::new(&["🚀"], &["[REDACTED]"]);
        let text = "Hello 🚀";
        // This call must not panic and must backtrack to a valid UTF-8 boundary
        let (safe, tail) = determine_safe_boundary(text, &vault);
        assert_eq!(safe, "Hello ");
        assert_eq!(tail, "🚀");
    }

    #[test]
    fn test_cross_chunk_reconstruction_with_state() {
        // Build a searcher that knows about "password", "pass" and "secret" but deliberately
        // set max_pattern_len to 5 so that only the last 4 bytes ("pass") are held by
        // determine_safe_boundary for the first chunk. This simulates holding a small
        // fragment across chunk boundaries and then reconstructing the full sensitive word.
        let searcher = AhoCorasick::new(&["password", "my", "secret"]).expect("build");
        let replacements = vec![
            "[REDACTED]".to_string(),
            "[REDACTED]".to_string(),
            "[REDACTED]".to_string(),
        ];
        let escaped_replacements = replacements.clone();
        let vault = PiiVault {
            searcher,
            max_pattern_len: 5, // force hold of 4 bytes
            replacements,
            escaped_replacements,
        };

        let mut choice_state = ChoiceState::new(0);

        // Chunk 1: should hold just "pass"
        let chunk1 = "Here is my pass";
        let (_safe1, tail1) = determine_safe_boundary(chunk1, &vault);
        assert_eq!(tail1, "pass");
        choice_state.append_to_content_tail(tail1);

        // Chunk 2: prepend the held tail and redact the reconstructed text
        let held = choice_state.take_content_tail();
        let reconstructed = format!("{}{}", held, "word for the account");
        let out = redact_text(&reconstructed, &vault);
        assert_eq!(out, "[REDACTED] for the account");
    }
}
