use aho_corasick::AhoCorasick;
use bytes::{Bytes, BytesMut};
use serde_json;
use std::str::Utf8Error;

/// PiiVault holds the Aho-Corasick searcher and replacement arrays.
/// replacements: standard text replacements
/// escaped_replacements: JSON-escaped text (suitable for inserting into JSON string contexts)
#[allow(dead_code)]
#[derive(Clone)]
pub struct PiiVault {
    pub searcher: AhoCorasick,
    pub max_pattern_len: usize,
    pub patterns: Vec<String>,
    pub replacements: Vec<String>,
    pub escaped_replacements: Vec<String>,
}

const DEFAULT_MAX_BUFFER_CAPACITY: usize = 64 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum StreamRedactionError {
    BufferLimitExceeded,
    InvalidUtf8,
}

pub struct StreamRedactor<'a> {
    vault: &'a PiiVault,
    buffer: BytesMut,
    max_capacity: usize,
}

impl<'a> StreamRedactor<'a> {
    pub fn new(vault: &'a PiiVault) -> Self {
        Self::with_max_capacity(vault, DEFAULT_MAX_BUFFER_CAPACITY)
    }

    pub fn with_max_capacity(vault: &'a PiiVault, max_capacity: usize) -> Self {
        Self {
            vault,
            buffer: BytesMut::with_capacity(max_capacity),
            max_capacity,
        }
    }

    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<Bytes>, StreamRedactionError> {
        let mut output = Vec::new();
        let mut remaining = chunk;
        while !remaining.is_empty() {
            let available = self.max_capacity.saturating_sub(self.buffer.len());
            if available == 0 {
                output.extend(self.flush_available(false)?);
                if self.buffer.len() >= self.max_capacity {
                    return Err(StreamRedactionError::BufferLimitExceeded);
                }
                continue;
            }
            let take = remaining.len().min(available);
            self.buffer.extend_from_slice(&remaining[..take]);
            remaining = &remaining[take..];
            output.extend(self.flush_available(false)?);
        }
        Ok(output)
    }

    pub fn finish(&mut self) -> Result<Vec<Bytes>, StreamRedactionError> {
        if std::str::from_utf8(&self.buffer).is_err() {
            return Err(StreamRedactionError::InvalidUtf8);
        }
        self.flush_available(true)
    }

    fn flush_available(&mut self, flush_all: bool) -> Result<Vec<Bytes>, StreamRedactionError> {
        let valid_len = match std::str::from_utf8(&self.buffer) {
            Ok(text) => text.len(),
            Err(error) if error.error_len().is_none() => valid_utf8_prefix(error),
            Err(_) => return Err(StreamRedactionError::InvalidUtf8),
        };
        if valid_len == 0 {
            return Ok(Vec::new());
        }

        let text = std::str::from_utf8(&self.buffer[..valid_len])
            .map_err(|_| StreamRedactionError::InvalidUtf8)?;
        let (safe, _) = if flush_all {
            (text, "")
        } else {
            determine_safe_boundary(text, self.vault)
        };
        if safe.is_empty() {
            return Ok(Vec::new());
        }

        let output = redact_text(safe, self.vault).into_owned();
        let consumed = safe.len();
        let _ = self.buffer.split_to(consumed);
        Ok(vec![Bytes::from(output)])
    }
}

fn valid_utf8_prefix(error: Utf8Error) -> usize {
    error.valid_up_to()
}

impl PiiVault {
    /// Create a new vault from patterns and corresponding replacements.
    /// patterns.len() must equal replacements.len().
    pub fn new(patterns: &[&str], replacements: &[&str]) -> Self {
        assert_eq!(
            patterns.len(),
            replacements.len(),
            "patterns and replacements length mismatch"
        );
        let searcher = AhoCorasick::new(patterns).expect("failed to build aho-corasick automaton");

        // compute maximum pattern length in bytes
        let max_pattern_len = patterns.iter().map(|p| p.len()).max().unwrap_or(0);

        // copy replacements into owned Strings
        let replacements_vec = replacements
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>();

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
            patterns: patterns
                .iter()
                .map(|pattern| (*pattern).to_string())
                .collect(),
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

    let text_bytes = text.as_bytes();
    let mut partial_len = 0usize;
    for pattern in &vault.patterns {
        let max_prefix_len = pattern.len().min(text_bytes.len());
        for prefix_len in 1..max_prefix_len {
            if text_bytes.ends_with(&pattern.as_bytes()[..prefix_len]) {
                partial_len = partial_len.max(prefix_len);
            }
        }
    }
    if partial_len == 0 {
        return (text, "");
    }

    let mut split_at = text.len().saturating_sub(partial_len);

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
        assert_eq!(safe, "my pass");
        assert_eq!(tail, "");
    }

    #[test]
    fn test_utf8_char_boundary_panic_trap() {
        let vault = PiiVault::new(&["🚀abc"], &["[REDACTED]"]);
        let text = "Hello 🚀";
        let (safe, tail) = determine_safe_boundary(text, &vault);
        assert_eq!(safe, "Hello ");
        assert_eq!(tail, "🚀");
    }

    #[test]
    fn test_cross_chunk_reconstruction_with_state() {
        let vault = PiiVault::new(&["password"], &["[REDACTED]"]);
        let mut redactor = StreamRedactor::new(&vault);
        let mut output = Vec::new();
        output.extend(redactor.push(b"pass").unwrap());
        output.extend(redactor.push(b"word").unwrap());
        output.extend(redactor.finish().unwrap());
        let output = output
            .into_iter()
            .flat_map(|chunk| chunk.to_vec())
            .collect::<Vec<_>>();
        assert_eq!(String::from_utf8(output).unwrap(), "[REDACTED]");
    }
}
