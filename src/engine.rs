use aho_corasick::AhoCorasick;
use bytes::{Bytes, BytesMut};
use serde_json;
use std::str::Utf8Error;

const DEFAULT_MAX_BUFFER_CAPACITY: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputSegment {
    Input(Bytes),
    Replacement(Bytes),
}

#[derive(Debug, PartialEq, Eq)]
pub enum StreamRedactionError {
    BufferLimitExceeded,
    InvalidUtf8,
}

#[allow(dead_code)]
#[derive(Clone)]
pub struct PiiVault {
    pub searcher: AhoCorasick,
    pub max_pattern_len: usize,
    pub patterns: Vec<String>,
    pub replacements: Vec<Bytes>,
    pub replacement_strings: Vec<String>,
    pub escaped_replacements: Vec<String>,
}

pub struct StreamRedactor<'a> {
    vault: &'a PiiVault,
    pending: BytesMut,
    max_capacity: usize,
}

impl<'a> StreamRedactor<'a> {
    pub fn new(vault: &'a PiiVault) -> Self {
        Self::with_max_capacity(vault, DEFAULT_MAX_BUFFER_CAPACITY)
    }

    pub fn with_max_capacity(vault: &'a PiiVault, max_capacity: usize) -> Self {
        assert!(
            max_capacity > 0,
            "redaction buffer capacity must be non-zero"
        );
        Self {
            vault,
            pending: BytesMut::new(),
            max_capacity,
        }
    }

    pub fn push(&mut self, chunk: Bytes) -> Result<Vec<OutputSegment>, StreamRedactionError> {
        if chunk.is_empty() {
            return Ok(Vec::new());
        }
        let source = if self.pending.is_empty() {
            chunk
        } else {
            let mut combined = BytesMut::with_capacity(self.pending.len() + chunk.len());
            combined.extend_from_slice(&self.pending);
            combined.extend_from_slice(&chunk);
            self.pending.clear();
            combined.freeze()
        };
        self.process_source(source, false)
    }

    pub fn finish(&mut self) -> Result<Vec<OutputSegment>, StreamRedactionError> {
        if self.pending.is_empty() {
            return Ok(Vec::new());
        }
        let source = self.pending.split().freeze();
        self.process_source(source, true)
    }

    fn process_source(
        &mut self,
        source: Bytes,
        flush_all: bool,
    ) -> Result<Vec<OutputSegment>, StreamRedactionError> {
        let valid_len = match std::str::from_utf8(&source) {
            Ok(text) => text.len(),
            Err(error) if error.error_len().is_none() => valid_utf8_prefix(error),
            Err(_) => return Err(StreamRedactionError::InvalidUtf8),
        };
        if flush_all && valid_len != source.len() {
            return Err(StreamRedactionError::InvalidUtf8);
        }
        let text = std::str::from_utf8(&source[..valid_len])
            .map_err(|_| StreamRedactionError::InvalidUtf8)?;
        let safe_len = if flush_all {
            text.len()
        } else {
            determine_safe_boundary(text, self.vault).0.len()
        };
        let output = self.redact_source(&source, safe_len);
        let retained_end = if flush_all { source.len() } else { valid_len };
        if safe_len < retained_end {
            self.pending
                .extend_from_slice(&source[safe_len..retained_end]);
        }
        if !flush_all && valid_len < source.len() {
            self.pending.extend_from_slice(&source[valid_len..]);
        }
        if self.pending.len() > self.max_capacity {
            return Err(StreamRedactionError::BufferLimitExceeded);
        }
        Ok(output)
    }

    fn redact_source(&self, source: &Bytes, safe_len: usize) -> Vec<OutputSegment> {
        let mut output = Vec::new();
        let mut last = 0;
        for mat in self.vault.searcher.find_iter(&source[..safe_len]) {
            if mat.start() > last {
                output.push(OutputSegment::Input(source.slice(last..mat.start())));
            }
            output.push(OutputSegment::Replacement(
                self.vault.replacements[mat.pattern()].clone(),
            ));
            last = mat.end();
        }
        if last < safe_len {
            output.push(OutputSegment::Input(source.slice(last..safe_len)));
        }
        output
    }
}

fn valid_utf8_prefix(error: Utf8Error) -> usize {
    error.valid_up_to()
}

impl PiiVault {
    pub fn new(patterns: &[&str], replacements: &[&str]) -> Self {
        assert_eq!(
            patterns.len(),
            replacements.len(),
            "patterns and replacements length mismatch"
        );
        let searcher = AhoCorasick::new(patterns).expect("failed to build aho-corasick automaton");
        let replacement_strings = replacements
            .iter()
            .map(|value| (*value).to_string())
            .collect::<Vec<_>>();
        let replacements_bytes = replacement_strings
            .iter()
            .map(|value| Bytes::copy_from_slice(value.as_bytes()))
            .collect::<Vec<_>>();
        let escaped_replacements_vec = replacements
            .iter()
            .map(|value| {
                let quoted = serde_json::to_string(value).unwrap_or_else(|_| String::from("\"\""));
                if quoted.len() >= 2 && quoted.starts_with('"') && quoted.ends_with('"') {
                    quoted[1..quoted.len() - 1].to_string()
                } else {
                    quoted
                }
            })
            .collect::<Vec<_>>();
        Self {
            searcher,
            max_pattern_len: patterns
                .iter()
                .map(|pattern| pattern.len())
                .max()
                .unwrap_or(0),
            patterns: patterns
                .iter()
                .map(|pattern| (*pattern).to_string())
                .collect(),
            replacements: replacements_bytes,
            replacement_strings,
            escaped_replacements: escaped_replacements_vec,
        }
    }
}

pub fn redact_text<'a>(text: &'a str, vault: &PiiVault) -> std::borrow::Cow<'a, str> {
    if vault.searcher.find(text).is_none() {
        return std::borrow::Cow::Borrowed(text);
    }
    let mut output = String::with_capacity(text.len());
    let mut last = 0;
    for mat in vault.searcher.find_iter(text) {
        if mat.start() >= last {
            output.push_str(&text[last..mat.start()]);
            output.push_str(&vault.replacement_strings[mat.pattern()]);
            last = mat.end();
        }
    }
    output.push_str(&text[last..]);
    tracing::info!("redaction applied: replaced patterns detected");
    metrics::increment_counter!("pii_redactions_total");
    std::borrow::Cow::Owned(output)
}

pub fn determine_safe_boundary<'a>(text: &'a str, vault: &PiiVault) -> (&'a str, &'a str) {
    if vault.max_pattern_len <= 1 {
        return (text, "");
    }
    if text.len() <= vault.max_pattern_len {
        return ("", text);
    }
    let mut partial_len = 0;
    for pattern in &vault.patterns {
        for prefix_len in 1..pattern.len().min(text.len()) {
            if text.as_bytes().ends_with(&pattern.as_bytes()[..prefix_len]) {
                partial_len = partial_len.max(prefix_len);
            }
        }
    }
    if partial_len == 0 {
        return (text, "");
    }
    let mut split_at = text.len() - partial_len;
    while split_at > 0 && !text.is_char_boundary(split_at) {
        split_at -= 1;
    }
    if split_at == 0 {
        ("", text)
    } else {
        (&text[..split_at], &text[split_at..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vault() -> PiiVault {
        PiiVault::new(&["password", "secret"], &["[REDACTED]", "[REDACTED]"])
    }

    #[test]
    fn test_basic_redaction() {
        assert_eq!(
            redact_text("my password is secret", &vault()),
            "my [REDACTED] is [REDACTED]"
        );
    }

    #[test]
    fn passing_frame_is_sliced_without_copying() {
        let source = Bytes::from_static(b"prefix suffix");
        let configured = vault();
        let mut redactor = StreamRedactor::new(&configured);
        assert_eq!(
            redactor.push(source.clone()).unwrap(),
            vec![OutputSegment::Input(source)]
        );
    }

    #[test]
    fn test_boundary_hold_partial_pii() {
        let configured = PiiVault::new(&["xxxxx", "pass"], &["[REDACTED]", "[REDACTED]"]);
        let (safe, tail) = determine_safe_boundary("my pass", &configured);
        assert_eq!(safe, "my pass");
        assert_eq!(tail, "");
    }

    #[test]
    fn test_utf8_char_boundary_panic_trap() {
        let configured = PiiVault::new(&["🚀abc"], &["[REDACTED]"]);
        let (safe, tail) = determine_safe_boundary("Hello 🚀", &configured);
        assert_eq!(safe, "Hello ");
        assert_eq!(tail, "🚀");
    }

    #[test]
    fn split_utf8_and_pii_are_redacted() {
        let configured = PiiVault::new(
            &["password", "email@example.com"],
            &["[REDACTED]", "[REDACTED]"],
        );
        let mut redactor = StreamRedactor::new(&configured);
        let mut output = Vec::new();
        for chunk in [
            b"hello \xF0\x9F".as_slice(),
            b"\x9A\x80 password e".as_slice(),
            b"mail@example.com".as_slice(),
        ] {
            output.extend(redactor.push(Bytes::copy_from_slice(chunk)).unwrap());
        }
        output.extend(redactor.finish().unwrap());
        let collected = output
            .into_iter()
            .flat_map(|segment| match segment {
                OutputSegment::Input(bytes) | OutputSegment::Replacement(bytes) => bytes.to_vec(),
            })
            .collect::<Vec<_>>();
        assert_eq!(collected, b"hello \xF0\x9F\x9A\x80 [REDACTED] [REDACTED]");
    }

    #[test]
    fn pending_state_has_a_hard_bound() {
        let configured = PiiVault::new(&["sensitive"], &["[REDACTED]"]);
        let mut redactor = StreamRedactor::with_max_capacity(&configured, 8);
        assert_eq!(
            redactor.push(Bytes::from_static(b"123456789")),
            Err(StreamRedactionError::BufferLimitExceeded)
        );
    }

    #[test]
    fn redacted_stream_has_expected_blake3_receipt() {
        let configured = PiiVault::new(&["password"], &["[REDACTED]"]);
        let mut redactor = StreamRedactor::new(&configured);
        let mut hasher = blake3::Hasher::new();
        let mut outputs = redactor
            .push(Bytes::from_static(b"password stays private"))
            .unwrap();
        outputs.extend(redactor.finish().unwrap());
        for output in outputs {
            let bytes = match output {
                OutputSegment::Input(bytes) | OutputSegment::Replacement(bytes) => bytes,
            };
            hasher.update(&bytes);
        }
        assert_eq!(hasher.finalize(), blake3::hash(b"[REDACTED] stays private"));
    }
}
