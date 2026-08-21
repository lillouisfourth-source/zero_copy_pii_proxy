use aho_corasick::AhoCorasick;
use bytes::{Bytes, BytesMut};
use std::str::Utf8Error;

const DEFAULT_MAX_BUFFER_CAPACITY: usize = 64 * 1024;
static REDACTED_BYTES: &[u8] = b"[REDACTED]";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputSegment {
    Input(Bytes),
    Replacement(Bytes),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamRedactionError {
    BufferLimitExceeded,
    InvalidUtf8,
}

pub struct StreamRedactorV2 {
    searcher: AhoCorasick,
    patterns: Vec<Vec<u8>>,
    max_pattern_len: usize,
    pending: BytesMut,
    max_capacity: usize,
    replacement: Bytes,
}

impl StreamRedactorV2 {
    pub fn new(patterns: &[&str]) -> Self {
        Self::with_max_capacity(patterns, DEFAULT_MAX_BUFFER_CAPACITY)
    }

    pub fn with_max_capacity(patterns: &[&str], max_capacity: usize) -> Self {
        assert!(
            max_capacity > 0,
            "redaction buffer capacity must be non-zero"
        );
        let searcher = AhoCorasick::new(patterns).expect("failed to build aho-corasick automaton");
        Self {
            searcher,
            patterns: patterns
                .iter()
                .map(|pattern| pattern.as_bytes().to_vec())
                .collect(),
            max_pattern_len: patterns
                .iter()
                .map(|pattern| pattern.len())
                .max()
                .unwrap_or(0),
            pending: BytesMut::new(),
            max_capacity,
            replacement: Bytes::from_static(REDACTED_BYTES),
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
            determine_safe_boundary(text, &self.patterns, self.max_pattern_len)
                .0
                .len()
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
        for mat in self.searcher.find_iter(&source[..safe_len]) {
            if mat.start() > last {
                output.push(OutputSegment::Input(source.slice(last..mat.start())));
            }
            output.push(OutputSegment::Replacement(self.replacement.clone()));
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

fn determine_safe_boundary<'a>(
    text: &'a str,
    patterns: &[Vec<u8>],
    max_pattern_len: usize,
) -> (&'a str, &'a str) {
    if max_pattern_len <= 1 || text.len() <= max_pattern_len {
        return if max_pattern_len <= 1 {
            (text, "")
        } else {
            ("", text)
        };
    }
    let mut partial_len = 0;
    for pattern in patterns {
        for prefix_len in 1..pattern.len().min(text.len()) {
            if text.as_bytes().ends_with(&pattern[..prefix_len]) {
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

    fn collect(segments: Vec<OutputSegment>) -> Vec<u8> {
        segments
            .into_iter()
            .flat_map(|segment| match segment {
                OutputSegment::Input(bytes) | OutputSegment::Replacement(bytes) => bytes.to_vec(),
            })
            .collect()
    }

    #[test]
    fn passing_frame_is_sliced_without_copying() {
        let source = Bytes::from_static(b"prefix suffix");
        let mut redactor = StreamRedactorV2::new(&["secret"]);
        assert_eq!(
            redactor.push(source.clone()).unwrap(),
            vec![OutputSegment::Input(source)]
        );
    }

    #[test]
    fn split_utf8_and_pii_are_redacted() {
        let mut redactor = StreamRedactorV2::new(&["password", "email@example.com"]);
        let mut output = Vec::new();
        for chunk in [
            b"hello \xF0\x9F".as_slice(),
            b"\x9A\x80 password e".as_slice(),
            b"mail@example.com".as_slice(),
        ] {
            output.extend(redactor.push(Bytes::copy_from_slice(chunk)).unwrap());
        }
        output.extend(redactor.finish().unwrap());
        assert_eq!(
            collect(output),
            b"hello \xF0\x9F\x9A\x80 [REDACTED] [REDACTED]"
        );
    }

    #[test]
    fn pending_state_has_a_hard_bound() {
        let mut redactor = StreamRedactorV2::with_max_capacity(&["sensitive"], 8);
        assert_eq!(
            redactor.push(Bytes::from_static(b"123456789")),
            Err(StreamRedactionError::BufferLimitExceeded)
        );
    }
}
