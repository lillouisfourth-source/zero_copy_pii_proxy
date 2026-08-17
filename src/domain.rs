#![allow(dead_code)]

use std::borrow::Cow;
use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// Domain layer: strict, zero-copy-friendly data contracts for SSE chunks coming from OpenAI.
// All string fields use Cow<'a, str> and structs use #[serde(borrow)] to enable zero-copy
// deserialization from borrowed input when possible.

#[derive(Debug, Serialize, Deserialize)]
pub struct SSEChunk<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Cow<'a, str>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub object: Option<Cow<'a, str>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<i64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<Cow<'a, str>>,

    #[serde(default, borrow)]
    pub choices: Vec<Choice<'a>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Choice<'a> {
    // the index of the choice in the response
    pub index: usize,

    // finish_reason can be null in streamed messages
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finish_reason: Option<Cow<'a, str>>,

    // delta holds incremental streamed content (role/content/tool_call)
    #[serde(skip_serializing_if = "Option::is_none", borrow)]
    pub delta: Option<Delta<'a>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Delta<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<Cow<'a, str>>,

    // streamed text content (may be empty when only tool_call is present)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<Cow<'a, str>>,

    // tool_call is represented conservatively as its own structure
    #[serde(skip_serializing_if = "Option::is_none", borrow)]
    pub tool_call: Option<ToolCall<'a>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ToolCall<'a> {
    // tool/function name
    pub name: Cow<'a, str>,

    // arguments are stored as raw string (JSON text) to avoid building a dynamic DOM
    // and to preserve zero-copy behavior when possible.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments: Option<Cow<'a, str>>,

    // a nested Function entry is provided for compatibility with function-calling schemas
    #[serde(skip_serializing_if = "Option::is_none", borrow)]
    pub function: Option<Function<'a>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Function<'a> {
    pub name: Cow<'a, str>,

    // function arguments represented as a raw JSON string; keep as Cow<'a, str> to avoid
    // unnecessary allocations during streaming.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments: Option<Cow<'a, str>>,
}

// ChoiceState and StreamState: lightweight in-memory buffers for handling cross-chunk
// boundaries and isolating state by choice index (and by tool index when tool-calls are present).

/// Per-choice buffering state used by the engine to accumulate partial fragments that
/// cannot be flushed immediately (e.g., because they might form part of a multi-byte
/// UTF-8 sequence or they span PII pattern boundaries).
#[allow(dead_code)]
#[derive(Debug, Default)]
pub struct ChoiceState {
    pub index: usize,

    // content_tail accumulates bytes (as UTF-8) that are being held until it is safe to flush.
    // String is used because tails are owned while buffered across incoming chunk boundaries.
    pub content_tail: String,

    // tool_tails maps a tool-call index to its own tail buffer so tool-specific arguments
    // or fragments do not collide when multiple tool-calls are active concurrently.
    pub tool_tails: HashMap<usize, String>,
}

impl ChoiceState {
    pub fn new(index: usize) -> Self {
        Self {
            index,
            content_tail: String::new(),
            tool_tails: HashMap::new(),
        }
    }

    pub fn clear(&mut self) {
        self.content_tail.clear();
        self.tool_tails.clear();
    }

    pub fn append_to_content_tail(&mut self, s: &str) {
        self.content_tail.push_str(s);
    }

    pub fn take_content_tail(&mut self) -> String {
        std::mem::take(&mut self.content_tail)
    }

    pub fn append_to_tool_tail(&mut self, tool_index: usize, s: &str) {
        self.tool_tails.entry(tool_index).or_default().push_str(s);
    }

    pub fn take_tool_tail(&mut self, tool_index: usize) -> Option<String> {
        self.tool_tails.remove(&tool_index)
    }
}

/// StreamState holds per-choice buffers for a streaming response with N choices. It
/// ensures isolation by index and provides convenience accessors to ensure capacity.
#[allow(dead_code)]
#[derive(Debug, Default)]
pub struct StreamState {
    pub choices: Vec<ChoiceState>,
}

impl StreamState {
    pub fn new() -> Self {
        Self {
            choices: Vec::new(),
        }
    }

    /// Ensure a ChoiceState exists at `index` and return a mutable reference to it.
    /// Expands the internal vector with default ChoiceState entries as needed.
    pub fn ensure_choice(&mut self, index: usize) -> &mut ChoiceState {
        if index >= self.choices.len() {
            // pre-allocate up to index (inclusive)
            let additional = index + 1 - self.choices.len();
            for _ in 0..additional {
                let idx = self.choices.len();
                self.choices.push(ChoiceState::new(idx));
            }
        }
        &mut self.choices[index]
    }

    /// Reset all buffered state (useful after a finished stream or when reusing the struct).
    pub fn reset(&mut self) {
        for c in &mut self.choices {
            c.clear();
        }
        self.choices.clear();
    }
}
