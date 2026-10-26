//! Inbound de-tokenization.
//!
//! * `TextDetokenizer` restores placeholders in a text stream and holds back any
//!   trailing fragment that could still become a placeholder (`[AWS_ACC` + `ESS_KEY_..]`).
//! * `SseProcessor` splits `text/event-stream` bytes into events at arbitrary TCP
//!   fragment boundaries, parses each `data:` JSON payload and runs one detokenizer per
//!   text field (OpenAI `choices/N/delta/content`, Anthropic `delta/text`, tool-call
//!   argument fragments, Responses API `delta`). Held-back text that never completed is
//!   re-emitted before the terminal event of its block, or at end of stream.

use std::{collections::HashMap, sync::Arc};

use bytes::Bytes;
use serde_json::Value;
use tracing::warn;

use crate::state::Session;

const MAX_PLACEHOLDER_LEN: usize = 80;
const MAX_EVENT_BYTES: usize = 16 * 1024 * 1024;
const STREAM_TEXT_KEYS: [&str; 7] = [
    "content",
    "text",
    "partial_json",
    "arguments",
    "delta",
    "thinking",
    "reasoning_content",
];

// ---------------------------------------------------------------------------
// Placeholder shape recognition
// ---------------------------------------------------------------------------

enum Shape {
    /// A complete `[KIND_hex]` token of this byte length.
    Complete(usize),
    /// Could still become a placeholder once more bytes arrive.
    Partial,
    /// Cannot be a placeholder.
    No,
}

fn valid_inner(inner: &str) -> bool {
    let Some((kind, hex)) = inner.rsplit_once('_') else {
        return false;
    };
    !kind.is_empty()
        && kind.as_bytes()[0].is_ascii_uppercase()
        && kind
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        && (8..=64).contains(&hex.len())
        && hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// `s` must start with `[`.
fn classify(s: &str) -> Shape {
    let bytes = s.as_bytes();
    let mut i = 1usize;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b']' {
            return if valid_inner(&s[1..i]) {
                Shape::Complete(i + 1)
            } else {
                Shape::No
            };
        }
        if i == 1 && !b.is_ascii_uppercase() {
            return Shape::No;
        }
        if !(b.is_ascii_alphanumeric() || b == b'_') {
            return Shape::No;
        }
        i += 1;
        if i > MAX_PLACEHOLDER_LEN {
            return Shape::No;
        }
    }
    Shape::Partial
}

pub fn json_escape(s: &str) -> String {
    let quoted = serde_json::to_string(s).unwrap_or_default();
    if quoted.len() >= 2 {
        quoted[1..quoted.len() - 1].to_string()
    } else {
        String::new()
    }
}

// ---------------------------------------------------------------------------
// Text-level streaming detokenizer
// ---------------------------------------------------------------------------

pub struct TextDetokenizer {
    session: Arc<Session>,
    pending: String,
    /// Restored values are inserted into a JSON string literal (tool-call arguments).
    escape: bool,
}

impl TextDetokenizer {
    pub fn new(session: Arc<Session>, escape: bool) -> Self {
        Self {
            session,
            pending: String::new(),
            escape,
        }
    }

    pub fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    pub fn push(&mut self, text: &str) -> String {
        let mut input = std::mem::take(&mut self.pending);
        input.push_str(text);

        let mut out = String::with_capacity(input.len());
        let mut idx = 0usize;
        while idx < input.len() {
            match input[idx..].find('[') {
                None => {
                    out.push_str(&input[idx..]);
                    idx = input.len();
                }
                Some(rel) => {
                    out.push_str(&input[idx..idx + rel]);
                    let start = idx + rel;
                    match classify(&input[start..]) {
                        Shape::Complete(len) => {
                            let ph = &input[start..start + len];
                            match self.session.resolve(ph) {
                                Some(raw) => {
                                    if self.escape {
                                        out.push_str(&json_escape(&raw));
                                    } else {
                                        out.push_str(&raw);
                                    }
                                }
                                None => out.push_str(ph),
                            }
                            idx = start + len;
                        }
                        Shape::Partial => {
                            self.pending = input[start..].to_string();
                            return out;
                        }
                        Shape::No => {
                            out.push('[');
                            idx = start + 1;
                        }
                    }
                }
            }
        }
        out
    }

    /// Releases any held-back text verbatim (it never became a placeholder).
    pub fn flush(&mut self) -> String {
        std::mem::take(&mut self.pending)
    }
}

/// Whole-string restoration (no cross-chunk state).
pub fn restore_plain(session: &Arc<Session>, text: &str) -> String {
    if !text.contains('[') {
        return text.to_string();
    }
    let mut d = TextDetokenizer::new(session.clone(), false);
    let mut out = d.push(text);
    out.push_str(&d.flush());
    out
}

fn walk_strings(v: &mut Value, path: &mut Vec<String>, f: &mut dyn FnMut(&[String], &mut String)) {
    match v {
        Value::String(s) => f(path, s),
        Value::Array(a) => {
            for (i, x) in a.iter_mut().enumerate() {
                path.push(i.to_string());
                walk_strings(x, path, f);
                path.pop();
            }
        }
        Value::Object(m) => {
            for (k, x) in m.iter_mut() {
                path.push(k.clone());
                walk_strings(x, path, f);
                path.pop();
            }
        }
        _ => {}
    }
}

/// Restores placeholders in every complete string of a JSON value (non-streaming bodies,
/// and SSE events that carry whole strings such as `message_start` or `*.done`).
pub fn restore_value(v: &mut Value, session: &Arc<Session>) {
    let mut path = Vec::new();
    walk_strings(v, &mut path, &mut |p: &[String], s: &mut String| {
        if !s.contains('[') {
            return;
        }
        let escape = p
            .last()
            .is_some_and(|k| k == "arguments" || k == "partial_json");
        let mut d = TextDetokenizer::new(session.clone(), escape);
        let mut out = d.push(s);
        out.push_str(&d.flush());
        *s = out;
    });
}

// ---------------------------------------------------------------------------
// SSE framing
// ---------------------------------------------------------------------------

struct SseEvent {
    meta: Vec<String>,
    name: Option<String>,
    data: Vec<String>,
}

fn parse_event(text: &str) -> SseEvent {
    let mut ev = SseEvent {
        meta: Vec::new(),
        name: None,
        data: Vec::new(),
    };
    for line in text.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if let Some(rest) = line.strip_prefix("data:") {
            ev.data
                .push(rest.strip_prefix(' ').unwrap_or(rest).to_string());
        } else if let Some(rest) = line.strip_prefix("event:") {
            ev.name = Some(rest.strip_prefix(' ').unwrap_or(rest).to_string());
        } else if !line.is_empty() {
            ev.meta.push(line.to_string());
        }
    }
    ev
}

fn write_event(out: &mut Vec<u8>, meta: &[String], name: &Option<String>, data: &str) {
    for m in meta {
        out.extend_from_slice(m.as_bytes());
        out.push(b'\n');
    }
    if let Some(n) = name {
        out.extend_from_slice(b"event: ");
        out.extend_from_slice(n.as_bytes());
        out.push(b'\n');
    }
    for line in data.split('\n') {
        out.extend_from_slice(b"data: ");
        out.extend_from_slice(line.as_bytes());
        out.push(b'\n');
    }
    out.push(b'\n');
}

/// Returns `(index_of_event_end, delimiter_len)` for the first blank-line delimiter.
fn find_event_end(buf: &[u8]) -> Option<(usize, usize)> {
    let mut i = 0usize;
    while i < buf.len() {
        match buf[i] {
            b'\n' => {
                if buf.get(i + 1) == Some(&b'\n') {
                    return Some((i, 2));
                }
                if buf.get(i + 1) == Some(&b'\r') && buf.get(i + 2) == Some(&b'\n') {
                    return Some((i, 3));
                }
            }
            b'\r' => {
                if buf.get(i + 1) == Some(&b'\n')
                    && buf.get(i + 2) == Some(&b'\r')
                    && buf.get(i + 3) == Some(&b'\n')
                {
                    return Some((i, 4));
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

fn is_delta_event(v: &Value) -> bool {
    if v.get("object").and_then(Value::as_str) == Some("chat.completion.chunk") {
        return true;
    }
    if let Some(t) = v.get("type").and_then(Value::as_str) {
        if t == "content_block_delta" || t.ends_with(".delta") {
            return true;
        }
    }
    v.get("choices")
        .and_then(Value::as_array)
        .is_some_and(|c| c.iter().any(|x| x.get("delta").is_some()))
}

/// Key prefixes of the fields whose held-back text must be released *before* this event.
/// Empty vec = not a terminal event. A single empty-string prefix = flush everything.
fn terminal_prefixes(v: &Value) -> Vec<String> {
    if let Some(t) = v.get("type").and_then(Value::as_str) {
        if t == "content_block_stop" {
            let idx = v.get("index").and_then(Value::as_u64).unwrap_or(0);
            return vec![format!("idx{idx}/")];
        }
        if t == "message_stop"
            || t == "message_delta"
            || t == "response.completed"
            || t.ends_with(".done")
        {
            return vec![String::new()];
        }
    }
    let mut prefixes = Vec::new();
    if let Some(choices) = v.get("choices").and_then(Value::as_array) {
        for (pos, c) in choices.iter().enumerate() {
            if c.get("finish_reason").is_some_and(|f| !f.is_null()) {
                prefixes.push(format!("choices/{pos}/"));
            }
        }
    }
    prefixes
}

fn needs_json_escape(last_key: &str, event_type: &str) -> bool {
    last_key == "arguments"
        || last_key == "partial_json"
        || (last_key == "delta" && event_type.contains("arguments"))
}

fn set_string_at(v: &mut Value, path: &[String], new: String) -> bool {
    let mut cur = v;
    for seg in path {
        cur = match cur {
            Value::Object(m) => match m.get_mut(seg.as_str()) {
                Some(x) => x,
                None => return false,
            },
            Value::Array(a) => match seg.parse::<usize>().ok().and_then(|i| a.get_mut(i)) {
                Some(x) => x,
                None => return false,
            },
            _ => return false,
        };
    }
    *cur = Value::String(new);
    true
}

fn null_finish_reasons(v: &mut Value) {
    if let Some(choices) = v.get_mut("choices").and_then(Value::as_array_mut) {
        for c in choices {
            if let Some(o) = c.as_object_mut() {
                if o.contains_key("finish_reason") {
                    o.insert("finish_reason".to_string(), Value::Null);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SSE processor
// ---------------------------------------------------------------------------

struct Template {
    value: Value,
    path: Vec<String>,
    name: Option<String>,
    meta: Vec<String>,
}

struct FieldState {
    detok: TextDetokenizer,
    /// Last event that left this field with held-back text; cloned to re-emit it.
    template: Option<Template>,
}

pub struct SseProcessor {
    session: Arc<Session>,
    buf: Vec<u8>,
    fields: HashMap<String, FieldState>,
}

impl SseProcessor {
    pub fn new(session: Arc<Session>) -> Self {
        Self {
            session,
            buf: Vec::new(),
            fields: HashMap::new(),
        }
    }

    /// Feeds one network chunk; returns the bytes that are safe to forward now.
    pub fn push(&mut self, chunk: &[u8]) -> Bytes {
        self.buf.extend_from_slice(chunk);
        let mut out: Vec<u8> = Vec::with_capacity(chunk.len() + 64);

        while let Some((end, dlen)) = find_event_end(&self.buf) {
            let raw: Vec<u8> = self.buf.drain(..end).collect();
            let delim: Vec<u8> = self.buf.drain(..dlen).collect();
            self.process_event(&raw, &delim, &mut out);
        }

        if self.buf.len() > MAX_EVENT_BYTES {
            warn!("SSE event exceeded {MAX_EVENT_BYTES} bytes without a delimiter; passing through raw");
            out.extend_from_slice(&self.buf);
            self.buf.clear();
        }
        Bytes::from(out)
    }

    /// Call at end of upstream body: releases held-back text and any partial trailing event.
    pub fn finish(&mut self) -> Bytes {
        let mut out = Vec::new();
        self.flush_prefixes(&[String::new()], &mut out);
        if !self.buf.is_empty() {
            out.extend_from_slice(&self.buf);
            self.buf.clear();
        }
        Bytes::from(out)
    }

    fn process_event(&mut self, raw: &[u8], delim: &[u8], out: &mut Vec<u8>) {
        let passthrough = |out: &mut Vec<u8>| {
            out.extend_from_slice(raw);
            out.extend_from_slice(delim);
        };
        let Ok(text) = std::str::from_utf8(raw) else {
            passthrough(out);
            return;
        };
        let ev = parse_event(text);
        if ev.data.is_empty() {
            passthrough(out); // comment / keep-alive
            return;
        }
        let data = ev.data.join("\n");
        if data.trim() == "[DONE]" {
            self.flush_prefixes(&[String::new()], out);
            passthrough(out);
            return;
        }

        match serde_json::from_str::<Value>(&data) {
            Ok(mut value) => {
                // Edge case: if a placeholder completes inside the very chunk that also carries
                // finish_reason, the held-back head is flushed literally (not restored).
                let prefixes = terminal_prefixes(&value);
                if !prefixes.is_empty() {
                    self.flush_prefixes(&prefixes, out);
                }
                if is_delta_event(&value) {
                    self.process_delta(&mut value, &ev.name, &ev.meta);
                } else {
                    restore_value(&mut value, &self.session);
                }
                let serialized = serde_json::to_string(&value).unwrap_or(data);
                write_event(out, &ev.meta, &ev.name, &serialized);
            }
            Err(_) => {
                let restored = restore_plain(&self.session, &data);
                write_event(out, &ev.meta, &ev.name, &restored);
            }
        }
    }

    fn process_delta(&mut self, value: &mut Value, name: &Option<String>, meta: &[String]) {
        let scope = value
            .get("index")
            .and_then(Value::as_u64)
            .map(|n| format!("idx{n}/"))
            .unwrap_or_default();
        let etype = value
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let session = self.session.clone();
        let mut pending: Vec<(String, Vec<String>)> = Vec::new();

        {
            let fields = &mut self.fields;
            let mut path = Vec::new();
            walk_strings(value, &mut path, &mut |p: &[String], s: &mut String| {
                let Some(last) = p.last() else { return };
                if !STREAM_TEXT_KEYS.contains(&last.as_str()) {
                    return;
                }
                let key = format!("{scope}{}", p.join("/"));
                let escape = needs_json_escape(last, &etype);
                let st = fields.entry(key.clone()).or_insert_with(|| FieldState {
                    detok: TextDetokenizer::new(session.clone(), escape),
                    template: None,
                });
                let produced = st.detok.push(s);
                *s = produced;
                if st.detok.has_pending() {
                    pending.push((key, p.to_vec()));
                } else {
                    st.template = None;
                }
            });
        }

        for (key, path) in pending {
            if let Some(st) = self.fields.get_mut(&key) {
                st.template = Some(Template {
                    value: value.clone(),
                    path,
                    name: name.clone(),
                    meta: meta.to_vec(),
                });
            }
        }
    }

    fn flush_prefixes(&mut self, prefixes: &[String], out: &mut Vec<u8>) {
        let mut keys: Vec<String> = self
            .fields
            .iter()
            .filter(|(k, st)| {
                st.detok.has_pending() && prefixes.iter().any(|p| k.starts_with(p.as_str()))
            })
            .map(|(k, _)| k.clone())
            .collect();
        keys.sort();

        for key in keys {
            let Some(st) = self.fields.get_mut(&key) else {
                continue;
            };
            let leftover = st.detok.flush();
            let Some(tpl) = st.template.take() else {
                warn!(field = %key, "held-back text without a template; dropping");
                continue;
            };
            if leftover.is_empty() {
                continue;
            }
            let mut v = tpl.value;
            let target = tpl.path;
            let mut p = Vec::new();
            // Blank every other text leaf so re-emitting the template cannot duplicate text.
            walk_strings(&mut v, &mut p, &mut |pp: &[String], s: &mut String| {
                if pp
                    .last()
                    .is_some_and(|k| STREAM_TEXT_KEYS.contains(&k.as_str()))
                    && pp != target.as_slice()
                {
                    s.clear();
                }
            });
            if !set_string_at(&mut v, &target, leftover) {
                continue;
            }
            null_finish_reasons(&mut v);
            match serde_json::to_string(&v) {
                Ok(s) => write_event(out, &tpl.meta, &tpl.name, &s),
                Err(e) => warn!(error = %e, "failed to serialize flushed event"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::SessionRegistry;

    const KEY: &str = "AKIAABCDEFGHIJKLMNOP";

    #[test]
    fn restores_placeholder_split_across_chunks() {
        let reg = SessionRegistry::new();
        let s = reg.create();
        let ph = s.tokenize("AWS_ACCESS_KEY", KEY);
        let (a, b) = ph.split_at(7);
        let mut d = TextDetokenizer::new(s.clone(), false);
        let mut out = d.push(&format!("key: {a}"));
        out.push_str(&d.push(&format!("{b} done")));
        out.push_str(&d.flush());
        assert_eq!(out, format!("key: {KEY} done"));
    }

    #[test]
    fn leaves_ordinary_brackets_alone() {
        let reg = SessionRegistry::new();
        let s = reg.create();
        let mut d = TextDetokenizer::new(s, false);
        let mut out = d.push("see [1] and [foo] and [");
        out.push_str(&d.flush());
        assert_eq!(out, "see [1] and [foo] and [");
    }

    #[test]
    fn sse_restores_placeholder_split_across_events() {
        let reg = SessionRegistry::new();
        let s = reg.create();
        let ph = s.tokenize("AWS_ACCESS_KEY", KEY);
        let (a, b) = ph.split_at(9);
        let ev = |t: &str| {
            format!(
                "event: content_block_delta\ndata: {}\n\n",
                serde_json::json!({
                    "type": "content_block_delta",
                    "index": 0,
                    "delta": {"type": "text_delta", "text": t}
                })
            )
        };
        let mut p = SseProcessor::new(s);
        let mut out = Vec::new();
        out.extend_from_slice(&p.push(ev(&format!("use {a}")).as_bytes()));
        out.extend_from_slice(&p.push(ev(&format!("{b} now")).as_bytes()));
        out.extend_from_slice(&p.finish());
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains(KEY));
        assert!(!text.contains(&ph));
    }

    #[test]
    fn sse_handles_network_fragmentation_mid_event() {
        let reg = SessionRegistry::new();
        let s = reg.create();
        let ph = s.tokenize("SECRET", "hunter2hunter2");
        let body = format!(
            "data: {}\n\ndata: [DONE]\n\n",
            serde_json::json!({
                "object": "chat.completion.chunk",
                "choices": [{"index": 0, "delta": {"content": ph}, "finish_reason": null}]
            })
        );
        let mut p = SseProcessor::new(s);
        let mut out = Vec::new();
        for chunk in body.as_bytes().chunks(7) {
            out.extend_from_slice(&p.push(chunk));
        }
        out.extend_from_slice(&p.finish());
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("hunter2hunter2"));
        assert!(text.contains("[DONE]"));
    }

    #[test]
    fn empty_sse_stream_finishes_without_output() {
        let session = SessionRegistry::new().create();
        let mut processor = SseProcessor::new(session);
        assert!(processor.finish().is_empty());
    }

    #[test]
    fn malformed_event_keeps_incomplete_placeholder_literal() {
        let session = SessionRegistry::new().create();
        let synthetic = "synthetic-secret-value";
        let placeholder = session.tokenize("SECRET", synthetic);
        let partial = &placeholder[..placeholder.len() - 1];
        let mut processor = SseProcessor::new(session);
        let input = format!("data: malformed {partial}\n\n");
        let out = processor.push(input.as_bytes());
        let out = String::from_utf8(out.to_vec()).expect("SSE output remains UTF-8");
        assert!(out.contains(partial));
        assert!(!out.contains(synthetic), "partial placeholder restored unexpectedly");
    }

    #[test]
    fn interrupted_trailing_event_is_forwarded_without_restoring_placeholder() {
        let session = SessionRegistry::new().create();
        let synthetic = "synthetic-interrupted-secret";
        let placeholder = session.tokenize("SECRET", synthetic);
        let mut processor = SseProcessor::new(session);
        let input = format!("data: {{\"delta\":\"{placeholder}\"");
        let mut out = processor.push(input.as_bytes()).to_vec();
        // Models the processor finalization used when an upstream body ends mid-event.
        out.extend_from_slice(&processor.finish());
        let out = String::from_utf8(out).expect("SSE output remains UTF-8");
        assert!(out.contains(&placeholder));
        assert!(!out.contains(synthetic), "unfinished event restored a secret");
    }

    #[test]
    fn tool_call_arguments_are_json_escaped() {
        let reg = SessionRegistry::new();
        let s = reg.create();
        let ph = s.tokenize("SECRET", "pa\"ss\\word12345");
        let mut d = TextDetokenizer::new(s, true);
        let out = d.push(&format!("{{\"pw\":\"{ph}\"}}"));
        let parsed: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed["pw"], "pa\"ss\\word12345");
    }
}
