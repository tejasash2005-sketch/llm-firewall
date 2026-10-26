//! Deterministic, dependency-free local benchmarks for the existing data path.
//!
//! Run with `cargo run --release --locked -- --benchmark`. These measurements are
//! informational and intentionally have no timing thresholds.

use std::{hint::black_box, sync::Arc, time::Instant};

use anyhow::Result;
use bytes::Bytes;
use serde_json::Value;

use crate::{
    proxy::mask_body_sync,
    scanner::Scanner,
    state::{Session, SessionRegistry},
    stream::{restore_value, SseProcessor},
};

const AWS_KEY: &str = "AKIAABCDEFGHIJKLMNOP";
const OPENAI_KEY: &str = "sk-12345678901234567890";
const TARGET_BYTES_PER_CASE: usize = 1024 * 1024;

struct Workload {
    input: String,
    expected_findings: usize,
}

fn workload(size: usize, expected_findings: usize) -> Workload {
    let secrets = match expected_findings {
        0 => "",
        1 => AWS_KEY,
        _ => "AKIAABCDEFGHIJKLMNOP sk-12345678901234567890",
    };
    let content = if secrets.is_empty() {
        String::new()
    } else {
        format!("{secrets} ")
    };
    assert!(size >= content.len());
    let mut input = String::with_capacity(size);
    input.push_str(&content);
    input.extend(std::iter::repeat_n('x', size - content.len()));
    Workload {
        input,
        expected_findings,
    }
}

fn iterations(size: usize) -> usize {
    (TARGET_BYTES_PER_CASE / size).max(1)
}

fn report(label: &str, bytes: usize, operation: &str, count: usize, elapsed: std::time::Duration) {
    let seconds = elapsed.as_secs_f64();
    let total_bytes = bytes.saturating_mul(count);
    let ops_per_sec = count as f64 / seconds;
    let mib_per_sec = total_bytes as f64 / (1024.0 * 1024.0) / seconds;
    let micros_per_op = seconds * 1_000_000.0 / count as f64;
    println!(
        "{label:24} op={operation:20} bytes={bytes:6} iterations={count:7} elapsed_ms={:10.3} ops_per_sec={ops_per_sec:12.1} MiB_per_sec={mib_per_sec:9.2} mean_us={micros_per_op:10.2}",
        elapsed.as_secs_f64() * 1000.0,
    );
}

fn measure(label: &str, bytes: usize, operation: &str, count: usize, mut run: impl FnMut()) {
    let warmup = count.min(100).max(10);
    for _ in 0..warmup {
        run();
    }
    let start = Instant::now();
    for _ in 0..count {
        run();
    }
    report(label, bytes, operation, count, start.elapsed());
}

fn streaming_roundtrip(
    session: Arc<Session>,
    first: &str,
    first_marker: &str,
    second: &str,
    second_marker: &str,
) -> Vec<u8> {
    let mut processor = SseProcessor::new(session);
    let mut output = Vec::with_capacity(first.len() + second.len());
    for (event, marker) in [(first, first_marker), (second, second_marker)] {
        let token_start = event
            .find(marker)
            .expect("fragment in synthetic SSE fixture");
        let token_split = token_start + marker.len().max(2) / 2;
        output.extend_from_slice(&processor.push(&event.as_bytes()[..token_split]));
        output.extend_from_slice(&processor.push(&event.as_bytes()[token_split..]));
    }
    output.extend_from_slice(&processor.finish());
    output
}

pub(crate) fn run() -> Result<()> {
    let scanner = Scanner::new(&[])?;
    let registry = SessionRegistry::new();
    let session = registry.create();

    println!("llm-firewall local synthetic benchmark; release build recommended");
    println!(
        "warm-up: min(iterations, 100), at least 10; target about 1 MiB per scanner/mask case"
    );
    println!("timings are aggregate wall-clock means, not p50/p99; no pass/fail thresholds");
    println!("operation columns: ops/sec, input MiB/sec, mean microseconds/op");

    for (size_label, size) in [("short", 128), ("medium", 4096), ("large", 65536)] {
        for (case, findings) in [("none", 0), ("one", 1), ("multiple", 2)] {
            let label = format!("scan/{size_label}/{case}");
            let input = workload(size, findings);
            assert_eq!(scanner.scan(&input.input).len(), input.expected_findings);
            measure(
                &label,
                input.input.len(),
                "scan",
                iterations(input.input.len()),
                || {
                    black_box(scanner.scan(black_box(&input.input)));
                },
            );

            let label = format!("mask/{size_label}/{case}");
            let body = Bytes::copy_from_slice(input.input.as_bytes());
            let (masked, count, _) =
                mask_body_sync(&scanner, &session, "text/plain", body.clone(), true)?;
            assert_eq!(count, input.expected_findings);
            if count > 0 {
                assert!(!String::from_utf8_lossy(&masked).contains(AWS_KEY));
                assert!(!String::from_utf8_lossy(&masked).contains(OPENAI_KEY));
            }
            measure(
                &label,
                body.len(),
                "mask_body_sync",
                iterations(body.len()),
                || {
                    black_box(
                        mask_body_sync(&scanner, &session, "text/plain", body.clone(), true)
                            .expect("synthetic text body is scannable"),
                    );
                },
            );
        }
    }

    let aws_placeholder = session.tokenize("AWS_ACCESS_KEY", AWS_KEY);
    let openai_placeholder = session.tokenize("OPENAI_KEY", OPENAI_KEY);
    let response = format!(
        r#"{{"choices":[{{"message":{{"content":"{aws_placeholder} {openai_placeholder}"}}}}]}}"#
    );
    let restore_count = 10_000;
    let response_value: Value = serde_json::from_str(&response)?;
    let mut restored = response_value.clone();
    restore_value(&mut restored, &session);
    let restored_text = restored.to_string();
    assert!(restored_text.contains(AWS_KEY) && restored_text.contains(OPENAI_KEY));
    measure(
        "restore/json/multiple",
        response.len(),
        "clone+restore_value",
        restore_count,
        || {
            let mut value = black_box(&response_value).clone();
            restore_value(&mut value, &session);
            black_box(value);
        },
    );

    let (first_fragment, second_fragment) = aws_placeholder.split_at(aws_placeholder.len() / 2);
    let event_for = |fragment: &str| {
        format!(
            "data: {}\n\n",
            serde_json::json!({
                "object": "chat.completion.chunk",
                "choices": [{"index": 0, "delta": {"content": fragment}, "finish_reason": null}]
            })
        )
    };
    let first_event = event_for(first_fragment);
    let second_event = event_for(second_fragment);
    let stream_count = 5_000;
    let streamed = streaming_roundtrip(
        session.clone(),
        &first_event,
        first_fragment,
        &second_event,
        second_fragment,
    );
    let streamed_text = String::from_utf8(streamed).expect("synthetic SSE is UTF-8");
    assert!(streamed_text.contains(AWS_KEY));
    assert!(!streamed_text.contains(&aws_placeholder));
    assert!(streamed_text.ends_with("\n\n"));
    assert_eq!(streamed_text.matches("\n\n").count(), 2);
    let stream_bytes = first_event.len() + second_event.len();
    measure(
        "restore/sse/split-token",
        stream_bytes,
        "SseProcessor",
        stream_count,
        || {
            black_box(streaming_roundtrip(
                session.clone(),
                &first_event,
                first_fragment,
                &second_event,
                second_fragment,
            ));
        },
    );

    println!("fixture keys are synthetic; no network, provider, timing assertions, or external services used");
    Ok(())
}
