use std::error::Error;

use positron_runtime::ListenerRole;

use super::{producer, support};

#[test]
fn malformed_compression_payloads_and_headers_have_stable_statuses() -> Result<(), Box<dyn Error>> {
    let harness = support::LiveLokiHarness::start("malformed")?;
    let bearer = format!("Bearer {}", harness.bearer());

    for (content_type, content_encoding, body, status) in [
        ("application/json", None, b"{not-json}".as_slice(), 400),
        (
            "application/json",
            Some("gzip"),
            [0xff, 0xff].as_slice(),
            400,
        ),
        (
            "application/json",
            Some("deflate"),
            [0xff, 0xff].as_slice(),
            400,
        ),
        (
            "application/x-protobuf",
            Some("snappy"),
            [0xff, 0xff].as_slice(),
            400,
        ),
        ("text/plain", None, b"secret body".as_slice(), 415),
    ] {
        let mut headers = vec![
            ("Authorization", bearer.as_str()),
            ("Content-Type", content_type),
        ];
        if let Some(content_encoding) = content_encoding {
            headers.push(("Content-Encoding", content_encoding));
        }
        let response = harness.http(
            ListenerRole::LokiPush,
            "POST",
            "/loki/api/v1/push",
            &headers,
            body,
        )?;
        support::assert_status(response.clone(), status);
        assert!(!response.contains("secret body"));
    }

    support::assert_status(
        harness.http(
            ListenerRole::LokiPush,
            "POST",
            "/loki/api/v1/push",
            &[
                ("Authorization", bearer.as_str()),
                ("Content-Type", "application/json"),
                ("X-Scope-OrgID", "tenant"),
                ("X-Scope-OrgID", "tenant"),
            ],
            br#"{"streams":[]}"#,
        )?,
        400,
    );
    support::assert_status(
        harness.http_with_advertised_length(
            ListenerRole::LokiPush,
            "POST",
            "/loki/api/v1/push",
            &[
                ("Authorization", bearer.as_str()),
                ("Content-Type", "application/json"),
            ],
            64,
        )?,
        400,
    );
    support::assert_status(
        harness.http(
            ListenerRole::LokiPush,
            "POST",
            "/loki/api/v1/push",
            &[
                ("Authorization", bearer.as_str()),
                ("Content-Type", "application/json"),
            ],
            br#"{"streams":[]}"#,
        )?,
        204,
    );
    Ok(())
}

#[test]
fn invalid_label_sets_fail_without_storage_and_valid_follow_up_succeeds()
-> Result<(), Box<dyn Error>> {
    let harness = support::LiveLokiHarness::start("il")?;
    let bearer = format!("Bearer {}", harness.bearer());
    let headers = [
        ("Authorization", bearer.as_str()),
        ("Content-Type", "application/json"),
    ];

    for body in [
        br#"{"streams":[{"stream":{},"values":[["1","empty-labels"]]}]}"#.as_slice(),
        br#"{"streams":[{"stream":{"dup":"one","dup":"two"},"values":[["2","duplicate-label"]]}]}"#
            .as_slice(),
        br#"{"streams":[{"stream":{"1bad":"value"},"values":[["3","invalid-name"]]}]}"#.as_slice(),
        br#"{"streams":[{"stream":{"a":"one","\u0061":"two"},"values":[["3","semantic-duplicate"]]}]}"#.as_slice(),
        br#"{"streams":[{"stream":{"app":"api"},"values":[["3","metadata-duplicate",{"m":"one","\u006d":"two"}]]}]}"#.as_slice(),
        br#"{"streams":[{"stream":{"\uD800":"value"},"values":[["3","bad-surrogate"]]}]}"#.as_slice(),
    ] {
        support::assert_status(
            harness.http(
                ListenerRole::LokiPush,
                "POST",
                "/loki/api/v1/push",
                &headers,
                body,
            )?,
            400,
        );
    }
    let protobuf_headers = [
        ("Authorization", bearer.as_str()),
        ("Content-Type", "application/x-protobuf"),
        ("Content-Encoding", "snappy"),
    ];
    for labels in [
        r#"{app="bad\z"}"#,
        r#"{app=""}"#,
        r#"{app="\xAF"}"#,
        "\x0b{app=\"api\"}",
    ] {
        support::assert_status(
            harness.http(
                ListenerRole::LokiPush,
                "POST",
                "/loki/api/v1/push",
                &protobuf_headers,
                &producer::snappy_push_with_labels("invalid-protobuf", labels)?,
            )?,
            400,
        );
    }
    let query = "logs | range query_time 0 2000000000 | limit 16";
    assert!(harness.query_log_bodies(query)?.is_empty());

    support::assert_status(
        single_record_follow_up(|| {
            harness.http(
                ListenerRole::LokiPush,
                "POST",
                "/loki/api/v1/push",
                &headers,
                br#"{"streams":[{"stream":{"a\u0070p":"api"},"values":[["4","follow-up"]]}]}"#,
            )
        })?,
        204,
    );
    support::assert_status(
        single_record_follow_up(|| {
            harness.http(
                ListenerRole::LokiPush,
                "POST",
                "/loki/api/v1/push",
                &protobuf_headers,
                &producer::snappy_push_with_labels(
                    "protobuf-follow-up",
                    r#"{app="",env="\x70\x72\x6f\x64"}"#,
                )?,
            )
        })?,
        204,
    );
    assert_eq!(
        harness.query_log_bodies(query)?,
        vec!["follow-up", "protobuf-follow-up"]
    );
    Ok(())
}

const SINGLE_RECORD_CAPACITY_REPLY: &str = "HTTP/1.1 429 Too Many Requests\r\nContent-Type: application/json\r\nContent-Length: 69\r\nRetry-After: 1\r\nConnection: close\r\n\r\n{\"status\":\"error\",\"error\":\"Loki Push ingest capacity is unavailable\"}";

fn single_record_follow_up(
    mut submit: impl FnMut() -> Result<String, Box<dyn Error>>,
) -> Result<String, Box<dyn Error>> {
    let response = submit()?;
    if response == SINGLE_RECORD_CAPACITY_REPLY {
        submit()
    } else {
        Ok(response)
    }
}

#[test]
fn single_record_follow_up_retries_only_exact_capacity_refusal() -> Result<(), Box<dyn Error>> {
    let success = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n";
    for (first, second, expected_calls) in [
        (
            SINGLE_RECORD_CAPACITY_REPLY.to_owned(),
            success.to_owned(),
            2,
        ),
        (
            SINGLE_RECORD_CAPACITY_REPLY.to_owned(),
            SINGLE_RECORD_CAPACITY_REPLY.to_owned(),
            2,
        ),
        (
            "HTTP/1.1 503 Service Unavailable\r\n\r\n".to_owned(),
            success.to_owned(),
            1,
        ),
        (
            SINGLE_RECORD_CAPACITY_REPLY.replace("Retry-After: 1\r\n", ""),
            success.to_owned(),
            1,
        ),
        (
            SINGLE_RECORD_CAPACITY_REPLY
                .replace("capacity is unavailable", "commit outcome is ambiguous"),
            success.to_owned(),
            1,
        ),
    ] {
        let mut replies = std::collections::VecDeque::from([first.clone(), second.clone()]);
        let mut calls = 0;
        let response = single_record_follow_up(|| {
            calls += 1;
            replies
                .pop_front()
                .ok_or_else(|| "fixed submission bound exceeded".into())
        })?;
        assert_eq!(calls, expected_calls);
        assert_eq!(response, if expected_calls == 2 { second } else { first });
    }
    Ok(())
}
