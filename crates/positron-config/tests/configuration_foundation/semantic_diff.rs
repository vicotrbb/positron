#[test]
fn semantic_diff_renders_complete_changed_listener_profiles_without_unchanged_settings()
-> Result<(), ConfigurationFailure> {
    let defaults = inputs(None, [], []).and_then(resolve)?;
    for role in ["operations", "api", "otlp_grpc", "otlp_http", "loki_push"] {
        let fields = [
            ("transport", "tls", "plaintext", "\"plaintext\""),
            ("accepted_socket_limit", "128", "96", "96"),
            ("per_address_accepted_socket_limit", "16", "12", "12"),
            ("tls_handshake_limit", "16", "8", "8"),
            ("tls_handshake_deadline_seconds", "2", "3", "3"),
            ("header_deadline_seconds", "2", "4", "4"),
            ("body_deadline_seconds", "2", "5", "5"),
            ("request_deadline_seconds", "30", "45", "45"),
            ("idle_deadline_seconds", "30", "60", "60"),
        ];
        let mut document = String::from("schema_version = 1\n[listener]\n");
        for (field, _, _, value) in fields {
            document.push_str(&format!("{role}_{field} = {value}\n"));
        }
        for field in ["tls_certificate_file", "tls_private_key_file", "tls_client_ca_file"] {
            document.push_str(&format!("{role}_{field} = \"/fixture/secret-canary-{role}-{field}\"\n"));
        }
        let candidate = inputs(Some(&document), [], []).and_then(resolve)?;
        let diff = defaults.semantic_diff(&candidate);
        assert_eq!(diff.changes().len(), fields.len() + 3, "{role}");
        for field in ["tls_certificate_file", "tls_private_key_file", "tls_client_ca_file"] {
            let path = format!("listener.{role}_{field}");
            let change = diff.changes().iter().find(|change| change.setting().path() == path)
                .expect("changed protected reference");
            assert_eq!((change.before(), change.after()), ("<redacted>", "<redacted>"));
        }
        assert!(!format!("{diff:?}").contains("secret-canary"));
        assert_eq!(diff.plan(), positron_config::ConfigurationDiffPlan::DrainThenPublish);
        for (field, before, after, _) in fields {
            let path = format!("listener.{role}_{field}");
            let change = diff.changes().iter().find(|change| change.setting().path() == path)
                .expect("every changed listener setting is rendered");
            assert_eq!((change.before(), change.after()), (before, after), "{path}");
            assert_eq!(change.before_source(), Some(SettingSource::CompiledDefault));
            assert_eq!(change.after_source(), Some(SettingSource::ConfigurationFile));
        }
        assert!(!diff.changes().iter().any(|change| change.setting().path() == "storage.data_directory"));
        assert!(candidate.semantic_diff(&candidate).changes().is_empty());
    }
    Ok(())
}

#[test]
fn semantic_diff_renders_coupled_proxy_trust_and_http2_values_exactly()
-> Result<(), ConfigurationFailure> {
    let defaults = inputs(None, [], []).and_then(resolve)?;
    for role in ["operations", "api", "otlp_grpc", "otlp_http", "loki_push"] {
        let document = format!("schema_version = 1\n[listener.{role}]\ntrusted_proxy_cidrs = [\"198.51.100.0/24\", \"2001:db8::/32\"]\nforwarded_hops = 2\n");
        let candidate = inputs(Some(&document), [], []).and_then(resolve)?;
        let diff = defaults.semantic_diff(&candidate);
        assert_eq!(diff.changes().len(), 2);
        for (field, before, after) in [
            ("trusted_proxy_cidrs", "", "198.51.100.0/24,2001:db8::/32"),
            ("forwarded_hops", "0", "2"),
        ] {
            let path = format!("listener.{role}.{field}");
            let change = diff.changes().iter().find(|change| change.setting().path() == path)
                .expect("coupled proxy policy change");
            assert_eq!((change.before(), change.after()), (before, after), "{path}");
        }
    }
    for (role, streams_before) in [("api", "1"), ("otlp_grpc", "16")] {
        let fields = [
            ("max_concurrent_streams", streams_before, "8"),
            ("initial_stream_window_bytes", "65535", "32768"),
            ("initial_connection_window_bytes", "65535", "131072"),
            ("max_frame_bytes", "16384", "32768"),
            ("max_header_list_bytes", "8192", "4096"),
            ("minimum_ping_interval_seconds", "5", "10"),
        ];
        let mut document = String::from("schema_version = 1\n[listener]\n");
        for (field, _, after) in fields {
            document.push_str(&format!("{role}_http2_{field} = {after}\n"));
        }
        let candidate = inputs(Some(&document), [], []).and_then(resolve)?;
        let diff = defaults.semantic_diff(&candidate);
        assert_eq!(diff.changes().len(), fields.len());
        for (field, before, after) in fields {
            let path = format!("listener.{role}_http2_{field}");
            let change = diff.changes().iter().find(|change| change.setting().path() == path)
                .expect("changed HTTP2 setting");
            assert_eq!((change.before(), change.after()), (before, after), "{path}");
        }
    }
    Ok(())
}
