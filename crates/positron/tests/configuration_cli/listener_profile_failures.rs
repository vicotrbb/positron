use super::*;

pub(super) fn assert_profile_refusal(
    document_path: &std::path::Path,
    document: &str,
    source: &str,
    code: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::write(
        document_path,
        format!("# operator-document-canary\nschema_version = 1\n{document}"),
    )?;
    let output = run(["config", "validate", "--config", path(document_path)?]);
    let error = stderr(&output)?;
    let success = stdout(&output)?;
    for canary in ["operator-document-canary", "profile-reference-canary"] {
        assert!(
            !error.contains(canary) && !success.contains(canary),
            "configuration diagnostic echoed protected input"
        );
    }
    assert!(
        !output.status.success(),
        "invalid operator profile must fail"
    );
    assert!(
        output.stdout.is_empty(),
        "rejection must not publish a result"
    );
    assert_eq!(
        error,
        format!(
            "positron: configuration_rejected code={code} retry=after_input_correction completion=rejected source={source}\n"
        )
    );
    Ok(())
}

#[test]
fn invalid_http2_fields_name_the_exact_operator_setting() -> Result<(), Box<dyn std::error::Error>>
{
    let root = temporary_root()?;
    let document = root.join("http2.toml");
    for role in ["api", "otlp_grpc"] {
        for field in [
            "max_concurrent_streams",
            "initial_stream_window_bytes",
            "initial_connection_window_bytes",
            "max_frame_bytes",
            "max_header_list_bytes",
            "minimum_ping_interval_seconds",
        ] {
            let setting = format!("{role}_http2_{field}");
            assert_profile_refusal(
                &document,
                &format!("[listener]\n{setting} = 0\n"),
                &format!("listener.{setting}"),
                "unsupported_value",
            )?;
        }
    }
    Ok(())
}

#[test]
fn malformed_listener_addresses_name_the_exact_operator_setting()
-> Result<(), Box<dyn std::error::Error>> {
    let root = temporary_root()?;
    let document = root.join("address.toml");
    for role in ["operations", "api", "otlp_grpc", "otlp_http", "loki_push"] {
        let setting = format!("{role}_bind_address");
        assert_profile_refusal(
            &document,
            &format!("[listener]\n{setting} = \"operator-document-canary\"\n"),
            &format!("listener.{setting}"),
            "malformed",
        )?;
    }
    Ok(())
}

#[test]
fn unsafe_tls_references_name_the_exact_operator_setting_without_echoing_paths()
-> Result<(), Box<dyn std::error::Error>> {
    let root = temporary_root()?;
    let document = root.join("tls.toml");
    for role in ["operations", "api", "otlp_grpc", "otlp_http", "loki_push"] {
        for invalid in ["certificate", "private_key", "client_ca"] {
            let mut profile = format!("[listener]\n{role}_transport = \"tls\"\n");
            for field in ["certificate", "private_key", "client_ca"] {
                let reference = if field == invalid {
                    "/profile-reference-canary/../private.pem"
                } else {
                    "/protected/fixture.pem"
                };
                profile.push_str(&format!("{role}_tls_{field}_file = \"{reference}\"\n"));
            }
            assert_profile_refusal(
                &document,
                &profile,
                &format!("listener.{role}_tls_{invalid}_file"),
                "unsafe_combination",
            )?;
        }
    }
    Ok(())
}

#[test]
fn invalid_proxy_trust_fields_name_the_exact_operator_setting()
-> Result<(), Box<dyn std::error::Error>> {
    let root = temporary_root()?;
    let document = root.join("proxy.toml");
    for role in ["operations", "api", "otlp_grpc", "otlp_http", "loki_push"] {
        assert_profile_refusal(
            &document,
            &format!(
                "[listener.{role}]\ntrusted_proxy_cidrs = [\"operator-document-canary\"]\nforwarded_hops = 1\n"
            ),
            &format!("listener.{role}.trusted_proxy_cidrs"),
            "unsupported_value",
        )?;
        assert_profile_refusal(
            &document,
            &format!(
                "[listener.{role}]\ntrusted_proxy_cidrs = [\"127.0.0.1/32\"]\nforwarded_hops = 256\n"
            ),
            &format!("listener.{role}.forwarded_hops"),
            "unsupported_value",
        )?;
    }
    Ok(())
}
