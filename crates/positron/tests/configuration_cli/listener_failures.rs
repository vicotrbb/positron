use super::*;

#[test]
fn invalid_listener_protection_names_the_exact_operator_setting_without_echoing_document()
-> Result<(), Box<dyn std::error::Error>> {
    let root = temporary_root()?;
    let document_path = root.join("listener.toml");
    for role in ["operations", "api", "otlp_grpc", "otlp_http", "loki_push"] {
        for field in [
            "accepted_socket_limit",
            "per_address_accepted_socket_limit",
            "tls_handshake_limit",
            "tls_handshake_deadline_seconds",
            "header_deadline_seconds",
            "body_deadline_seconds",
            "request_deadline_seconds",
            "idle_deadline_seconds",
        ] {
            let setting = format!("listener.{role}_{field}");
            std::fs::write(
                &document_path,
                format!(
                    "# operator-document-canary-must-not-echo\nschema_version = 1\n[listener]\n{role}_{field} = 0\n"
                ),
            )?;
            let rejected = run(["config", "validate", "--config", path(&document_path)?]);
            let error = stderr(&rejected)?;
            assert!(
                !error.contains("operator-document-canary"),
                "diagnostic echoed input document"
            );
            assert!(
                !stdout(&rejected)?.contains("operator-document-canary"),
                "stdout echoed input document"
            );
            assert!(
                !rejected.status.success(),
                "invalid setting must be refused"
            );
            assert!(
                rejected.stdout.is_empty(),
                "rejection must not publish a successful result"
            );
            assert_eq!(
                error,
                format!(
                    "positron: configuration_rejected code=unsupported_value retry=after_input_correction completion=rejected source={setting}\n"
                )
            );
        }
    }
    Ok(())
}
