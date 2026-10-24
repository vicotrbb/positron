use super::listener_profile_failures::assert_profile_refusal;
use super::*;

#[test]
fn invalid_operator_values_name_the_exact_public_setting() -> Result<(), Box<dyn std::error::Error>>
{
    let root = temporary_root()?;
    let document = root.join("operator-safety.toml");
    for (profile, source, code) in [
        (
            "[diagnostics]\nlog_level = \"operator-document-canary\"\n",
            "diagnostics.log_level",
            "unsupported_value",
        ),
        (
            "[runtime]\nshutdown_grace_seconds = 0\n",
            "runtime.shutdown_grace_seconds",
            "unsupported_value",
        ),
        (
            "[runtime]\nmax_registered_tenants = 0\n",
            "runtime.max_registered_tenants",
            "unsupported_value",
        ),
        (
            "[listener]\ncontrol_path = \"/profile-reference-canary/../control.sock\"\n",
            "listener.control_path",
            "unsafe_combination",
        ),
        (
            "[listener]\nadmission_rate_per_second = 0\n",
            "listener.admission_rate_per_second",
            "unsupported_value",
        ),
        (
            "[listener]\nper_address_admission_rate_per_second = 0\n",
            "listener.per_address_admission_rate_per_second",
            "unsupported_value",
        ),
        (
            "[listener]\notlp_grpc_max_message_bytes = 0\n",
            "listener.otlp_grpc_max_message_bytes",
            "unsupported_value",
        ),
        (
            "[listener.api]\ncors_allowed_origins = [\"https://example.test/path\"]\n",
            "listener.api.cors_allowed_origins",
            "unsupported_value",
        ),
        (
            "[security]\nkey_cache_lease_seconds = 3601\n",
            "security.key_cache_lease_seconds",
            "unsupported_value",
        ),
        (
            "[security]\nlocal_key_file = \"/profile-reference-canary/../key\"\n",
            "security.local_key_file",
            "unsafe_combination",
        ),
        (
            "[storage]\ndata_directory = \"/profile-reference-canary/../data\"\n",
            "storage.data_directory",
            "unsafe_combination",
        ),
        (
            "[storage]\nsecrets_directory = \"/profile-reference-canary/../secrets\"\n",
            "storage.secrets_directory",
            "unsafe_combination",
        ),
    ] {
        assert_profile_refusal(&document, profile, source, code)?;
    }
    for role in ["operations", "api", "otlp_grpc", "otlp_http", "loki_push"] {
        assert_profile_refusal(
            &document,
            &format!("[listener]\n{role}_transport = \"operator-document-canary\"\n"),
            &format!("listener.{role}_transport"),
            "unsupported_value",
        )?;
    }
    Ok(())
}

#[test]
fn individually_valid_operator_settings_reject_unsafe_combinations()
-> Result<(), Box<dyn std::error::Error>> {
    let root = temporary_root()?;
    let document = root.join("operator-combinations.toml");
    for (profile, source) in [
        (
            "[diagnostics]\ntrace_otlp_grpc_address = \"127.0.0.1:4317\"\n",
            "diagnostics.trace_otlp_grpc_address",
        ),
        (
            "[storage]\ndata_directory = \"/shared-root\"\nsecrets_directory = \"/shared-root\"\n",
            "storage.data_directory",
        ),
        (
            "[listener.api]\ntrusted_proxy_cidrs = [\"127.0.0.1/32\"]\n",
            "listener.api.trusted_proxy_cidrs",
        ),
        (
            "[listener.api]\nforwarded_hops = 1\n",
            "listener.api.forwarded_hops",
        ),
    ] {
        assert_profile_refusal(&document, profile, source, "unsafe_combination")?;
    }
    Ok(())
}
