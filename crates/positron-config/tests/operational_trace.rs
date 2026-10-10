use positron_config::{CommandLineOverrides, ConfigurationInputs, EnvironmentOverrides, resolve};

#[test]
fn explicit_trace_destination_is_disabled_by_default_and_rejects_self_export()
-> Result<(), Box<dyn std::error::Error>> {
    fn parse(
        document: &str,
    ) -> Result<positron_config::EffectiveConfiguration, Box<dyn std::error::Error>> {
        Ok(resolve(ConfigurationInputs::try_new(
            Some(document),
            EnvironmentOverrides::try_from_pairs([] as [(&str, &str); 0])?,
            CommandLineOverrides::try_from_pairs([] as [(&str, &str); 0])?,
        )?)?)
    }
    assert!(
        parse("schema_version=1")?
            .operational_trace_address()
            .is_none()
    );
    assert_eq!(
        parse("schema_version=1\n[diagnostics]\ntrace_otlp_grpc_address=\"127.0.0.1:14317\"")?
            .operational_trace_address(),
        Some("127.0.0.1:14317".parse()?)
    );
    assert_eq!(
        parse("schema_version=1\n[diagnostics]\ntrace_otlp_grpc_address=\"192.0.2.10:4317\"")?
            .operational_trace_address(),
        Some("192.0.2.10:4317".parse()?)
    );
    for address in [
        "127.0.0.1:4317",
        "[::ffff:127.0.0.1]:4317",
        "0.0.0.0:14317",
        "127.0.0.1:0",
        "canary-secret.invalid:14317",
    ] {
        assert!(
            parse(&format!(
                "schema_version=1\n[diagnostics]\ntrace_otlp_grpc_address=\"{address}\""
            ))
            .is_err()
        );
    }
    Ok(())
}

#[test]
fn self_destination_guard_handles_loopback_aliases_mapped_addresses_and_wildcards()
-> Result<(), Box<dyn std::error::Error>> {
    for (destination, listener, conflict) in [
        ("127.0.0.1:4317", "127.0.0.2:4317", true),
        ("[::ffff:127.0.0.1]:4317", "127.0.0.1:4317", true),
        ("127.0.0.1:4317", "[::]:4317", true),
        ("127.0.0.1:4317", "0.0.0.0:4317", true),
        ("192.0.2.10:4317", "127.0.0.1:4317", false),
        ("192.0.2.10:4317", "192.0.2.11:4317", false),
        ("127.0.0.1:4317", "127.0.0.1:4318", false),
        ("127.0.0.1:4317", "127.0.0.1:0", false),
    ] {
        assert_eq!(
            positron_config::operational_trace_conflicts(destination.parse()?, listener.parse()?),
            conflict,
            "{destination} vs {listener}"
        );
    }
    Ok(())
}
