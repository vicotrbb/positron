//! Public protobuf enum names are stable schema spellings, not Rust variant names.
use positron_api::api_keys::protobuf::*;

#[test]
fn canonical_enum_names_and_numbers_remain_compatible() {
    macro_rules! names {
        ($kind:ty, $prefix:literal, [$($number:literal => $suffix:literal),+ $(,)?]) => {{
            $(
                let value = <$kind>::try_from($number).expect("declared protobuf discriminant");
                let name = concat!($prefix, $suffix);
                assert_eq!(value.as_str_name(), name);
                assert_eq!(<$kind>::from_str_name(name), Some(value));
                assert_eq!(value as i32, $number);
                assert_eq!(<$kind>::from_str_name(&name.to_ascii_lowercase()), None);
            )+
            assert!(<$kind>::try_from(-1).is_err());
            assert!(<$kind>::try_from(i32::MAX).is_err());
            assert_eq!(<$kind>::from_str_name("UNKNOWN_FUTURE_VARIANT"), None);
        }};
    }
    // Only these five schema enums use standard ProtoJSON. Other public
    // enums deliberately have different serde adapters or no JSON adapter.
    macro_rules! protojson_names {
        ($kind:ty, $prefix:literal, [$($number:literal => $suffix:literal),+ $(,)?]) => {{
            names!($kind, $prefix, [$($number => $suffix),+]);
            $(
                let value = <$kind>::try_from($number).expect("declared enum");
                let name = concat!($prefix, $suffix);
                assert_eq!(serde_json::to_value(value).expect("enum JSON"), serde_json::json!(name));
                assert_eq!(serde_json::from_value::<$kind>(serde_json::json!(name)).expect("enum name"), value);
                assert_eq!(serde_json::from_value::<$kind>(serde_json::json!($number)).expect("enum number"), value);
            )+
            for invalid in [serde_json::json!(-1), serde_json::json!(i32::MAX), serde_json::json!(1.5), serde_json::json!("UNKNOWN_FUTURE_VARIANT")] {
                assert!(serde_json::from_value::<$kind>(invalid).is_err());
            }
        }};
    }
    names!(TenantLifecycleTarget, "TENANT_LIFECYCLE_TARGET_", [0=>"UNSPECIFIED",1=>"ACTIVE",2=>"READ_ONLY",3=>"SUSPENDED",4=>"PURGING",5=>"PURGED"]);
    names!(RetentionReclamation, "RETENTION_RECLAMATION_", [0=>"NONE",1=>"AT",2=>"BLOCKED_BY_DURABLE_LEASE",3=>"BLOCKED_BY_IN_PROCESS_SNAPSHOT"]);
    names!(KeyAction, "KEY_ACTION_", [0=>"UNSPECIFIED",1=>"CREATE",2=>"LIST",3=>"ROTATE",4=>"REVOKE",5=>"SCOPE_INSPECT"]);
    names!(KeyScope, "KEY_SCOPE_", [0=>"UNSPECIFIED",1=>"INGEST",2=>"QUERY",3=>"TENANT_ADMINISTRATION",4=>"SYSTEM_ADMINISTRATION"]);
    names!(Capability, "CAPABILITY_", [0=>"UNSPECIFIED",1=>"CANONICAL_PUBLIC_INTERFACE",2=>"RELEASE_ONE_QUERY",3=>"METRICS"]);
    names!(CapabilityAvailability, "CAPABILITY_AVAILABILITY_", [0=>"UNSPECIFIED",1=>"IMPLEMENTED",2=>"UNAVAILABLE",3=>"UNSUPPORTED",4=>"VERSION_INCOMPATIBLE"]);
    protojson_names!(RetryClass, "RETRY_CLASS_", [0=>"UNSPECIFIED",1=>"NEVER",2=>"AFTER_BACKOFF",3=>"AFTER_INPUT_CORRECTION"]);
    protojson_names!(CompletionState, "COMPLETION_STATE_", [0=>"UNSPECIFIED",1=>"REJECTED"]);
    names!(DeprecationState, "DEPRECATION_STATE_", [0=>"UNSPECIFIED",1=>"CURRENT",2=>"DEPRECATED"]);
    protojson_names!(PublicErrorCode, "PUBLIC_ERROR_CODE_", [0=>"UNSPECIFIED",1=>"UNSUPPORTED_API_VERSION",2=>"CAPABILITY_UNAVAILABLE",3=>"CAPABILITY_UNSUPPORTED",4=>"MALFORMED_REQUEST",5=>"REQUEST_TOO_LARGE",6=>"UNKNOWN_FIELD",7=>"AUTHENTICATION_REJECTED",8=>"CAPACITY_UNAVAILABLE",9=>"QUERY_UNAVAILABLE"]);
    protojson_names!(FailureSource, "FAILURE_SOURCE_", [0=>"UNSPECIFIED",1=>"CAPABILITY_NEGOTIATION",2=>"GRPC_DECODE",3=>"HTTP_DECODE",4=>"QUERY_EXECUTION"]);
    protojson_names!(SafeDetail, "SAFE_DETAIL_", [0=>"UNSPECIFIED",1=>"API_MAJOR_UNSUPPORTED",2=>"CAPABILITY_NOT_AVAILABLE",3=>"CAPABILITY_NOT_SUPPORTED",4=>"REQUEST_MALFORMED",5=>"REQUEST_LIMIT_EXCEEDED",6=>"FIELD_NOT_RECOGNIZED",7=>"AUTHENTICATION_REJECTED",8=>"CAPACITY_UNAVAILABLE",9=>"QUERY_UNAVAILABLE"]);
    names!(UpgradePhase, "UPGRADE_PHASE_", [0=>"UNSPECIFIED",1=>"PREFLIGHT",2=>"DRAINING",3=>"SNAPSHOT",4=>"PUBLISHING",5=>"AWAITING_RESTART",6=>"VERIFYING",7=>"SUCCEEDED"]);
}
