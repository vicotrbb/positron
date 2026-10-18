use super::{ServiceFailure, api};
use positron_domain::value::{AttributeValueKind, MarkerAction, ValidatedAttributeValue};

pub(super) fn text(value: &str) -> Result<String, ServiceFailure> {
    let mut output = String::new();
    output
        .try_reserve_exact(value.len())
        .map_err(|_| ServiceFailure::CapacityUnavailable)?;
    output.push_str(value);
    Ok(output)
}
pub(super) fn native(
    value: &ValidatedAttributeValue,
    depth: u8,
) -> Result<api::LogQueryValue, ServiceFailure> {
    use api::log_query_value::Value;
    if depth > 32 {
        return Err(ServiceFailure::Internal);
    }
    let item = if let Some(action) = value.truncation_action() {
        Value::TruncatedValue(Box::new(api::LogQueryTruncated {
            action: action_name(action).into(),
            value: Some(Box::new(native(
                value.truncated_value().ok_or(ServiceFailure::Internal)?,
                depth + 1,
            )?)),
        }))
    } else {
        match value.kind() {
            AttributeValueKind::Null => Value::NullValue(api::LogQueryNull {}),
            AttributeValueKind::Boolean => {
                Value::BooleanValue(value.as_boolean().ok_or(ServiceFailure::Internal)?)
            },
            AttributeValueKind::SignedInteger => {
                Value::IntegerValue(value.as_signed_integer().ok_or(ServiceFailure::Internal)?)
            },
            AttributeValueKind::FloatingPoint => Value::FloatBits(
                value
                    .as_floating_point_bits()
                    .ok_or(ServiceFailure::Internal)?,
            ),
            AttributeValueKind::String => {
                Value::TextValue(text(value.as_str().ok_or(ServiceFailure::Internal)?)?)
            },
            AttributeValueKind::Bytes => {
                let bytes = value.as_bytes().ok_or(ServiceFailure::Internal)?;
                let mut output = Vec::new();
                output
                    .try_reserve_exact(bytes.len())
                    .map_err(|_| ServiceFailure::CapacityUnavailable)?;
                output.extend_from_slice(bytes);
                Value::BytesValue(output)
            },
            AttributeValueKind::Array => {
                let count = value.array_len().ok_or(ServiceFailure::Internal)?;
                let mut values = Vec::new();
                values
                    .try_reserve_exact(count)
                    .map_err(|_| ServiceFailure::CapacityUnavailable)?;
                for index in 0..count {
                    values.push(native(
                        value.array_entry(index).ok_or(ServiceFailure::Internal)?,
                        depth + 1,
                    )?);
                }
                Value::ArrayValue(api::LogQueryArray { values })
            },
            AttributeValueKind::KeyValueList => {
                let count = value.key_value_list_len().ok_or(ServiceFailure::Internal)?;
                let mut entries = Vec::new();
                entries
                    .try_reserve_exact(count)
                    .map_err(|_| ServiceFailure::CapacityUnavailable)?;
                for index in 0..count {
                    let entry = value
                        .key_value_entry(index)
                        .ok_or(ServiceFailure::Internal)?;
                    entries.push(api::LogQueryKeyValue {
                        key: text(entry.key())?,
                        value: Some(native(entry.value(), depth + 1)?),
                    });
                }
                Value::ObjectValue(api::LogQueryObject { entries })
            },
            AttributeValueKind::Marker => Value::MarkerValue(api::LogQueryMarker {
                action: action_name(value.marker_action().ok_or(ServiceFailure::Internal)?).into(),
                original_kind: kind_name(
                    value
                        .marker_original_kind()
                        .ok_or(ServiceFailure::Internal)?,
                )
                .into(),
            }),
        }
    };
    Ok(api::LogQueryValue { value: Some(item) })
}
pub(super) const fn kind_name(kind: AttributeValueKind) -> &'static str {
    match kind {
        AttributeValueKind::Null => "null",
        AttributeValueKind::Boolean => "boolean",
        AttributeValueKind::SignedInteger => "signed_integer",
        AttributeValueKind::FloatingPoint => "floating_point_bits",
        AttributeValueKind::String => "string",
        AttributeValueKind::Bytes => "bytes",
        AttributeValueKind::Array => "array",
        AttributeValueKind::KeyValueList => "key_value_list",
        AttributeValueKind::Marker => "marker",
    }
}
pub(super) const fn action_name(action: MarkerAction) -> &'static str {
    match action {
        MarkerAction::Removed => "removed",
        MarkerAction::Redacted => "redacted",
        MarkerAction::TruncatedBytes => "truncated_bytes",
        MarkerAction::TruncatedElements => "truncated_elements",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use positron_domain::value::{
        CandidateAttributeValue as C, CandidateKeyValue, ValueLimitProfile,
    };

    #[test]
    fn wire_values_preserve_native_types_float_payloads_duplicate_keys_and_markers() {
        let candidates = vec![
            C::null(),
            C::boolean(false),
            C::signed_integer(i64::MIN),
            C::floating_point_bits(0x7ff8_0000_0000_0001),
            C::string("42".into()),
            C::bytes(vec![0, 255]),
            C::array(vec![C::signed_integer(42), C::string("42".into())]),
            C::key_value_list(vec![
                CandidateKeyValue::new("same".into(), C::null()),
                CandidateKeyValue::new("same".into(), C::boolean(true)),
            ]),
            C::redaction_marker(AttributeValueKind::Bytes, MarkerAction::Redacted),
            C::redaction_marker(AttributeValueKind::String, MarkerAction::Removed),
            C::truncated(C::bytes(vec![1, 2]), MarkerAction::TruncatedBytes),
            C::truncated(C::array(vec![C::null()]), MarkerAction::TruncatedElements),
        ];
        let expected = vec![
            serde_json::json!({"nullValue":{}}),
            serde_json::json!({"booleanValue":false}),
            serde_json::json!({"integerValue":"-9223372036854775808"}),
            serde_json::json!({"floatBits":"9221120237041090561"}),
            serde_json::json!({"textValue":"42"}),
            serde_json::json!({"bytesValue":"AP8="}),
            serde_json::json!({"arrayValue":{"values":[{"integerValue":"42"},{"textValue":"42"}]}}),
            serde_json::json!({"objectValue":{"entries":[{"key":"same","value":{"nullValue":{}}},{"key":"same","value":{"booleanValue":true}}]}}),
            serde_json::json!({"markerValue":{"action":"redacted","originalKind":"bytes"}}),
            serde_json::json!({"markerValue":{"action":"removed","originalKind":"string"}}),
            serde_json::json!({"truncatedValue":{"action":"truncated_bytes","value":{"bytesValue":"AQI="}}}),
            serde_json::json!({"truncatedValue":{"action":"truncated_elements","value":{"arrayValue":{"values":[{"nullValue":{}}]}}}}),
        ];
        for (candidate, expected) in candidates.into_iter().zip(expected) {
            let value = candidate
                .validate_log_body(ValueLimitProfile::release_1_system_maximum())
                .expect("bounded value");
            let wire = native(&value, 0).expect("wire value");
            assert_eq!(serde_json::to_value(&wire).expect("ProtoJSON"), expected);
        }
    }
}
