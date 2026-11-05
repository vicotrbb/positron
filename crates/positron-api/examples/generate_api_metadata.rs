//! Synchronize derived API metadata from the pinned Protobuf descriptor.
use serde_json::{Value, json};
use std::{error::Error, fs, path::Path};

fn field_schema(field: &Value) -> Result<Value, Box<dyn Error>> {
    let kind = field["type"].as_u64().ok_or("field type")?;
    let mut schema = match kind {
        3 | 16 | 18 => json!({"type":"string", "pattern":"^-?[0-9]+$", "format":"int64"}),
        4 | 6 => json!({"type":"string", "pattern":"^[0-9]+$", "format":"uint64"}),
        5 | 7 | 13 | 15 | 17 => json!({"type":"integer"}),
        8 => json!({"type":"boolean"}),
        9 => json!({"type":"string"}),
        12 => json!({"type":"string", "contentEncoding":"base64"}),
        11 | 14 => {
            let name = field["type_name"]
                .as_str()
                .and_then(|name| name.rsplit('.').next())
                .ok_or("field type name")?;
            json!({"$ref":format!("#/components/schemas/{name}")})
        },
        _ => return Err("unsupported public metadata field type".into()),
    };
    if field["repeated"] == true {
        schema = json!({"type":"array", "items":schema});
    }
    schema["x-protobuf-field-number"] = field["number"].clone();
    Ok(schema)
}
fn write(path: &Path, document: &Value) -> Result<(), Box<dyn Error>> {
    let mut bytes = serde_json::to_vec_pretty(document)?;
    bytes.push(b'\n');
    fs::write(path, bytes)?;
    Ok(())
}
fn main() -> Result<(), Box<dyn Error>> {
    let output = std::env::args_os()
        .nth(1)
        .ok_or("usage: generate_api_metadata API_DIRECTORY")?;
    let output = Path::new(&output);
    let metadata: Value = serde_json::from_str(include_str!(concat!(
        env!("OUT_DIR"),
        "/canonical_metadata.json"
    )))?;
    let digest = positron_api::generated::SchemaDigest::canonical().as_str();
    let mut http: Value = serde_json::from_slice(&fs::read(output.join("http.json"))?)?;
    let mut openapi: Value = serde_json::from_slice(&fs::read(output.join("openapi.json"))?)?;
    http["schema_digest"] = json!(digest);
    openapi["info"]["x-positron-schema-digest"] = json!(digest);
    for (name, values) in metadata["enums"].as_object().ok_or("enum metadata")? {
        http["enums"][name] = values.clone();
        let values = values.as_array().ok_or("enum values")?;
        let prefix = values
            .first()
            .and_then(|value| value["name"].as_str())
            .and_then(|name| name.rsplit_once('_'))
            .map(|(prefix, _)| format!("{prefix}_"))
            .ok_or("enum prefix")?;
        let names = values
            .iter()
            .map(|value| {
                value["name"]
                    .as_str()
                    .and_then(|name| name.strip_prefix(&prefix))
                    .ok_or("enum name")
            })
            .collect::<Result<Vec<_>, _>>()?;
        // The legacy API-key JSON adapters deliberately use named snake-case
        // enums. Preserve those mappings while deriving wire metadata.
        if openapi["components"]["schemas"][name]["type"] == "string" {
            continue;
        }
        let numbers = values
            .iter()
            .map(|value| &value["number"])
            .collect::<Vec<_>>();
        let deprecated = values
            .iter()
            .map(|value| &value["deprecated"])
            .collect::<Vec<_>>();
        let schema = if matches!(
            name.as_str(),
            "PublicErrorCode" | "RetryClass" | "CompletionState" | "FailureSource" | "SafeDetail"
        ) {
            json!({"oneOf":[{"type":"integer", "enum":numbers},{"type":"string", "enum":values.iter().map(|value| &value["name"]).collect::<Vec<_>>()}], "x-enumNames":names, "x-enumDeprecated":deprecated})
        } else {
            json!({"type":"integer", "enum":numbers,"x-enumNames": names,"x-enumDeprecated":deprecated})
        };
        openapi["components"]["schemas"][name] = schema;
    }
    for (name, fields) in metadata["messages"].as_object().ok_or("message metadata")? {
        if !name.starts_with("LogQuery") {
            continue;
        }
        let mut properties = serde_json::Map::new();
        for field in fields.as_array().ok_or("message fields")? {
            properties.insert(
                field["json_name"]
                    .as_str()
                    .ok_or("JSON field name")?
                    .to_owned(),
                field_schema(field)?,
            );
        }
        openapi["components"]["schemas"][name] =
            json!({"type":"object", "additionalProperties":false, "properties": properties});
    }
    for route in http["mappings"].as_array_mut().ok_or("HTTP routes")? {
        let request = route["request"].as_str().ok_or("route request")?;
        let canonical = metadata["messages"][request]
            .as_array()
            .ok_or("request field metadata")?;
        // Native administration routes retain their existing JSON field names.
        // Removed or reserved Protobuf fields cannot remain advertised.
        route["request_fields"]
            .as_array_mut()
            .ok_or("request fields")?
            .retain(|field| {
                canonical
                    .iter()
                    .any(|item| item["number"] == field["number"])
            });
        if !route["rpc"]
            .as_str()
            .is_some_and(|rpc| rpc.starts_with("positron.v1.LogQueryService/"))
        {
            continue;
        }
        for (message_key, fields_key) in [
            ("request", "request_fields"),
            ("response", "response_fields"),
        ] {
            let message = route[message_key].as_str().ok_or("route message")?;
            let fields = metadata["messages"][message]
                .as_array()
                .ok_or("route fields")?;
            let mut mapped = Vec::new();
            for field in fields {
                let name = field["type_name"]
                    .as_str()
                    .and_then(|name| name.rsplit('.').next());
                let kind = match field["type"].as_u64().ok_or("field type")? {
                    9 => "string",
                    12 => "bytes",
                    8 => "bool",
                    13 => "uint32",
                    11 | 14 => name.ok_or("type name")?,
                    _ => return Err("unsupported top-level route field".into()),
                };
                let mut value = json!({"proto":field["name"],"json":field["json_name"],"type":kind,"number":field["number"],"deprecated":field["deprecated"]});
                if field["optional"] == true {
                    value["optional"] = json!(true);
                }
                if field["repeated"] == true {
                    value["repeated"] = json!(true);
                }
                mapped.push(value);
            }
            route[fields_key] = json!(mapped);
        }
    }
    let fixture_text = fs::read_to_string(output.join("validation-fixtures.json"))?;
    let fixtures: Value = serde_json::from_str(&fixture_text)?;
    let old_digest = fixtures["schema_digest"]
        .as_str()
        .ok_or("fixture Schema Digest")?;
    fs::write(output.join("schema.sha256"), format!("{digest}\n"))?;
    write(&output.join("http.json"), &http)?;
    write(&output.join("openapi.json"), &openapi)?;
    fs::write(
        output.join("validation-fixtures.json"),
        fixture_text.replace(old_digest, digest),
    )?;
    Ok(())
}
