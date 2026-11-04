//! Canonical language-neutral SDK metadata, owned by Public Interface.
use serde_json::{Value, json};
use std::{error::Error, fs, path::Path};
type Result<T> = std::result::Result<T, Box<dyn Error>>;
pub struct Contract {
    pub http: Value,
    pub openapi: Value,
    pub descriptor: Value,
    pub digest: String,
    pub errors: Value,
}
pub fn contract(root: &Path) -> Result<Contract> {
    let http: Value = serde_json::from_slice(&fs::read(root.join("api/positron/v1/http.json"))?)?;
    let mut openapi: Value =
        serde_json::from_slice(&fs::read(root.join("api/positron/v1/openapi.json"))?)?;
    let descriptor: Value = serde_json::from_str(include_str!(concat!(
        env!("OUT_DIR"),
        "/canonical_metadata.json"
    )))?;
    let digest = positron_api::generated::SchemaDigest::canonical().as_str();
    if http["schema_digest"] != digest || openapi["info"]["x-positron-schema-digest"] != digest {
        return Err("derived API metadata is stale; regenerate it first".into());
    }
    // The lifecycle JSON adapter predates the OpenAPI document. Derive its
    // public schema from the canonical route fields, retaining its named enums.
    for route in http["mappings"].as_array().ok_or("routes")? {
        for (message, fields) in [
            ("request", "request_fields"),
            ("response", "response_fields"),
        ] {
            let name = route[message].as_str().ok_or("message")?;
            if !openapi["components"]["schemas"][name].is_null() {
                continue;
            }
            let mut properties = serde_json::Map::new();
            for field in route[fields].as_array().ok_or("fields")? {
                let schema = match field["type"].as_str().ok_or("field type")? {
                    "string" => json!({"type":"string"}),
                    "uint64" => json!({"type":"integer", "minimum":0}),
                    "TenantLifecycleTarget" => {
                        json!({"type":"string", "enum":descriptor["enums"]["TenantLifecycleTarget"].as_array().ok_or("lifecycle enum")?.iter().filter_map(|value| value["name"].as_str()?.strip_prefix("TENANT_LIFECYCLE_TARGET_")).filter(|name| *name != "UNSPECIFIED").map(str::to_ascii_lowercase).collect::<Vec<_>>()})
                    },
                    _ => return Err("unmapped public JSON schema".into()),
                };
                properties.insert(field["json"].as_str().ok_or("JSON name")?.into(), schema);
            }
            let required = properties.keys().cloned().collect::<Vec<_>>();
            openapi["components"]["schemas"][name] = json!({"type":"object", "additionalProperties":false, "required":required, "properties":properties});
        }
    }
    // The canonical native capability response explicitly emits null for no refusal.
    openapi["components"]["schemas"]["CapabilityResponse"]["properties"]["refusal"]["nullable"] =
        json!(true);
    // Legacy administration adapters serialize lifecycle names, not enum numbers.
    let lifecycle = descriptor["enums"]["TenantLifecycleTarget"]
        .as_array()
        .ok_or("lifecycle enum")?
        .iter()
        .filter_map(|value| {
            value["name"]
                .as_str()?
                .strip_prefix("TENANT_LIFECYCLE_TARGET_")
        })
        .filter(|name| *name != "UNSPECIFIED")
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>();
    openapi["components"]["schemas"]["TenantLifecycleTarget"] =
        json!({"type":"string","enum":lifecycle});
    // Native administration JSON writes u64 as JSON numbers. Keep values above
    // JavaScript's safe integer range as bigint without changing their wire form.
    for (name, fields) in descriptor["messages"].as_object().ok_or("messages")? {
        for field in fields.as_array().ok_or("fields")? {
            if !matches!(field["type"].as_u64(), Some(3 | 4 | 6 | 16 | 18)) {
                continue;
            }
            let key = field["name"].as_str().ok_or("field name")?;
            let Some(schema) = openapi["components"]["schemas"]
                .get_mut(name)
                .and_then(|schema| schema.get_mut("properties"))
                .and_then(|fields| fields.get_mut(key))
            else {
                continue;
            };
            if schema["type"] == "integer" {
                schema["format"] = json!(if matches!(field["type"].as_u64(), Some(4 | 6)) {
                    "uint64-json"
                } else {
                    "int64-json"
                });
            }
        }
    }
    let mut errors = Vec::new();
    for value in descriptor["enums"]["PublicErrorCode"]
        .as_array()
        .ok_or("error codes")?
    {
        let name = value["name"]
            .as_str()
            .ok_or("error name")?
            .strip_prefix("PUBLIC_ERROR_CODE_")
            .ok_or("error prefix")?
            .to_ascii_lowercase();
        for status in [400, 401, 403, 409, 410, 413, 422, 429, 500, 503] {
            let rejection = if name == "malformed_request" {
                "invalid_request"
            } else {
                &name
            };
            if let Ok(bytes) = positron_api::log_query::query_rejection(status, rejection) {
                let error: Value = serde_json::from_slice(&bytes)?;
                let failure = if matches!(name.as_str(), "malformed_request" | "request_too_large")
                {
                    "InvalidRequest".into()
                } else {
                    name.split('_')
                        .map(|word| {
                            let mut chars = word.chars();
                            format!(
                                "{}{}",
                                chars
                                    .next()
                                    .map(|c| c.to_ascii_uppercase())
                                    .unwrap_or_default(),
                                chars.as_str()
                            )
                        })
                        .collect::<String>()
                };
                errors.push(json!({"status":status, "error":error, "failure":failure}));
            }
        }
    }
    Ok(Contract {
        http,
        openapi,
        descriptor,
        digest: digest.into(),
        errors: json!(errors),
    })
}
