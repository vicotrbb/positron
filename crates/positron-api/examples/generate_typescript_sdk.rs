//! Generate the npm SDK from the canonical Public Interface descriptor and mappings.
use serde_json::{Value, json};
use std::{error::Error, fmt::Write, fs, path::Path};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn schema_type(schema: &Value) -> Result<String> {
    if schema["nullable"] == true {
        let mut schema = schema.clone();
        schema.as_object_mut().ok_or("schema")?.remove("nullable");
        return Ok(format!("{} | null", schema_type(&schema)?));
    }
    if let Some(value) = schema.get("const") {
        return Ok(value.to_string());
    }
    if let Some(reference) = schema["$ref"].as_str() {
        return Ok(reference
            .rsplit('/')
            .next()
            .ok_or("schema reference")?
            .into());
    }
    for combinator in ["oneOf", "anyOf"] {
        if let Some(variants) = schema[combinator].as_array() {
            return Ok(variants
                .iter()
                .map(schema_type)
                .collect::<Result<Vec<_>>>()?
                .join(" | "));
        }
    }
    if let Some(values) = schema["enum"].as_array() {
        return Ok(values
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join(" | "));
    }
    if let Some(kinds) = schema["type"].as_array() {
        return Ok(kinds
            .iter()
            .map(|kind| {
                let mut variant = schema.clone();
                variant["type"] = kind.clone();
                schema_type(&variant)
            })
            .collect::<Result<Vec<_>>>()?
            .join(" | "));
    }
    match schema["type"].as_str() {
        Some("integer")
            if matches!(
                schema["format"].as_str(),
                Some("uint64-json" | "int64-json")
            ) =>
        {
            Ok("number | bigint".into())
        },
        Some("integer" | "number") => Ok("number".into()),
        Some("string") => Ok("string".into()),
        Some("boolean") => Ok("boolean".into()),
        Some("null") => Ok("null".into()),
        Some("array") => Ok(format!("ReadonlyArray<{}>", schema_type(&schema["items"])?)),
        Some("object") => {
            let Some(properties) = schema["properties"].as_object() else {
                return Ok("Readonly<Record<string, unknown>>".into());
            };
            let mut fields = String::from("{ ");
            for (name, field) in properties {
                let required = schema["required"]
                    .as_array()
                    .is_some_and(|fields| fields.iter().any(|field| field == name));
                write!(
                    fields,
                    "readonly {name}{}: {}; ",
                    if required { "" } else { "?" },
                    schema_type(field)?
                )?;
            }
            fields.push('}');
            Ok(fields)
        },
        None if schema.as_object().is_some_and(serde_json::Map::is_empty) => {
            Ok("Readonly<Record<string, never>>".into())
        },
        _ => Err(format!("unsupported schema {schema}").into()),
    }
}
fn main() -> Result<()> {
    let owner = Path::new(env!("CARGO_MANIFEST_DIR"));
    let root = owner
        .parent()
        .and_then(Path::parent)
        .ok_or("repository root")?;
    let output = std::env::args_os()
        .nth(1)
        .ok_or("usage: generate_typescript_sdk OUTPUT")?;
    let output = Path::new(&output);
    fs::create_dir_all(output.join("src"))?;
    fs::create_dir_all(output.join("api"))?;
    fs::create_dir_all(output.join("examples"))?;
    fs::copy(
        owner.join("typescript/example.ts"),
        output.join("examples/query.ts"),
    )?;
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
    let mut types = String::from("// Generated by positron-api; do not edit.\n");
    for (name, schema) in openapi["components"]["schemas"]
        .as_object()
        .ok_or("schemas")?
    {
        let mut schema = schema.clone();
        let mut groups = std::collections::BTreeMap::<u64, Vec<(String, Value)>>::new();
        if name.starts_with("LogQuery") {
            for field in descriptor["messages"][name]
                .as_array()
                .into_iter()
                .flatten()
            {
                if let (Some(group), Some(key)) =
                    (field["oneof"].as_u64(), field["json_name"].as_str())
                {
                    if let Some(property) = schema["properties"]
                        .as_object_mut()
                        .and_then(|properties| properties.remove(key))
                    {
                        groups
                            .entry(group)
                            .or_default()
                            .push((key.to_owned(), property));
                    }
                }
            }
        }
        let mut shape = schema_type(&schema)?;
        for choices in groups.values() {
            let mut variants = Vec::new();
            for (selected, value) in choices {
                let mut variant = format!("{{ readonly {selected}: {}; ", schema_type(value)?);
                for (other, _) in choices {
                    if other != selected {
                        write!(variant, "readonly {other}?: never; ")?;
                    }
                }
                variant.push('}');
                variants.push(variant);
            }
            write!(shape, " & ({})", variants.join(" | "))?;
        }
        writeln!(types, "export type {name} = {shape};")?;
    }
    types.push_str("export type WireTypes = {\n");
    for name in openapi["components"]["schemas"]
        .as_object()
        .ok_or("schemas")?
        .keys()
    {
        writeln!(types, "readonly {name}: {name};")?;
    }
    types.push_str("};\n");
    let routes = http["mappings"].as_array().ok_or("routes")?;
    let mut methods = String::new();
    for route in routes {
        let rpc = route["rpc"].as_str().ok_or("rpc")?;
        let (service, method) = rpc
            .strip_prefix("positron.v1.")
            .and_then(|rpc| rpc.split_once('/'))
            .ok_or("rpc identity")?;
        let name = format!(
            "{}{}",
            service.strip_suffix("Service").ok_or("service")?,
            method
        );
        let mut chars = name.chars();
        let name = format!(
            "{}{}",
            chars.next().ok_or("method name")?.to_ascii_lowercase(),
            chars.as_str()
        );
        let input = route["request"].as_str().ok_or("input")?;
        let response = route["response"].as_str().ok_or("response")?;
        writeln!(
            methods,
            "  async {name}(request: types.{input}, options: CallOptions = {{}}): Promise<types.{response}> {{ return this.call({rpc:?}, request, options) as Promise<types.{response}>; }}"
        )?;
    }
    let source = fs::read_to_string(owner.join("typescript/client.ts"))?
        .replace("/* GENERATED_METHODS */", &methods);
    fs::write(output.join("src/client.ts"), source)?;
    fs::write(output.join("src/types.ts"), types)?;
    fs::copy(
        owner.join("typescript/codec.ts"),
        output.join("src/codec.ts"),
    )?;
    fs::copy(
        owner.join("typescript/errors.ts"),
        output.join("src/errors.ts"),
    )?;
    fs::copy(
        owner.join("typescript/query.ts"),
        output.join("src/query.ts"),
    )?;
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
    fs::write(
        output.join("src/contract.ts"),
        format!(
            "// Generated canonical metadata; do not edit.\nexport const apiVersion = 'positron.v1';\nexport const schemaDigest = {digest:?};\nexport const schemas = {} as const;\nexport const descriptor = {descriptor} as const;\nexport const routes = {} as const;\nexport const queryErrors = {} as const;\n",
            openapi["components"]["schemas"],
            http["mappings"],
            serde_json::to_string(&errors)?
        ),
    )?;
    fs::write(
        output.join("src/index.ts"),
        "export * from './types.js';\nexport * from './client.js';\nexport {encode,decode,WireError} from './codec.js';\nexport {BatchTracker,decodeQuery,terminalStatus} from './query.js';\nexport type {QueryMode,TerminalStatus} from './query.js';\nexport * from './errors.js';\nexport {apiVersion, schemaDigest} from './contract.js';\n",
    )?;
    let manifest = json!({
        "name":"@positron/sdk", "version":env!("CARGO_PKG_VERSION"), "type":"module", "description":"Generated typed client for the Positron v1 public API", "license":env!("CARGO_PKG_LICENSE"), "engines":{"node":">=22"},
        "exports":{".":{"types":"./dist/index.d.ts", "import":"./dist/index.js"}},
        "types":"./dist/index.d.ts", "files":["dist", "api", "examples", "LICENSE", "README.md"],
        "scripts":{"build":"tsc -p tsconfig.json"}, "devDependencies":{"typescript":"5.9.3", "@types/node":"24.10.1"},
        "publishConfig":{"registry":"https://registry.npmjs.org", "access":"public", "provenance":true},
        "positron":{"api_version":"positron.v1", "schema_digest":digest, "release_manifest_surface":"SdkTypeScript", "registry":"https://registry.npmjs.org", "generator":"positron-api=1,typescript=5.9.3,protoc-bin-vendored=3.2.0"}
    });
    fs::write(
        output.join("package.json"),
        format!("{}\n", serde_json::to_string_pretty(&manifest)?),
    )?;
    let mut lock: Value =
        serde_json::from_slice(&fs::read(owner.join("typescript/package-lock.json"))?)?;
    lock["version"] = json!(env!("CARGO_PKG_VERSION"));
    lock["packages"][""]["version"] = json!(env!("CARGO_PKG_VERSION"));
    lock["packages"][""]["license"] = json!(env!("CARGO_PKG_LICENSE"));
    fs::write(
        output.join("package-lock.json"),
        format!("{}\n", serde_json::to_string_pretty(&lock)?),
    )?;
    fs::write(output.join(".gitignore"), "node_modules/\n*.tgz\n")?;
    fs::write(
        output.join("tsconfig.json"),
        "{\"compilerOptions\":{\"target\":\"ES2022\",\"module\":\"NodeNext\",\"moduleResolution\":\"NodeNext\",\"strict\":true,\"noUncheckedIndexedAccess\":true,\"exactOptionalPropertyTypes\":true,\"declaration\":true,\"outDir\":\"dist\"},\"include\":[\"src/**/*.ts\"]}\n",
    )?;
    for name in [
        "positron.proto",
        "schema.sha256",
        "http.json",
        "openapi.json",
        "query-golden-fixtures.json",
        "query-error-fixtures.json",
        "validation-fixtures.json",
    ] {
        fs::copy(
            root.join("api/positron/v1").join(name),
            output.join("api").join(name),
        )?;
    }
    fs::copy(root.join("LICENSE"), output.join("LICENSE"))?;
    fs::copy(root.join("sdk/typescript.md"), output.join("README.md"))?;
    Ok(())
}
