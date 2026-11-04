mod log_query;
pub(crate) use log_query::configure as configure_log_query;
mod emission;
mod operations;
mod validation;

use std::error::Error;
use std::path::Path;

pub(crate) fn generate_clients(descriptor: &Path, mapping: &str) -> Result<(), Box<dyn Error>> {
    let operations = validation::ValidatedOperations::load(descriptor, Path::new(mapping))?;
    emission::generate_all(&operations)
}

/// Derive deprecation metadata from the same descriptor as the wire enums.
pub(crate) fn generate_enum_metadata(
    descriptor: &prost_types::FileDescriptorSet,
) -> Result<(), Box<dyn Error>> {
    use std::fmt::Write;
    let mut output = String::new();
    for file in &descriptor.file {
        if file.package.as_deref() != Some("positron.v1") {
            continue;
        }
        for enumeration in &file.enum_type {
            let name = enumeration.name.as_deref().ok_or("unnamed public enum")?;
            let deprecated: Vec<_> = enumeration
                .value
                .iter()
                .filter(|value| {
                    value
                        .options
                        .as_ref()
                        .is_some_and(|options| options.deprecated == Some(true))
                })
                .filter_map(|value| value.number)
                .collect();
            let expression = if deprecated.is_empty() {
                "false".to_owned()
            } else {
                format!(
                    "matches!(self as i32, {})",
                    deprecated
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(" | ")
                )
            };
            writeln!(
                &mut output,
                "impl {name} {{ #[must_use] pub const fn is_deprecated(self) -> bool {{ {expression} }} }}"
            )?;
        }
    }
    let output_path = std::path::PathBuf::from(std::env::var("OUT_DIR")?).join("enum_metadata.rs");
    std::fs::write(output_path, output)?;
    let mut enums = std::collections::BTreeMap::new();
    let mut messages = std::collections::BTreeMap::new();
    for file in &descriptor.file {
        if file.package.as_deref() != Some("positron.v1") {
            continue;
        }
        for enumeration in &file.enum_type {
            let name = enumeration.name.as_ref().ok_or("unnamed public enum")?;
            let values = enumeration.value.iter().map(|value| serde_json::json!({
                "name": value.name, "number": value.number,
                "deprecated": value.options.as_ref().is_some_and(|options| options.deprecated == Some(true)),
            })).collect::<Vec<_>>();
            enums.insert(name, values);
        }
        for message in &file.message_type {
            let name = message.name.as_ref().ok_or("unnamed public message")?;
            let fields = message.field.iter().map(|field| serde_json::json!({
                "name": field.name, "json_name": field.json_name, "number": field.number,
                "type": field.r#type, "type_name": field.type_name, "repeated": field.label == Some(3),
                "optional": field.proto3_optional == Some(true) || field.oneof_index.is_some(),
                "oneof": field.oneof_index.filter(|_| field.proto3_optional != Some(true)),
                "deprecated": field.options.as_ref().is_some_and(|options| options.deprecated == Some(true)),
            })).collect::<Vec<_>>();
            messages.insert(name, fields);
        }
    }
    std::fs::write(
        std::path::PathBuf::from(std::env::var("OUT_DIR")?).join("canonical_metadata.json"),
        serde_json::to_vec(&serde_json::json!({ "enums": enums, "messages": messages }))?,
    )?;
    Ok(())
}
