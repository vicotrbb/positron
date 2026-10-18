//! Generate standard ProtoJSON for the canonical Log Query messages.
use prost::Message;
use prost_types::FileDescriptorSet;
use std::error::Error;

pub(crate) fn configure(
    _config: &mut prost_build::Config,
    descriptor: &FileDescriptorSet,
) -> Result<(), Box<dyn Error>> {
    let mut paths: Vec<_> = descriptor
        .file
        .iter()
        .filter(|file| file.package.as_deref() == Some("positron.v1"))
        .flat_map(|file| &file.message_type)
        .filter_map(|message| message.name.as_deref())
        .filter(|name| name.starts_with("LogQuery"))
        .map(|name| format!(".positron.v1.{name}"))
        .collect();
    paths.extend(
        [
            "PublicError",
            "PublicErrorCode",
            "RetryClass",
            "CompletionState",
            "FailureSource",
            "SafeDetail",
        ]
        .into_iter()
        .map(|name| format!(".positron.v1.{name}")),
    );
    pbjson_build::Builder::new()
        .register_descriptors(&descriptor.encode_to_vec())?
        .build(&paths)?;
    Ok(())
}
