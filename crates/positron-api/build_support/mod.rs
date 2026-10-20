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
