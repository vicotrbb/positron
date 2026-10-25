//! Operator-owned references used by Upgrade and Release Trust.
use super::{
    ConfigurationFailure, ConfigurationFailureCode, FailureSource, ProtectedFileReference, Setting,
};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ExecutableDistribution {
    #[default]
    Native,
    Nix,
}

#[derive(Clone, Eq, PartialEq)]
pub struct InstalledReleaseConfiguration {
    executable_distribution: ExecutableDistribution,
    project_trust_root_file: ProtectedFileReference,
    current_manifest_file: ProtectedFileReference,
    current_inventory_file: Option<ProtectedFileReference>,
    candidate_manifest_file: Option<ProtectedFileReference>,
    candidate_artifact_files: Vec<ProtectedFileReference>,
    query_credential_file: Option<ProtectedFileReference>,
}
impl InstalledReleaseConfiguration {
    pub const fn executable_distribution(&self) -> ExecutableDistribution {
        self.executable_distribution
    }
    pub fn project_trust_root_file(&self) -> &ProtectedFileReference {
        &self.project_trust_root_file
    }
    pub fn current_manifest_file(&self) -> &ProtectedFileReference {
        &self.current_manifest_file
    }
    pub fn current_inventory_file(&self) -> Option<&ProtectedFileReference> {
        self.current_inventory_file.as_ref()
    }
    pub fn candidate_manifest_file(&self) -> Option<&ProtectedFileReference> {
        self.candidate_manifest_file.as_ref()
    }
    pub fn candidate_artifact_files(&self) -> &[ProtectedFileReference] {
        &self.candidate_artifact_files
    }
    pub fn query_credential_file(&self) -> Option<&ProtectedFileReference> {
        self.query_credential_file.as_ref()
    }
    pub(crate) fn parse(
        table: &toml::map::Map<String, toml::Value>,
    ) -> Result<Self, ConfigurationFailure> {
        let invalid = || {
            ConfigurationFailure::new(
                ConfigurationFailureCode::UnsupportedValue,
                FailureSource::ConfigurationDocument,
            )
        };
        if table.keys().any(|key| {
            !matches!(
                key.as_str(),
                "project_trust_root_file"
                    | "executable_distribution"
                    | "current_manifest_file"
                    | "current_inventory_file"
                    | "candidate_manifest_file"
                    | "candidate_artifact_files"
                    | "query_credential_file"
            )
        }) {
            return Err(invalid());
        }
        let path = |key: &str| -> Result<Option<ProtectedFileReference>, ConfigurationFailure> {
            table
                .get(key)
                .map(|value| {
                    value.as_str().ok_or_else(invalid).and_then(|value| {
                        ProtectedFileReference::parse(value, Setting::ReleaseInstallation)
                    })
                })
                .transpose()
        };
        let project_trust_root_file = path("project_trust_root_file")?.ok_or_else(invalid)?;
        let executable_distribution = match table.get("executable_distribution") {
            None => ExecutableDistribution::Native,
            Some(value) => match value.as_str() {
                Some("native") => ExecutableDistribution::Native,
                Some("nix") => ExecutableDistribution::Nix,
                _ => return Err(invalid()),
            },
        };
        let current_manifest_file = path("current_manifest_file")?.ok_or_else(invalid)?;
        let current_inventory_file = path("current_inventory_file")?;
        let candidate_manifest_file = path("candidate_manifest_file")?;
        let query_credential_file = path("query_credential_file")?;
        let mut candidate_artifact_files = Vec::new();
        if let Some(value) = table.get("candidate_artifact_files") {
            let files = value.as_array().ok_or_else(invalid)?;
            let super::ValueDomain::ReleaseInstallation(maximum, _) =
                super::setting_definition(Setting::ReleaseInstallation).domain()
            else {
                return Err(invalid());
            };
            if files.len() > maximum {
                return Err(invalid());
            }
            for file in files {
                let file = ProtectedFileReference::parse(
                    file.as_str().ok_or_else(invalid)?,
                    Setting::ReleaseInstallation,
                )?;
                candidate_artifact_files.push(file);
            }
        }
        if candidate_manifest_file.is_some() == candidate_artifact_files.is_empty() {
            return Err(invalid());
        }
        Ok(Self {
            executable_distribution,
            project_trust_root_file,
            current_manifest_file,
            current_inventory_file,
            candidate_manifest_file,
            candidate_artifact_files,
            query_credential_file,
        })
    }
    pub(crate) fn identity_value(&self) -> String {
        let path = |value: Option<&ProtectedFileReference>| {
            value.map_or_else(
                || "disabled".to_owned(),
                |value| super::render_toml_basic_string(&value.path),
            )
        };
        let files = self
            .candidate_artifact_files
            .iter()
            .map(|value| super::render_toml_basic_string(&value.path))
            .collect::<Vec<_>>()
            .join(",");
        let mut identity = format!(
            "root={};current={};inventory={};candidate={};query={};files=[{}]",
            path(Some(&self.project_trust_root_file)),
            path(Some(&self.current_manifest_file)),
            path(self.current_inventory_file.as_ref()),
            path(self.candidate_manifest_file.as_ref()),
            path(self.query_credential_file.as_ref()),
            files
        );
        if self.executable_distribution == ExecutableDistribution::Nix {
            identity.push_str(";executable_distribution=nix");
        }
        identity
    }
}
impl std::fmt::Debug for InstalledReleaseConfiguration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("InstalledReleaseConfiguration { <protected references> }")
    }
}
pub(crate) fn schema(maximum: usize, path: usize) -> String {
    let file = format!(
        "{{\"type\":\"string\",\"maxLength\":{path},\"pattern\":\"^/\",\"x-positron-protected-file-reference\":true}}"
    );
    format!(
        "{{\"type\":\"object\",\"additionalProperties\":false,\"writeOnly\":true,\"required\":[\"project_trust_root_file\",\"current_manifest_file\"],\"properties\":{{\"executable_distribution\":{{\"type\":\"string\",\"enum\":[\"native\",\"nix\"],\"default\":\"native\"}},\"project_trust_root_file\":{file},\"current_manifest_file\":{file},\"current_inventory_file\":{file},\"candidate_manifest_file\":{file},\"query_credential_file\":{file},\"candidate_artifact_files\":{{\"type\":\"array\",\"maxItems\":{maximum},\"items\":{file}}}}}}}"
    )
}
