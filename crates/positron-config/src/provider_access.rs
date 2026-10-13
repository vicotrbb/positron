//! Closed native authentication selectors. Credential values have no representation.
use super::*;

#[derive(Clone, Eq, PartialEq)]
pub struct ProviderAccess {
    uri: String,
    version: String,
    authentication: ProviderAuthentication,
}

#[derive(Clone, Eq, PartialEq)]
pub enum ProviderAuthentication {
    AwsStandardChain,
    GoogleApplicationDefault,
    AzureManagedIdentity {
        selector: Option<AzureManagedIdentitySelector>,
    },
    AzureWorkloadIdentity {
        tenant_id: Option<String>,
        client_id: Option<String>,
        token_file: Option<ProtectedFileReference>,
    },
    VaultToken {
        token_file: ProtectedFileReference,
        trust_roots: Option<ProtectedFileReference>,
    },
    OpenBaoToken {
        token_file: ProtectedFileReference,
        trust_roots: Option<ProtectedFileReference>,
    },
    VaultKubernetes {
        role: String,
        jwt_file: ProtectedFileReference,
        mount: String,
        trust_roots: Option<ProtectedFileReference>,
    },
    OpenBaoKubernetes {
        role: String,
        jwt_file: ProtectedFileReference,
        mount: String,
        trust_roots: Option<ProtectedFileReference>,
    },
    VaultJwt {
        role: String,
        jwt_file: ProtectedFileReference,
        mount: String,
        trust_roots: Option<ProtectedFileReference>,
    },
    OpenBaoJwt {
        role: String,
        jwt_file: ProtectedFileReference,
        mount: String,
        trust_roots: Option<ProtectedFileReference>,
    },
    KmipMutualTls {
        certificate: ProtectedFileReference,
        private_key: ProtectedFileReference,
        trust_roots: ProtectedFileReference,
    },
}

#[derive(Clone, Eq, PartialEq)]
pub enum AzureManagedIdentitySelector {
    ClientId(String),
    ObjectId(String),
    ResourceId(String),
}

impl ProviderAccess {
    #[must_use]
    pub fn uri(&self) -> &str {
        &self.uri
    }
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }
    #[must_use]
    pub fn authentication(&self) -> &ProviderAuthentication {
        &self.authentication
    }
    // This feeds the existing semantic configuration digest, never diagnostics.
    pub(crate) fn identity_value(&self) -> String {
        let mut result = String::new();
        for value in [&self.uri, &self.version] {
            append(&mut result, value);
        }
        match &self.authentication {
            ProviderAuthentication::AwsStandardChain => append(&mut result, "aws-standard-chain"),
            ProviderAuthentication::GoogleApplicationDefault => {
                append(&mut result, "google-application-default")
            },
            ProviderAuthentication::AzureManagedIdentity { selector } => {
                append(&mut result, "azure-managed-identity");
                match selector {
                    None => append(&mut result, "system-assigned"),
                    Some(AzureManagedIdentitySelector::ClientId(value)) => {
                        append(&mut result, "client-id");
                        append(&mut result, value);
                    },
                    Some(AzureManagedIdentitySelector::ObjectId(value)) => {
                        append(&mut result, "object-id");
                        append(&mut result, value);
                    },
                    Some(AzureManagedIdentitySelector::ResourceId(value)) => {
                        append(&mut result, "resource-id");
                        append(&mut result, value);
                    },
                }
            },
            ProviderAuthentication::AzureWorkloadIdentity {
                tenant_id,
                client_id,
                token_file,
            } => {
                append(&mut result, "azure-workload-identity");
                for value in [
                    tenant_id.as_deref(),
                    client_id.as_deref(),
                    token_file.as_ref().map(|p| p.path.as_str()),
                ] {
                    append(&mut result, value.unwrap_or(""));
                }
            },
            ProviderAuthentication::KmipMutualTls {
                certificate,
                private_key,
                trust_roots,
            } => {
                append(&mut result, "kmip-mtls");
                for p in [certificate, private_key, trust_roots] {
                    append(&mut result, &p.path);
                }
            },
            ProviderAuthentication::VaultToken {
                token_file,
                trust_roots,
            }
            | ProviderAuthentication::OpenBaoToken {
                token_file,
                trust_roots,
            } => {
                append(
                    &mut result,
                    if matches!(
                        self.authentication,
                        ProviderAuthentication::VaultToken { .. }
                    ) {
                        "vault-token"
                    } else {
                        "openbao-token"
                    },
                );
                append(&mut result, &token_file.path);
                append(
                    &mut result,
                    trust_roots.as_ref().map_or("", |p| p.path.as_str()),
                );
            },
            ProviderAuthentication::VaultKubernetes {
                role,
                jwt_file,
                mount,
                trust_roots,
            }
            | ProviderAuthentication::OpenBaoKubernetes {
                role,
                jwt_file,
                mount,
                trust_roots,
            }
            | ProviderAuthentication::VaultJwt {
                role,
                jwt_file,
                mount,
                trust_roots,
            }
            | ProviderAuthentication::OpenBaoJwt {
                role,
                jwt_file,
                mount,
                trust_roots,
            } => {
                let mode = match self.authentication {
                    ProviderAuthentication::VaultKubernetes { .. } => "vault-kubernetes",
                    ProviderAuthentication::OpenBaoKubernetes { .. } => "openbao-kubernetes",
                    ProviderAuthentication::VaultJwt { .. } => "vault-jwt",
                    _ => "openbao-jwt",
                };
                for value in [
                    mode,
                    role,
                    &jwt_file.path,
                    mount,
                    trust_roots.as_ref().map_or("", |p| p.path.as_str()),
                ] {
                    append(&mut result, value);
                }
            },
        }
        result
    }
    pub(crate) fn parse(table: &toml::Table) -> Result<Self, ConfigurationFailure> {
        let uri = text(table, "uri", 512)?;
        let version = text(table, "version", 128)?;
        if uri.contains(['?', '#', '@']) || version.contains(['?', '#', '@']) {
            return Err(failure());
        }
        let mode = text(table, "authentication", 32)?;
        let mut allowed = vec!["uri", "version", "authentication"];
        let authentication = match mode.as_str() {
            "aws-standard-chain" if uri.starts_with("arn:") && version == "immutable" => {
                ProviderAuthentication::AwsStandardChain
            },
            "google-application-default" if uri.starts_with("projects/") => {
                ProviderAuthentication::GoogleApplicationDefault
            },
            "azure-managed-identity" if uri.starts_with("https://") => {
                allowed.extend(["client_id", "object_id", "resource_id"]);
                let client = optional_text(table, "client_id", 128)?;
                let object = optional_text(table, "object_id", 128)?;
                let resource = optional_text(table, "resource_id", 128)?;
                let selector = match (client, object, resource) {
                    (None, None, None) => None,
                    (Some(value), None, None) => {
                        Some(AzureManagedIdentitySelector::ClientId(value))
                    },
                    (None, Some(value), None) => {
                        Some(AzureManagedIdentitySelector::ObjectId(value))
                    },
                    (None, None, Some(value)) => {
                        Some(AzureManagedIdentitySelector::ResourceId(value))
                    },
                    _ => return Err(failure()),
                };
                ProviderAuthentication::AzureManagedIdentity { selector }
            },
            "azure-workload-identity" if uri.starts_with("https://") => {
                allowed.extend(["tenant_id", "client_id", "token_file"]);
                ProviderAuthentication::AzureWorkloadIdentity {
                    tenant_id: optional_text(table, "tenant_id", 128)?,
                    client_id: optional_text(table, "client_id", 128)?,
                    token_file: optional_path(table, "token_file")?,
                }
            },
            "kmip-mtls" if uri.starts_with("kmip://") => {
                allowed.extend(["certificate_file", "private_key_file", "trust_roots_file"]);
                ProviderAuthentication::KmipMutualTls {
                    certificate: path(table, "certificate_file")?,
                    private_key: path(table, "private_key_file")?,
                    trust_roots: path(table, "trust_roots_file")?,
                }
            },
            "vault-token" | "openbao-token" if uri.starts_with("https://") => {
                allowed.extend(["token_file", "trust_roots_file"]);
                let token_file = path(table, "token_file")?;
                let trust_roots = optional_path(table, "trust_roots_file")?;
                if mode == "vault-token" {
                    ProviderAuthentication::VaultToken {
                        token_file,
                        trust_roots,
                    }
                } else {
                    ProviderAuthentication::OpenBaoToken {
                        token_file,
                        trust_roots,
                    }
                }
            },
            "vault-kubernetes" | "openbao-kubernetes" | "vault-jwt" | "openbao-jwt"
                if uri.starts_with("https://") =>
            {
                allowed.extend(["role", "jwt_file", "mount", "trust_roots_file"]);
                let role = text(table, "role", 128)?;
                let jwt_file = path(table, "jwt_file")?;
                let mount = text(table, "mount", 128)?;
                let trust_roots = optional_path(table, "trust_roots_file")?;
                match mode.as_str() {
                    "vault-kubernetes" => ProviderAuthentication::VaultKubernetes {
                        role,
                        jwt_file,
                        mount,
                        trust_roots,
                    },
                    "openbao-kubernetes" => ProviderAuthentication::OpenBaoKubernetes {
                        role,
                        jwt_file,
                        mount,
                        trust_roots,
                    },
                    "vault-jwt" => ProviderAuthentication::VaultJwt {
                        role,
                        jwt_file,
                        mount,
                        trust_roots,
                    },
                    _ => ProviderAuthentication::OpenBaoJwt {
                        role,
                        jwt_file,
                        mount,
                        trust_roots,
                    },
                }
            },
            _ => return Err(failure()),
        };
        if table.keys().any(|key| !allowed.contains(&key.as_str())) {
            return Err(failure());
        }
        Ok(Self {
            uri,
            version,
            authentication,
        })
    }
}
fn append(output: &mut String, value: &str) {
    output.push_str(&value.len().to_string());
    output.push(':');
    output.push_str(value);
}
fn failure() -> ConfigurationFailure {
    ConfigurationFailure::unsupported_value(FailureSource::SecurityProviderAccess)
}
fn text(table: &toml::Table, name: &str, limit: usize) -> Result<String, ConfigurationFailure> {
    let value = table
        .get(name)
        .and_then(toml::Value::as_str)
        .ok_or_else(failure)?;
    if value.is_empty() || value.len() > limit || !value.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(failure());
    }
    Ok(value.to_owned())
}
fn optional_text(
    table: &toml::Table,
    name: &str,
    limit: usize,
) -> Result<Option<String>, ConfigurationFailure> {
    table
        .get(name)
        .map(|_| text(table, name, limit))
        .transpose()
}
fn path(table: &toml::Table, name: &str) -> Result<ProtectedFileReference, ConfigurationFailure> {
    let value = table
        .get(name)
        .and_then(toml::Value::as_str)
        .ok_or_else(failure)?;
    // The existing protected path validator is reused; table selectors are not secrets.
    ProtectedFileReference::parse(value, Setting::SecurityProviderAccess)
}
fn optional_path(
    table: &toml::Table,
    name: &str,
) -> Result<Option<ProtectedFileReference>, ConfigurationFailure> {
    table.get(name).map(|_| path(table, name)).transpose()
}

pub(crate) fn schema(uri: usize, version: usize, path: usize) -> String {
    let variants: &[(&str, &[&str], &[&str])] = &[
        ("aws-standard-chain", &[], &[]),
        ("google-application-default", &[], &[]),
        ("azure-managed-identity", &[], &[]),
        ("azure-managed-identity", &["client_id"], &[]),
        ("azure-managed-identity", &["object_id"], &[]),
        ("azure-managed-identity", &["resource_id"], &[]),
        (
            "azure-workload-identity",
            &[],
            &["tenant_id", "client_id", "token_file"],
        ),
        (
            "kmip-mtls",
            &["certificate_file", "private_key_file", "trust_roots_file"],
            &[],
        ),
        ("vault-token", &["token_file"], &["trust_roots_file"]),
        ("openbao-token", &["token_file"], &["trust_roots_file"]),
        (
            "vault-kubernetes",
            &["role", "jwt_file", "mount"],
            &["trust_roots_file"],
        ),
        (
            "openbao-kubernetes",
            &["role", "jwt_file", "mount"],
            &["trust_roots_file"],
        ),
        (
            "vault-jwt",
            &["role", "jwt_file", "mount"],
            &["trust_roots_file"],
        ),
        (
            "openbao-jwt",
            &["role", "jwt_file", "mount"],
            &["trust_roots_file"],
        ),
    ];
    let mut result = String::from("{\"type\": \"object\", \"writeOnly\": true, \"oneOf\": [");
    for (index, (mode, required, optional)) in variants.iter().enumerate() {
        if index != 0 {
            result.push_str(", ");
        }
        result.push_str("{\"additionalProperties\": false, \"required\": [\"uri\", \"version\", \"authentication\"");
        for field in *required {
            result.push_str(&format!(", \"{field}\""));
        }
        result.push_str(&format!("], \"properties\": {{\"uri\": {{\"type\": \"string\", \"minLength\": 1, \"maxLength\": {uri}}}, \"version\": {{\"type\": \"string\", \"minLength\": 1, \"maxLength\": {version}}}, \"authentication\": {{\"const\": \"{mode}\"}}"));
        for field in required.iter().chain(optional.iter()) {
            let maximum = if field.ends_with("_file") { path } else { 128 };
            let protected = if field.ends_with("_file") {
                ", \"writeOnly\": true, \"x-positron-path-kind\": \"protected-absolute\""
            } else {
                ""
            };
            result.push_str(&format!(", \"{field}\": {{\"type\": \"string\", \"minLength\": 1, \"maxLength\": {maximum}{protected}}}"));
        }
        result.push_str("}}");
    }
    result.push_str("]}");
    result
}
