//! Canonical access selectors become native adapter inputs before credential I/O.
use positron_config::{
    AzureManagedIdentitySelector, ProtectedFileReference, ProviderAccess, ProviderAuthentication,
};
use positron_kernel::key_provider::{
    AzureManagedIdentityId, AzureWorkloadIdentity, CredentialFileReference, KeyProviderFailure,
    NativeAzureAuthentication, NativeRootConfiguration, ProviderCredentialModel, ProviderFamily,
    ProviderKeyUri, TransitAuthentication,
};

pub fn native_root_configuration(
    access: &ProviderAccess,
) -> Result<NativeRootConfiguration, KeyProviderFailure> {
    let identity = |family| ProviderKeyUri::new(family, access.uri(), access.version());
    let azure = |authentication| {
        if let Ok(identity) = identity(ProviderFamily::AzureKeyVault) {
            Ok(NativeRootConfiguration::AzureKeyVault {
                identity,
                authentication,
            })
        } else {
            Ok(NativeRootConfiguration::AzureManagedHsm {
                identity: identity(ProviderFamily::AzureManagedHsm)?,
                authentication,
            })
        }
    };
    match access.authentication() {
        ProviderAuthentication::AwsStandardChain => Ok(NativeRootConfiguration::Aws(identity(
            ProviderFamily::AwsKms,
        )?)),
        ProviderAuthentication::GoogleApplicationDefault => Ok(NativeRootConfiguration::Google(
            identity(ProviderFamily::GoogleCloudKms)?,
        )),
        ProviderAuthentication::AzureManagedIdentity { selector } => {
            azure(NativeAzureAuthentication::ManagedIdentity(
                selector.as_ref().map(|selector| match selector {
                    AzureManagedIdentitySelector::ClientId(value) => {
                        AzureManagedIdentityId::ClientId(value.clone())
                    },
                    AzureManagedIdentitySelector::ObjectId(value) => {
                        AzureManagedIdentityId::ObjectId(value.clone())
                    },
                    AzureManagedIdentitySelector::ResourceId(value) => {
                        AzureManagedIdentityId::ResourceId(value.clone())
                    },
                }),
            ))
        },
        ProviderAuthentication::AzureWorkloadIdentity {
            tenant_id,
            client_id,
            token_file,
        } => azure(NativeAzureAuthentication::WorkloadIdentity(
            AzureWorkloadIdentity {
                tenant_id: tenant_id.clone(),
                client_id: client_id.clone(),
                token_file: optional_file(token_file)?,
            },
        )),
        ProviderAuthentication::KmipMutualTls {
            certificate,
            private_key,
            trust_roots,
        } => Ok(NativeRootConfiguration::Kmip {
            identity: identity(ProviderFamily::Kmip21)?,
            credentials: ProviderCredentialModel::KmipMutualTls {
                certificate: file(certificate)?,
                private_key: file(private_key)?,
                trust_roots: file(trust_roots)?,
            },
        }),
        ProviderAuthentication::VaultToken {
            token_file,
            trust_roots,
        } => transit(
            identity(ProviderFamily::VaultTransit)?,
            TransitAuthentication::ProtectedTokenFile(file(token_file)?),
            "",
            trust_roots,
        ),
        ProviderAuthentication::OpenBaoToken {
            token_file,
            trust_roots,
        } => transit(
            identity(ProviderFamily::OpenBaoTransit)?,
            TransitAuthentication::ProtectedTokenFile(file(token_file)?),
            "",
            trust_roots,
        ),
        ProviderAuthentication::VaultKubernetes {
            role,
            jwt_file,
            mount,
            trust_roots,
        } => transit(
            identity(ProviderFamily::VaultTransit)?,
            TransitAuthentication::Kubernetes {
                role: role.clone(),
                jwt_file: file(jwt_file)?,
            },
            mount,
            trust_roots,
        ),
        ProviderAuthentication::OpenBaoKubernetes {
            role,
            jwt_file,
            mount,
            trust_roots,
        } => transit(
            identity(ProviderFamily::OpenBaoTransit)?,
            TransitAuthentication::Kubernetes {
                role: role.clone(),
                jwt_file: file(jwt_file)?,
            },
            mount,
            trust_roots,
        ),
        ProviderAuthentication::VaultJwt {
            role,
            jwt_file,
            mount,
            trust_roots,
        } => transit(
            identity(ProviderFamily::VaultTransit)?,
            TransitAuthentication::Jwt {
                role: role.clone(),
                jwt_file: file(jwt_file)?,
            },
            mount,
            trust_roots,
        ),
        ProviderAuthentication::OpenBaoJwt {
            role,
            jwt_file,
            mount,
            trust_roots,
        } => transit(
            identity(ProviderFamily::OpenBaoTransit)?,
            TransitAuthentication::Jwt {
                role: role.clone(),
                jwt_file: file(jwt_file)?,
            },
            mount,
            trust_roots,
        ),
    }
}
fn file(reference: &ProtectedFileReference) -> Result<CredentialFileReference, KeyProviderFailure> {
    CredentialFileReference::new(reference.as_path())
}
fn optional_file(
    reference: &Option<ProtectedFileReference>,
) -> Result<Option<CredentialFileReference>, KeyProviderFailure> {
    reference.as_ref().map(file).transpose()
}
fn transit(
    identity: ProviderKeyUri,
    authentication: TransitAuthentication,
    mount: &str,
    trust_roots: &Option<ProtectedFileReference>,
) -> Result<NativeRootConfiguration, KeyProviderFailure> {
    let trust_roots = optional_file(trust_roots)?;
    match identity.family() {
        ProviderFamily::VaultTransit => Ok(NativeRootConfiguration::Vault {
            identity,
            authentication,
            mount: mount.to_owned(),
            trust_roots,
        }),
        ProviderFamily::OpenBaoTransit => Ok(NativeRootConfiguration::OpenBao {
            identity,
            authentication,
            mount: mount.to_owned(),
            trust_roots,
        }),
        _ => Err(KeyProviderFailure::InvalidConfiguration),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn access(
        document: &str,
    ) -> Result<positron_config::EffectiveConfiguration, Box<dyn std::error::Error>> {
        Ok(positron_config::resolve(
            positron_config::ConfigurationInputs::try_new(
                Some(document),
                positron_config::EnvironmentOverrides::try_from_pairs([] as [(&str, &str); 0])?,
                positron_config::CommandLineOverrides::try_from_pairs([] as [(&str, &str); 0])?,
            )?,
        )?)
    }
    #[test]
    fn canonical_access_constructs_every_native_authentication_selector_without_credentials_io()
    -> Result<(), Box<dyn std::error::Error>> {
        let azure = "https://fixture.vault.azure.net/keys/root/0123456789abcdef0123456789abcdef";
        let mut cases = vec![
            (
                "aws-standard-chain",
                "arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
                "immutable",
                "",
                ProviderFamily::AwsKms,
            ),
            (
                "google-application-default",
                "projects/project-1/locations/us-central1/keyRings/ring/cryptoKeys/root/cryptoKeyVersions/7",
                "7",
                "",
                ProviderFamily::GoogleCloudKms,
            ),
            (
                "azure-managed-identity",
                azure,
                "0123456789abcdef0123456789abcdef",
                "",
                ProviderFamily::AzureKeyVault,
            ),
            (
                "azure-workload-identity",
                azure,
                "0123456789abcdef0123456789abcdef",
                "tenant_id = 'tenant'\nclient_id = 'client'\ntoken_file = '/protected/token'\n",
                ProviderFamily::AzureKeyVault,
            ),
            (
                "azure-managed-identity",
                "https://fixture.managedhsm.azure.net/keys/root/0123456789abcdef0123456789abcdef",
                "0123456789abcdef0123456789abcdef",
                "",
                ProviderFamily::AzureManagedHsm,
            ),
            (
                "kmip-mtls",
                "kmip://localhost:5696/objects/immutable-id",
                "sha256:0606060606060606060606060606060606060606060606060606060606060606",
                "certificate_file = '/protected/client'\nprivate_key_file = '/protected/key'\ntrust_roots_file = '/protected/ca'\n",
                ProviderFamily::Kmip21,
            ),
        ];
        for (mode, family) in [
            ("vault-token", ProviderFamily::VaultTransit),
            ("openbao-token", ProviderFamily::OpenBaoTransit),
        ] {
            cases.push((
                mode,
                "https://transit.example:8200/v1/transit/keys/root",
                "1",
                "token_file = '/protected/token'\n",
                family,
            ));
        }
        for (mode, family) in [
            ("vault-kubernetes", ProviderFamily::VaultTransit),
            ("openbao-kubernetes", ProviderFamily::OpenBaoTransit),
            ("vault-jwt", ProviderFamily::VaultTransit),
            ("openbao-jwt", ProviderFamily::OpenBaoTransit),
        ] {
            cases.push((mode, "https://transit.example:8200/v1/transit/keys/root", "1", "mount = 'auth/team.jwt'\nrole = 'positron'\njwt_file = '/protected/jwt'\ntrust_roots_file = '/protected/ca'\n", family));
        }
        for (mode, uri, version, fields, family) in cases {
            let document = format!(
                "schema_version = 1\n[security.provider_access]\nuri = '{uri}'\nversion = '{version}'\nauthentication = '{mode}'\n{fields}"
            );
            let effective = access(&document)?;
            let configured =
                native_root_configuration(effective.provider_access().ok_or("native access")?)?;
            assert_eq!(configured.identity().family(), family);
            assert_eq!(configured.identity().locator(), uri);
            assert_eq!(configured.identity().version(), version);
        }
        for (field, expected) in [("client_id", 0), ("object_id", 1), ("resource_id", 2)] {
            let effective = access(&format!(
                "schema_version = 1\n[security.provider_access]\nuri = '{azure}'\nversion = '0123456789abcdef0123456789abcdef'\nauthentication = 'azure-managed-identity'\n{field} = 'selector'\n"
            ))?;
            let NativeRootConfiguration::AzureKeyVault {
                authentication: NativeAzureAuthentication::ManagedIdentity(Some(selector)),
                ..
            } = native_root_configuration(effective.provider_access().ok_or("native access")?)?
            else {
                return Err("managed identity selector unavailable".into());
            };
            assert!(
                matches!((expected, selector), (0, AzureManagedIdentityId::ClientId(value)) | (1, AzureManagedIdentityId::ObjectId(value)) | (2, AzureManagedIdentityId::ResourceId(value)) if value == "selector")
            );
        }
        Ok(())
    }
}
