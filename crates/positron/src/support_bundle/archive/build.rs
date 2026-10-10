/// A standard ustar archive. Its manifest binds every admitted member and the
/// redaction report; the writer never receives raw unclassified input.
use super::*;

pub(crate) struct SupportBundle {
    archive: Vec<u8>,
    report: RedactionReport,
    count: usize,
}
impl SupportBundle {
    #[cfg(test)]
    pub(crate) fn build(
        input: impl IntoIterator<Item = BundleMember>,
        limits: BundleLimits,
    ) -> Result<Self, ()> {
        Self::build_with_export_policy(
            input,
            limits,
            false,
            "not_applied",
            "not_applied",
            IdentifierRetentionPolicy::from_requested(IdentifierRetention::Ephemeral),
            None,
        )
    }
    #[cfg(test)]
    pub(crate) fn build_for_explicit_plaintext(
        input: impl IntoIterator<Item = BundleMember>,
        limits: BundleLimits,
    ) -> Result<Self, ()> {
        Self::build_with_export_policy(
            input,
            limits,
            true,
            "plaintext_explicit",
            "not_applied",
            IdentifierRetentionPolicy::from_requested(IdentifierRetention::Ephemeral),
            None,
        )
    }
    #[cfg(test)]
    pub(crate) fn build_authenticated(
        input: impl IntoIterator<Item = BundleMember>,
        limits: BundleLimits,
        authentication: ManifestAuthentication<'_>,
    ) -> Result<Self, ()> {
        Self::build_authenticated_with_retention(
            input,
            limits,
            authentication,
            IdentifierRetention::Ephemeral,
        )
    }
    pub(crate) fn build_authenticated_with_retention(
        input: impl IntoIterator<Item = BundleMember>,
        limits: BundleLimits,
        authentication: ManifestAuthentication<'_>,
        identifier_retention: IdentifierRetention,
    ) -> Result<Self, ()> {
        Self::build_authenticated_with_retention_policy(
            input,
            limits,
            authentication,
            IdentifierRetentionPolicy::from_requested(identifier_retention),
        )
    }

    pub(crate) fn build_authenticated_with_retention_policy(
        input: impl IntoIterator<Item = BundleMember>,
        limits: BundleLimits,
        authentication: ManifestAuthentication<'_>,
        identifier_retention: IdentifierRetentionPolicy,
    ) -> Result<Self, ()> {
        match authentication {
            ManifestAuthentication::Signed(signer) => Self::build_with_export_policy(
                input,
                limits,
                false,
                "age_x25519",
                "signed",
                identifier_retention,
                Some(signer),
            ),
            ManifestAuthentication::UnsignedKeyUnavailableOffline => {
                Self::build_with_export_policy(
                    input,
                    limits,
                    false,
                    "age_x25519",
                    "unsigned_key_unavailable_offline",
                    identifier_retention,
                    None,
                )
            },
        }
    }
    pub(crate) fn build_authenticated_for_explicit_plaintext_with_retention(
        input: impl IntoIterator<Item = BundleMember>,
        limits: BundleLimits,
        authentication: ManifestAuthentication<'_>,
        identifier_retention: IdentifierRetention,
    ) -> Result<Self, ()> {
        match authentication {
            ManifestAuthentication::Signed(signer) => Self::build_with_export_policy(
                input,
                limits,
                true,
                "plaintext_explicit",
                "signed",
                IdentifierRetentionPolicy::from_requested(identifier_retention),
                Some(signer),
            ),
            ManifestAuthentication::UnsignedKeyUnavailableOffline => {
                Self::build_with_export_policy(
                    input,
                    limits,
                    true,
                    "plaintext_explicit",
                    "unsigned_key_unavailable_offline",
                    IdentifierRetentionPolicy::from_requested(identifier_retention),
                    None,
                )
            },
        }
    }
    fn build_with_export_policy(
        input: impl IntoIterator<Item = BundleMember>,
        limits: BundleLimits,
        plaintext_warning: bool,
        encryption_state: &'static str,
        signature_state: &'static str,
        identifier_retention: IdentifierRetentionPolicy,
        signer: Option<&positron_kernel::ExportManifestSigner>,
    ) -> Result<Self, ()> {
        // age 0.11.5 admits at most 16 native X25519 stanzas (99 bytes
        // each). Its header, bounded GREASE stanza and nonce use at most
        // 288 additional bytes; each 64 KiB payload chunk adds a 16-byte
        // authentication tag. Reserve the closed recipient-set maximum so
        // archive selection stays deterministic despite randomized framing.
        let archive_limit = if encryption_state == "age_x25519" {
            let tags = limits.bytes.div_ceil(65_536).max(1) * 16;
            limits.bytes.checked_sub(288 + 16 * 99 + tags).ok_or(())?
        } else {
            limits.bytes
        };
        let mut selected = Vec::new();
        selected.try_reserve_exact(limits.count).map_err(|_| ())?;
        let mut unknown = 0;
        let mut omissions = Vec::new();
        // Admit bounded content first, then account for the exact metadata
        // below. Content is removed in reverse admission order if necessary.
        let mut projected = FOOTER;
        for member in input {
            let Some(class) = member.class else {
                unknown += 1;
                continue;
            };
            for omission in member.omissions {
                once(&mut omissions, omission)?;
            }
            if selected.len() == limits.count {
                once(&mut omissions, "member_count_limit")?;
                continue;
            }
            let next = BLOCK + blocks(member.bytes.len());
            if projected.saturating_add(next) > archive_limit {
                once(&mut omissions, "archive_byte_limit")?;
                continue;
            };
            projected += next;
            selected.push((class, member.bytes));
        }
        if unknown != 0 {
            once(&mut omissions, "unknown_member_class")?;
        }
        let (report, redaction, manifest, signature) = loop {
            let included_classes = selected
                .iter()
                .map(|(class, _)| class.report_name())
                .collect::<Vec<_>>()
                .join(",");
            let omitted_classes = Class::ALL
                .into_iter()
                .filter(|class| {
                    !selected
                        .iter()
                        .any(|(included, _)| included.path() == class.path())
                })
                .map(Class::report_name)
                .collect::<Vec<_>>()
                .join(",");
            let report = RedactionReport {
                unknown,
                omissions,
                plaintext_warning,
            };
            let redaction = format!(
                "policy_version={POLICY}\nincluded_classes={included_classes}\nomitted_allowlisted_classes={omitted_classes}\nexcluded_classes=tenant_telemetry,query_results,api_key_secrets_and_hashes,tls_private_keys,encryption_key_material,local_root_key_files,recovery_bundles,provider_credentials,authorization_headers,secret_environment_values,kubernetes_secret_values,raw_memory,core_dumps\nidentifier_pseudonymization={}\nrequested_retained_identifier_classes={}\nretained_identifier_classes={}\nidentifier_retention_outcome={}\nmember_count_limit={}\narchive_byte_limit={}\noutput_byte_limit={}\nelapsed_time_limit_seconds={}\ninput_log_window_seconds={}\nsource_file_limit={}\nexcluded_unknown_members={}\nomissions={}\nencryption={encryption_state}\nplaintext_export_warning={}\nsignature={signature_state}\n",
                identifier_retention
                    .applied_retention()
                    .pseudonymization_value(),
                identifier_retention.requested().report_value(),
                identifier_retention.applied_retention().report_value(),
                identifier_retention.outcome(),
                limits.count,
                archive_limit,
                limits.bytes,
                limits.elapsed_limit.as_secs(),
                limits.log_window.as_secs(),
                limits.source_file_limit,
                report.unknown,
                report.omissions.join(","),
                plaintext_warning
            );
            let mut manifest = format!(
                "format=positron-support-bundle-tar-v1\nredaction_policy_version={POLICY}\narchive_byte_limit={}\noutput_byte_limit={}\nrequested_retained_identifier_classes={}\nretained_identifier_classes={}\nidentifier_retention_outcome={}\n",
                archive_limit,
                limits.bytes,
                identifier_retention.requested().report_value(),
                identifier_retention.applied_retention().report_value(),
                identifier_retention.outcome(),
            );
            for (class, bytes) in &selected {
                manifest.push_str(&format!(
                    "member={} bytes={} sha256={}\n",
                    class.path(),
                    bytes.len(),
                    hex(bytes)?
                ));
            }
            manifest.push_str(&format!(
                "redaction_report_sha256={}\n",
                hex(redaction.as_bytes())?
            ));
            let signature = signer
                .map(|signer| {
                    let signature = signer.sign(manifest.as_bytes()).map_err(|_| ())?;
                    Ok(format!(
                        "integrity_identity={}\nsignature={}\n",
                        encode_bytes(&signature.integrity_identity().public_key())?,
                        encode_bytes(&signature.bytes())?
                    ))
                })
                .transpose()?;
            let meta =
                (BLOCK + blocks(manifest.len())).saturating_add(BLOCK + blocks(redaction.len()));
            let meta = signature.as_ref().map_or(meta, |signature| {
                meta.saturating_add(BLOCK + blocks(signature.len()))
            });
            if projected.saturating_add(meta) > archive_limit {
                let (_, bytes) = selected.pop().ok_or(())?;
                projected = projected.saturating_sub(BLOCK + blocks(bytes.len()));
                omissions = report.omissions;
                once(&mut omissions, "archive_byte_limit")?;
                continue;
            }
            break (report, redaction, manifest, signature);
        };
        let mut archive = BoundedArchive::new(archive_limit);
        {
            let mut tar = tar::Builder::new(&mut archive);
            append(&mut tar, "manifest.txt", manifest.as_bytes()).map_err(|_| ())?;
            append(&mut tar, "redaction-report.txt", redaction.as_bytes()).map_err(|_| ())?;
            for (class, bytes) in &selected {
                append(&mut tar, class.path(), bytes).map_err(|_| ())?;
            }
            if let Some(signature) = &signature {
                append(&mut tar, "manifest-signature.txt", signature.as_bytes()).map_err(|_| ())?;
            }
            tar.finish().map_err(|_| ())?;
        }
        let archive = archive.into_bytes();
        (archive.len() <= archive_limit)
            .then_some(Self {
                archive,
                report,
                count: selected.len(),
            })
            .ok_or(())
    }
    pub(crate) const fn included_member_count(&self) -> usize {
        self.count
    }
    pub(crate) fn redaction_report(&self) -> &RedactionReport {
        &self.report
    }
    pub(crate) fn archive(&self) -> &[u8] {
        &self.archive
    }
    /// Verifies the archive that is actually handed to an operator.  The
    /// signature authenticates the canonical manifest; every data member is
    /// then checked against that manifest before it can be trusted.
    #[cfg(test)]
    pub(crate) fn verify_signed_archive(
        archive: &[u8],
        expected: positron_kernel::BootstrapIntegrityIdentity,
    ) -> Result<(), ()> {
        const MAX_ARCHIVE: usize = 1_048_576;
        if archive.len() > MAX_ARCHIVE {
            return Err(());
        }
        let mut entries = tar::Archive::new(archive);
        let mut manifest = None;
        let mut signature = None;
        let mut members = Vec::new();
        for entry in entries.entries().map_err(|_| ())? {
            let entry = entry.map_err(|_| ())?;
            let path = entry.path().map_err(|_| ())?.into_owned();
            let path = path.to_str().ok_or(())?;
            if !matches!(
                path,
                "manifest.txt"
                    | "manifest-signature.txt"
                    | "redaction-report.txt"
                    | "effective-configuration.txt"
                    | "compatibility-manifest.txt"
                    | "product-identity.txt"
                    | "health-state.txt"
                    | "operational-telemetry.txt"
                    | "operational-logs.txt"
                    | "catalog-summary.txt"
                    | "resource-status.txt"
                    | "maintenance-status.txt"
                    | "listener-status.txt"
                    | "backup-repository-status.txt"
                    | "environment.txt"
                    | "doctor-report.txt"
                    | "sanitized-crash-records.txt"
            ) {
                return Err(());
            }
            let mut bytes = Vec::new();
            use std::io::Read as _;
            entry.take(42_496).read_to_end(&mut bytes).map_err(|_| ())?;
            match path {
                "manifest.txt" if manifest.is_none() => manifest = Some(bytes),
                "manifest-signature.txt" if signature.is_none() => signature = Some(bytes),
                "manifest.txt" | "manifest-signature.txt" => return Err(()),
                _ => members.push((path.to_owned(), bytes)),
            }
        }
        let manifest = manifest.ok_or(())?;
        let signature = signature.ok_or(())?;
        let signature = std::str::from_utf8(&signature).map_err(|_| ())?;
        let mut fields = signature.lines();
        let key = fields
            .next()
            .ok_or(())?
            .strip_prefix("integrity_identity=")
            .ok_or(())?;
        let bytes = fields
            .next()
            .ok_or(())?
            .strip_prefix("signature=")
            .ok_or(())?;
        if fields.next().is_some() || key != encode_bytes(&expected.public_key())? {
            return Err(());
        }
        let signature = positron_kernel::ExportManifestSignature::new(expected, decode_64(bytes)?)
            .map_err(|_| ())?;
        signature.verify(expected, &manifest).map_err(|_| ())?;
        for line in std::str::from_utf8(&manifest).map_err(|_| ())?.lines() {
            let Some(rest) = line.strip_prefix("member=") else {
                continue;
            };
            let mut fields = rest.split_whitespace();
            let path = fields.next().ok_or(())?;
            let count = fields
                .next()
                .and_then(|value| value.strip_prefix("bytes="))
                .ok_or(())?
                .parse::<usize>()
                .map_err(|_| ())?;
            let digest = fields
                .next()
                .and_then(|value| value.strip_prefix("sha256="))
                .ok_or(())?;
            if fields.next().is_some() {
                return Err(());
            }
            let actual = members
                .iter()
                .find(|(actual, _)| actual == path)
                .ok_or(())?;
            if actual.1.len() != count || digest != hex(&actual.1)? {
                return Err(());
            }
        }
        Ok(())
    }
    #[cfg(test)]
    pub(in crate::support_bundle) fn write_plaintext_explicitly(
        &self,
        destination: &output::OutputDestination,
    ) -> Result<(), ()> {
        output::write_new_owner_only(destination, &self.archive)
    }
    pub(in crate::support_bundle) fn write_plaintext_explicitly_before_publication(
        &self,
        destination: &output::OutputDestination,
        publication_permitted: impl FnOnce() -> bool,
    ) -> Result<(), output::PublicationFailure> {
        output::write_new_owner_only_before_publication(
            destination,
            &self.archive,
            publication_permitted,
        )
    }
    #[cfg(test)]
    pub(in crate::support_bundle) fn write_plaintext_explicitly_with_after_close_hook(
        &self,
        destination: &output::OutputDestination,
        after_close: impl FnOnce(),
    ) -> Result<(), ()> {
        output::write_new_owner_only_with_after_close_hook(destination, &self.archive, after_close)
    }
    #[cfg(test)]
    pub(in crate::support_bundle) fn write_plaintext_explicitly_with_after_close_deadline_hook(
        &self,
        destination: &output::OutputDestination,
        after_close: impl FnOnce(),
        publication_permitted: impl FnOnce() -> bool,
    ) -> Result<(), output::PublicationFailure> {
        output::write_new_owner_only_with_after_close_deadline_hook(
            destination,
            &self.archive,
            after_close,
            publication_permitted,
        )
    }
    #[cfg(test)]
    pub(in crate::support_bundle) fn write_encrypted(
        &self,
        destination: &output::OutputDestination,
        ciphertext: &[u8],
    ) -> Result<(), ()> {
        output::write_new_owner_only(destination, ciphertext)
    }
    pub(in crate::support_bundle) fn write_encrypted_before_publication(
        &self,
        destination: &output::OutputDestination,
        ciphertext: &[u8],
        publication_permitted: impl FnOnce() -> bool,
    ) -> Result<(), output::PublicationFailure> {
        output::write_new_owner_only_before_publication(
            destination,
            ciphertext,
            publication_permitted,
        )
    }
}
