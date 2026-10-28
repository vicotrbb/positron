//! Deterministic standalone chart; native configuration and lifecycle retain authority.
use crate::{ReleaseError, ReleaseInventory, Surface, inventory::hex};
use flate2::{Compression, GzBuilder};

/// Build unsigned Helm payload bytes. Only complete Release Trust authenticates them.
pub fn helm_chart(inventory: &ReleaseInventory) -> Result<Vec<u8>, ReleaseError> {
    inventory.canonical_bytes()?;
    let mut indexes = inventory
        .artifacts
        .iter()
        .filter(|a| a.surface == Surface::OciIndex);
    let index = indexes.next().ok_or(ReleaseError::PartialSet)?;
    if indexes.next().is_some() {
        return Err(ReleaseError::IdentityMismatch);
    }
    let definition = positron_config::setting_definitions()
        .into_iter()
        .find(|d| d.setting() == positron_config::Setting::RuntimeShutdownGraceSeconds)
        .ok_or(ReleaseError::Unsupported)?;
    let positron_config::ValueDomain::UnsignedIntegerRange(_, maximum) = definition.domain() else {
        return Err(ReleaseError::Unsupported);
    };
    let grace = maximum.checked_add(5).ok_or(ReleaseError::LimitExceeded)?;
    let digest = hex(&inventory.file(&index.file)?.identity.sha256);
    let configuration = positron_config::generated_example()
        .replace("/var/lib/positron\"", "/var/lib/positron/instance\"")
        .replace(
            "/var/lib/positron-secrets\"",
            "/var/lib/positron-secrets/instance\"",
        )
        .replace(
            "/var/run/positron/control.sock",
            "/run/positron/control/control.sock",
        )
        .replace("127.0.0.1:8080", "0.0.0.0:8080")
        .replace("127.0.0.1:4317", "0.0.0.0:4317")
        .replace("127.0.0.1:4318", "0.0.0.0:4318")
        .replace("127.0.0.1:3100", "0.0.0.0:3100");
    let mut configuration = configuration;
    let mut tls = String::new();
    for role in ["operations", "api", "otlp_grpc", "otlp_http", "loki_push"] {
        tls.push_str(&format!("{role}_tls_certificate_file = \"/etc/positron/tls/server.pem\"\n{role}_tls_private_key_file = \"/etc/positron/tls/server-key.pem\"\n"));
    }
    configuration = configuration.replace("[listener]\n", &format!("[listener]\n{tls}"));
    configuration.push_str(
        "\n[security]\nlocal_key_file = \"/var/lib/positron-secrets/instance/local-root-key.v1\"\n",
    );
    let configuration = configuration
        .lines()
        .map(|line| format!("  {line}\n"))
        .collect::<String>();
    let gzip = GzBuilder::new()
        .mtime(0)
        .operating_system(255)
        .write(Vec::new(), Compression::default());
    let mut archive = tar::Builder::new(gzip);
    for (name, template) in [
        (
            "Chart.yaml",
            include_str!("../../../deploy/helm/Chart.yaml.in"),
        ),
        (
            "values.yaml",
            include_str!("../../../deploy/helm/values.yaml.in"),
        ),
        (
            "values.schema.json",
            include_str!("../../../deploy/helm/values.schema.json"),
        ),
        (
            "templates/_helpers.tpl",
            include_str!("../../../deploy/helm/templates/_helpers.tpl"),
        ),
        (
            "templates/configuration.yaml",
            include_str!("../../../deploy/helm/templates/configuration.yaml"),
        ),
        (
            "templates/statefulset.yaml",
            include_str!("../../../deploy/helm/templates/statefulset.yaml"),
        ),
        (
            "templates/storage.yaml",
            include_str!("../../../deploy/helm/templates/storage.yaml"),
        ),
        (
            "templates/service.yaml",
            include_str!("../../../deploy/helm/templates/service.yaml"),
        ),
        (
            "templates/maintenance.yaml",
            include_str!("../../../deploy/helm/templates/maintenance.yaml"),
        ),
    ] {
        let content = template
            .replace(
                "@VERSION@",
                &format!(
                    "{}.{}.{}",
                    inventory.version.major, inventory.version.minor, inventory.version.patch
                ),
            )
            .replace("@SOURCE@", &inventory.source_commit)
            .replace("@INDEX_SHA256@", &digest)
            .replace("@STOP_GRACE_SECONDS@", &grace.to_string())
            .replace("@CONFIGURATION@", &configuration);
        let mut header = tar::Header::new_ustar();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_cksum();
        archive
            .append_data(&mut header, format!("positron/{name}"), content.as_bytes())
            .map_err(|_| ReleaseError::Unavailable)?;
    }
    archive
        .into_inner()
        .and_then(|gzip| gzip.finish())
        .map_err(|_| ReleaseError::Unavailable)
}
