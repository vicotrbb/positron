use super::*;
use crate::{InitializationPlan, InstanceBootstrap};
use positron_governance::{AdministrativeIdempotencyKey, DurableOperationAdministration};
use positron_kernel::Catalog;
use std::sync::Arc;

#[test]
fn native_upgrade_expired_admission_preserves_catalog_and_publishes_no_intent()
-> Result<(), Box<dyn std::error::Error>> {
    let roots = crate::process_lifecycle::TestRoots::new("upgrade-native-deadline")?;
    let paths = roots.bootstrap_paths()?;
    drop(InstanceBootstrap::initialize(
        &paths,
        InitializationPlan::non_interactive(),
    )?);
    let administrator = InstanceBootstrap::claim(&paths)?.secret().to_owned();
    let instance = Arc::new(InstanceBootstrap::reopen(&paths)?);
    let services = ServiceHandle::new(Arc::clone(&instance))?;
    let state = crate::health::ProcessState::starting();
    state.set_inspection_authority(Arc::clone(&instance))?;
    state.transition(crate::ProcessPhase::Serving);
    let inspect = || -> Result<_, Box<dyn std::error::Error>> {
        let catalog = Catalog::open(
            &instance._authority,
            instance.instance,
            instance.key.catalog_secret(instance.instance)?,
        )?;
        let key = AdministrativeIdempotencyKey::new([0x41; 16])?;
        assert!(DurableOperationAdministration::inspect_by_idempotency(&catalog, key)?.is_none());
        Ok(catalog.pin()?.identity())
    };
    let before = inspect()?;
    let resources = instance.resource_governor().inspect()?;
    let body = format!(r#"{{"action":"start","candidate_manifest":"{}","repository_id":"11111111-1111-1111-1111-111111111111","retention_seconds":3600,"expected_catalog_generation":1,"idempotency_key":"41414141-4141-4141-4141-414141414141"}}"#, "ab".repeat(32)).into_bytes();
    let mut raw = Cursor::new(format!("POST {} HTTP/1.1\r\nAuthorization: Bearer {administrator}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n", positron_api::upgrade::HTTP_PATH, body.len()).into_bytes());
    let head = io::read_head(&mut raw).map_err(|_| "request head")?;
    let response = route_buffered_api(
        head,
        body,
        "127.0.0.1:1".parse()?,
        None,
        &state.health(),
        Some(&services),
        std::time::Instant::now(),
    );
    assert_eq!(response.status(), 503);
    assert!(std::str::from_utf8(response.body())?.contains("capacity_unavailable"));
    assert_eq!(inspect()?, before);
    let after = instance.resource_governor().inspect()?;
    assert_eq!(
        after.outstanding_reservations(),
        resources.outstanding_reservations()
    );
    for dimension in positron_kernel::ResourceDimension::ALL {
        assert_eq!(after.usage(dimension), resources.usage(dimension));
    }
    Ok(())
}
