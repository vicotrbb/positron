use super::*;
#[test]
fn local_provider_verifies_payload_scope_and_survives_reopen()
-> Result<(), Box<dyn std::error::Error>> {
    let root = protection::local_key::test_support::SecurityRoot::create()?;
    let custody = protection::BootstrapKeyCustody::initialize(&root.path)?;
    let provider = LocalKeyProvider::from_custody(custody)?;
    let session = KeyProviderSession::new(&provider);
    let context = EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 1, 1)?;
    ready(session.verify_live(context))?;
    let envelope = ready(session.wrap(SecretKek::from_owned(Box::new([57; 32])), context))?;
    let reopened =
        LocalKeyProvider::from_custody(protection::BootstrapKeyCustody::open(&root.path)?)?;
    let reopened = KeyProviderSession::new(&reopened);
    assert!(ready(reopened.verify(&envelope, context)).is_ok());
    let wrong = EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 2, 1)?;
    assert_eq!(
        ready(reopened.verify(&envelope, wrong)),
        Err(KeyProviderFailure::ContextMismatch)
    );
    Ok(())
}

#[test]
fn shared_conformance_runs_against_two_real_local_custody_targets()
-> Result<(), Box<dyn std::error::Error>> {
    use protection::key_provider::{KeyProviderConformance, ProviderConformanceTarget};
    let root = protection::local_key::test_support::SecurityRoot::create()?;
    let replacement_root = protection::local_key::test_support::SecurityRoot::create()?;
    let first =
        LocalKeyProvider::from_custody(protection::BootstrapKeyCustody::initialize(&root.path)?)?;
    let second = LocalKeyProvider::from_custody(protection::BootstrapKeyCustody::initialize(
        &replacement_root.path,
    )?)?;
    let context = EnvelopeContext::new([1; 16], KeyScope::System, [2; 32], 1, 1)?;
    let target = ProviderConformanceTarget::new(
        ProviderFamily::LocalFile,
        "Positron protected local file",
        "v1",
        "native host filesystem",
    )?;
    let harness = ready(KeyProviderConformance::healthy(&first, target, context))?;
    ready(harness.recovery(&first))?;
    let target = ProviderConformanceTarget::new(
        ProviderFamily::LocalFile,
        "Positron protected local file",
        "v1",
        "second pre-provisioned local root",
    )?;
    let successor = ready(harness.rotation_and_migration(&first, &second, target))?;
    ready(successor.recovery(&second))?;
    ready(harness.recovery(&first))?;
    Ok(())
}
