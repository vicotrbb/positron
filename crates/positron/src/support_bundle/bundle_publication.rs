use super::*;

pub(crate) fn write_bundle(
    bundle: &SupportBundle,
    options: &BundleOptions,
    output_destination: &output::OutputDestination,
    started: Instant,
) -> Result<(), BundleFailure> {
    write_bundle_after_publication(bundle, options, output_destination, started, || {})
}

#[cfg(test)]
pub(crate) fn write_bundle_with_after_publication_hook(
    bundle: &SupportBundle,
    options: &BundleOptions,
    output_destination: &output::OutputDestination,
    started: Instant,
    after_publication: impl FnOnce(),
) -> Result<(), BundleFailure> {
    write_bundle_after_publication(
        bundle,
        options,
        output_destination,
        started,
        after_publication,
    )
}

#[cfg(test)]
pub(crate) fn write_plaintext_bundle_with_after_close_hook(
    bundle: &SupportBundle,
    options: &BundleOptions,
    output_destination: &output::OutputDestination,
    started: Instant,
    after_close: impl FnOnce(),
) -> Result<(), BundleFailure> {
    if options.deadline_exceeded(started) {
        return Err(BundleFailure::DeadlineExceeded);
    }
    bundle
        .write_plaintext_explicitly_with_after_close_deadline_hook(
            output_destination,
            after_close,
            || !options.deadline_exceeded(started),
        )
        .map_err(publication_failure)
}

fn write_bundle_after_publication(
    bundle: &SupportBundle,
    options: &BundleOptions,
    output_destination: &output::OutputDestination,
    started: Instant,
    after_publication: impl FnOnce(),
) -> Result<(), BundleFailure> {
    if options.deadline_exceeded(started) {
        return Err(BundleFailure::DeadlineExceeded);
    }
    if options.plaintext_warning {
        if options.deadline_exceeded(started) {
            return Err(BundleFailure::DeadlineExceeded);
        }
        bundle
            .write_plaintext_explicitly_before_publication(output_destination, || {
                !options.deadline_exceeded(started)
            })
            .map_err(publication_failure)?;
    } else {
        let recipients = AgeRecipients::parse(options.recipients.clone())
            .map_err(|_| BundleFailure::Arguments)?;
        let ciphertext = recipients
            .encrypt_bounded(bundle.archive(), options.output_limit)
            .map_err(|_| BundleFailure::OutputUnavailable)?;
        if options.deadline_exceeded(started) {
            return Err(BundleFailure::DeadlineExceeded);
        }
        bundle
            .write_encrypted_before_publication(output_destination, &ciphertext, || {
                !options.deadline_exceeded(started)
            })
            .map_err(publication_failure)?;
    }
    after_publication();
    Ok(())
}

pub(super) fn publication_failure(failure: output::PublicationFailure) -> BundleFailure {
    match failure {
        output::PublicationFailure::Unavailable => BundleFailure::OutputUnavailable,
        output::PublicationFailure::DeadlineExceeded => BundleFailure::DeadlineExceeded,
    }
}
