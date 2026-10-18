//! Bounded native package metadata, using the standard namespace-aware XML parser.
use crate::ReleaseError;
pub(crate) fn document(bytes: &[u8]) -> Result<roxmltree::Document<'_>, ReleaseError> {
    if bytes.len() > 1_048_576 {
        return Err(ReleaseError::LimitExceeded);
    }
    roxmltree::Document::parse_with_options(
        std::str::from_utf8(bytes).map_err(|_| ReleaseError::Invalid)?,
        roxmltree::ParsingOptions {
            allow_dtd: false,
            nodes_limit: 16_384,
            entity_resolver: None,
        },
    )
    .map_err(|_| ReleaseError::Invalid)
}
pub(crate) fn child<'a, 'input>(
    node: roxmltree::Node<'a, 'input>,
    name: &str,
) -> Result<roxmltree::Node<'a, 'input>, ReleaseError> {
    let mut matches = node.children().filter(|child| {
        child.is_element()
            && child.tag_name().name() == name
            && child.tag_name().namespace() == node.tag_name().namespace()
    });
    let found = matches.next().ok_or(ReleaseError::IdentityMismatch)?;
    if matches.next().is_some() {
        return Err(ReleaseError::Invalid);
    }
    Ok(found)
}
pub(crate) fn text(node: roxmltree::Node<'_, '_>) -> Result<String, ReleaseError> {
    if node.children().any(|child| child.is_element()) {
        return Err(ReleaseError::Invalid);
    }
    let text: String = node.children().filter_map(|child| child.text()).collect();
    let text = text.trim();
    if text.is_empty() || text.len() > 4096 || text.chars().any(char::is_control) {
        return Err(ReleaseError::Invalid);
    }
    Ok(text.into())
}
