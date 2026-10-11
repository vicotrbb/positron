// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
//! Optional caller-owned file custody; the SDK retains identity selection and refresh.
/// Caller-owned admission for native projected-token reads.
pub trait Runtime: std::fmt::Debug + Send + Sync {
    /// Captures the exact App Service endpoint after the SDK selects that source.
    fn bind_app_service_endpoint(&self, _endpoint: &azure_core::http::Url, _selector: Option<(&str, &str)>) -> azure_core::Result<()> {
        Ok(())
    }
    /// A bounded read admitted before open/allocation, including projected symlinks.
    fn read_file(&self, path: &std::path::Path) -> std::io::Result<String>;
}
