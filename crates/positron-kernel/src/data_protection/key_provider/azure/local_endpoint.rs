//! Capability for the exact local endpoint selected by the official SDK.
use super::*;

pub(super) struct LocalEndpoint(
    azure_core::http::Url,
    Option<(String, String)>,
    &'static str,
);
impl LocalEndpoint {
    pub(super) fn new(
        endpoint: &azure_core::http::Url,
        selector: Option<(&str, &str)>,
        resource: &'static str,
    ) -> Result<Self, KeyProviderFailure> {
        if endpoint.as_str().len() > 4096
            || endpoint.scheme() != "http"
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.fragment().is_some()
            || endpoint.query().is_some()
            || endpoint.host_str().is_none()
        {
            return Err(KeyProviderFailure::InvalidConfiguration);
        }
        if let Some(ip) = endpoint.host_str().and_then(|host| {
            host.trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .ok()
        }) {
            let local = match ip {
                std::net::IpAddr::V4(ip) => ip.is_loopback() || ip.is_link_local(),
                std::net::IpAddr::V6(ip) => ip.is_loopback() || ip.is_unicast_link_local(),
            };
            if !local {
                return Err(KeyProviderFailure::InvalidConfiguration);
            }
        }
        Ok(Self(
            endpoint.clone(),
            selector.map(|(key, value)| (key.to_owned(), value.to_owned())),
            resource,
        ))
    }
    pub(super) fn validate(
        &self,
        request: &azure_core::http::Request,
    ) -> Result<(), KeyProviderFailure> {
        let uri = request.url();
        if request.method() != azure_core::http::Method::Get
            || uri.scheme() != self.0.scheme()
            || uri.host_str() != self.0.host_str()
            || uri.port_or_known_default() != self.0.port_or_known_default()
            || uri.path() != self.0.path()
            || !uri.username().is_empty()
            || uri.password().is_some()
            || uri.fragment().is_some()
        {
            return Err(KeyProviderFailure::InvalidConfiguration);
        }
        let mut version = false;
        let mut resource = false;
        let mut selector = false;
        for (key, value) in uri.query_pairs() {
            match key.as_ref() {
                "api-version" if !version && value == "2019-08-01" => version = true,
                "resource" if !resource && value == self.2 => resource = true,
                "client_id" | "object_id"
                    if !selector
                        && self
                            .1
                            .as_ref()
                            .is_some_and(|(expected_key, expected_value)| {
                                key == *expected_key && value == *expected_value
                            }) =>
                {
                    selector = true
                },
                _ => return Err(KeyProviderFailure::InvalidConfiguration),
            }
        }
        if !version || !resource || selector != self.1.is_some() {
            return Err(KeyProviderFailure::InvalidConfiguration);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn selected_endpoint_refuses_remote_routing_and_unexpected_sdk_query()
    -> Result<(), Box<dyn std::error::Error>> {
        for uri in [
            "http://192.0.2.1:8081/token",
            "https://127.0.0.1/token",
            "http://user@127.0.0.1/token",
            "http://127.0.0.1/token?redirect=1",
            "http://127.0.0.1/token#fragment",
        ] {
            assert!(
                LocalEndpoint::new(
                    &azure_core::http::Url::parse(uri)?,
                    None,
                    "https://vault.azure.net"
                )
                .is_err()
            );
        }
        let endpoint = LocalEndpoint::new(
            &azure_core::http::Url::parse("http://127.0.0.1:8081/token")?,
            Some(("client_id", "fixture-client")),
            "https://vault.azure.net",
        )?;
        let valid = "http://127.0.0.1:8081/token?api-version=2019-08-01&resource=https%3A%2F%2Fvault.azure.net&client_id=fixture-client";
        assert_eq!(
            endpoint.validate(&azure_core::http::Request::new(
                azure_core::http::Url::parse(valid)?,
                azure_core::http::Method::Get
            )),
            Ok(())
        );
        for uri in [
            valid.replace(":8081", ":8082"),
            valid.replace("/token?", "/other?"),
            valid.replace("fixture-client", "other-client"),
            valid.replace("vault.azure.net", "vault.azure.cn"),
            format!("{valid}&client_id=fixture-client"),
            format!("{valid}&redirect=1"),
            valid.replace("2019-08-01", "2025-07-01"),
        ] {
            assert!(
                endpoint
                    .validate(&azure_core::http::Request::new(
                        azure_core::http::Url::parse(&uri)?,
                        azure_core::http::Method::Get
                    ))
                    .is_err()
            );
        }
        Ok(())
    }
}
