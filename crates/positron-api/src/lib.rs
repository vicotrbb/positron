//! Public-interface foundations for the canonical Positron v1 API.
//!
//! The public source lives exclusively in `api/positron/v1/positron.proto`.
//! Keep this module and its HTTP/JSON, OpenAPI, and Schema Digest artifacts
//! synchronized with that contract.

#![forbid(unsafe_code)]

/// V1 wire and in-memory interface types.
pub mod generated;

/// V1 API-key administration wire types and bounded client encoding.
pub mod api_keys;
pub mod maintenance;
pub mod policy;
pub mod provider_migration;
pub mod repository;

/// V1 tenant-quota administration wire types and bounded client encoding.
pub mod tenant_quotas;

/// V1 tenant lifecycle transition wire types.
pub mod tenant_lifecycle;

/// V1 immutable external tenant-alias administration wire types.
pub mod tenant_aliases;

/// V1 tenant retention preview and confirmed update wire types.
pub mod tenant_retention;

pub mod tenant_purge;
/// V1 system tenant-registry administration wire types.
pub mod tenant_service;

mod http_client;
mod validation;

pub mod backup;

pub mod upgrade;
