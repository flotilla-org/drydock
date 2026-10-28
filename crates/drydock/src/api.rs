//! The public provider HTTP surface, shared with hosts: see [`drydock_client::api`].
pub use drydock_client::api::*;
pub(crate) use drydock_provider::rest::{ApiJson, ApiPath};
