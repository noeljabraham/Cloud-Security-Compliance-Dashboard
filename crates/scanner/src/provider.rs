use cloudsec_domain::{CloudProvider, DiscoveredResource, Id};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{future::Future, pin::Pin};

use crate::error::ScannerError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationContext {
    pub connection_id: Id,
    pub account_id: Id,
    pub provider: CloudProvider,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationReport {
    pub is_valid: bool,
    pub identity: String,
    pub enabled_regions: Vec<String>,
    pub details: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryContext {
    pub organization_id: Id,
    pub account_id: Id,
    pub region: String,
    pub services: Vec<String>,
    #[serde(default)]
    pub page_size: Option<u32>,
    #[serde(default)]
    pub page_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderCapabilities {
    pub provider: CloudProvider,
    pub supported_regions: Vec<String>,
    pub supported_services: Vec<String>,
    pub default_rate_limit_per_second: u32,
}

pub trait CloudProviderClient: Send + Sync {
    fn provider(&self) -> CloudProvider;

    fn capabilities(&self) -> ProviderCapabilities;

    fn validate_credentials<'a>(
        &'a self,
        context: &'a ValidationContext,
    ) -> Pin<Box<dyn Future<Output = Result<ValidationReport, ScannerError>> + Send + 'a>>;

    fn discover_resources<'a>(
        &'a self,
        context: &'a DiscoveryContext,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<DiscoveredResource>, ScannerError>> + Send + 'a>>;
}
