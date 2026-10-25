use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    sync::{
        Mutex,
        atomic::{AtomicU32, Ordering},
    },
    time::Duration,
};

use cloudsec_domain::{CloudProvider, DiscoveredResource};
use serde_json::json;

use crate::{
    error::ScannerError,
    provider::{
        CloudProviderClient, DiscoveryContext, ProviderCapabilities, ValidationContext,
        ValidationReport,
    },
};

pub struct FakeCloudProvider {
    provider: CloudProvider,
    resources: Mutex<HashMap<String, Vec<DiscoveredResource>>>, // key: "region:service"
    throttles_remaining: AtomicU32,
    permission_denied_services: Mutex<Vec<String>>,
    simulated_delay: Mutex<Option<Duration>>,
    validation_valid: bool,
}

impl FakeCloudProvider {
    pub fn new(provider: CloudProvider) -> Self {
        Self {
            provider,
            resources: Mutex::new(HashMap::new()),
            throttles_remaining: AtomicU32::new(0),
            permission_denied_services: Mutex::new(Vec::new()),
            simulated_delay: Mutex::new(None),
            validation_valid: true,
        }
    }

    pub fn with_resource(self, region: &str, service: &str, resource: DiscoveredResource) -> Self {
        let key = format!("{region}:{service}");
        self.resources
            .lock()
            .unwrap()
            .entry(key)
            .or_default()
            .push(resource);
        self
    }

    pub fn set_throttle_count(&self, count: u32) {
        self.throttles_remaining.store(count, Ordering::SeqCst);
    }

    pub fn set_permission_denied(&self, service: &str) {
        self.permission_denied_services
            .lock()
            .unwrap()
            .push(service.to_string());
    }

    pub fn set_simulated_delay(&self, delay: Duration) {
        *self.simulated_delay.lock().unwrap() = Some(delay);
    }
}

impl CloudProviderClient for FakeCloudProvider {
    fn provider(&self) -> CloudProvider {
        self.provider
    }

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            provider: self.provider,
            supported_regions: vec![
                "us-east-1".to_string(),
                "eastus".to_string(),
                "us-central1".to_string(),
            ],
            supported_services: vec!["s3".to_string(), "iam".to_string(), "storage".to_string()],
            default_rate_limit_per_second: 50,
        }
    }

    fn validate_credentials<'a>(
        &'a self,
        _context: &'a ValidationContext,
    ) -> Pin<Box<dyn Future<Output = Result<ValidationReport, ScannerError>> + Send + 'a>> {
        Box::pin(async move {
            if self.validation_valid {
                Ok(ValidationReport {
                    is_valid: true,
                    identity: format!("{}-test-identity", self.provider.as_str()),
                    enabled_regions: vec![
                        "us-east-1".to_string(),
                        "eastus".to_string(),
                        "us-central1".to_string(),
                    ],
                    details: json!({"authenticated": true}),
                })
            } else {
                Err(ScannerError::AuthenticationFailed(
                    "Invalid or expired test credentials".to_string(),
                ))
            }
        })
    }

    fn discover_resources<'a>(
        &'a self,
        context: &'a DiscoveryContext,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<DiscoveredResource>, ScannerError>> + Send + 'a>>
    {
        Box::pin(async move {
            let delay = *self.simulated_delay.lock().unwrap();
            if let Some(delay) = delay {
                tokio::time::sleep(delay).await;
            }

            // Check throttling
            let remaining = self.throttles_remaining.load(Ordering::SeqCst);
            if remaining > 0 {
                self.throttles_remaining.fetch_sub(1, Ordering::SeqCst);
                return Err(ScannerError::Throttling {
                    message: "Simulated rate limit exceeded".to_string(),
                    retry_after_ms: Some(50),
                });
            }

            // Check permission denied
            let denied = self.permission_denied_services.lock().unwrap();
            for service in &context.services {
                if denied.contains(service) {
                    return Err(ScannerError::PermissionDenied {
                        service: service.clone(),
                        resource: None,
                        action: format!("{service}:ListResources"),
                    });
                }
            }

            // Return resources
            let mut result = Vec::new();
            let store = self.resources.lock().unwrap();
            for service in &context.services {
                let key = format!("{}:{}", context.region, service);
                if let Some(items) = store.get(&key) {
                    result.extend(items.clone());
                }
            }

            Ok(result)
        })
    }
}
