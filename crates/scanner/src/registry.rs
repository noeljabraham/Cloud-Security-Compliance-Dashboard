use cloudsec_domain::CloudProvider;
use std::{collections::HashMap, sync::Arc};

use crate::{check::Check, provider::CloudProviderClient};

#[derive(Default)]
pub struct ProviderRegistry {
    providers: HashMap<CloudProvider, Arc<dyn CloudProviderClient>>,
    checks: Vec<Arc<dyn Check>>,
}

impl ProviderRegistry {
    pub fn new() -> Self {
        Self {
            providers: HashMap::new(),
            checks: Vec::new(),
        }
    }

    pub fn register_provider(&mut self, provider: Arc<dyn CloudProviderClient>) {
        self.providers.insert(provider.provider(), provider);
    }

    pub fn get_provider(&self, provider: CloudProvider) -> Option<Arc<dyn CloudProviderClient>> {
        self.providers.get(&provider).cloned()
    }

    pub fn register_check(&mut self, check: Arc<dyn Check>) {
        self.checks.retain(|c| c.id() != check.id());
        self.checks.push(check);
    }

    pub fn get_checks_for_provider(&self, provider: CloudProvider) -> Vec<Arc<dyn Check>> {
        self.checks
            .iter()
            .filter(|c| c.provider() == provider)
            .cloned()
            .collect()
    }

    pub fn get_checks_for_service(
        &self,
        provider: CloudProvider,
        service: &str,
    ) -> Vec<Arc<dyn Check>> {
        self.checks
            .iter()
            .filter(|c| c.provider() == provider && c.service() == service)
            .cloned()
            .collect()
    }

    pub fn get_check(&self, check_id: &str) -> Option<Arc<dyn Check>> {
        self.checks.iter().find(|c| c.id() == check_id).cloned()
    }

    pub fn all_checks(&self) -> Vec<Arc<dyn Check>> {
        self.checks.clone()
    }
}
