use cloudsec_domain::{
    CloudProvider, ComprehensiveCostRiskReport, CostAllocationConfidence, CostOfRiskItem, Finding,
    FindingStatus, Id, Resource, Severity,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudBillingRecord {
    pub provider: CloudProvider,
    pub account_id: String,
    pub resource_id: Option<String>,
    pub service: String,
    pub region: Option<String>,
    pub currency: String,
    pub amount_usd: f64,
    pub period_start: String,
    pub period_end: String,
}

pub struct CostSecurityEngine;

impl CostSecurityEngine {
    pub fn normalize_cost_to_usd(amount: f64, currency: &str) -> f64 {
        match currency.to_uppercase().as_str() {
            "USD" => amount,
            "EUR" => amount * 1.08,
            "GBP" => amount * 1.28,
            "CAD" => amount * 0.73,
            "AUD" => amount * 0.65,
            _ => amount, // default fallback
        }
    }

    pub fn calculate_risk_exposure(
        findings: &[Finding],
        resource_id: Id,
        resource_type: &str,
    ) -> (f64, usize, usize) {
        let mut critical_count = 0;
        let mut high_count = 0;
        let mut exposure = 0.0;

        for f in findings
            .iter()
            .filter(|f| f.resource_id == resource_id && f.status == FindingStatus::Open)
        {
            match f.severity {
                Severity::Critical => {
                    critical_count += 1;
                    exposure += 250_000.0; // Benchmark average breach risk exposure
                }
                Severity::High => {
                    high_count += 1;
                    exposure += 50_000.0;
                }
                Severity::Medium => {
                    exposure += 10_000.0;
                }
                Severity::Low | Severity::Informational => {
                    exposure += 1_000.0;
                }
            }
        }

        // Sensitive data store modifier
        if resource_type.contains("s3")
            || resource_type.contains("sql")
            || resource_type.contains("storage")
        {
            exposure *= 1.5;
        }

        (exposure, critical_count, high_count)
    }

    pub fn detect_waste_and_savings(resource: &Resource) -> (f64, String) {
        if resource.resource_type == "aws_ec2_eip"
            || resource.resource_type.contains("unattached_ip")
        {
            (
                7.30,
                "Unattached public IP address costing continuous hourly allocation fees"
                    .to_string(),
            )
        } else if resource.resource_type.contains("idle") {
            (
                45.00,
                "Idle development/staging instance with near-zero utilization".to_string(),
            )
        } else if resource.resource_type == "aws_ebs_volume"
            && resource.configuration.get("attachments").is_none()
        {
            (
                20.00,
                "Unattached EBS block storage volume persisting without host".to_string(),
            )
        } else {
            (0.0, String::new())
        }
    }

    pub fn compute_cost_risk_report(
        resources: &[Resource],
        findings: &[Finding],
        billing_records: &[CloudBillingRecord],
    ) -> ComprehensiveCostRiskReport {
        let mut items = Vec::new();
        let mut total_spend = 0.0;
        let mut total_risk = 0.0;
        let mut total_savings = 0.0;

        for r in resources {
            // Match billing record by resource_id
            let matched_bill = billing_records.iter().find(|b| {
                b.resource_id
                    .as_deref()
                    .map(|id| id == r.provider_native_id || r.provider_native_id.contains(id))
                    .unwrap_or(false)
            });

            let (spend_usd, confidence) = if let Some(bill) = matched_bill {
                (
                    Self::normalize_cost_to_usd(bill.amount_usd, &bill.currency),
                    CostAllocationConfidence::Direct,
                )
            } else {
                // Inferred based on service or base minimum
                let inferred_bill = billing_records.iter().find(|b| {
                    r.resource_type.contains(&b.service) || b.service.contains(&r.resource_type)
                });
                if let Some(ib) = inferred_bill {
                    (
                        Self::normalize_cost_to_usd(ib.amount_usd * 0.25, &ib.currency),
                        CostAllocationConfidence::Inferred,
                    )
                } else {
                    (0.0, CostAllocationConfidence::Unallocated)
                }
            };

            let (risk_exposure, crit_count, high_count) =
                Self::calculate_risk_exposure(findings, r.id, &r.resource_type);
            let (savings, waste_rec) = Self::detect_waste_and_savings(r);

            total_spend += spend_usd;
            total_risk += risk_exposure;
            total_savings += savings;

            let recommendation = if !waste_rec.is_empty() {
                format!("Cost Savings Opportunity: {waste_rec}")
            } else if risk_exposure > 0.0 {
                format!(
                    "High Security Risk: Remediate {crit_count} critical and {high_count} high findings"
                )
            } else {
                "Resource configuration compliant and optimized".to_string()
            };

            let provider = if r.resource_type.starts_with("aws_") {
                CloudProvider::Aws
            } else if r.resource_type.starts_with("azure_") {
                CloudProvider::Azure
            } else {
                CloudProvider::Gcp
            };

            items.push(CostOfRiskItem {
                resource_id: r.id,
                provider_native_id: r.provider_native_id.clone(),
                provider,
                service: r.resource_type.clone(),
                actual_monthly_spend_usd: spend_usd,
                estimated_risk_exposure_usd: risk_exposure,
                savings_potential_usd: savings,
                confidence,
                critical_findings_count: crit_count,
                high_findings_count: high_count,
                recommendation,
            });
        }

        ComprehensiveCostRiskReport {
            total_actual_monthly_spend_usd: total_spend,
            total_risk_exposure_usd: total_risk,
            total_monthly_savings_potential_usd: total_savings,
            items,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cloudsec_domain::FindingStatus;
    use serde_json::json;
    use uuid::Uuid;

    #[test]
    fn normalizes_foreign_currencies_to_usd() {
        assert_eq!(
            CostSecurityEngine::normalize_cost_to_usd(100.0, "USD"),
            100.0
        );
        assert!((CostSecurityEngine::normalize_cost_to_usd(100.0, "EUR") - 108.0).abs() < 0.001);
        assert!((CostSecurityEngine::normalize_cost_to_usd(100.0, "GBP") - 128.0).abs() < 0.001);
    }

    #[test]
    fn calculates_cost_of_risk_and_savings_accurately() {
        let org_id = Uuid::new_v4();
        let acc_id = Uuid::new_v4();
        let r1_id = Uuid::new_v4();
        let r2_id = Uuid::new_v4();

        let resources = vec![
            Resource {
                id: r1_id,
                organization_id: org_id,
                account_id: acc_id,
                provider_native_id: "customer-data-bucket".to_string(),
                resource_type: "aws_s3_bucket".to_string(),
                name: Some("customer-data-bucket".to_string()),
                tags: json!({}),
                region: Some("us-east-1".to_string()),
                configuration: json!({}),
            },
            Resource {
                id: r2_id,
                organization_id: org_id,
                account_id: acc_id,
                provider_native_id: "eipalloc-12345".to_string(),
                resource_type: "aws_ec2_eip".to_string(),
                name: Some("idle-ip".to_string()),
                tags: json!({}),
                region: Some("us-east-1".to_string()),
                configuration: json!({}),
            },
        ];

        let findings = vec![Finding {
            id: Uuid::new_v4(),
            organization_id: org_id,
            check_id: "aws-s3-block-public-access".to_string(),
            resource_id: r1_id,
            severity: Severity::Critical,
            status: FindingStatus::Open,
            evidence: json!({}),
            fingerprint: "fp1".to_string(),
        }];

        let billing = vec![
            CloudBillingRecord {
                provider: CloudProvider::Aws,
                account_id: "123456789012".to_string(),
                resource_id: Some("customer-data-bucket".to_string()),
                service: "s3".to_string(),
                region: Some("us-east-1".to_string()),
                currency: "USD".to_string(),
                amount_usd: 85.50,
                period_start: "2026-10-01".to_string(),
                period_end: "2026-10-31".to_string(),
            },
            CloudBillingRecord {
                provider: CloudProvider::Aws,
                account_id: "123456789012".to_string(),
                resource_id: Some("eipalloc-12345".to_string()),
                service: "ec2".to_string(),
                region: Some("us-east-1".to_string()),
                currency: "EUR".to_string(),
                amount_usd: 10.00,
                period_start: "2026-10-01".to_string(),
                period_end: "2026-10-31".to_string(),
            },
        ];

        let report = CostSecurityEngine::compute_cost_risk_report(&resources, &findings, &billing);

        assert_eq!(report.items.len(), 2);
        // Risk exposure for r1: 250,000 * 1.5 (S3 modifier) = 375,000 USD
        assert_eq!(report.items[0].estimated_risk_exposure_usd, 375_000.0);
        assert_eq!(report.items[0].confidence, CostAllocationConfidence::Direct);

        // Savings for unattached EIP: 7.30 USD
        assert_eq!(report.items[1].savings_potential_usd, 7.30);
        assert!(report.total_monthly_savings_potential_usd >= 7.30);
    }
}
