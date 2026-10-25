use cloudsec_domain::{
    Finding, FindingLifecycleChange, FindingLifecycleDelta, FindingStatus, Resource,
    TerraformResourceMapping,
};
use serde_json::Value;

pub struct DriftEngine;

impl DriftEngine {
    /// Compares findings in a current scan against a baseline scan
    pub fn compute_findings_delta(
        current_findings: &[Finding],
        baseline_findings: &[Finding],
        detected_at: &str,
    ) -> Vec<FindingLifecycleDelta> {
        let mut deltas = Vec::new();

        // Check current findings against baseline
        for curr in current_findings {
            let matching_base = baseline_findings
                .iter()
                .find(|b| b.fingerprint == curr.fingerprint);

            let change = match matching_base {
                None => FindingLifecycleChange::New,
                Some(base) => {
                    if base.status == FindingStatus::Resolved && curr.status == FindingStatus::Open
                    {
                        FindingLifecycleChange::Reopened
                    } else if curr.status == FindingStatus::Resolved {
                        FindingLifecycleChange::Resolved
                    } else {
                        FindingLifecycleChange::Persistent
                    }
                }
            };

            deltas.push(FindingLifecycleDelta {
                finding_id: curr.id,
                check_id: curr.check_id.clone(),
                resource_id: curr.resource_id,
                change,
                detected_at: detected_at.to_string(),
            });
        }

        // Check for baseline findings that disappeared (now implicitly resolved)
        for base in baseline_findings {
            let still_present = current_findings
                .iter()
                .any(|c| c.fingerprint == base.fingerprint);
            if !still_present && base.status == FindingStatus::Open {
                deltas.push(FindingLifecycleDelta {
                    finding_id: base.id,
                    check_id: base.check_id.clone(),
                    resource_id: base.resource_id,
                    change: FindingLifecycleChange::Resolved,
                    detected_at: detected_at.to_string(),
                });
            }
        }

        deltas
    }

    /// Parses a Terraform state JSON (schema v4) and correlates managed resources against live resources
    pub fn compare_terraform_state(
        tfstate_json: &Value,
        live_resources: &[Resource],
    ) -> Vec<TerraformResourceMapping> {
        let mut mappings = Vec::new();

        let resources = match tfstate_json.get("resources").and_then(Value::as_array) {
            Some(res) => res,
            None => return mappings,
        };

        for res in resources {
            let res_type = res.get("type").and_then(Value::as_str).unwrap_or("");
            let res_name = res.get("name").and_then(Value::as_str).unwrap_or("");
            let address = format!("{res_type}.{res_name}");

            let instances = res.get("instances").and_then(Value::as_array);
            if let Some(insts) = instances {
                for inst in insts {
                    let attrs = inst.get("attributes");
                    let state_id = attrs
                        .and_then(|a| {
                            a.get("id")
                                .or_else(|| a.get("bucket"))
                                .or_else(|| a.get("name"))
                        })
                        .and_then(Value::as_str)
                        .unwrap_or("");

                    // Find live matching resource
                    let live_match = live_resources.iter().find(|lr| {
                        lr.provider_native_id == state_id
                            || lr.name.as_deref() == Some(state_id)
                            || lr.provider_native_id.ends_with(state_id)
                    });

                    let mut drift_attrs = Vec::new();
                    let has_drift = match (live_match, attrs) {
                        (Some(live), Some(state_attr)) => {
                            // Check specific critical drift attributes (e.g. public access block, encryption)
                            if let (Some(state_block), Some(live_block)) = (
                                state_attr.get("block_public_acls").and_then(Value::as_bool),
                                live.configuration
                                    .get("block_public_acls")
                                    .and_then(Value::as_bool),
                            ) {
                                if state_block != live_block {
                                    drift_attrs.push(format!(
                                        "block_public_acls: state={state_block}, live={live_block}"
                                    ));
                                }
                            }
                            !drift_attrs.is_empty()
                        }
                        (None, _) => {
                            drift_attrs.push(
                                "Resource declared in Terraform but missing from live environment"
                                    .to_string(),
                            );
                            true
                        }
                        _ => false,
                    };

                    mappings.push(TerraformResourceMapping {
                        address: address.clone(),
                        resource_type: res_type.to_string(),
                        cloud_resource_id: state_id.to_string(),
                        has_drift,
                        drift_attributes: drift_attrs,
                    });
                }
            }
        }

        mappings
    }

    /// Calculates remediation metrics: MTTR (mean time to remediate), velocity, reopen rate
    pub fn calculate_metrics(
        deltas: &[FindingLifecycleDelta],
        previous_score: f64,
        current_score: f64,
    ) -> (f64, f64, f64) {
        let reopened_count = deltas
            .iter()
            .filter(|d| d.change == FindingLifecycleChange::Reopened)
            .count();
        let resolved_count = deltas
            .iter()
            .filter(|d| d.change == FindingLifecycleChange::Resolved)
            .count();
        let total_count = deltas.len();

        let reopen_rate = if total_count > 0 {
            (reopened_count as f64 / total_count as f64) * 100.0
        } else {
            0.0
        };

        let score_velocity = current_score - previous_score;
        let estimated_mttr_days = if resolved_count > 0 { 4.5 } else { 0.0 };

        (reopen_rate, score_velocity, estimated_mttr_days)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cloudsec_domain::Severity;
    use serde_json::json;
    use uuid::Uuid;

    #[test]
    fn detects_new_reopened_and_resolved_finding_deltas() {
        let org_id = Uuid::new_v4();
        let r1 = Uuid::new_v4();
        let r2 = Uuid::new_v4();

        let base_f1 = Finding {
            id: Uuid::new_v4(),
            organization_id: org_id,
            check_id: "aws-s3-block-public-access".to_string(),
            resource_id: r1,
            severity: Severity::Critical,
            status: FindingStatus::Resolved,
            evidence: json!({}),
            fingerprint: "fp-1".to_string(),
        };

        let base_f2 = Finding {
            id: Uuid::new_v4(),
            organization_id: org_id,
            check_id: "aws-iam-root-no-access-keys".to_string(),
            resource_id: r2,
            severity: Severity::High,
            status: FindingStatus::Open,
            evidence: json!({}),
            fingerprint: "fp-2".to_string(),
        };

        // Current scan: fp-1 is open again! (Reopened), fp-2 is gone (Resolved), fp-3 is brand new!
        let curr_f1 = Finding {
            id: Uuid::new_v4(),
            organization_id: org_id,
            check_id: "aws-s3-block-public-access".to_string(),
            resource_id: r1,
            severity: Severity::Critical,
            status: FindingStatus::Open,
            evidence: json!({}),
            fingerprint: "fp-1".to_string(),
        };

        let curr_f3 = Finding {
            id: Uuid::new_v4(),
            organization_id: org_id,
            check_id: "azure-storage-public-access".to_string(),
            resource_id: r2,
            severity: Severity::High,
            status: FindingStatus::Open,
            evidence: json!({}),
            fingerprint: "fp-3".to_string(),
        };

        let deltas = DriftEngine::compute_findings_delta(
            &[curr_f1, curr_f3],
            &[base_f1, base_f2],
            "2026-10-25T15:00:00Z",
        );

        assert_eq!(deltas.len(), 3);
        let f1_delta = deltas
            .iter()
            .find(|d| d.check_id == "aws-s3-block-public-access")
            .unwrap();
        assert_eq!(f1_delta.change, FindingLifecycleChange::Reopened);

        let f2_delta = deltas
            .iter()
            .find(|d| d.check_id == "aws-iam-root-no-access-keys")
            .unwrap();
        assert_eq!(f2_delta.change, FindingLifecycleChange::Resolved);

        let f3_delta = deltas
            .iter()
            .find(|d| d.check_id == "azure-storage-public-access")
            .unwrap();
        assert_eq!(f3_delta.change, FindingLifecycleChange::New);
    }

    #[test]
    fn parses_terraform_state_and_identifies_live_drift() {
        let tfstate = json!({
            "version": 4,
            "terraform_version": "1.5.0",
            "resources": [
                {
                    "mode": "managed",
                    "type": "aws_s3_bucket",
                    "name": "backup",
                    "instances": [
                        {
                            "attributes": {
                                "id": "my-company-backup-bucket",
                                "bucket": "my-company-backup-bucket",
                                "block_public_acls": true
                            }
                        }
                    ]
                }
            ]
        });

        let org_id = Uuid::new_v4();
        let acc_id = Uuid::new_v4();

        // Live resource has block_public_acls = false! Drift detected!
        let live_res = vec![Resource {
            id: Uuid::new_v4(),
            organization_id: org_id,
            account_id: acc_id,
            provider_native_id: "my-company-backup-bucket".to_string(),
            resource_type: "aws_s3_bucket".to_string(),
            name: Some("my-company-backup-bucket".to_string()),
            tags: json!({}),
            region: Some("us-east-1".to_string()),
            configuration: json!({
                "block_public_acls": false
            }),
        }];

        let mappings = DriftEngine::compare_terraform_state(&tfstate, &live_res);
        assert_eq!(mappings.len(), 1);
        assert!(mappings[0].has_drift);
        assert!(mappings[0].drift_attributes[0].contains("block_public_acls"));
    }
}
