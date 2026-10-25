# Security Incident Response & Key Rotation Runbooks

**Document Version:** 1.0.0  
**Target:** CloudSec Platform v0.1.0 MVP  
**Audience:** Security Operations (SecOps), Platform Engineering, DevOps  

---

## 1. Incident Classification Matrix

| Severity Level | Definition | Target Response (SLA) | Example Scenarios |
| :--- | :--- | :--- | :--- |
| **SEV-1 (Critical)** | Active compromise of platform credentials or cross-tenant data leakage. | Immediate (< 15 mins) | Cross-account IAM role compromised, database credentials exposed, cross-tenant finding leakage. |
| **SEV-2 (High)** | Degradation of critical security controls or unauthenticated webhook tampering. | < 1 hour | Webhook secret leak, failed lease lock causing race condition, unauthorized exception approval. |
| **SEV-3 (Medium)** | Non-exploitable vulnerability or isolated scan failure. | < 4 hours | Outdated dependency in CI, provider throttle rate exceeding threshold. |
| **SEV-4 (Low)** | Informational or cosmetic security inquiry. | < 24 hours | Minor documentation typo in remediation template. |

---

## 2. Emergency Credential Revocation Procedures

### 2.1 AWS Cross-Account Role Revocation
If an AWS connection or its external ID is suspected of compromise:
1. **Immediate Revocation via AWS CLI**:
   ```bash
   # Attach an inline deny policy to immediately block STS AssumeRole sessions
   aws iam put-role-policy \
     --role-name CloudSecSecurityAuditRole \
     --policy-name EmergencyDenyAll \
     --policy-document '{
       "Version": "2012-10-17",
       "Statement": [{
         "Effect": "Deny",
         "Action": "*",
         "Resource": "*"
       }]
     }'
   ```
2. **Revoke Active IAM Sessions**:
   ```bash
   aws iam put-role-policy \
     --role-name CloudSecSecurityAuditRole \
     --policy-name RevokeOlderSessions \
     --policy-document "{
       \"Version\": \"2012-10-17\",
       \"Statement\": [{
         \"Effect\": \"Deny\",
         \"Action\": \"*\",
         \"Resource\": \"*\",
         \"Condition\": {
           \"DateLessThan\": {
             \"aws:TokenIssueTime\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"
           }
         }
       }]
     }"
   ```
3. **Disable Connection in CloudSec API**:
   ```bash
   curl -X POST https://api.cloudsec.internal/api/connections/<CONNECTION_ID>/disable \
     -H "Authorization: Bearer $ADMIN_TOKEN"
   ```

### 2.2 Azure Service Principal Credential Revocation
1. **Delete Compromised Password Credential**:
   ```bash
   az ad app credential delete \
     --id $AZURE_CLIENT_ID \
     --key-id $KEY_ID
   ```
2. **Disable the Service Principal Object**:
   ```bash
   az ad sp update --id $AZURE_CLIENT_ID --account-enabled false
   ```

### 2.3 GCP Service Account Key Revocation
1. **Delete Compromised Key**:
   ```bash
   gcloud iam service-accounts keys delete $KEY_ID \
     --iam-account=$SERVICE_ACCOUNT_EMAIL \
     --quiet
   ```
2. **Disable Service Account**:
   ```bash
   gcloud iam service-accounts disable $SERVICE_ACCOUNT_EMAIL
   ```

---

## 3. Platform Master Key Rotation Runbook

CloudSec uses AES-256-GCM authenticated encryption for secret references. In the event of platform key rotation:

1. **Generate New Primary Key**:
   ```bash
   export NEW_MASTER_KEY=$(openssl rand -hex 32)
   ```
2. **Re-encrypt Stored Connection Secrets**:
   - The platform supports dual-key rotation: secrets encrypted with `PREVIOUS_MASTER_KEY` remain decryptable while all new updates and scans persist with `ACTIVE_MASTER_KEY`.
   - Trigger the programmatic re-encryption migration:
     ```bash
     cargo run -p cloudsec-api --bin reencrypt -- --old-key-env PREVIOUS_MASTER_KEY --new-key-env ACTIVE_MASTER_KEY
     ```
3. **Decommission Old Master Key**:
   - Verify all connection records and webhook secrets have been re-encrypted.
   - Remove `PREVIOUS_MASTER_KEY` from deployment environment variables / secrets manager.

---

## 4. Tenant Data Deletion & Offboarding Procedure

When a tenant offboards or requests GDPR/CCPA data erasure:
1. **Soft Deletion & Connection Severing**:
   - Disable all cloud connections belonging to the organization.
   - Delete all scheduled recurring scan jobs.
2. **Hard Purge Execution**:
   - Run the deletion command targeting the organization UUID:
     ```bash
     DELETE FROM finding_exceptions WHERE organization_id = $ORG_ID;
     DELETE FROM remediations WHERE organization_id = $ORG_ID;
     DELETE FROM findings WHERE organization_id = $ORG_ID;
     DELETE FROM resources WHERE organization_id = $ORG_ID;
     DELETE FROM scan_jobs WHERE organization_id = $ORG_ID;
     DELETE FROM scan_runs WHERE organization_id = $ORG_ID;
     DELETE FROM cloud_connections WHERE organization_id = $ORG_ID;
     DELETE FROM audit_logs WHERE organization_id = $ORG_ID;
     DELETE FROM organizations WHERE id = $ORG_ID;
     ```
3. **Audit Log of Erasure**:
   - Record an immutable out-of-band erasure record in SecOps logging storage noting tenant ID, requesting identity, and timestamp.

