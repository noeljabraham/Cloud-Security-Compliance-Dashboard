# CloudSec REST API Reference

**Base URL**: `http://127.0.0.1:8080`  
**API Specification**: OpenAPI 3.1.0 available at `GET /api/openapi.json`  
**Authentication**: `Authorization: Bearer <JWT_OR_ROLE_TOKEN>`  

---

## 1. Authentication & Health

### 1.1 Health Probe
```bash
curl -X GET http://127.0.0.1:8080/health
```

### 1.2 Readiness Probe
```bash
curl -X GET http://127.0.0.1:8080/ready
```

---

## 2. Connections & Cloud Onboarding

### 2.1 List Connections
```bash
curl -X GET http://127.0.0.1:8080/api/connections \
  -H "Authorization: Bearer engineer-token"
```

### 2.2 Onboard AWS Account (STS AssumeRole)
```bash
curl -X POST http://127.0.0.1:8080/api/connections \
  -H "Authorization: Bearer admin-token" \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "aws",
    "name": "Production AWS Account",
    "metadata": {
      "role_arn": "arn:aws:iam::123456789012:role/CloudSecSecurityAuditRole",
      "account_id": "123456789012",
      "external_id": "ext-id-prod-12345678"
    }
  }'
```

### 2.3 Test Connection Connectivity
```bash
curl -X POST http://127.0.0.1:8080/api/connections/<CONNECTION_ID>/test \
  -H "Authorization: Bearer engineer-token"
```

---

## 3. Scans & Assessment Execution

### 3.1 Trigger Security Scan
```bash
curl -X POST http://127.0.0.1:8080/api/scans \
  -H "Authorization: Bearer engineer-token" \
  -H "Content-Type: application/json" \
  -d '{"profile": "strict_production"}'
```

### 3.2 Cancel Running Scan
```bash
curl -X POST http://127.0.0.1:8080/api/scans/<SCAN_ID>/cancel \
  -H "Authorization: Bearer engineer-token"
```

---

## 4. Findings & Remediation Guidance

### 4.1 List Findings with Faceted Search
```bash
curl -X GET "http://127.0.0.1:8080/api/findings?severity=critical&status=open" \
  -H "Authorization: Bearer engineer-token"
```

### 4.2 Generate Remediation Guidance
```bash
curl -X POST http://127.0.0.1:8080/api/remediations/generate \
  -H "Authorization: Bearer engineer-token" \
  -H "Content-Type: application/json" \
  -d '{
    "check_id": "aws-s3-block-public-access",
    "target_resource": "my-secure-bucket",
    "account_id": "123456789012",
    "region": "us-east-1"
  }'
```

---

## 5. Continuous Monitoring, Drift & Alerting

### 5.1 Promote Baseline Posture
```bash
curl -X POST http://127.0.0.1:8080/api/drift/baseline \
  -H "Authorization: Bearer admin-token" \
  -H "Content-Type: application/json" \
  -d '{
    "scan_run_id": "<SCAN_ID>",
    "notes": "Approved Q4 release baseline posture"
  }'
```

### 5.2 Compare Terraform State Drift
```bash
curl -X POST http://127.0.0.1:8080/api/drift/terraform \
  -H "Authorization: Bearer engineer-token" \
  -H "Content-Type: application/json" \
  -d '{"terraform_state": { "version": 4, "resources": [...] }}'
```

### 5.3 Test Webhook Alert Destination
```bash
curl -X POST http://127.0.0.1:8080/api/alerts/destinations/<DESTINATION_ID>/test \
  -H "Authorization: Bearer admin-token"
```

### 5.4 Export Security Report (PDF / Markdown / CSV / JSON)
```bash
curl -X POST http://127.0.0.1:8080/api/reports/export \
  -H "Authorization: Bearer engineer-token" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Quarterly Technical Audit",
    "format": "pdf",
    "is_partial_data": false
  }'
```

---

## 6. Operations & Retention

### 6.1 Query Platform SLO Status
```bash
curl -X GET http://127.0.0.1:8080/api/operations/slo \
  -H "Authorization: Bearer engineer-token"
```

### 6.2 Execute Retention Cleanup (Dry-Run or Live)
```bash
curl -X POST http://127.0.0.1:8080/api/operations/cleanup \
  -H "Authorization: Bearer admin-token" \
  -H "Content-Type: application/json" \
  -d '{
    "retention_days": 90,
    "dry_run": true
  }'
```

