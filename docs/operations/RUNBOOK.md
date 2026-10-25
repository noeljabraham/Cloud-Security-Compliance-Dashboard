# CloudSec Operations & Deployment Runbook

**Document Version:** 1.0.0  
**Target:** CloudSec Platform v0.1.0 MVP  
**Audience:** Site Reliability Engineers (SRE), Platform Operations  

---

## 1. Zero-Downtime Deployment & Rolling Upgrades

CloudSec is deployed as a modular monolith composed of stateless API/worker containers backed by PostgreSQL and managed KMS secrets.

### 1.1 Deployment Sequence
1. **Pre-flight Migration Verification**:
   - Backward-compatible schema migrations are tested against the staging database before rolling deployments:
     ```bash
     cargo run -p cloudsec-api --bin migrate
     ```
   - Rules: All migrations must be additive (new nullable columns or tables first; drops only after full version deprecation).
2. **Rolling Pod / Container Update**:
   - Kubernetes / ECS rolling update strategy (`maxUnavailable: 0`, `maxSurge: 1`).
   - Health check probes:
     - **Liveness Probe**: `GET /health` (expects HTTP 200 within 2s)
     - **Readiness Probe**: `GET /ready` (expects HTTP 200 only after database connection pools and registered checks are initialized)
3. **Traffic Drain & Zero Disruption**:
   - In-flight scans use cancellation tokens and save stage checkpoints (`ScanExecutionStage`) in Redis/memory.
   - When a worker pod receives `SIGTERM`, it completes the current check stage and flushes checkpoints before exiting.

---

## 2. Rollback Runbook

If a critical defect or regression is detected in a new release:
1. **Trigger Rolling Rollback**:
   ```bash
   kubectl rollout undo deployment/cloudsec-api -n cloudsec
   kubectl rollout undo deployment/cloudsec-worker -n cloudsec
   ```
2. **Verify Database Compatibility**:
   - Because migrations follow additive zero-downtime rules, old API code functions against the migrated database.
3. **Validate Operational Telemetry**:
   ```bash
   curl -f http://127.0.0.1:8080/api/operations/slo -H "Authorization: Bearer $ENGINEER_TOKEN"
   ```

---

## 3. Disaster Recovery & Restoration (RPO < 1h, RTO < 30m)

### 3.1 Point-in-Time Recovery (PITR)
CloudSec production uses AWS RDS / Cloud SQL with automated continuous WAL archiving and daily snapshot backups.

1. **Restore to Alternate Instance**:
   ```bash
   aws rds restore-db-instance-to-point-in-time \
     --source-db-instance-identifier cloudsec-prod-db \
     --target-db-instance-identifier cloudsec-restored-db \
     --restore-time "2026-10-25T14:30:00Z" \
     --db-subnet-group-name cloudsec-private-subnets
   ```
2. **Restore from Snapshot Script**:
   ```bash
   ./scripts/backup_restore.sh restore backups/cloudsec_backup_latest.sql.gz
   ```
3. **Verify Integrity**:
   - Run health check and verify tenant count:
     ```bash
     curl http://127.0.0.1:8080/api/connections -H "Authorization: Bearer $ADMIN_TOKEN"
     ```

---

## 4. Retention Policy & Automated Cleanup

To maintain database query latency and storage cost efficiency:
- Scan runs, raw evidence snapshots, and resolved findings older than the retention threshold (default: 90 days) can be pruned.
- **Dry-run Execution (Auditing impact without deleting)**:
  ```bash
  curl -X POST http://127.0.0.1:8080/api/operations/cleanup \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"retention_days": 90, "dry_run": true}'
  ```
- **Live Prune Execution**:
  ```bash
  curl -X POST http://127.0.0.1:8080/api/operations/cleanup \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"retention_days": 90, "dry_run": false}'
  ```
- Every cleanup execution automatically emits an immutable audit event (`retention.cleanup_executed`) recording the number of purged entities.

