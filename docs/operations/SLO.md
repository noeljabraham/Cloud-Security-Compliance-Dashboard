# Platform Service Level Objectives (SLOs) & Reliability Targets

**Document Version:** 1.0.0  
**Target:** CloudSec Platform v0.1.0 MVP  
**Review Cadence:** Monthly  

---

## 1. Core Service Level Indicators (SLIs) & Objectives (SLOs)

| Metric / Objective | SLI Definition | Target (SLO) | Error Budget (30 days) | Alert Threshold |
| :--- | :--- | :--- | :--- | :--- |
| **API Availability** | Successful `2xx`/`3xx` responses over total HTTP requests (excluding 4xx client errors). | **>= 99.90%** | 43.2 minutes downtime / mo | Availability < 99.85% over 5m window |
| **Scan Completion Latency** | 95th percentile latency from scan start to completion for up to 10,000 resources. | **p95 < 10 mins** | 5% of completed scans | p95 > 12 mins over 1h |
| **Posture Data Freshness** | Maximum wall-clock time between completed scheduled scans for active connections. | **< 24.0 hours** | 0 connection regressions | Any active connection without scan in 26h |
| **Alert Delivery Reliability** | Successful outbound webhook deliveries (`status 2xx`) across Slack and PagerDuty channels. | **>= 99.50%** | 0.5% failed attempts | Delivery failure rate > 2% over 15m |
| **Queue Depth Stability** | Number of active scan jobs waiting in the distributed queue. | **< 20 jobs** | Instantaneous | Queue depth > 50 for > 10m |
| **Provider Throttling** | Rate of `429 Too Many Requests` or `ThrottlingException` received from cloud APIs. | **< 0.10%** | 0.10% total calls | Throttle rate > 0.5% over 5m |

---

## 2. Platform Telemetry Endpoint

The platform exposes real-time SLI/SLO metrics via:
```http
GET /api/operations/slo
Authorization: Bearer <TOKEN>
```

Example response:
```json
{
  "api_availability_pct": 99.98,
  "api_availability_target_pct": 99.90,
  "scan_completion_p95_minutes": 3.2,
  "scan_completion_target_minutes": 10.0,
  "data_freshness_max_hours": 8.5,
  "data_freshness_target_hours": 24.0,
  "alert_delivery_success_pct": 100.0,
  "alert_delivery_target_pct": 99.50,
  "queue_depth": 0,
  "provider_throttle_rate_pct": 0.02,
  "all_slos_met": true
}
```

---

## 3. Burn Rate Alerting Rules

CloudSec uses multi-window multi-burn-rate alerting to detect critical reliability regressions:
- **14.4x Burn Rate (1-hour window)**: 2% of budget consumed in 1 hour -> **P1 Alert (PagerDuty)**.
- **6x Burn Rate (6-hour window)**: 5% of budget consumed in 6 hours -> **P2 Alert (Slack Ops)**.
- **1x Burn Rate (3-day window)**: 10% of budget consumed in 3 days -> **P3 Ticket (Jira/Linear)**.

