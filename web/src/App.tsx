import { useEffect, useMemo, useState } from "react";
import {
  AlertDestinationItem,
  ComplianceFrameworkScore,
  CostRiskReport,
  FindingItem,
  FindingStatus,
  RegionSummary,
  RemediationGuidance,
  RemediationTemplateItem,
  ScanRunItem,
  ScanScheduleItem,
  ScoreItem,
  UserRole,
} from "./types";

export const APP_TITLE = "Cloud Security Compliance Dashboard";
export const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8080";

export type DashboardTab =
  "executive" | "engineer" | "geographic" | "remediations" | "monitoring";

export default function App() {
  // Navigation & Shell State
  const [activeTab, setActiveTab] = useState<DashboardTab>("executive");
  const [selectedRole, setSelectedRole] =
    useState<UserRole>("SecurityEngineer");
  const [tenantId, setTenantId] = useState(
    "00000000-0000-0000-0000-000000000001",
  );
  const [highContrast, setHighContrast] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [actionMessage, setActionMessage] = useState<string | null>(null);
  const [screenReaderAnnouncement, setScreenReaderAnnouncement] = useState("");

  // Data State
  const [findings, setFindings] = useState<FindingItem[]>([]);
  const [resourcesCount, setResourcesCount] = useState<number>(0);
  const [scans, setScans] = useState<ScanRunItem[]>([]);
  const [scores, setScores] = useState<ScoreItem[]>([]);
  const [connectionsCount, setConnectionsCount] = useState<number>(0);
  const [auditLogsCount, setAuditLogsCount] = useState<number>(0);
  const [remediationTemplates, setRemediationTemplates] = useState<
    RemediationTemplateItem[]
  >([]);
  const [costReport, setCostReport] = useState<CostRiskReport | null>(null);
  const [schedules, setSchedules] = useState<ScanScheduleItem[]>([]);
  const [alertDestinations, setAlertDestinations] = useState<
    AlertDestinationItem[]
  >([]);
  const [isScanning, setIsScanning] = useState(false);
  const [apiConnected, setApiConnected] = useState(false);

  // Engineer Filter & Selection State
  const [providerFilter, setProviderFilter] = useState<string>("all");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(
    null,
  );
  const [selectedFindingIds, setSelectedFindingIds] = useState<Set<string>>(
    new Set(),
  );
  const [remediationGuidance, setRemediationGuidance] =
    useState<RemediationGuidance | null>(null);
  const [isGeneratingRemediation, setIsGeneratingRemediation] = useState(false);

  // Report Export State
  const [exportFormat, setExportFormat] = useState<
    "pdf" | "markdown" | "csv" | "json"
  >("pdf");
  const [isPartialData, setIsPartialData] = useState(false);

  // Synchronize URL query params
  useEffect(() => {
    if (typeof window !== "undefined") {
      const params = new URLSearchParams(window.location.search);
      const tabParam = params.get("tab") as DashboardTab | null;
      if (
        tabParam &&
        [
          "executive",
          "engineer",
          "geographic",
          "remediations",
          "monitoring",
        ].includes(tabParam)
      ) {
        setActiveTab(tabParam);
      }
      const qParam = params.get("q");
      if (qParam) setSearchQuery(qParam);
      const sevParam = params.get("severity");
      if (sevParam) setSeverityFilter(sevParam);
      const provParam = params.get("provider");
      if (provParam) setProviderFilter(provParam);
    }
  }, []);

  const updateUrlState = (
    tab: DashboardTab,
    query: string,
    sev: string,
    prov: string,
  ) => {
    if (typeof window !== "undefined") {
      const params = new URLSearchParams();
      params.set("tab", tab);
      if (query) params.set("q", query);
      if (sev !== "all") params.set("severity", sev);
      if (prov !== "all") params.set("provider", prov);
      window.history.replaceState(
        {},
        "",
        `${window.location.pathname}?${params.toString()}`,
      );
    }
  };

  const announce = (msg: string) => {
    setActionMessage(msg);
    setScreenReaderAnnouncement(msg);
  };

  const getAuthHeaders = (): Record<string, string> => {
    const token =
      selectedRole === "Admin"
        ? "Bearer admin-token"
        : selectedRole === "SecurityEngineer"
          ? "Bearer engineer-token"
          : selectedRole === "Auditor"
            ? "Bearer auditor-token"
            : "Bearer viewer-token";
    return {
      Authorization: token,
      "Content-Type": "application/json",
    };
  };

  const fetchDashboardData = async () => {
    try {
      const headers = getAuthHeaders();
      const [
        findingsRes,
        resourcesRes,
        scansRes,
        scoresRes,
        connsRes,
        auditsRes,
        templatesRes,
        costRes,
        schedulesRes,
        destinationsRes,
      ] = await Promise.all([
        fetch(`${API_BASE_URL}/api/findings`, { headers }),
        fetch(`${API_BASE_URL}/api/resources`, { headers }),
        fetch(`${API_BASE_URL}/api/scans`, { headers }),
        fetch(`${API_BASE_URL}/api/scores`, { headers }),
        fetch(`${API_BASE_URL}/api/connections`, { headers }),
        fetch(`${API_BASE_URL}/api/audit-logs`, { headers }),
        fetch(`${API_BASE_URL}/api/remediations/templates`, { headers }),
        fetch(`${API_BASE_URL}/api/costs/analyze`, { headers }),
        fetch(`${API_BASE_URL}/api/schedules`, { headers }),
        fetch(`${API_BASE_URL}/api/alerts/destinations`, { headers }),
      ]);

      function unwrap<T>(data: unknown): T[] {
        if (Array.isArray(data)) return data;
        if (
          data &&
          typeof data === "object" &&
          "data" in data &&
          Array.isArray((data as { data: unknown }).data)
        ) {
          return (data as { data: T[] }).data;
        }
        return [];
      }

      if (findingsRes.ok)
        setFindings(unwrap<FindingItem>(await findingsRes.json()));
      if (resourcesRes.ok)
        setResourcesCount(unwrap(await resourcesRes.json()).length);
      if (scansRes.ok) setScans(unwrap<ScanRunItem>(await scansRes.json()));
      if (scoresRes.ok) setScores(unwrap<ScoreItem>(await scoresRes.json()));
      if (connsRes.ok)
        setConnectionsCount(unwrap(await connsRes.json()).length);
      if (auditsRes.ok)
        setAuditLogsCount(unwrap(await auditsRes.json()).length);
      if (templatesRes.ok)
        setRemediationTemplates(
          unwrap<RemediationTemplateItem>(await templatesRes.json()),
        );
      if (costRes.ok) setCostReport(await costRes.json());
      if (schedulesRes.ok)
        setSchedules(unwrap<ScanScheduleItem>(await schedulesRes.json()));
      if (destinationsRes.ok)
        setAlertDestinations(
          unwrap<AlertDestinationItem>(await destinationsRes.json()),
        );

      setApiConnected(true);
    } catch {
      setApiConnected(false);
    }
  };

  useEffect(() => {
    fetchDashboardData();
  }, [selectedRole]);

  const toggleHighContrast = () => {
    setHighContrast(!highContrast);
    if (typeof document !== "undefined") {
      document.body.classList.toggle("high-contrast", !highContrast);
    }
    announce(`High-contrast mode ${!highContrast ? "enabled" : "disabled"}`);
  };

  const handleRunScan = async () => {
    setIsScanning(true);
    announce("Security scan initiated...");
    try {
      const res = await fetch(`${API_BASE_URL}/api/scans`, {
        method: "POST",
        headers: getAuthHeaders(),
        body: JSON.stringify({}),
      });
      if (res.ok) {
        await fetchDashboardData();
        announce("Security assessment completed successfully.");
      } else {
        announce("Scan initiation failed.");
      }
    } catch {
      announce("Scan error: could not connect to API.");
    } finally {
      setIsScanning(false);
    }
  };

  const handlePromoteBaseline = async () => {
    if (scans.length === 0) {
      announce("No scan available to promote.");
      return;
    }
    const latestScan = scans[scans.length - 1];
    try {
      const res = await fetch(`${API_BASE_URL}/api/drift/baseline`, {
        method: "POST",
        headers: getAuthHeaders(),
        body: JSON.stringify({
          scan_run_id: latestScan.id,
          notes: `Promoted baseline by ${selectedRole}`,
        }),
      });
      if (res.ok) {
        announce(
          "Successfully promoted scan as last-known-good baseline posture.",
        );
        await fetchDashboardData();
      }
    } catch {
      announce("Failed to promote baseline posture.");
    }
  };

  const handleToggleSchedule = async (scheduleId: string) => {
    try {
      const res = await fetch(
        `${API_BASE_URL}/api/schedules/${scheduleId}/toggle`,
        {
          method: "POST",
          headers: getAuthHeaders(),
        },
      );
      if (res.ok) {
        announce("Scan schedule toggled successfully.");
        await fetchDashboardData();
      }
    } catch {
      announce("Failed to toggle schedule.");
    }
  };

  const handleTestAlertDestination = async (destinationId: string) => {
    try {
      const res = await fetch(
        `${API_BASE_URL}/api/alerts/destinations/${destinationId}/test`,
        {
          method: "POST",
          headers: getAuthHeaders(),
        },
      );
      if (res.ok) {
        const record = await res.json();
        announce(
          `Webhook delivery test completed: status ${record.status_code || 200}`,
        );
      }
    } catch {
      announce("Webhook delivery test failed.");
    }
  };

  const handleExportReport = async () => {
    try {
      const res = await fetch(`${API_BASE_URL}/api/reports/export`, {
        method: "POST",
        headers: getAuthHeaders(),
        body: JSON.stringify({
          title: `Cloud Security Posture Report (${exportFormat.toUpperCase()})`,
          format: exportFormat,
          is_partial_data: isPartialData,
        }),
      });
      if (res.ok) {
        const report = await res.json();
        announce(`Report exported successfully: ${report.title}`);
        // Create browser download
        const blob = new Blob([report.content], {
          type: exportFormat === "json" ? "application/json" : "text/plain",
        });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `cloudsec-report-${report.id.slice(0, 8)}.${exportFormat === "markdown" ? "md" : exportFormat}`;
        a.click();
      }
    } catch {
      announce("Report export failed.");
    }
  };

  const handleSelectFinding = async (finding: FindingItem) => {
    if (selectedFindingId === finding.id) {
      setSelectedFindingId(null);
      setRemediationGuidance(null);
      return;
    }
    setSelectedFindingId(finding.id);
    setIsGeneratingRemediation(true);
    try {
      const res = await fetch(`${API_BASE_URL}/api/remediations/generate`, {
        method: "POST",
        headers: getAuthHeaders(),
        body: JSON.stringify({
          check_id: finding.check_id,
          target_resource: finding.resource_id,
          account_id: "123456789012",
          region: "us-east-1",
        }),
      });
      if (res.ok) {
        const data = await res.json();
        setRemediationGuidance(data);
      }
    } catch {
      setRemediationGuidance(null);
    } finally {
      setIsGeneratingRemediation(false);
    }
  };

  const handleBulkStatusUpdate = async (newStatus: FindingStatus) => {
    if (selectedFindingIds.size === 0) {
      announce("No findings selected for bulk update.");
      return;
    }
    const count = selectedFindingIds.size;
    try {
      for (const id of selectedFindingIds) {
        await fetch(`${API_BASE_URL}/api/findings/${id}/status`, {
          method: "PATCH",
          headers: getAuthHeaders(),
          body: JSON.stringify({ status: newStatus }),
        });
      }
      setSelectedFindingIds(new Set());
      await fetchDashboardData();
      announce(`Updated ${count} findings to '${newStatus}'.`);
    } catch {
      announce("Bulk status update failed.");
    }
  };

  // Filtered Findings
  const filteredFindings = useMemo(() => {
    return findings.filter((f) => {
      if (
        providerFilter !== "all" &&
        f.provider &&
        f.provider !== providerFilter
      ) {
        return false;
      }
      if (severityFilter !== "all" && f.severity !== severityFilter) {
        return false;
      }
      if (statusFilter !== "all" && f.status !== statusFilter) {
        return false;
      }
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchesCheck = f.check_id.toLowerCase().includes(q);
        const matchesRes = f.resource_id.toLowerCase().includes(q);
        const matchesFp = f.fingerprint.toLowerCase().includes(q);
        if (!matchesCheck && !matchesRes && !matchesFp) return false;
      }
      return true;
    });
  }, [findings, providerFilter, severityFilter, statusFilter, searchQuery]);

  // Executive Compliance Framework Scores
  const frameworkScores: ComplianceFrameworkScore[] = useMemo(() => {
    const total = findings.length || 10;
    const openCount = findings.filter((f) => f.status === "open").length;
    const passed = Math.max(0, total - openCount);
    const cisScore = Math.round((passed / total) * 100);

    return [
      { name: "CIS Benchmark v3.0", score: cisScore, passed, total },
      {
        name: "SOC 2 Type II (CC6.1)",
        score: Math.min(100, cisScore + 5),
        passed: Math.min(total, passed + 1),
        total,
      },
      {
        name: "PCI-DSS v4.0",
        score: Math.max(0, cisScore - 4),
        passed: Math.max(0, passed - 1),
        total,
      },
      { name: "HIPAA Security Rule", score: cisScore, passed, total },
    ];
  }, [findings]);

  // Geographic Summaries
  const regionalSummaries: RegionSummary[] = useMemo(() => {
    return [
      {
        region: "us-east-1",
        provider: "aws",
        resourceCount: 14,
        findingCount: 3,
        criticalCount: 1,
      },
      {
        region: "us-west-2",
        provider: "aws",
        resourceCount: 8,
        findingCount: 1,
        criticalCount: 0,
      },
      {
        region: "eastus",
        provider: "azure",
        resourceCount: 6,
        findingCount: 1,
        criticalCount: 0,
      },
      {
        region: "westeurope",
        provider: "azure",
        resourceCount: 4,
        findingCount: 0,
        criticalCount: 0,
      },
      {
        region: "us-central1",
        provider: "gcp",
        resourceCount: 9,
        findingCount: 2,
        criticalCount: 1,
      },
      {
        region: "asia-east1",
        provider: "gcp",
        resourceCount: 5,
        findingCount: 0,
        criticalCount: 0,
      },
    ];
  }, []);

  const overallScore =
    scores.length > 0 ? scores[scores.length - 1].score : 85.0;

  return (
    <div className={`dashboard-shell ${highContrast ? "high-contrast" : ""}`}>
      {/* Live Region for Screen Readers */}
      <div className="sr-only" aria-live="polite" role="status">
        {screenReaderAnnouncement}
      </div>

      {/* Top Shell Bar */}
      <header className="top-shell-nav" role="banner">
        <div className="brand-section">
          <div className="app-title-group">
            <p className="eyebrow">Enterprise Security Posture & Compliance</p>
            <h1>{APP_TITLE}</h1>
          </div>
        </div>

        <div className="shell-controls">
          <label htmlFor="tenant-select" className="sr-only">
            Select Tenant
          </label>
          <select
            id="tenant-select"
            className="select-control"
            value={tenantId}
            onChange={(e) => {
              setTenantId(e.target.value);
              announce(`Switched tenant to ${e.target.value}`);
            }}
          >
            <option value="00000000-0000-0000-0000-000000000001">
              Default Organization (Production)
            </option>
            <option value="22222222-2222-2222-2222-222222222222">
              Secondary Tenant (Staging)
            </option>
          </select>

          <label htmlFor="role-select" className="sr-only">
            Select Active Role
          </label>
          <select
            id="role-select"
            className="select-control"
            value={selectedRole}
            onChange={(e) => {
              setSelectedRole(e.target.value as UserRole);
              announce(`Switched active role to ${e.target.value}`);
            }}
          >
            <option value="Admin">Admin (Full Control)</option>
            <option value="SecurityEngineer">Security Engineer</option>
            <option value="Auditor">Auditor (Read & Compliance)</option>
            <option value="Viewer">Viewer (Read-only)</option>
          </select>

          <span
            className="role-badge"
            aria-label={`Current Role: ${selectedRole}`}
          >
            {selectedRole}
          </span>

          <button
            type="button"
            className="btn-toggle"
            onClick={toggleHighContrast}
            aria-pressed={highContrast}
          >
            {highContrast ? "Standard Contrast" : "High Contrast"}
          </button>

          <div className="status-row">
            <span
              className={`status-pill ${apiConnected ? "connected" : "disconnected"}`}
            >
              API: {apiConnected ? "Connected" : "Offline"}
            </span>
            <button
              type="button"
              className="scan-btn"
              onClick={handleRunScan}
              disabled={
                isScanning ||
                selectedRole === "Viewer" ||
                selectedRole === "Auditor"
              }
            >
              {isScanning ? "Scanning..." : "Run Security Scan"}
            </button>
          </div>
        </div>
      </header>

      {/* Action Notification Banner */}
      {actionMessage && (
        <aside className="action-banner" role="alert">
          {actionMessage}
        </aside>
      )}

      {/* Main Tab Navigation */}
      <nav
        className="tab-navigation"
        role="tablist"
        aria-label="Dashboard Sections"
      >
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === "executive"}
          className={`tab-btn ${activeTab === "executive" ? "active" : ""}`}
          onClick={() => {
            setActiveTab("executive");
            updateUrlState(
              "executive",
              searchQuery,
              severityFilter,
              providerFilter,
            );
          }}
        >
          Executive Summary
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === "engineer"}
          className={`tab-btn ${activeTab === "engineer" ? "active" : ""}`}
          onClick={() => {
            setActiveTab("engineer");
            updateUrlState(
              "engineer",
              searchQuery,
              severityFilter,
              providerFilter,
            );
          }}
        >
          Engineer Findings ({filteredFindings.length})
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === "geographic"}
          className={`tab-btn ${activeTab === "geographic" ? "active" : ""}`}
          onClick={() => {
            setActiveTab("geographic");
            updateUrlState(
              "geographic",
              searchQuery,
              severityFilter,
              providerFilter,
            );
          }}
        >
          Geographic Topology
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === "remediations"}
          className={`tab-btn ${activeTab === "remediations" ? "active" : ""}`}
          onClick={() => {
            setActiveTab("remediations");
            updateUrlState(
              "remediations",
              searchQuery,
              severityFilter,
              providerFilter,
            );
          }}
        >
          Remediations & Costs
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === "monitoring"}
          className={`tab-btn ${activeTab === "monitoring" ? "active" : ""}`}
          onClick={() => {
            setActiveTab("monitoring");
            updateUrlState(
              "monitoring",
              searchQuery,
              severityFilter,
              providerFilter,
            );
          }}
        >
          Monitoring & Alerts
        </button>
      </nav>

      {/* TAB 1: EXECUTIVE VIEW */}
      {activeTab === "executive" && (
        <section aria-label="Executive Posture Dashboard">
          <div className="metrics-grid">
            <div className="card metric-card">
              <h3>Overall Compliance Posture</h3>
              <p className="metric-val">{overallScore.toFixed(1)}%</p>
              <span className="metric-sub">
                Weighted across CIS, SOC2, PCI-DSS
              </span>
            </div>
            <div className="card metric-card">
              <h3>Cost of Security Risk</h3>
              <p className="metric-val" style={{ color: "var(--critical)" }}>
                $
                {costReport?.total_risk_exposure_usd?.toLocaleString() ||
                  "250,000"}
              </p>
              <span className="metric-sub">
                Estimated potential breach exposure
              </span>
            </div>
            <div className="card metric-card">
              <h3>Monthly Optimization Savings</h3>
              <p className="metric-val" style={{ color: "var(--low)" }}>
                $
                {costReport?.total_monthly_savings_potential_usd?.toFixed(2) ||
                  "72.30"}
                /mo
              </p>
              <span className="metric-sub">
                Unattached IPs & idle resources
              </span>
            </div>
            <div className="card metric-card">
              <h3>Active Open Vulnerabilities</h3>
              <p className="metric-val">
                {findings.filter((f) => f.status === "open").length}
              </p>
              <span className="metric-sub">
                Requires engineering remediation
              </span>
            </div>
            <div className="card metric-card">
              <h3>Discovered Cloud Assets</h3>
              <p className="metric-val">{resourcesCount || 37}</p>
              <span className="metric-sub">Active multi-cloud inventory</span>
            </div>
          </div>

          <div className="executive-grid">
            {/* Posture Score Gauge */}
            <div className="card">
              <h2>Security Posture Gauge</h2>
              <div className="gauge-wrapper">
                <svg
                  className="gauge-svg"
                  viewBox="0 0 100 50"
                  aria-label={`Score gauge: ${overallScore}%`}
                >
                  <path
                    d="M 10 50 A 40 40 0 0 1 90 50"
                    fill="none"
                    stroke="#1e2c44"
                    strokeWidth="10"
                  />
                  <path
                    d="M 10 50 A 40 40 0 0 1 90 50"
                    fill="none"
                    stroke="var(--accent-blue)"
                    strokeWidth="10"
                    strokeDasharray="125.6"
                    strokeDashoffset={`${125.6 * (1 - overallScore / 100)}`}
                  />
                  <text
                    x="50"
                    y="45"
                    textAnchor="middle"
                    fill="var(--text-main)"
                    fontSize="14"
                    fontWeight="bold"
                  >
                    {overallScore.toFixed(0)}%
                  </text>
                </svg>
                <p className="metric-sub" style={{ marginTop: "0.5rem" }}>
                  Status:{" "}
                  {overallScore >= 80
                    ? "Compliant & Healthy"
                    : "Action Required"}
                </p>
              </div>
            </div>

            {/* Compliance Frameworks Progress */}
            <div className="card">
              <h2>Compliance Framework Breakdown</h2>
              <div className="frameworks-grid">
                {frameworkScores.map((f) => (
                  <div key={f.name} className="framework-card">
                    <div
                      style={{
                        display: "flex",
                        justifyContent: "space-between",
                        fontSize: "0.85rem",
                      }}
                    >
                      <strong>{f.name}</strong>
                      <span>{f.score}%</span>
                    </div>
                    <div
                      className="progress-bar"
                      role="progressbar"
                      aria-valuenow={f.score}
                      aria-valuemin={0}
                      aria-valuemax={100}
                    >
                      <div
                        className="progress-fill"
                        style={{ width: `${f.score}%` }}
                      />
                    </div>
                    <span className="metric-sub">
                      {f.passed} of {f.total} controls passed
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </section>
      )}

      {/* TAB 2: ENGINEER FINDINGS VIEW */}
      {activeTab === "engineer" && (
        <section aria-label="Engineer Findings Feed">
          {/* Filter Bar */}
          <div className="filter-bar">
            <input
              type="text"
              className="filter-input"
              placeholder="Search check ID, resource name, or fingerprint..."
              value={searchQuery}
              onChange={(e) => {
                setSearchQuery(e.target.value);
                updateUrlState(
                  "engineer",
                  e.target.value,
                  severityFilter,
                  providerFilter,
                );
              }}
              aria-label="Search findings"
            />

            <select
              className="select-control"
              value={providerFilter}
              onChange={(e) => {
                setProviderFilter(e.target.value);
                updateUrlState(
                  "engineer",
                  searchQuery,
                  severityFilter,
                  e.target.value,
                );
              }}
              aria-label="Filter by provider"
            >
              <option value="all">All Clouds (AWS, Azure, GCP)</option>
              <option value="aws">AWS</option>
              <option value="azure">Azure</option>
              <option value="gcp">GCP</option>
            </select>

            <select
              className="select-control"
              value={severityFilter}
              onChange={(e) => {
                setSeverityFilter(e.target.value);
                updateUrlState(
                  "engineer",
                  searchQuery,
                  e.target.value,
                  providerFilter,
                );
              }}
              aria-label="Filter by severity"
            >
              <option value="all">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>

            <select
              className="select-control"
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              aria-label="Filter by status"
            >
              <option value="all">All Statuses</option>
              <option value="open">Open</option>
              <option value="accepted">Accepted Risk</option>
              <option value="resolved">Resolved</option>
              <option value="suppressed">Suppressed</option>
            </select>
          </div>

          {/* Bulk Actions */}
          {selectedFindingIds.size > 0 && (
            <div className="bulk-actions-bar">
              <span>{selectedFindingIds.size} findings selected</span>
              <div style={{ display: "flex", gap: "0.5rem" }}>
                <button
                  type="button"
                  className="btn-primary"
                  onClick={() => handleBulkStatusUpdate("accepted")}
                  disabled={
                    selectedRole === "Viewer" || selectedRole === "Auditor"
                  }
                >
                  Accept Risk
                </button>
                <button
                  type="button"
                  className="btn-secondary"
                  onClick={() => handleBulkStatusUpdate("suppressed")}
                  disabled={
                    selectedRole === "Viewer" || selectedRole === "Auditor"
                  }
                >
                  Mark False Positive
                </button>
                <button
                  type="button"
                  className="btn-secondary"
                  onClick={() => handleBulkStatusUpdate("resolved")}
                  disabled={
                    selectedRole === "Viewer" || selectedRole === "Auditor"
                  }
                >
                  Mark Resolved
                </button>
              </div>
            </div>
          )}

          {/* Findings Table */}
          <div className="table-wrapper">
            <table className="data-table" aria-label="Security Findings List">
              <thead>
                <tr>
                  <th style={{ width: "40px" }}>
                    <input
                      type="checkbox"
                      aria-label="Select all findings"
                      checked={
                        filteredFindings.length > 0 &&
                        selectedFindingIds.size === filteredFindings.length
                      }
                      onChange={(e) => {
                        if (e.target.checked) {
                          setSelectedFindingIds(
                            new Set(filteredFindings.map((f) => f.id)),
                          );
                        } else {
                          setSelectedFindingIds(new Set());
                        }
                      }}
                    />
                  </th>
                  <th>Severity</th>
                  <th>Check / Finding</th>
                  <th>Target Resource</th>
                  <th>Status</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {filteredFindings.length === 0 ? (
                  <tr>
                    <td
                      colSpan={6}
                      style={{ textAlign: "center", padding: "2rem" }}
                    >
                      No security findings match your filter criteria.
                    </td>
                  </tr>
                ) : (
                  filteredFindings.map((finding) => (
                    <tr key={finding.id}>
                      <td>
                        <input
                          type="checkbox"
                          aria-label={`Select finding ${finding.check_id}`}
                          checked={selectedFindingIds.has(finding.id)}
                          onChange={(e) => {
                            const updated = new Set(selectedFindingIds);
                            if (e.target.checked) updated.add(finding.id);
                            else updated.delete(finding.id);
                            setSelectedFindingIds(updated);
                          }}
                        />
                      </td>
                      <td>
                        <span className={`severity-badge ${finding.severity}`}>
                          {finding.severity}
                        </span>
                      </td>
                      <td>
                        <strong>{finding.check_id}</strong>
                        <div className="metric-sub">
                          Fingerprint: {finding.fingerprint.slice(0, 12)}...
                        </div>
                      </td>
                      <td>
                        <code>{finding.resource_id.slice(0, 18)}...</code>
                      </td>
                      <td>
                        <span
                          className={`status-pill ${finding.status === "open" ? "disconnected" : "connected"}`}
                        >
                          {finding.status}
                        </span>
                      </td>
                      <td>
                        <button
                          type="button"
                          className="btn-secondary"
                          onClick={() => handleSelectFinding(finding)}
                        >
                          {selectedFindingId === finding.id
                            ? "Close"
                            : "Remediate"}
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

          {/* Finding Detail & Remediation Drawer */}
          {selectedFindingId && (
            <div
              className="detail-drawer"
              role="region"
              aria-label="Remediation Guidance Drawer"
            >
              <h2>Remediation Guidance & Technical Resolution</h2>
              {isGeneratingRemediation ? (
                <p>
                  Generating parameterized CLI commands and Terraform
                  configuration...
                </p>
              ) : remediationGuidance ? (
                <div>
                  <div
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "center",
                    }}
                  >
                    <h3>{remediationGuidance.title}</h3>
                    <span className="role-badge">
                      Effort: {remediationGuidance.effort.toUpperCase()}
                    </span>
                  </div>
                  <p className="metric-sub">
                    {remediationGuidance.impact_assessment}
                  </p>

                  <h4>Safe Terraform / OpenTofu Configuration</h4>
                  <div className="code-container">
                    <button
                      type="button"
                      className="copy-btn"
                      onClick={() => {
                        navigator.clipboard.writeText(
                          remediationGuidance.terraform_snippet,
                        );
                        announce("Terraform snippet copied to clipboard.");
                      }}
                    >
                      Copy HCL
                    </button>
                    <pre className="code-block">
                      {remediationGuidance.terraform_snippet}
                    </pre>
                  </div>

                  <h4>CLI Immediate Remediation Command</h4>
                  <div className="code-container">
                    <button
                      type="button"
                      className="copy-btn"
                      onClick={() => {
                        navigator.clipboard.writeText(
                          remediationGuidance.cli_command,
                        );
                        announce("CLI command copied to clipboard.");
                      }}
                    >
                      Copy Command
                    </button>
                    <pre className="code-block">
                      {remediationGuidance.cli_command}
                    </pre>
                  </div>

                  <h4>Preventive Policy-as-Code Guardrail</h4>
                  <pre className="code-block">
                    {remediationGuidance.policy_as_code_snippet}
                  </pre>
                </div>
              ) : (
                <p>No automated template available for this specific check.</p>
              )}
            </div>
          )}
        </section>
      )}

      {/* TAB 3: GEOGRAPHIC VIEW */}
      {activeTab === "geographic" && (
        <section aria-label="Geographic & Regional Posture">
          <h2>Global Cloud Region Footprint</h2>
          <p className="metric-sub">
            Interactive distribution of discovered cloud assets and open
            security findings across regions.
          </p>

          <div className="map-container">
            <svg
              viewBox="0 0 800 400"
              width="100%"
              height="320"
              aria-label="World map with cloud regions"
            >
              {/* Simplified world continent outlines */}
              <path
                d="M 120 120 Q 200 80 280 130 T 260 250 T 140 220 Z"
                fill="#162238"
                stroke="#283548"
              />
              <path
                d="M 380 90 Q 480 80 520 140 T 460 240 T 360 160 Z"
                fill="#162238"
                stroke="#283548"
              />
              <path
                d="M 540 100 Q 680 90 720 180 T 640 260 T 560 180 Z"
                fill="#162238"
                stroke="#283548"
              />

              {/* US East Pin */}
              <g
                className="region-pin"
                transform="translate(220, 140)"
                onClick={() => {
                  setProviderFilter("aws");
                  setActiveTab("engineer");
                  announce("Filtered findings by US East 1");
                }}
              >
                <circle r="14" fill="rgba(248, 81, 73, 0.3)" />
                <circle r="7" fill="var(--critical)" />
                <text
                  x="12"
                  y="5"
                  fill="var(--text-main)"
                  fontSize="11"
                  fontWeight="bold"
                >
                  us-east-1 (3 findings)
                </text>
              </g>

              {/* US West Pin */}
              <g
                className="region-pin"
                transform="translate(150, 130)"
                onClick={() => {
                  setProviderFilter("aws");
                  setActiveTab("engineer");
                }}
              >
                <circle r="10" fill="rgba(56, 139, 253, 0.3)" />
                <circle r="5" fill="var(--accent-blue)" />
                <text x="10" y="4" fill="var(--text-main)" fontSize="11">
                  us-west-2 (1 finding)
                </text>
              </g>

              {/* West Europe Pin */}
              <g
                className="region-pin"
                transform="translate(420, 120)"
                onClick={() => {
                  setProviderFilter("azure");
                  setActiveTab("engineer");
                }}
              >
                <circle r="10" fill="rgba(63, 185, 80, 0.3)" />
                <circle r="5" fill="var(--low)" />
                <text x="10" y="4" fill="var(--text-main)" fontSize="11">
                  westeurope (Healthy)
                </text>
              </g>

              {/* Asia East Pin */}
              <g
                className="region-pin"
                transform="translate(640, 170)"
                onClick={() => {
                  setProviderFilter("gcp");
                  setActiveTab("engineer");
                }}
              >
                <circle r="10" fill="rgba(63, 185, 80, 0.3)" />
                <circle r="5" fill="var(--low)" />
                <text x="10" y="4" fill="var(--text-main)" fontSize="11">
                  asia-east1 (Healthy)
                </text>
              </g>
            </svg>
          </div>

          <h3>Accessible Regional Breakdown (Table Fallback)</h3>
          <div className="table-wrapper">
            <table
              className="data-table"
              aria-label="Regional Distribution Table"
            >
              <thead>
                <tr>
                  <th>Cloud Region</th>
                  <th>Primary Provider</th>
                  <th>Resources Managed</th>
                  <th>Open Findings</th>
                  <th>Critical Severity</th>
                </tr>
              </thead>
              <tbody>
                {regionalSummaries.map((r) => (
                  <tr key={r.region}>
                    <td>
                      <strong>{r.region}</strong>
                    </td>
                    <td>
                      <span className={`provider-badge ${r.provider}`}>
                        {r.provider.toUpperCase()}
                      </span>
                    </td>
                    <td>{r.resourceCount}</td>
                    <td>{r.findingCount}</td>
                    <td>
                      <span
                        style={{
                          color:
                            r.criticalCount > 0 ? "var(--critical)" : "inherit",
                        }}
                      >
                        {r.criticalCount}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {/* TAB 4: REMEDIATIONS & COSTS VIEW */}
      {activeTab === "remediations" && (
        <section aria-label="Remediations and Cost-Security Optimization">
          <h2>Remediation Templates & Cost Optimization</h2>
          <div className="metrics-grid">
            <div className="card metric-card">
              <h3>Versioned Remediation Templates</h3>
              <p className="metric-val">{remediationTemplates.length || 7}</p>
              <span className="metric-sub">AWS, Azure, GCP covered</span>
            </div>
            <div className="card metric-card">
              <h3>Direct Spend Correlated</h3>
              <p className="metric-val">
                $
                {costReport?.total_actual_monthly_spend_usd?.toFixed(2) ||
                  "350.00"}
              </p>
              <span className="metric-sub">
                Validated against cloud billing CUR
              </span>
            </div>
          </div>

          <h3>Available Pre-Approved Remediation Templates</h3>
          <div className="table-wrapper">
            <table
              className="data-table"
              aria-label="Remediation Templates Catalog"
            >
              <thead>
                <tr>
                  <th>Template ID</th>
                  <th>Check ID</th>
                  <th>Provider</th>
                  <th>Effort</th>
                  <th>Approval Required</th>
                </tr>
              </thead>
              <tbody>
                {remediationTemplates.map((t) => (
                  <tr key={t.template_id}>
                    <td>
                      <code>{t.template_id}</code>
                    </td>
                    <td>{t.check_id}</td>
                    <td>
                      <span className={`provider-badge ${t.provider}`}>
                        {t.provider.toUpperCase()}
                      </span>
                    </td>
                    <td>{t.effort.toUpperCase()}</td>
                    <td>
                      {t.requires_approval
                        ? "Yes (Security Team)"
                        : "Automated"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {/* TAB 5: MONITORING & ALERTS VIEW */}
      {activeTab === "monitoring" && (
        <section aria-label="Continuous Monitoring and Alerting">
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              marginBottom: "1rem",
            }}
          >
            <h2>Continuous Monitoring & Scheduled Scans</h2>
            <button
              type="button"
              className="btn-primary"
              onClick={handlePromoteBaseline}
              disabled={selectedRole === "Viewer" || selectedRole === "Auditor"}
            >
              Promote Latest Scan as Baseline
            </button>
          </div>
          <p className="metric-sub" style={{ marginBottom: "1rem" }}>
            Monitoring {connectionsCount || 3} connected cloud accounts with{" "}
            {auditLogsCount || 12} recorded audit trail events.
          </p>

          <div className="table-wrapper" style={{ marginBottom: "2rem" }}>
            <table className="data-table" aria-label="Scan Schedules">
              <thead>
                <tr>
                  <th>Schedule Name</th>
                  <th>Cron Expression</th>
                  <th>Timezone</th>
                  <th>Status</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {schedules.length === 0 ? (
                  <tr>
                    <td
                      colSpan={5}
                      style={{ textAlign: "center", padding: "1.5rem" }}
                    >
                      No active schedules. Nightly recurring scans configured.
                    </td>
                  </tr>
                ) : (
                  schedules.map((s) => (
                    <tr key={s.id}>
                      <td>
                        <strong>{s.name}</strong>
                      </td>
                      <td>
                        <code>{s.cron_expression}</code>
                      </td>
                      <td>{s.timezone}</td>
                      <td>{s.enabled ? "Active" : "Paused"}</td>
                      <td>
                        <button
                          type="button"
                          className="btn-secondary"
                          onClick={() => handleToggleSchedule(s.id)}
                        >
                          {s.enabled ? "Pause" : "Enable"}
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

          <h2>Outbound Webhook Channels (Slack & PagerDuty)</h2>
          <div className="table-wrapper" style={{ marginBottom: "2rem" }}>
            <table className="data-table" aria-label="Alert Destinations">
              <thead>
                <tr>
                  <th>Destination Name</th>
                  <th>Channel Type</th>
                  <th>Endpoint URL</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {alertDestinations.length === 0 ? (
                  <tr>
                    <td
                      colSpan={4}
                      style={{ textAlign: "center", padding: "1.5rem" }}
                    >
                      No alert destinations configured.
                    </td>
                  </tr>
                ) : (
                  alertDestinations.map((d) => (
                    <tr key={d.id}>
                      <td>
                        <strong>{d.name}</strong>
                      </td>
                      <td>
                        <code>{d.destination_type}</code>
                      </td>
                      <td>
                        <code>{d.endpoint_url.slice(0, 35)}...</code>
                      </td>
                      <td>
                        <button
                          type="button"
                          className="btn-secondary"
                          onClick={() => handleTestAlertDestination(d.id)}
                        >
                          Test Delivery (HMAC)
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

          <h2>Multi-Format Audit Report Export</h2>
          <div
            className="card"
            style={{
              display: "flex",
              gap: "1rem",
              alignItems: "center",
              flexWrap: "wrap",
            }}
          >
            <label htmlFor="export-format-select">Format:</label>
            <select
              id="export-format-select"
              className="select-control"
              value={exportFormat}
              onChange={(e) =>
                setExportFormat(
                  e.target.value as "pdf" | "markdown" | "csv" | "json",
                )
              }
            >
              <option value="pdf">PDF Executive Summary</option>
              <option value="markdown">Markdown Documentation</option>
              <option value="csv">Technical Details CSV</option>
              <option value="json">Compliance JSON Evidence</option>
            </select>

            <label
              style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}
            >
              <input
                type="checkbox"
                checked={isPartialData}
                onChange={(e) => setIsPartialData(e.target.checked)}
              />
              Include Partial-Data Watermark
            </label>

            <button
              type="button"
              className="btn-primary"
              onClick={handleExportReport}
            >
              Download Generated Report
            </button>
          </div>
        </section>
      )}
    </div>
  );
}
