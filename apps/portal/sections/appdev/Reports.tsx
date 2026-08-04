import { useCallback, useEffect, useMemo, useState } from "react";
import { createPortal } from "react-dom";
import {
  AlertTriangle,
  AppWindow,
  ArrowLeft,
  ArrowRight,
  BarChart3,
  CalendarDays,
  Check,
  CheckCircle2,
  Clock3,
  Copy,
  Download,
  Eye,
  FileText,
  Filter,
  KeyRound,
  Loader2,
  LockKeyhole,
  MoreVertical,
  Search,
  Server,
  ShieldCheck,
  Smartphone,
  UserCheck,
  X,
  XCircle,
} from "lucide-react";
import AppdevFooter from "../../components/appdev/Footer";
import { backendUrl } from "../../lib/config";

type DeveloperApp = {
  id: string;
  projectId: string;
  name: string;
  signerDigestSha256: string;
};

type DeviceReport = {
  id: string;
  scopedDeviceId: string;
  issuerBackendId: string;
  buildFingerprint?: string | null;
  lastSeen: string;
  lastVerdict?: { isTrusted?: boolean; reasonCodes?: string[] } | null;
  lastState?: Record<string, unknown> | null;
  application: DeveloperApp;
};

type FederationBackend = {
  id: string;
  backendId: string;
  name: string;
  status: string;
};

const documentationUrl = "https://github.com/unifiedAttestation/Website/wiki";

export default function AppdevReports({
  onProfileLoaded,
}: {
  onProfileLoaded?: (name: string) => void;
}) {
  const [apps, setApps] = useState<DeveloperApp[]>([]);
  const [reports, setReports] = useState<DeviceReport[]>([]);
  const [backends, setBackends] = useState<FederationBackend[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [appFilter, setAppFilter] = useState("all");
  const [verdictFilter, setVerdictFilter] = useState("all");
  const [days, setDays] = useState("30");
  const [page, setPage] = useState(1);
  const [selectedReport, setSelectedReport] = useState<DeviceReport | null>(null);
  const [menuId, setMenuId] = useState<string | null>(null);
  const [menuPosition, setMenuPosition] = useState({ top: 0, left: 0 });
  const [copied, setCopied] = useState(false);
  const pageSize = 10;

  const load = useCallback(async () => {
    const token = localStorage.getItem("ua_access");
    if (!token) {
      window.location.href = "/login";
      return;
    }
    setLoading(true);
    try {
      const headers = { Authorization: `Bearer ${token}` };
      const [appsResponse, profileResponse, federationResponse] = await Promise.all([
        fetch(`${backendUrl}/api/v1/apps`, { headers }),
        fetch(`${backendUrl}/api/v1/profile`, { headers }),
        fetch(`${backendUrl}/api/v1/federation/backends`),
      ]);
      if (appsResponse.status === 401 || profileResponse.status === 401) {
        localStorage.removeItem("ua_access");
        localStorage.removeItem("ua_refresh");
        window.location.href = "/login";
        return;
      }
      if (!appsResponse.ok || !profileResponse.ok) {
        throw new Error("Unable to load device reports.");
      }
      const appData: DeveloperApp[] = await appsResponse.json();
      const profile = await profileResponse.json();
      const groups = await Promise.all(
        appData.map(async (application) => {
          const response = await fetch(`${backendUrl}/api/v1/apps/${application.id}/reports`, {
            headers,
          });
          if (!response.ok) return [];
          const data: Array<Omit<DeviceReport, "application">> = await response.json();
          return data.map((report) => ({ ...report, application }));
        }),
      );
      setApps(appData);
      setReports(groups.flat().sort((a, b) => +new Date(b.lastSeen) - +new Date(a.lastSeen)));
      setBackends(federationResponse.ok ? await federationResponse.json() : []);
      onProfileLoaded?.(profile.displayName || profile.email?.split("@")[0] || "App Developer");
      setError(null);
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Unable to load reports.");
    } finally {
      setLoading(false);
    }
  }, [onProfileLoaded]);

  useEffect(() => {
    load();
  }, [load]);

  const filteredReports = useMemo(() => {
    const query = search.trim().toLowerCase();
    const cutoff = days === "all" ? null : Date.now() - Number(days) * 24 * 60 * 60 * 1000;
    return reports.filter((report) => {
      const trusted = report.lastVerdict?.isTrusted === true;
      return (
        (!query ||
          `${report.scopedDeviceId} ${report.application.name} ${report.application.projectId}`
            .toLowerCase()
            .includes(query)) &&
        (appFilter === "all" || report.application.id === appFilter) &&
        (verdictFilter === "all" || (verdictFilter === "trusted" ? trusted : !trusted)) &&
        (!cutoff || +new Date(report.lastSeen) >= cutoff)
      );
    });
  }, [reports, search, appFilter, verdictFilter, days]);

  useEffect(() => setPage(1), [search, appFilter, verdictFilter, days]);

  const totalPages = Math.max(1, Math.ceil(filteredReports.length / pageSize));
  const visibleReports = filteredReports.slice((page - 1) * pageSize, page * pageSize);
  const trusted = reports.filter((report) => report.lastVerdict?.isTrusted === true).length;
  const failing = reports.length - trusted;
  const reportingApps = new Set(reports.map((report) => report.application.id)).size;

  const exportReports = (items: DeviceReport[] = filteredReports) => {
    const rows = [
      ["Device", "Application", "Project ID", "Verdict", "Last Seen", "Signer Match", "Reason"],
      ...items.map((report) => [
        report.scopedDeviceId,
        report.application.name,
        report.application.projectId,
        report.lastVerdict?.isTrusted === true ? "Trusted" : "Failing",
        report.lastSeen,
        signerMatches(report) ? "Matched" : "Mismatch",
        report.lastVerdict?.reasonCodes?.join("|") || "",
      ]),
    ];
    const csv = rows
      .map((row) => row.map((value) => `"${String(value).replace(/"/g, '""')}"`).join(","))
      .join("\n");
    const url = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = `device-reports-${new Date().toISOString().slice(0, 10)}.csv`;
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="flex min-h-[calc(100vh-3rem)] flex-col gap-4">
      <header className="flex flex-col gap-4 border-b border-slate-200 pb-4 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-[#071226]">Device Reports</h1>
          <p className="mt-1 text-sm text-slate-500">
            Review device attestation results associated with your applications.
          </p>
        </div>
        <div className="flex flex-col gap-2 sm:flex-row">
          <a
            href={documentationUrl}
            target="_blank"
            rel="noreferrer"
            className="flex h-10 items-center justify-center gap-2 rounded-lg border border-slate-300 bg-white px-4 text-sm text-slate-700 hover:bg-slate-50"
          >
            <FileText size={17} />
            Integration Guide
          </a>
          <button
            type="button"
            disabled={filteredReports.length === 0}
            onClick={() => exportReports()}
            className="flex h-10 items-center justify-center gap-2 rounded-lg border border-slate-300 bg-white px-4 text-sm text-slate-700 hover:bg-slate-50 disabled:opacity-40"
          >
            <Download size={17} />
            Export Reports
          </button>
        </div>
      </header>
      {error && (
        <div className="flex items-center justify-between rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
          <span>{error}</span>
          <button type="button" onClick={() => setError(null)}>
            <X size={17} />
          </button>
        </div>
      )}

      <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          label="Total Reports"
          value={reports.length}
          subtitle={reports.length ? "Reports received" : "No reports received"}
          icon={<BarChart3 />}
          tone="blue"
        />
        <StatCard
          label="Trusted"
          value={trusted}
          subtitle={reports.length ? `${Math.round((trusted / reports.length) * 100)}%` : "—"}
          icon={<CheckCircle2 />}
          tone="green"
        />
        <StatCard
          label="Failing"
          value={failing}
          subtitle={failing ? "Requires review" : "No failures"}
          icon={<XCircle />}
          tone="red"
        />
        <StatCard
          label="Applications Reporting"
          value={reportingApps}
          subtitle={`of ${apps.length}`}
          icon={<AppWindow />}
          tone="blue"
        />
      </section>

      <section className="grid min-w-0 gap-4 xl:grid-cols-[minmax(0,1fr)_300px]">
        <article className="overflow-visible rounded-xl border border-slate-200 bg-white shadow-sm">
          <header className="border-b border-slate-200 p-4">
            <h2 className="text-lg font-semibold text-[#071226]">Attestation Reports</h2>
            <p className="text-xs text-slate-500">
              Reports appear when a device attests with one of your registered applications.
            </p>
            <div className="mt-4 grid gap-2 md:grid-cols-2 xl:grid-cols-[1.3fr_1fr_1fr_1fr_auto]">
              <label className="relative">
                <Search
                  size={17}
                  className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400"
                />
                <input
                  value={search}
                  onChange={(event) => setSearch(event.target.value)}
                  placeholder="Search device or application"
                  className="h-10 w-full rounded-lg border border-slate-200 pl-10 pr-3 text-sm outline-none focus:border-blue-600"
                />
              </label>
              <select
                value={appFilter}
                onChange={(event) => setAppFilter(event.target.value)}
                className="h-10 rounded-lg border border-slate-200 bg-white px-3 text-sm"
              >
                <option value="all">All applications</option>
                {apps.map((app) => (
                  <option key={app.id} value={app.id}>
                    {app.name}
                  </option>
                ))}
              </select>
              <select
                value={verdictFilter}
                onChange={(event) => setVerdictFilter(event.target.value)}
                className="h-10 rounded-lg border border-slate-200 bg-white px-3 text-sm"
              >
                <option value="all">All verdicts</option>
                <option value="trusted">Trusted</option>
                <option value="failing">Failing</option>
              </select>
              <label className="relative">
                <CalendarDays
                  size={16}
                  className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500"
                />
                <select
                  value={days}
                  onChange={(event) => setDays(event.target.value)}
                  className="h-10 w-full rounded-lg border border-slate-200 bg-white pl-9 pr-3 text-sm"
                >
                  <option value="7">Last 7 days</option>
                  <option value="30">Last 30 days</option>
                  <option value="90">Last 90 days</option>
                  <option value="all">All time</option>
                </select>
              </label>
              <button
                type="button"
                onClick={load}
                className="flex h-10 items-center justify-center rounded-lg border border-slate-200 px-3 text-slate-600 hover:bg-slate-50"
              >
                <Filter size={17} />
              </button>
            </div>
          </header>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[900px] text-left text-xs">
              <thead className="bg-slate-50 text-slate-500">
                <tr>
                  <th className="px-4 py-3">Device</th>
                  <th className="px-4 py-3">Application</th>
                  <th className="px-4 py-3">Verdict</th>
                  <th className="px-4 py-3">Last Seen</th>
                  <th className="px-4 py-3">Signer Match</th>
                  <th className="px-4 py-3">Reason</th>
                  <th className="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {visibleReports.map((report) => (
                  <ReportRow
                    key={report.id}
                    report={report}
                    menuOpen={menuId === report.id}
                    menuPosition={menuPosition}
                    onMenu={(event) => {
                      const rect = event.currentTarget.getBoundingClientRect();
                      setMenuPosition({
                        top: Math.min(rect.bottom + 6, window.innerHeight - 120),
                        left: Math.max(12, rect.right - 180),
                      });
                      setMenuId(menuId === report.id ? null : report.id);
                    }}
                    closeMenu={() => setMenuId(null)}
                    onView={() => {
                      setMenuId(null);
                      setSelectedReport(report);
                    }}
                    onExport={() => {
                      setMenuId(null);
                      exportReports([report]);
                    }}
                  />
                ))}
              </tbody>
            </table>
            {loading && (
              <div className="flex items-center justify-center gap-2 py-14 text-sm text-slate-500">
                <Loader2 size={18} className="animate-spin" />
                Loading reports...
              </div>
            )}
            {!loading && visibleReports.length === 0 && <EmptyReports app={apps[0]} />}
          </div>
          <footer className="flex items-center justify-between border-t border-slate-200 px-4 py-3 text-xs text-slate-500">
            <span>{filteredReports.length} reports</span>
            <div className="flex gap-2">
              <button
                type="button"
                disabled={page === 1}
                onClick={() => setPage((value) => value - 1)}
                className="rounded-lg border border-slate-200 p-2 disabled:opacity-40"
              >
                <ArrowLeft size={14} />
              </button>
              <span className="flex min-w-8 items-center justify-center rounded-lg border border-blue-600 text-blue-700">
                {page}
              </span>
              <button
                type="button"
                disabled={page === totalPages}
                onClick={() => setPage((value) => value + 1)}
                className="rounded-lg border border-slate-200 p-2 disabled:opacity-40"
              >
                <ArrowRight size={14} />
              </button>
            </div>
          </footer>
        </article>
        <ReportGuide />
      </section>

      <section className="grid gap-4 xl:grid-cols-3">
        <IntegrationStatus app={apps[0]} hasReports={reports.length > 0} />
        <HowReportsAppear app={apps[0]} hasReports={reports.length > 0} />
        <FederationAvailability backends={backends} />
      </section>
      <AboutReports />
      <AppdevFooter />

      {selectedReport &&
        typeof document !== "undefined" &&
        createPortal(
          <>
            <button
              type="button"
              aria-label="Close report details"
              onClick={() => setSelectedReport(null)}
              className="fixed inset-0 z-[9998] bg-[#071226]/55 backdrop-blur-sm"
            />
            <aside className="fixed inset-y-0 right-0 z-[9999] flex w-full max-w-md flex-col bg-white shadow-2xl">
              <header className="flex items-center justify-between border-b border-slate-200 px-6 py-5">
                <h2 className="text-lg font-semibold text-[#071226]">Device Report Details</h2>
                <button type="button" onClick={() => setSelectedReport(null)}>
                  <X size={20} />
                </button>
              </header>
              <ReportDetails
                report={selectedReport}
                copied={copied}
                onCopy={async () => {
                  await navigator.clipboard.writeText(selectedReport.scopedDeviceId);
                  setCopied(true);
                  window.setTimeout(() => setCopied(false), 1200);
                }}
              />
              <footer className="grid grid-cols-2 gap-3 border-t border-slate-200 p-6">
                <button
                  type="button"
                  onClick={() => exportReports([selectedReport])}
                  className="flex h-11 items-center justify-center gap-2 rounded-lg border border-slate-300 text-sm"
                >
                  <Download size={17} />
                  Export
                </button>
                <a
                  href="/appdev/applications"
                  className="flex h-11 items-center justify-center rounded-lg bg-[#071226] text-sm font-medium text-white"
                >
                  View Application
                </a>
              </footer>
            </aside>
          </>,
          document.body,
        )}
    </div>
  );
}

function StatCard({
  label,
  value,
  subtitle,
  icon,
  tone,
}: {
  label: string;
  value: number;
  subtitle: string;
  icon: React.ReactNode;
  tone: "blue" | "green" | "red";
}) {
  const colors = {
    blue: "bg-blue-50 text-blue-700",
    green: "bg-emerald-50 text-emerald-700",
    red: "bg-red-50 text-red-600",
  };
  return (
    <article className="flex min-h-24 items-center gap-4 rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
      <div className={`flex h-12 w-12 items-center justify-center rounded-xl ${colors[tone]}`}>
        {icon}
      </div>
      <div>
        <p className="text-xs text-slate-500">{label}</p>
        <strong className="mt-1 block text-2xl text-[#071226]">{value}</strong>
        <p className="text-xs text-slate-400">{subtitle}</p>
      </div>
    </article>
  );
}

function ReportRow({
  report,
  menuOpen,
  menuPosition,
  onMenu,
  closeMenu,
  onView,
  onExport,
}: {
  report: DeviceReport;
  menuOpen: boolean;
  menuPosition: { top: number; left: number };
  onMenu: (event: React.MouseEvent<HTMLButtonElement>) => void;
  closeMenu: () => void;
  onView: () => void;
  onExport: () => void;
}) {
  const reason = report.lastVerdict?.reasonCodes?.[0] || "—";
  return (
    <tr className="hover:bg-slate-50/70">
      <td className="max-w-40 truncate px-4 py-3 font-mono">{report.scopedDeviceId}</td>
      <td className="px-4 py-3">
        <p className="font-medium text-slate-700">{report.application.name}</p>
        <p className="text-[10px] text-slate-400">{report.application.projectId}</p>
      </td>
      <td className="px-4 py-3">
        <Verdict trusted={report.lastVerdict?.isTrusted === true} />
      </td>
      <td className="px-4 py-3 text-slate-500">{new Date(report.lastSeen).toLocaleString()}</td>
      <td className="px-4 py-3">
        <MatchBadge matched={signerMatches(report)} />
      </td>
      <td className="px-4 py-3 text-slate-500">{reason}</td>
      <td className="px-4 py-3 text-right">
        <button
          type="button"
          onClick={onMenu}
          className="rounded-lg p-2 text-slate-500 hover:bg-slate-100"
        >
          <MoreVertical size={18} />
        </button>
        {menuOpen &&
          typeof document !== "undefined" &&
          createPortal(
            <>
              <button
                type="button"
                aria-label="Close report menu"
                onClick={closeMenu}
                className="fixed inset-0 z-[9990]"
              />
              <div
                className="fixed z-[9991] w-44 overflow-hidden rounded-lg border border-slate-200 bg-white py-1 shadow-xl"
                style={menuPosition}
              >
                <button
                  type="button"
                  onClick={onView}
                  className="flex w-full items-center gap-2 px-4 py-2.5 text-sm text-slate-700 hover:bg-slate-50"
                >
                  <Eye size={16} />
                  View Details
                </button>
                <button
                  type="button"
                  onClick={onExport}
                  className="flex w-full items-center gap-2 px-4 py-2.5 text-sm text-slate-700 hover:bg-slate-50"
                >
                  <Download size={16} />
                  Export Report
                </button>
              </div>
            </>,
            document.body,
          )}
      </td>
    </tr>
  );
}

function EmptyReports({ app }: { app?: DeveloperApp }) {
  return (
    <div className="px-5 py-14 text-center">
      <h3 className="font-semibold text-[#071226]">No Device Reports Yet</h3>
      <p className="mt-2 text-sm text-slate-500">
        Complete the application integration and submit an attestation request to see reports here.
      </p>
      <div className="mt-5 flex flex-col justify-center gap-2 sm:flex-row">
        <a
          href={documentationUrl}
          target="_blank"
          rel="noreferrer"
          className="flex h-10 items-center justify-center rounded-lg bg-[#071226] px-5 text-sm font-medium text-white"
        >
          View Integration Guide
        </a>
        {app && (
          <a
            href="/appdev/applications"
            className="flex h-10 items-center justify-center rounded-lg border border-blue-600 px-5 text-sm text-blue-700"
          >
            Open {app.name}
          </a>
        )}
      </div>
    </div>
  );
}

function ReportGuide() {
  const items = [
    ["Device", "Masked device identifier", Smartphone],
    ["Application", "Application that reported", AppWindow],
    ["Verdict", "Trusted or failing result", ShieldCheck],
    ["Timestamp", "When the attestation occurred", Clock3],
    ["Signer Match", "Whether signer digest matched", UserCheck],
    ["Reason", "Failure code when rejected", AlertTriangle],
  ] as const;
  return (
    <aside className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
      <h2 className="text-lg font-semibold text-[#071226]">When Your First Report Arrives</h2>
      <p className="text-xs text-slate-500">These details are available in each report.</p>
      <div className="mt-4 space-y-4">
        {items.map(([label, text, Icon]) => (
          <div key={label} className="flex gap-3">
            <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-slate-200 bg-slate-50 text-slate-700">
              <Icon size={17} />
            </span>
            <div>
              <p className="text-sm font-medium text-slate-700">{label}</p>
              <p className="text-xs text-slate-500">{text}</p>
            </div>
          </div>
        ))}
      </div>
      <div className="mt-5 rounded-lg border border-blue-200 bg-blue-50 p-3 text-xs text-blue-700">
        Reports are available after a device submits an attestation request.
      </div>
    </aside>
  );
}

function IntegrationStatus({ app, hasReports }: { app?: DeveloperApp; hasReports: boolean }) {
  return (
    <article className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
      <h2 className="text-lg font-semibold text-[#071226]">Integration Status</h2>
      <dl className="mt-3 divide-y divide-slate-100 text-sm">
        <InfoRow label="Application" value={app?.name || "Not registered"} success={Boolean(app)} />
        <InfoRow label="Project ID" value={app?.projectId || "—"} />
        <InfoRow
          label="Signing Digest"
          value={app ? "Configured" : "Missing"}
          success={Boolean(app)}
        />
        <InfoRow
          label="Server Secret"
          value={app ? "Configured" : "Missing"}
          success={Boolean(app)}
        />
        <InfoRow
          label="First Report"
          value={hasReports ? "Received" : "Pending"}
          success={hasReports}
        />
      </dl>
      <a
        href="/appdev/applications"
        className="mt-4 flex h-9 items-center justify-center rounded-lg border border-blue-600 text-sm text-blue-700"
      >
        Review Application
      </a>
    </article>
  );
}

function HowReportsAppear({ app, hasReports }: { app?: DeveloperApp; hasReports: boolean }) {
  const steps = [
    ["Register application", Boolean(app)],
    ["Configure signing digest", Boolean(app)],
    ["Authenticate app server", Boolean(app)],
    ["Submit device attestation", hasReports],
  ] as const;
  return (
    <article className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
      <h2 className="text-lg font-semibold text-[#071226]">How Reports Appear</h2>
      <div className="mt-3 space-y-3">
        {steps.map(([label, done], index) => (
          <div key={label} className="flex items-center gap-3 text-sm">
            <span className="flex h-6 w-6 items-center justify-center rounded-full border border-slate-400 text-xs">
              {index + 1}
            </span>
            <span className="flex-1 text-slate-600">{label}</span>
            {done ? (
              <CheckCircle2 size={17} className="text-emerald-600" />
            ) : (
              <span className="text-xs text-amber-600">Pending</span>
            )}
          </div>
        ))}
      </div>
      <div className="mt-4 flex items-center justify-between border-t border-slate-200 pt-3 text-xs">
        <span className="text-slate-500">
          {steps.filter(([, done]) => done).length} of 4 complete
        </span>
        <a
          href={documentationUrl}
          target="_blank"
          rel="noreferrer"
          className="rounded-lg border border-blue-600 px-3 py-2 text-blue-700"
        >
          Open Integration Guide
        </a>
      </div>
    </article>
  );
}

function FederationAvailability({ backends }: { backends: FederationBackend[] }) {
  return (
    <article className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
      <h2 className="text-lg font-semibold text-[#071226]">Federation Availability</h2>
      <div className="mt-3 divide-y divide-slate-100">
        {backends.map((backend) => (
          <div key={backend.id} className="flex items-center gap-3 py-3">
            <Server size={17} className="text-slate-500" />
            <span className="flex-1 text-sm text-slate-700">{backend.name}</span>
            <Status active={backend.status === "active"} />
          </div>
        ))}
        {backends.length === 0 && (
          <p className="py-8 text-center text-sm text-slate-500">No federation servers.</p>
        )}
      </div>
      <div className="mt-3 flex items-center gap-2 border-t border-slate-200 pt-3 text-xs text-slate-500">
        <LockKeyhole size={14} />
        Federation configuration is read-only.
      </div>
    </article>
  );
}

function AboutReports() {
  return (
    <article className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
      <h2 className="text-lg font-semibold text-[#071226]">About Device Reports</h2>
      <div className="mt-4 grid gap-5 md:grid-cols-3">
        <AboutItem
          icon={<ShieldCheck />}
          title="Verdict"
          text="Trusted or failing result from attestation evaluation."
        />
        <AboutItem
          icon={<UserCheck />}
          title="Signer Match"
          text="Whether the application signer matches the registered digest."
        />
        <AboutItem
          icon={<AlertTriangle />}
          title="Reason"
          text="Failure code returned when attestation is rejected."
        />
      </div>
    </article>
  );
}

function AboutItem({ icon, title, text }: { icon: React.ReactNode; title: string; text: string }) {
  return (
    <div className="flex gap-3 border-slate-200 md:border-r md:pr-5 md:last:border-r-0">
      <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border border-slate-200 text-blue-700">
        {icon}
      </span>
      <div>
        <h3 className="font-medium text-[#071226]">{title}</h3>
        <p className="mt-1 text-xs text-slate-500">{text}</p>
      </div>
    </div>
  );
}

function ReportDetails({
  report,
  copied,
  onCopy,
}: {
  report: DeviceReport;
  copied: boolean;
  onCopy: () => void;
}) {
  return (
    <div className="flex-1 overflow-y-auto p-6">
      <Verdict trusted={report.lastVerdict?.isTrusted === true} />
      <h3 className="mt-4 font-semibold text-[#071226]">{report.application.name}</h3>
      <dl className="mt-6 grid grid-cols-[120px_1fr] gap-y-4 text-sm">
        <dt className="text-slate-500">Device ID</dt>
        <dd className="flex min-w-0 items-center gap-2 font-mono text-xs">
          <span className="truncate">{report.scopedDeviceId}</span>
          <button type="button" onClick={onCopy}>
            {copied ? <Check size={15} /> : <Copy size={15} />}
          </button>
        </dd>
        <dt className="text-slate-500">Application</dt>
        <dd>{report.application.name}</dd>
        <dt className="text-slate-500">Project ID</dt>
        <dd>{report.application.projectId}</dd>
        <dt className="text-slate-500">Last Seen</dt>
        <dd>{new Date(report.lastSeen).toLocaleString()}</dd>
        <dt className="text-slate-500">Issuer</dt>
        <dd>{report.issuerBackendId}</dd>
        <dt className="text-slate-500">Signer Match</dt>
        <dd>
          <MatchBadge matched={signerMatches(report)} />
        </dd>
        <dt className="text-slate-500">Reason</dt>
        <dd>{report.lastVerdict?.reasonCodes?.join(", ") || "—"}</dd>
      </dl>
      <div className="my-6 border-t border-slate-200" />
      <h3 className="font-semibold text-[#071226]">Raw State</h3>
      <pre className="mt-3 max-h-64 overflow-auto rounded-lg bg-slate-950 p-4 text-xs text-slate-200">
        {JSON.stringify(report.lastState || {}, null, 2)}
      </pre>
    </div>
  );
}

function signerMatches(report: DeviceReport) {
  return !(report.lastVerdict?.reasonCodes || []).some((reason) => reason.includes("SIGNER"));
}

function Verdict({ trusted }: { trusted: boolean }) {
  return (
    <span
      className={`inline-flex items-center gap-1 rounded border px-2 py-1 text-[10px] ${trusted ? "border-emerald-200 bg-emerald-50 text-emerald-700" : "border-red-200 bg-red-50 text-red-700"}`}
    >
      {trusted ? <CheckCircle2 size={13} /> : <XCircle size={13} />}
      {trusted ? "Trusted" : "Failing"}
    </span>
  );
}

function MatchBadge({ matched }: { matched: boolean }) {
  return (
    <span
      className={`inline-flex items-center gap-1 text-xs ${matched ? "text-emerald-600" : "text-red-600"}`}
    >
      {matched ? <CheckCircle2 size={15} /> : <XCircle size={15} />}
      {matched ? "Matched" : "Mismatch"}
    </span>
  );
}

function Status({ active }: { active: boolean }) {
  return (
    <span
      className={`rounded border px-2 py-1 text-[10px] ${active ? "border-emerald-200 bg-emerald-50 text-emerald-700" : "border-red-200 bg-red-50 text-red-700"}`}
    >
      {active ? "Active" : "Inactive"}
    </span>
  );
}

function InfoRow({
  label,
  value,
  success = false,
}: {
  label: string;
  value: string;
  success?: boolean;
}) {
  return (
    <div className="flex justify-between gap-3 py-2">
      <dt className="text-slate-500">{label}</dt>
      <dd
        className={
          success
            ? "text-emerald-600"
            : value === "Pending" || value === "Missing"
              ? "text-amber-600"
              : "text-slate-700"
        }
      >
        {value}
      </dd>
    </div>
  );
}
