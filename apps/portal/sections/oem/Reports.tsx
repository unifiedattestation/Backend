import { useCallback, useEffect, useMemo, useState } from "react";
import { createPortal } from "react-dom";
import {
  AlertTriangle,
  ArrowLeft,
  ArrowRight,
  BarChart3,
  CalendarDays,
  Check,
  CheckCircle2,
  Copy,
  Download,
  Eye,
  HelpCircle,
  Loader2,
  MoreVertical,
  RefreshCw,
  Search,
  ShieldCheck,
  ShieldX,
  X,
  XCircle,
} from "lucide-react";
import OemFooter from "../../components/oem/Footer";
import { backendUrl } from "../../lib/config";

type Verdict = "trusted" | "failing" | "unknown";

type DeviceFamily = {
  id: string;
  name: string;
  codename?: string | null;
  model?: string | null;
};

type AttestationReport = {
  id: string;
  scopedDeviceId: string;
  issuerBackendId?: string;
  deviceFamilyId?: string | null;
  deviceFamilyName: string;
  model?: string | null;
  buildPolicyId?: string | null;
  buildFingerprint?: string | null;
  matchedBuildFingerprint?: string | null;
  lastVerdict?: { isTrusted?: boolean; reasonCodes?: string[] } | null;
  lastState?: Record<string, unknown> | null;
  lastSeen: string;
};

function reportVerdict(report: AttestationReport): Verdict {
  if (report.lastVerdict?.isTrusted === true) return "trusted";
  if (report.lastVerdict?.isTrusted === false) return "failing";
  return "unknown";
}

function reasonCode(report: AttestationReport) {
  return report.lastVerdict?.reasonCodes?.[0] || "—";
}

function StatCard({
  label,
  value,
  subtitle,
  icon,
  color,
}: {
  label: string;
  value: number;
  subtitle: string;
  icon: React.ReactNode;
  color: string;
}) {
  return (
    <article className="flex min-h-28 items-center gap-4 rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
      <div className={`flex h-12 w-12 shrink-0 items-center justify-center rounded-xl ${color}`}>
        {icon}
      </div>
      <div>
        <p className="text-xs font-medium text-slate-500">{label}</p>
        <p className="mt-1 text-2xl font-semibold text-[#071226]">{value.toLocaleString()}</p>
        <p className={`mt-1 text-xs ${color.split(" ")[1]}`}>{subtitle}</p>
      </div>
    </article>
  );
}

export default function OemReports({
  onOrganizationLoaded,
}: {
  onOrganizationLoaded?: (name: string) => void;
}) {
  const [reports, setReports] = useState<AttestationReport[]>([]);
  const [families, setFamilies] = useState<DeviceFamily[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [days, setDays] = useState("30");
  const [search, setSearch] = useState("");
  const [familyFilter, setFamilyFilter] = useState("all");
  const [verdictFilter, setVerdictFilter] = useState("all");
  const [reasonFilter, setReasonFilter] = useState("all");
  const [page, setPage] = useState(1);
  const [selectedReport, setSelectedReport] = useState<AttestationReport | null>(null);
  const [actionMenu, setActionMenu] = useState<string | null>(null);
  const [actionPosition, setActionPosition] = useState({ top: 0, left: 0 });
  const [copied, setCopied] = useState(false);
  const pageSize = 10;

  const loadReports = useCallback(async () => {
    const token = localStorage.getItem("ua_access");
    if (!token) {
      window.location.href = "/login";
      return;
    }
    setLoading(true);
    try {
      const headers = { Authorization: `Bearer ${token}` };
      const [reportsResponse, familiesResponse, orgResponse] = await Promise.all([
        fetch(`${backendUrl}/api/v1/oem/reports?days=${days}`, { headers }),
        fetch(`${backendUrl}/api/v1/oem/device-families`, { headers }),
        fetch(`${backendUrl}/api/v1/oem/profile`, { headers }),
      ]);
      if (familiesResponse.status === 401) {
        localStorage.removeItem("ua_access");
        localStorage.removeItem("ua_refresh");
        window.location.href = "/login";
        return;
      }
      if (!familiesResponse.ok) throw new Error("Unable to load attestation reports.");
      const familyData: DeviceFamily[] = await familiesResponse.json();
      let reportData: AttestationReport[];
      if (reportsResponse.ok) {
        reportData = await reportsResponse.json();
      } else {
        const fallback = await fetch(`${backendUrl}/api/v1/oem/reports/failing-devices`, {
          headers,
        });
        if (!fallback.ok) throw new Error("Unable to load attestation reports.");
        const failingReports: Array<
          Omit<AttestationReport, "deviceFamilyName" | "model"> & {
            deviceFamilyId?: string | null;
          }
        > = await fallback.json();
        reportData = failingReports.map((report) => {
          const family = familyData.find((item) => item.id === report.deviceFamilyId);
          return {
            ...report,
            deviceFamilyName: family?.codename || family?.name || "Unknown",
            model: family?.model,
          };
        });
      }
      setFamilies(familyData);
      setReports(reportData);
      if (orgResponse.ok) {
        const org = await orgResponse.json();
        onOrganizationLoaded?.(org.name || "OEM Portal");
      }
      setError(null);
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Unable to load reports.");
    } finally {
      setLoading(false);
    }
  }, [days, onOrganizationLoaded]);

  useEffect(() => {
    loadReports();
  }, [loadReports]);

  useEffect(() => {
    setPage(1);
  }, [search, familyFilter, verdictFilter, reasonFilter]);

  const reasons = useMemo(
    () =>
      Array.from(
        new Set(reports.flatMap((report) => report.lastVerdict?.reasonCodes || []).filter(Boolean)),
      ).sort(),
    [reports],
  );

  const filteredReports = useMemo(() => {
    const query = search.trim().toLowerCase();
    return reports.filter((report) => {
      const verdict = reportVerdict(report);
      const matchesSearch =
        !query ||
        report.scopedDeviceId.toLowerCase().includes(query) ||
        report.deviceFamilyName.toLowerCase().includes(query) ||
        report.model?.toLowerCase().includes(query) ||
        report.buildFingerprint?.toLowerCase().includes(query);
      const matchesFamily = familyFilter === "all" || report.deviceFamilyId === familyFilter;
      const matchesVerdict = verdictFilter === "all" || verdict === verdictFilter;
      const matchesReason =
        reasonFilter === "all" || report.lastVerdict?.reasonCodes?.includes(reasonFilter);
      return matchesSearch && matchesFamily && matchesVerdict && matchesReason;
    });
  }, [reports, search, familyFilter, verdictFilter, reasonFilter]);

  const totalPages = Math.max(1, Math.ceil(filteredReports.length / pageSize));
  const visibleReports = filteredReports.slice((page - 1) * pageSize, page * pageSize);
  const trusted = reports.filter((report) => reportVerdict(report) === "trusted").length;
  const failing = reports.filter((report) => reportVerdict(report) === "failing").length;
  const unknown = reports.length - trusted - failing;
  const percent = (value: number) =>
    reports.length ? Math.round((value / reports.length) * 1000) / 10 : 0;

  const dailyData = useMemo(() => {
    const dayCount = days === "all" ? 30 : Math.min(Number(days), 30);
    const result = Array.from({ length: dayCount }, (_, index) => {
      const date = new Date();
      date.setHours(0, 0, 0, 0);
      date.setDate(date.getDate() - (dayCount - index - 1));
      return { date, trusted: 0, failing: 0 };
    });
    reports.forEach((report) => {
      const reportDate = new Date(report.lastSeen);
      const item = result.find((entry) => entry.date.toDateString() === reportDate.toDateString());
      if (!item) return;
      if (reportVerdict(report) === "trusted") item.trusted += 1;
      if (reportVerdict(report) === "failing") item.failing += 1;
    });
    return result;
  }, [reports, days]);

  const exportReports = (items: AttestationReport[] = filteredReports) => {
    const rows = [
      [
        "Device ID",
        "Device Family",
        "Model",
        "Last Seen",
        "Build Fingerprint",
        "Verdict",
        "Reason",
      ],
      ...items.map((report) => [
        report.scopedDeviceId,
        report.deviceFamilyName,
        report.model || "",
        report.lastSeen,
        report.buildFingerprint || "",
        reportVerdict(report),
        (report.lastVerdict?.reasonCodes || []).join("|"),
      ]),
    ];
    const csv = rows
      .map((row) => row.map((value) => `"${String(value).replace(/"/g, '""')}"`).join(","))
      .join("\n");
    const url = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = `attestation-reports-${new Date().toISOString().slice(0, 10)}.csv`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const copyDeviceId = async () => {
    if (!selectedReport) return;
    await navigator.clipboard.writeText(selectedReport.scopedDeviceId);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1400);
  };

  return (
    <div className="flex min-h-[calc(100vh-3rem)] flex-col gap-5">
      <header className="flex flex-col gap-4 border-b border-slate-200 pb-4 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-[#071226]">Attestation Reports</h1>
          <p className="mt-1 text-sm text-slate-500">
            Monitor device integrity, investigate failures, and review attestation evidence.
          </p>
        </div>
        <div className="flex flex-col gap-2 sm:flex-row">
          <label className="relative">
            <CalendarDays
              size={16}
              className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-500"
            />
            <select
              value={days}
              onChange={(event) => setDays(event.target.value)}
              className="h-10 rounded-lg border border-slate-200 bg-white pl-9 pr-8 text-sm outline-none"
            >
              <option value="7">Last 7 days</option>
              <option value="30">Last 30 days</option>
              <option value="90">Last 90 days</option>
              <option value="all">All time</option>
            </select>
          </label>
          <button
            type="button"
            onClick={() => exportReports()}
            className="flex h-10 items-center justify-center gap-2 rounded-lg border border-slate-300 bg-white px-4 text-sm text-slate-700 hover:bg-slate-50"
          >
            <Download size={17} /> Export
          </button>
          <button
            type="button"
            onClick={async () => {
              await loadReports();
              setNotice("Report data refreshed.");
            }}
            className="flex h-10 items-center justify-center gap-2 rounded-lg bg-[#071226] px-4 text-sm font-medium text-white hover:bg-[#101f36]"
          >
            <BarChart3 size={17} /> Generate Report
          </button>
        </div>
      </header>

      {error && (
        <div className="rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
          {error}
        </div>
      )}
      {notice && (
        <div className="flex items-center gap-2 rounded-xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-700">
          <Check size={17} /> {notice}
        </div>
      )}

      <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          label="Total Attestations"
          value={reports.length}
          subtitle={`${days === "all" ? "All time" : `Last ${days} days`}`}
          icon={<BarChart3 size={23} />}
          color="bg-blue-50 text-blue-700"
        />
        <StatCard
          label="Trusted"
          value={trusted}
          subtitle={`${percent(trusted)}%`}
          icon={<ShieldCheck size={23} />}
          color="bg-emerald-50 text-emerald-700"
        />
        <StatCard
          label="Failing"
          value={failing}
          subtitle={`${percent(failing)}%`}
          icon={<ShieldX size={23} />}
          color="bg-red-50 text-red-600"
        />
        <StatCard
          label="Unknown"
          value={unknown}
          subtitle={`${percent(unknown)}%`}
          icon={<HelpCircle size={23} />}
          color="bg-amber-50 text-amber-600"
        />
      </section>

      <section className="grid gap-4 xl:grid-cols-[1.5fr_1fr]">
        <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold text-[#071226]">Attestation Health</h2>
            <div className="flex gap-4 text-xs">
              <span className="flex items-center gap-1.5 text-slate-600">
                <span className="h-2 w-2 rounded-full bg-emerald-600" /> Trusted
              </span>
              <span className="flex items-center gap-1.5 text-slate-600">
                <span className="h-2 w-2 rounded-full bg-red-600" /> Failing
              </span>
            </div>
          </div>
          <HealthChart data={dailyData} />
        </div>
        <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
          <h2 className="text-lg font-semibold text-[#071226]">Verdict Distribution</h2>
          <div className="mt-5 grid items-center gap-6 sm:grid-cols-[170px_1fr]">
            <div
              className="relative mx-auto flex h-40 w-40 items-center justify-center rounded-full"
              style={{
                background: `conic-gradient(#16a34a 0 ${percent(trusted)}%, #dc2626 ${percent(
                  trusted,
                )}% ${percent(trusted) + percent(failing)}%, #f59e0b 0)`,
              }}
            >
              <div className="flex h-28 w-28 flex-col items-center justify-center rounded-full bg-white">
                <strong className="text-2xl text-[#071226]">
                  {reports.length.toLocaleString()}
                </strong>
                <span className="text-xs text-slate-500">Total</span>
              </div>
            </div>
            <div className="space-y-4 text-sm">
              {[
                ["Trusted", percent(trusted), "bg-emerald-600"],
                ["Failing", percent(failing), "bg-red-600"],
                ["Unknown", percent(unknown), "bg-amber-500"],
              ].map(([label, value, dot]) => (
                <div key={String(label)} className="flex items-center justify-between gap-4">
                  <span className="flex items-center gap-2 text-slate-600">
                    <span className={`h-2.5 w-2.5 rounded-full ${dot}`} /> {label}
                  </span>
                  <strong className="text-slate-800">{value}%</strong>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      <section className="overflow-visible rounded-xl border border-slate-200 bg-white shadow-sm">
        <header className="border-b border-slate-200 p-4">
          <h2 className="text-lg font-semibold text-[#071226]">Device Reports</h2>
          <div className="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-[1.5fr_1fr_1fr_1fr_auto]">
            <label className="relative">
              <Search
                size={18}
                className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-400"
              />
              <input
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                placeholder="Search device ID or model"
                className="h-10 w-full rounded-lg border border-slate-200 pl-10 pr-3 text-sm outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-100"
              />
            </label>
            <select
              value={familyFilter}
              onChange={(event) => setFamilyFilter(event.target.value)}
              className="h-10 rounded-lg border border-slate-200 bg-white px-3 text-sm outline-none"
            >
              <option value="all">All families</option>
              {families.map((family) => (
                <option key={family.id} value={family.id}>
                  {family.codename || family.name}
                </option>
              ))}
            </select>
            <select
              value={verdictFilter}
              onChange={(event) => setVerdictFilter(event.target.value)}
              className="h-10 rounded-lg border border-slate-200 bg-white px-3 text-sm outline-none"
            >
              <option value="all">All verdicts</option>
              <option value="trusted">Trusted</option>
              <option value="failing">Failing</option>
              <option value="unknown">Unknown</option>
            </select>
            <select
              value={reasonFilter}
              onChange={(event) => setReasonFilter(event.target.value)}
              className="h-10 rounded-lg border border-slate-200 bg-white px-3 text-sm outline-none"
            >
              <option value="all">All reasons</option>
              {reasons.map((reason) => (
                <option key={reason} value={reason}>
                  {reason}
                </option>
              ))}
            </select>
            <button
              type="button"
              onClick={loadReports}
              className="flex h-10 items-center justify-center rounded-lg border border-slate-200 px-3 text-slate-700 hover:bg-slate-50"
            >
              <RefreshCw size={17} className={loading ? "animate-spin" : ""} />
            </button>
          </div>
        </header>

        <div className="overflow-x-auto">
          <table className="w-full min-w-[1000px] text-left text-sm">
            <thead className="bg-slate-50 text-xs text-slate-500">
              <tr>
                <th className="px-4 py-3 font-semibold">Device</th>
                <th className="px-4 py-3 font-semibold">Device Family</th>
                <th className="px-4 py-3 font-semibold">Model</th>
                <th className="px-4 py-3 font-semibold">Last Seen</th>
                <th className="px-4 py-3 font-semibold">Build Fingerprint</th>
                <th className="px-4 py-3 font-semibold">Verdict</th>
                <th className="px-4 py-3 font-semibold">Reason Code</th>
                <th className="px-4 py-3 text-right font-semibold">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {visibleReports.map((report) => (
                <ReportRow
                  key={report.id}
                  report={report}
                  onView={() => {
                    setActionMenu(null);
                    setSelectedReport(report);
                  }}
                  onExport={() => {
                    setActionMenu(null);
                    exportReports([report]);
                  }}
                  actionMenu={actionMenu}
                  actionPosition={actionPosition}
                  setActionMenu={setActionMenu}
                  setActionPosition={setActionPosition}
                />
              ))}
            </tbody>
          </table>
          {loading && (
            <div className="flex items-center justify-center gap-2 px-5 py-14 text-sm text-slate-500">
              <Loader2 size={18} className="animate-spin" /> Loading reports...
            </div>
          )}
          {!loading && visibleReports.length === 0 && (
            <div className="px-5 py-14 text-center text-sm text-slate-500">No reports found.</div>
          )}
        </div>
        <footer className="flex items-center justify-between border-t border-slate-200 px-5 py-4 text-xs text-slate-500">
          <span>
            {filteredReports.length ? (page - 1) * pageSize + 1 : 0}–
            {Math.min(page * pageSize, filteredReports.length)} of {filteredReports.length}
          </span>
          <div className="flex items-center gap-2">
            <button
              type="button"
              disabled={page === 1}
              onClick={() => setPage((current) => current - 1)}
              className="rounded-lg border border-slate-200 p-2 disabled:opacity-40"
            >
              <ArrowLeft size={15} />
            </button>
            <span className="flex h-8 min-w-8 items-center justify-center rounded-lg border border-blue-600 px-2 font-medium text-blue-700">
              {page}
            </span>
            <button
              type="button"
              disabled={page === totalPages}
              onClick={() => setPage((current) => current + 1)}
              className="rounded-lg border border-slate-200 p-2 disabled:opacity-40"
            >
              <ArrowRight size={15} />
            </button>
          </div>
        </footer>
      </section>

      <OemFooter />

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
                <h2 className="text-lg font-semibold text-[#071226]">Report Details</h2>
                <button type="button" onClick={() => setSelectedReport(null)}>
                  <X size={20} className="text-slate-500" />
                </button>
              </header>
              <ReportDetails report={selectedReport} copied={copied} onCopy={copyDeviceId} />
              <footer className="grid grid-cols-2 gap-3 border-t border-slate-200 p-6">
                <button
                  type="button"
                  onClick={() => exportReports([selectedReport])}
                  className="flex h-11 items-center justify-center gap-2 rounded-lg border border-slate-300 text-sm text-slate-700"
                >
                  <Download size={17} /> Export Report
                </button>
                <a
                  href="/oem/build-policies"
                  className="flex h-11 items-center justify-center rounded-lg bg-[#071226] text-sm font-medium text-white hover:bg-[#101f36]"
                >
                  View Build Policy
                </a>
              </footer>
            </aside>
          </>,
          document.body,
        )}
    </div>
  );
}

function HealthChart({ data }: { data: Array<{ date: Date; trusted: number; failing: number }> }) {
  const width = 720;
  const height = 210;
  const padding = 24;
  const maxValue = Math.max(1, ...data.flatMap((item) => [item.trusted, item.failing]));
  const points = (key: "trusted" | "failing") =>
    data
      .map((item, index) => {
        const x = padding + (index / Math.max(1, data.length - 1)) * (width - padding * 2);
        const y = height - padding - (item[key] / maxValue) * (height - padding * 2);
        return `${x},${y}`;
      })
      .join(" ");
  return (
    <div className="mt-4 overflow-hidden">
      <svg viewBox={`0 0 ${width} ${height}`} className="h-52 w-full" role="img">
        {[0.25, 0.5, 0.75].map((position) => (
          <line
            key={position}
            x1={padding}
            x2={width - padding}
            y1={height * position}
            y2={height * position}
            stroke="#e2e8f0"
            strokeDasharray="4 4"
          />
        ))}
        <polyline fill="none" stroke="#16a34a" strokeWidth="3" points={points("trusted")} />
        <polyline fill="none" stroke="#dc2626" strokeWidth="3" points={points("failing")} />
      </svg>
      <div className="flex justify-between text-[10px] text-slate-400">
        <span>{data[0]?.date.toLocaleDateString()}</span>
        <span>{data[data.length - 1]?.date.toLocaleDateString()}</span>
      </div>
    </div>
  );
}

function VerdictBadge({ verdict }: { verdict: Verdict }) {
  const styles = {
    trusted: "border-emerald-200 bg-emerald-50 text-emerald-700",
    failing: "border-red-200 bg-red-50 text-red-700",
    unknown: "border-amber-200 bg-amber-50 text-amber-700",
  };
  return (
    <span className={`rounded-md border px-2 py-1 text-xs font-medium ${styles[verdict]}`}>
      {verdict[0].toUpperCase() + verdict.slice(1)}
    </span>
  );
}

function ReportRow({
  report,
  onView,
  onExport,
  actionMenu,
  actionPosition,
  setActionMenu,
  setActionPosition,
}: {
  report: AttestationReport;
  onView: () => void;
  onExport: () => void;
  actionMenu: string | null;
  actionPosition: { top: number; left: number };
  setActionMenu: React.Dispatch<React.SetStateAction<string | null>>;
  setActionPosition: React.Dispatch<React.SetStateAction<{ top: number; left: number }>>;
}) {
  return (
    <tr className="hover:bg-slate-50/70">
      <td className="max-w-44 truncate px-4 py-3 font-mono text-xs text-slate-700">
        {report.scopedDeviceId}
      </td>
      <td className="px-4 py-3 text-slate-700">{report.deviceFamilyName}</td>
      <td className="px-4 py-3 text-slate-500">{report.model || "—"}</td>
      <td className="px-4 py-3 text-xs text-slate-500">
        {new Date(report.lastSeen).toLocaleString()}
      </td>
      <td className="max-w-48 truncate px-4 py-3 font-mono text-xs text-slate-500">
        {report.buildFingerprint || "Unmatched"}
      </td>
      <td className="px-4 py-3">
        <VerdictBadge verdict={reportVerdict(report)} />
      </td>
      <td className="px-4 py-3 text-xs text-slate-700">{reasonCode(report)}</td>
      <td className="relative px-4 py-3 text-right">
        <button
          type="button"
          onClick={(event) => {
            if (actionMenu === report.id) {
              setActionMenu(null);
              return;
            }
            const rect = event.currentTarget.getBoundingClientRect();
            const menuHeight = 88;
            setActionPosition({
              top:
                rect.bottom + menuHeight + 8 <= window.innerHeight
                  ? rect.bottom + 6
                  : rect.top - menuHeight - 6,
              left: Math.max(12, rect.right - 176),
            });
            setActionMenu(report.id);
          }}
          className="rounded-lg p-2 text-slate-500 hover:bg-slate-100"
        >
          <MoreVertical size={18} />
        </button>
        {actionMenu === report.id &&
          typeof document !== "undefined" &&
          createPortal(
            <>
              <button
                type="button"
                aria-label="Close actions menu"
                onClick={() => setActionMenu(null)}
                className="fixed inset-0 z-[9990] cursor-default"
              />
              <div
                className="fixed z-[9991] w-44 overflow-hidden rounded-lg border border-slate-200 bg-white py-1 text-left shadow-xl"
                style={{ top: actionPosition.top, left: actionPosition.left }}
              >
                <button
                  type="button"
                  onClick={onView}
                  className="flex w-full items-center gap-2 px-3 py-2 text-sm text-slate-700 hover:bg-slate-50"
                >
                  <Eye size={16} /> View Details
                </button>
                <button
                  type="button"
                  onClick={onExport}
                  className="flex w-full items-center gap-2 px-3 py-2 text-sm text-slate-700 hover:bg-slate-50"
                >
                  <Download size={16} /> Export Report
                </button>
              </div>
            </>,
            document.body,
          )}
      </td>
    </tr>
  );
}

function ReportDetails({
  report,
  copied,
  onCopy,
}: {
  report: AttestationReport;
  copied: boolean;
  onCopy: () => void;
}) {
  const verdict = reportVerdict(report);
  const reasons = report.lastVerdict?.reasonCodes || [];
  const bootValid = !reasons.some(
    (reason) => reason.includes("BOOT") || reason.includes("INTEGRITY"),
  );
  const anchorValid = !reasons.some((reason) => reason.includes("ANCHOR"));
  const buildValid = !reasons.some((reason) => reason.includes("BUILD_POLICY"));
  return (
    <div className="flex-1 overflow-y-auto p-6">
      <VerdictBadge verdict={verdict} />
      <h3 className="mt-4 truncate font-mono text-lg font-semibold text-[#071226]">
        {report.scopedDeviceId}
      </h3>
      <dl className="mt-6 grid grid-cols-[130px_1fr] gap-y-4 text-sm">
        <dt className="text-slate-500">Device ID</dt>
        <dd className="flex min-w-0 items-center gap-2 font-mono text-xs text-slate-700">
          <span className="truncate">{report.scopedDeviceId}</span>
          <button type="button" onClick={onCopy}>
            {copied ? <Check size={15} /> : <Copy size={15} />}
          </button>
        </dd>
        <dt className="text-slate-500">Device family</dt>
        <dd>{report.deviceFamilyName}</dd>
        <dt className="text-slate-500">Model</dt>
        <dd>{report.model || "—"}</dd>
        <dt className="text-slate-500">Last seen</dt>
        <dd>{new Date(report.lastSeen).toLocaleString()}</dd>
        <dt className="text-slate-500">Build fingerprint</dt>
        <dd className="break-all font-mono text-xs">{report.buildFingerprint || "Unmatched"}</dd>
        <dt className="text-slate-500">Reason code</dt>
        <dd>{reasonCode(report)}</dd>
      </dl>
      <div className="my-6 border-t border-slate-200" />
      <h3 className="font-semibold text-[#071226]">Policy Evaluation</h3>
      <div className="mt-4 space-y-4">
        <Evaluation
          label="Boot state"
          valid={bootValid}
          validText="Verified"
          invalidText="Failed"
        />
        <Evaluation
          label="Trust anchor"
          valid={anchorValid}
          validText="Valid"
          invalidText="Invalid"
        />
        <Evaluation
          label="Build policy"
          valid={buildValid}
          validText="Matched"
          invalidText="Mismatch"
        />
      </div>
      <div className="my-6 border-t border-slate-200" />
      <h3 className="font-semibold text-[#071226]">Evidence Timeline</h3>
      <div className="mt-4 space-y-4 border-l-2 border-blue-200 pl-5">
        <Timeline label="Attestation received" value={report.lastSeen} valid />
        <Timeline label="Evidence verified" value={report.lastSeen} valid />
        <Timeline
          label={verdict === "failing" ? "Policy evaluation failed" : "Policy evaluation passed"}
          value={report.lastSeen}
          valid={verdict !== "failing"}
        />
      </div>
    </div>
  );
}

function Evaluation({
  label,
  valid,
  validText,
  invalidText,
}: {
  label: string;
  valid: boolean;
  validText: string;
  invalidText: string;
}) {
  return (
    <div className="flex items-center justify-between gap-4 text-sm">
      <span className="text-slate-600">{label}</span>
      <span
        className={`flex items-center gap-2 rounded-md border px-2 py-1 text-xs ${
          valid
            ? "border-emerald-200 bg-emerald-50 text-emerald-700"
            : "border-red-200 bg-red-50 text-red-700"
        }`}
      >
        {valid ? <CheckCircle2 size={16} /> : <XCircle size={16} />}
        {valid ? validText : invalidText}
      </span>
    </div>
  );
}

function Timeline({ label, value, valid }: { label: string; value: string; valid: boolean }) {
  return (
    <div className="relative">
      <span
        className={`absolute -left-[30px] top-0.5 flex h-4 w-4 items-center justify-center rounded-full bg-white ${
          valid ? "text-blue-700" : "text-red-600"
        }`}
      >
        {valid ? <CheckCircle2 size={16} /> : <XCircle size={16} />}
      </span>
      <p className="text-sm font-medium text-slate-700">{label}</p>
      <p className="mt-1 text-xs text-slate-500">{new Date(value).toLocaleString()}</p>
    </div>
  );
}
