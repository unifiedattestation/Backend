import { useCallback, useEffect, useMemo, useState } from "react";
import { createPortal } from "react-dom";
import {
  AlertTriangle,
  Bell,
  Boxes,
  Check,
  CheckCircle2,
  ChevronRight,
  CloudUpload,
  KeyRound,
  Layers3,
  Loader2,
  Plus,
  Search,
  Server,
  ShieldCheck,
  Smartphone,
  X,
} from "lucide-react";
import OemFooter from "../../components/oem/Footer";
import { backendUrl } from "../../lib/config";

type OverviewData = {
  organization: { id: string; name: string };
  stats: {
    deviceFamilies: number;
    activeBuilds: number;
    trustAnchors: number;
    totalDevices: number;
    trustedDevices: number;
    failingDevices: number;
    unknownDevices: number;
  };
  families: Array<{
    id: string;
    name: string;
    model?: string | null;
    enabled: boolean;
    activeBuilds: number;
    status: "healthy" | "warning" | "disabled";
  }>;
  recentReports: Array<{
    id: string;
    scopedDeviceId: string;
    deviceFamilyId?: string | null;
    deviceFamilyName: string;
    buildFingerprint?: string | null;
    reasonCodes: string[];
    lastSeen: string;
  }>;
  federationBackends: Array<{
    id: string;
    name: string;
    status: "active" | "disabled";
    createdAt: string;
  }>;
};

type Modal = "register" | "import" | null;

function StatCard({
  label,
  value,
  icon,
  color,
}: {
  label: string;
  value: number;
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
        <p className="mt-1 text-2xl font-semibold text-[#071226]">{value}</p>
      </div>
    </article>
  );
}

function Panel({ title, id, children }: { title: string; id?: string; children: React.ReactNode }) {
  return (
    <section id={id} className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
      <h2 className="text-lg font-semibold text-[#071226]">{title}</h2>
      {children}
    </section>
  );
}

function timeAgo(value: string) {
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(value).getTime()) / 1000));
  if (seconds < 60) return "Just now";
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

export default function OemOverview({
  onOrganizationLoaded,
}: {
  onOrganizationLoaded?: (name: string) => void;
}) {
  const [data, setData] = useState<OverviewData | null>(null);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  const [modal, setModal] = useState<Modal>(null);
  const [familyForm, setFamilyForm] = useState({ codename: "", model: "" });
  const [importJson, setImportJson] = useState("");

  const loadOverview = useCallback(async () => {
    const token = localStorage.getItem("ua_access");
    if (!token) {
      window.location.href = "/login";
      return;
    }
    setLoading(true);
    try {
      const response = await fetch(`${backendUrl}/api/v1/oem/overview`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (response.status === 401) {
        localStorage.removeItem("ua_access");
        localStorage.removeItem("ua_refresh");
        window.location.href = "/login";
        return;
      }
      let payload: OverviewData;
      if (response.ok) {
        payload = await response.json();
      } else {
        const headers = { Authorization: `Bearer ${token}` };
        const [
          familiesResponse,
          anchorsResponse,
          reportsResponse,
          federationResponse,
          profileResponse,
        ] = await Promise.all([
          fetch(`${backendUrl}/api/v1/oem/device-families`, { headers }),
          fetch(`${backendUrl}/api/v1/oem/anchors`, { headers }),
          fetch(`${backendUrl}/api/v1/oem/reports/failing-devices`, { headers }),
          fetch(`${backendUrl}/api/v1/federation/backends`),
          fetch(`${backendUrl}/api/v1/oem/profile`, { headers }),
        ]);
        if (!familiesResponse.ok) {
          throw new Error("Unable to load OEM overview.");
        }
        const families: Array<{
          id: string;
          name: string;
          codename?: string | null;
          model?: string | null;
          enabled: boolean;
          activeBuilds?: number;
        }> = await familiesResponse.json();
        const [anchors, reports, federation, profile] = await Promise.all([
          anchorsResponse.ok ? anchorsResponse.json() : Promise.resolve([]),
          reportsResponse.ok ? reportsResponse.json() : Promise.resolve([]),
          federationResponse.ok ? federationResponse.json() : Promise.resolve([]),
          profileResponse.ok ? profileResponse.json() : Promise.resolve({ name: "OEM Portal" }),
        ]);
        const buildResponses = await Promise.all(
          families.map((family) =>
            fetch(`${backendUrl}/api/v1/oem/device-families/${family.id}/builds`, { headers }),
          ),
        );
        const buildsByFamily = await Promise.all(
          buildResponses.map(async (buildResponse) =>
            buildResponse.ok ? await buildResponse.json() : [],
          ),
        );
        const activeBuildCounts = buildsByFamily.map(
          (builds: Array<{ enabled?: boolean }>) =>
            builds.filter((build) => build.enabled !== false).length,
        );
        const failingReports = reports as Array<{
          id: string;
          scopedDeviceId: string;
          deviceFamilyId?: string | null;
          buildFingerprint?: string | null;
          lastVerdict?: { reasonCodes?: string[] };
          lastSeen: string;
        }>;
        const anchorItems = anchors as Array<{
          deviceFamilyId?: string;
          revokedAt?: string | null;
        }>;
        payload = {
          organization: { id: profile.id || "", name: profile.name || "OEM Portal" },
          stats: {
            deviceFamilies: families.length,
            activeBuilds: activeBuildCounts.reduce((total, count) => total + count, 0),
            trustAnchors: anchorItems.filter((anchor) => !anchor.revokedAt).length,
            totalDevices: failingReports.length,
            trustedDevices: 0,
            failingDevices: failingReports.length,
            unknownDevices: 0,
          },
          families: families.map((family, index) => ({
            id: family.id,
            name: family.codename || family.name,
            model: family.model,
            enabled: family.enabled,
            activeBuilds: activeBuildCounts[index] || Number(family.activeBuilds || 0),
            status: failingReports.some((report) => report.deviceFamilyId === family.id)
              ? "warning"
              : family.enabled
                ? "healthy"
                : "disabled",
          })),
          recentReports: failingReports.slice(0, 5).map((report) => ({
            id: report.id,
            scopedDeviceId: report.scopedDeviceId,
            deviceFamilyId: report.deviceFamilyId,
            deviceFamilyName:
              families.find((family) => family.id === report.deviceFamilyId)?.codename ||
              families.find((family) => family.id === report.deviceFamilyId)?.name ||
              "Unknown",
            buildFingerprint: report.buildFingerprint,
            reasonCodes: report.lastVerdict?.reasonCodes || [],
            lastSeen: report.lastSeen,
          })),
          federationBackends: federation,
        };
      }
      payload.stats = {
        deviceFamilies: Number(payload.stats?.deviceFamilies || 0),
        activeBuilds: Number(payload.stats?.activeBuilds || 0),
        trustAnchors: Number(payload.stats?.trustAnchors || 0),
        totalDevices: Number(payload.stats?.totalDevices || 0),
        trustedDevices: Number(payload.stats?.trustedDevices || 0),
        failingDevices: Number(payload.stats?.failingDevices || 0),
        unknownDevices: Number(payload.stats?.unknownDevices || 0),
      };
      payload.families = (payload.families || []).map((family) => ({
        ...family,
        activeBuilds: Number(family.activeBuilds || 0),
      }));
      payload.recentReports = payload.recentReports || [];
      payload.federationBackends = payload.federationBackends || [];
      setData(payload);
      onOrganizationLoaded?.(payload.organization.name);
      setError(null);
    } catch (requestError) {
      setError(
        requestError instanceof Error ? requestError.message : "Unable to load OEM overview.",
      );
    } finally {
      setLoading(false);
    }
  }, [onOrganizationLoaded]);

  useEffect(() => {
    loadOverview();
  }, [loadOverview]);

  const createFamily = async () => {
    const token = localStorage.getItem("ua_access");
    if (!token || !familyForm.codename.trim()) return;
    setSubmitting(true);
    setError(null);
    try {
      const response = await fetch(`${backendUrl}/api/v1/oem/device-families`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          codename: familyForm.codename.trim(),
          model: familyForm.model.trim() || undefined,
        }),
      });
      if (!response.ok) throw new Error((await response.text()) || "Unable to register device.");
      setFamilyForm({ codename: "", model: "" });
      setModal(null);
      setNotice("Device family registered successfully.");
      await loadOverview();
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Unable to register device.");
    } finally {
      setSubmitting(false);
    }
  };

  const importDevice = async () => {
    const token = localStorage.getItem("ua_access");
    if (!token || !importJson.trim()) return;
    setSubmitting(true);
    setError(null);
    try {
      let payload: unknown;
      try {
        payload = JSON.parse(importJson);
      } catch {
        throw new Error("The imported JSON is not valid.");
      }
      const response = await fetch(`${backendUrl}/api/v1/oem/import-device`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(payload),
      });
      if (!response.ok) throw new Error((await response.text()) || "Unable to import device.");
      setImportJson("");
      setModal(null);
      setNotice("Device JSON imported successfully.");
      await loadOverview();
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Unable to import device.");
    } finally {
      setSubmitting(false);
    }
  };

  const visibleFamilies = useMemo(() => {
    const query = search.trim().toLowerCase();
    if (!query) return data?.families || [];
    return (data?.families || []).filter(
      (family) =>
        family.name.toLowerCase().includes(query) || family.model?.toLowerCase().includes(query),
    );
  }, [data?.families, search]);

  const visibleReports = useMemo(() => {
    const query = search.trim().toLowerCase();
    if (!query) return data?.recentReports || [];
    return (data?.recentReports || []).filter(
      (report) =>
        report.deviceFamilyName.toLowerCase().includes(query) ||
        report.reasonCodes.some((reason) => reason.toLowerCase().includes(query)),
    );
  }, [data?.recentReports, search]);

  const stats = data?.stats || {
    deviceFamilies: 0,
    activeBuilds: 0,
    trustAnchors: 0,
    totalDevices: 0,
    trustedDevices: 0,
    failingDevices: 0,
    unknownDevices: 0,
  };
  const healthPercent = stats.totalDevices
    ? Math.round((stats.trustedDevices / stats.totalDevices) * 1000) / 10
    : 100;

  return (
    <div className="flex min-h-[calc(100vh-3rem)] flex-col gap-5">
      <header className="flex flex-col gap-4 border-b border-slate-200 pb-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-[#071226]">OEM Overview</h1>
          <p className="mt-1 text-sm text-slate-500">
            Monitor device trust, build coverage, and attestation health.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <label className="relative min-w-0 flex-1 sm:w-80">
            <Search
              size={18}
              className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-400"
            />
            <input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Search devices, builds, reports..."
              className="h-10 w-full rounded-lg border border-slate-200 bg-white pl-10 pr-3 text-sm outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-100"
            />
          </label>
          <div className="relative">
            <button
              type="button"
              onClick={() => setNotificationsOpen((open) => !open)}
              className="relative flex h-10 w-10 items-center justify-center rounded-lg border border-slate-200 bg-white text-[#071226] hover:bg-slate-50"
              aria-label="Open notifications"
            >
              <Bell size={19} />
              {stats.failingDevices > 0 && (
                <span className="absolute -right-1 -top-1 flex h-5 min-w-5 items-center justify-center rounded-full bg-red-600 px-1 text-[10px] font-bold text-white">
                  {stats.failingDevices > 9 ? "9+" : stats.failingDevices}
                </span>
              )}
            </button>
            {notificationsOpen && (
              <div className="absolute right-0 top-12 z-40 w-[min(22rem,calc(100vw-2rem))] overflow-hidden rounded-xl border border-slate-200 bg-white shadow-xl">
                <div className="border-b border-slate-200 px-4 py-3 text-sm font-semibold text-[#071226]">
                  Recent alerts
                </div>
                {data?.recentReports.length ? (
                  data.recentReports.slice(0, 4).map((report) => (
                    <div
                      key={report.id}
                      className="border-b border-slate-100 px-4 py-3 last:border-0"
                    >
                      <p className="text-sm font-medium text-slate-800">
                        {report.reasonCodes[0] || "Attestation failed"}
                      </p>
                      <p className="mt-1 text-xs text-slate-500">
                        {report.deviceFamilyName} · {timeAgo(report.lastSeen)}
                      </p>
                    </div>
                  ))
                ) : (
                  <p className="px-4 py-8 text-center text-sm text-slate-500">No new alerts.</p>
                )}
              </div>
            )}
          </div>
        </div>
      </header>

      <section className="flex flex-col gap-3 sm:flex-row sm:justify-end">
        <button
          type="button"
          onClick={() => {
            setError(null);
            setModal("register");
          }}
          className="flex h-10 items-center justify-center gap-2 rounded-lg bg-[#071226] px-4 text-sm font-medium text-white hover:bg-[#101f36]"
        >
          <Plus size={18} />
          Register Device
        </button>
        <button
          type="button"
          onClick={() => {
            setError(null);
            setModal("import");
          }}
          className="flex h-10 items-center justify-center gap-2 rounded-lg border border-slate-300 bg-white px-4 text-sm font-medium text-slate-700 hover:bg-slate-50"
        >
          <CloudUpload size={18} />
          Import JSON
        </button>
      </section>

      {error && !modal && (
        <div className="rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
          {error}
        </div>
      )}
      {notice && (
        <div className="flex items-center gap-2 rounded-xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-700">
          <Check size={17} />
          {notice}
        </div>
      )}

      <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          label="Device Families"
          value={stats.deviceFamilies}
          icon={<Boxes size={23} />}
          color="bg-violet-50 text-violet-700"
        />
        <StatCard
          label="Active Builds"
          value={stats.activeBuilds}
          icon={<Layers3 size={23} />}
          color="bg-blue-50 text-blue-700"
        />
        <StatCard
          label="Trust Anchors"
          value={stats.trustAnchors}
          icon={<ShieldCheck size={23} />}
          color="bg-emerald-50 text-emerald-700"
        />
        <StatCard
          label="Failing Devices"
          value={stats.failingDevices}
          icon={<AlertTriangle size={23} />}
          color="bg-red-50 text-red-600"
        />
      </section>

      {loading ? (
        <div className="flex items-center justify-center gap-2 rounded-xl border border-slate-200 bg-white py-20 text-sm text-slate-500">
          <Loader2 size={18} className="animate-spin" />
          Loading OEM overview...
        </div>
      ) : (
        <>
          <section className="grid gap-4 xl:grid-cols-2">
            <Panel title="Device Trust Health">
              <div className="mt-5 grid items-center gap-6 sm:grid-cols-[220px_1fr]">
                <div>
                  <div
                    className="relative mx-auto flex h-48 w-48 items-center justify-center rounded-full"
                    style={{
                      background: `conic-gradient(#16a34a 0 ${healthPercent}%, #dc2626 ${healthPercent}% ${
                        healthPercent +
                        (stats.totalDevices ? (stats.failingDevices / stats.totalDevices) * 100 : 0)
                      }%, #94a3b8 0)`,
                    }}
                  >
                    <div className="flex h-36 w-36 flex-col items-center justify-center rounded-full bg-white">
                      <strong className="text-3xl text-[#071226]">{healthPercent}%</strong>
                      <span className="mt-1 text-sm font-medium text-emerald-600">Healthy</span>
                    </div>
                  </div>
                  <p className="mt-4 text-center text-xs text-slate-500">
                    Based on {stats.totalDevices.toLocaleString()} attested devices
                  </p>
                </div>
                <div className="divide-y divide-slate-100">
                  {[
                    ["Trusted", stats.trustedDevices, "bg-emerald-600", "text-emerald-700"],
                    ["Failing", stats.failingDevices, "bg-red-600", "text-red-600"],
                    ["Unknown", stats.unknownDevices, "bg-slate-400", "text-slate-700"],
                  ].map(([label, value, dot, color]) => (
                    <div key={String(label)} className="flex items-center justify-between py-4">
                      <span className="flex items-center gap-3 text-sm text-slate-600">
                        <span className={`h-2.5 w-2.5 rounded-full ${dot}`} />
                        {label}
                      </span>
                      <strong className={`text-xl ${color}`}>
                        {Number(value).toLocaleString()}
                      </strong>
                    </div>
                  ))}
                </div>
              </div>
            </Panel>

            <Panel title="Device Families" id="device-families">
              <div className="mt-3 divide-y divide-slate-100 overflow-hidden rounded-xl border border-slate-200">
                {visibleFamilies.slice(0, 6).map((family) => (
                  <a
                    key={family.id}
                    href={`/oem/devices?deviceFamilyId=${family.id}`}
                    className="flex items-center gap-3 px-4 py-3 transition hover:bg-slate-50"
                  >
                    <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-blue-50 text-blue-700">
                      <Smartphone size={20} />
                    </span>
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-sm font-medium text-slate-900">
                        {family.name}
                      </span>
                      <span className="block truncate text-xs text-slate-500">
                        {family.model || `${family.activeBuilds} active builds`}
                      </span>
                    </span>
                    <span
                      className={`flex items-center gap-1.5 text-xs font-medium ${
                        family.status === "healthy"
                          ? "text-emerald-700"
                          : family.status === "warning"
                            ? "text-amber-600"
                            : "text-red-600"
                      }`}
                    >
                      {family.status === "healthy" ? (
                        <CheckCircle2 size={18} />
                      ) : (
                        <AlertTriangle size={18} />
                      )}
                      {family.status === "healthy"
                        ? "Healthy"
                        : family.status === "warning"
                          ? "Warning"
                          : "Disabled"}
                    </span>
                    <ChevronRight size={17} className="text-slate-400" />
                  </a>
                ))}
                {visibleFamilies.length === 0 && (
                  <p className="px-4 py-12 text-center text-sm text-slate-500">
                    No device families found.
                  </p>
                )}
              </div>
            </Panel>
          </section>

          <section className="grid gap-4 lg:grid-cols-2 xl:grid-cols-3">
            <Panel title="Recent Reports" id="reports">
              <div className="mt-3 divide-y divide-slate-100">
                {visibleReports.slice(0, 4).map((report) => (
                  <div key={report.id} className="flex items-center gap-3 py-3">
                    <AlertTriangle size={20} className="shrink-0 text-amber-500" />
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-sm font-medium text-slate-800">
                        {report.reasonCodes[0] || "ATTESTATION_FAILED"}
                      </p>
                      <p className="truncate text-xs text-slate-500">
                        Device family: {report.deviceFamilyName}
                      </p>
                    </div>
                    <span className="shrink-0 text-xs text-slate-500">
                      {timeAgo(report.lastSeen)}
                    </span>
                  </div>
                ))}
                {visibleReports.length === 0 && (
                  <p className="py-10 text-center text-sm text-slate-500">No failing reports.</p>
                )}
              </div>
              <a href="/oem#reports" className="mt-4 inline-flex text-xs font-medium text-blue-700">
                View all reports
              </a>
            </Panel>

            <Panel title="Federation Health" id="federation">
              <div className="mt-3 divide-y divide-slate-100">
                {data?.federationBackends.slice(0, 4).map((backend) => (
                  <div key={backend.id} className="flex items-center gap-3 py-3">
                    <span className="flex h-10 w-10 items-center justify-center rounded-lg bg-blue-50 text-blue-700">
                      <Server size={20} />
                    </span>
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-sm font-medium text-slate-900">{backend.name}</p>
                      <p className="text-xs text-slate-500">Federation Server</p>
                    </div>
                    <span
                      className={`flex items-center gap-1.5 text-xs font-medium ${
                        backend.status === "active" ? "text-emerald-700" : "text-red-600"
                      }`}
                    >
                      {backend.status === "active" ? (
                        <CheckCircle2 size={18} />
                      ) : (
                        <AlertTriangle size={18} />
                      )}
                      {backend.status === "active" ? "Healthy" : "Disabled"}
                    </span>
                  </div>
                ))}
                {!data?.federationBackends.length && (
                  <p className="py-10 text-center text-sm text-slate-500">
                    No federated backends configured.
                  </p>
                )}
              </div>
            </Panel>

            <Panel title="Attestation Summary" id="trust-anchors">
              <div className="mt-3 divide-y divide-slate-100 text-sm">
                {[
                  ["Total Devices", stats.totalDevices, "text-slate-900"],
                  ["Trusted Devices", stats.trustedDevices, "text-emerald-700"],
                  ["Failing Devices", stats.failingDevices, "text-red-600"],
                  ["Unknown Devices", stats.unknownDevices, "text-slate-700"],
                  ["Trust Health", `${healthPercent}%`, "text-emerald-700"],
                ].map(([label, value, color]) => (
                  <div key={String(label)} className="flex justify-between py-3">
                    <span className="text-slate-500">{label}</span>
                    <strong className={String(color)}>{value}</strong>
                  </div>
                ))}
              </div>
            </Panel>
          </section>
        </>
      )}

      <div id="build-policies" />
      <div id="api-access" />
      <div id="organization" />
      <OemFooter />

      {modal &&
        typeof document !== "undefined" &&
        createPortal(
          <>
            <button
              type="button"
              aria-label="Close dialog"
              onClick={() => setModal(null)}
              className="fixed inset-0 z-[9998] bg-[#071226]/60 backdrop-blur-sm"
            />
            <section className="fixed left-1/2 top-1/2 z-[9999] w-[calc(100%-2rem)] max-w-lg -translate-x-1/2 -translate-y-1/2 overflow-hidden rounded-2xl bg-white shadow-2xl">
              <header className="flex items-center justify-between border-b border-slate-200 px-6 py-5">
                <h2 className="text-lg font-semibold text-[#071226]">
                  {modal === "register" ? "Register Device Family" : "Import Device JSON"}
                </h2>
                <button
                  type="button"
                  onClick={() => setModal(null)}
                  className="rounded-lg p-2 text-slate-500 hover:bg-slate-100"
                >
                  <X size={20} />
                </button>
              </header>
              <div className="space-y-4 p-6">
                {modal === "register" ? (
                  <>
                    <label className="block text-sm font-medium text-slate-700">
                      Device codename
                      <input
                        value={familyForm.codename}
                        onChange={(event) =>
                          setFamilyForm((current) => ({
                            ...current,
                            codename: event.target.value,
                          }))
                        }
                        placeholder="e.g., bluejay"
                        className="mt-2 h-11 w-full rounded-lg border border-slate-200 px-3 text-sm outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-100"
                      />
                    </label>
                    <label className="block text-sm font-medium text-slate-700">
                      Model
                      <input
                        value={familyForm.model}
                        onChange={(event) =>
                          setFamilyForm((current) => ({
                            ...current,
                            model: event.target.value,
                          }))
                        }
                        placeholder="e.g., Pixel 6a"
                        className="mt-2 h-11 w-full rounded-lg border border-slate-200 px-3 text-sm outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-100"
                      />
                    </label>
                  </>
                ) : (
                  <label className="block text-sm font-medium text-slate-700">
                    Device JSON
                    <textarea
                      value={importJson}
                      onChange={(event) => setImportJson(event.target.value)}
                      rows={10}
                      placeholder="Paste the complete JSON exported by the Android service"
                      className="mt-2 w-full resize-y rounded-lg border border-slate-200 p-3 font-mono text-xs outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-100"
                    />
                  </label>
                )}
                {error && (
                  <div className="rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
                    {error}
                  </div>
                )}
              </div>
              <footer className="grid grid-cols-2 gap-3 border-t border-slate-200 p-6">
                <button
                  type="button"
                  onClick={() => setModal(null)}
                  className="h-11 rounded-lg border border-slate-200 text-sm font-medium text-slate-700 hover:bg-slate-50"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={modal === "register" ? createFamily : importDevice}
                  disabled={
                    submitting ||
                    (modal === "register" ? !familyForm.codename.trim() : !importJson.trim())
                  }
                  className="flex h-11 items-center justify-center gap-2 rounded-lg bg-[#071226] text-sm font-medium text-white hover:bg-[#101f36] disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {submitting && <Loader2 size={17} className="animate-spin" />}
                  {modal === "register" ? "Register Device" : "Import JSON"}
                </button>
              </footer>
            </section>
          </>,
          document.body,
        )}
    </div>
  );
}
