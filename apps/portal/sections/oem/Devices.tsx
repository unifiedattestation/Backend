import { useCallback, useEffect, useMemo, useState } from "react";
import { createPortal } from "react-dom";
import {
  ArrowLeft,
  ArrowRight,
  Boxes,
  Check,
  CheckCircle2,
  CloudUpload,
  Info,
  Layers3,
  Loader2,
  MoreVertical,
  Plus,
  Search,
  ShieldCheck,
  Smartphone,
  Trash2,
  X,
} from "lucide-react";
import OemFooter from "../../components/oem/Footer";
import { backendUrl } from "../../lib/config";

type DeviceFamily = {
  id: string;
  name: string;
  codename?: string | null;
  model?: string | null;
  enabled: boolean;
  createdAt: string;
  activeBuilds: number;
  activeTrustAnchors: number;
  reports: number;
};

type DrawerTab = "register" | "import";

function StatCard({
  label,
  value,
  icon,
  color,
}: {
  label: string;
  value: string | number;
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

function timeAgo(value: string) {
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(value).getTime()) / 1000));
  if (seconds < 60) return "Just now";
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

export default function OemDevices({
  onOrganizationLoaded,
}: {
  onOrganizationLoaded?: (name: string) => void;
}) {
  const [families, setFamilies] = useState<DeviceFamily[]>([]);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [status, setStatus] = useState<"all" | "enabled" | "disabled">("all");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [drawerTab, setDrawerTab] = useState<DrawerTab>("register");
  const [actionMenu, setActionMenu] = useState<string | null>(null);
  const [actionPosition, setActionPosition] = useState({ top: 0, left: 0 });
  const [form, setForm] = useState({ codename: "", model: "", enabled: true });
  const [importJson, setImportJson] = useState("");

  const loadFamilies = useCallback(async () => {
    const token = localStorage.getItem("ua_access");
    if (!token) {
      window.location.href = "/login";
      return;
    }
    setLoading(true);
    try {
      const headers = { Authorization: `Bearer ${token}` };
      const [familiesResponse, profileResponse] = await Promise.all([
        fetch(`${backendUrl}/api/v1/oem/device-families`, { headers }),
        fetch(`${backendUrl}/api/v1/oem/profile`, { headers }),
      ]);
      if (familiesResponse.status === 401) {
        localStorage.removeItem("ua_access");
        localStorage.removeItem("ua_refresh");
        window.location.href = "/login";
        return;
      }
      if (!familiesResponse.ok) {
        throw new Error((await familiesResponse.text()) || "Unable to load device families.");
      }
      const familyData: DeviceFamily[] = await familiesResponse.json();
      setFamilies(
        familyData.map((family) => ({
          ...family,
          activeBuilds: Number(family.activeBuilds || 0),
          activeTrustAnchors: Number(family.activeTrustAnchors || 0),
          reports: Number(family.reports || 0),
        })),
      );
      if (profileResponse.ok) {
        const profile = await profileResponse.json();
        onOrganizationLoaded?.(profile.name || "OEM Portal");
      }
      setError(null);
    } catch (requestError) {
      setError(
        requestError instanceof Error ? requestError.message : "Unable to load device families.",
      );
    } finally {
      setLoading(false);
    }
  }, [onOrganizationLoaded]);

  useEffect(() => {
    loadFamilies();
  }, [loadFamilies]);

  useEffect(() => {
    setPage(1);
  }, [search, status, pageSize]);

  const openDrawer = (tab: DrawerTab) => {
    setDrawerTab(tab);
    setError(null);
    setDrawerOpen(true);
  };

  const createFamily = async () => {
    const token = localStorage.getItem("ua_access");
    if (!token || !form.codename.trim()) return;
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
          codename: form.codename.trim(),
          model: form.model.trim() || undefined,
          enabled: form.enabled,
        }),
      });
      if (!response.ok) throw new Error((await response.text()) || "Unable to register device.");
      setForm({ codename: "", model: "", enabled: true });
      setDrawerOpen(false);
      setNotice("Device family registered successfully.");
      await loadFamilies();
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
      setDrawerOpen(false);
      setNotice("Device JSON imported successfully.");
      await loadFamilies();
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Unable to import device.");
    } finally {
      setSubmitting(false);
    }
  };

  const toggleFamily = async (family: DeviceFamily) => {
    const token = localStorage.getItem("ua_access");
    if (!token) return;
    setActionMenu(null);
    try {
      const response = await fetch(`${backendUrl}/api/v1/oem/device-families/${family.id}`, {
        method: "PUT",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ enabled: !family.enabled }),
      });
      if (!response.ok) throw new Error((await response.text()) || "Unable to update device.");
      setNotice(`Device family ${family.enabled ? "disabled" : "enabled"}.`);
      await loadFamilies();
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Unable to update device.");
    }
  };

  const deleteFamily = async (family: DeviceFamily) => {
    if (!window.confirm(`Delete ${family.codename || family.name}?`)) return;
    const token = localStorage.getItem("ua_access");
    if (!token) return;
    setActionMenu(null);
    try {
      const response = await fetch(`${backendUrl}/api/v1/oem/device-families/${family.id}`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!response.ok) throw new Error((await response.text()) || "Unable to delete device.");
      setNotice("Device family deleted.");
      await loadFamilies();
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Unable to delete device.");
    }
  };

  const filteredFamilies = useMemo(() => {
    const query = search.trim().toLowerCase();
    return families.filter((family) => {
      const matchesSearch =
        !query ||
        family.name.toLowerCase().includes(query) ||
        family.codename?.toLowerCase().includes(query) ||
        family.model?.toLowerCase().includes(query);
      const matchesStatus =
        status === "all" ||
        (status === "enabled" && family.enabled) ||
        (status === "disabled" && !family.enabled);
      return matchesSearch && matchesStatus;
    });
  }, [families, search, status]);

  const totalPages = Math.max(1, Math.ceil(filteredFamilies.length / pageSize));
  const visibleFamilies = filteredFamilies.slice((page - 1) * pageSize, page * pageSize);
  const enabledCount = families.filter((family) => family.enabled).length;
  const activeBuilds = families.reduce(
    (total, family) => total + Number(family.activeBuilds || 0),
    0,
  );
  const coveredFamilies = families.filter((family) => family.activeTrustAnchors > 0).length;
  const trustCoverage = families.length ? Math.round((coveredFamilies / families.length) * 100) : 0;

  return (
    <div className="flex min-h-[calc(100vh-3rem)] flex-col gap-5">
      <header className="flex flex-col gap-4 border-b border-slate-200 pb-4 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-[#071226]">Device Families</h1>
          <p className="mt-1 text-sm text-slate-500">
            Manage device families and their trust configuration.
          </p>
        </div>
        <div className="flex flex-col gap-2 sm:flex-row">
          <button
            type="button"
            onClick={() => openDrawer("register")}
            className="flex h-10 items-center justify-center gap-2 rounded-lg bg-[#071226] px-4 text-sm font-medium text-white hover:bg-[#101f36]"
          >
            <Plus size={18} />
            Register Device
          </button>
          <button
            type="button"
            onClick={() => openDrawer("import")}
            className="flex h-10 items-center justify-center gap-2 rounded-lg border border-slate-300 bg-white px-4 text-sm font-medium text-slate-700 hover:bg-slate-50"
          >
            <CloudUpload size={18} />
            Import JSON
          </button>
        </div>
      </header>

      <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          label="Total Families"
          value={families.length}
          icon={<Boxes size={23} />}
          color="bg-violet-50 text-violet-700"
        />
        <StatCard
          label="Enabled"
          value={enabledCount}
          icon={<ShieldCheck size={23} />}
          color="bg-emerald-50 text-emerald-700"
        />
        <StatCard
          label="Active Builds"
          value={activeBuilds}
          icon={<Layers3 size={23} />}
          color="bg-blue-50 text-blue-700"
        />
        <StatCard
          label="Trust Coverage"
          value={`${trustCoverage}%`}
          icon={<CheckCircle2 size={23} />}
          color="bg-cyan-50 text-cyan-700"
        />
      </section>

      {error && !drawerOpen && (
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

      <section className="overflow-visible rounded-xl border border-slate-200 bg-white shadow-sm">
        <header className="flex flex-col gap-3 border-b border-slate-200 p-4 sm:flex-row">
          <label className="relative flex-1">
            <Search
              size={18}
              className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-400"
            />
            <input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Search device families..."
              className="h-10 w-full rounded-lg border border-slate-200 pl-10 pr-3 text-sm outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-100"
            />
          </label>
          <select
            value={status}
            onChange={(event) => setStatus(event.target.value as typeof status)}
            className="h-10 rounded-lg border border-slate-200 bg-white px-3 text-sm text-slate-700 outline-none"
          >
            <option value="all">All Statuses</option>
            <option value="enabled">Enabled</option>
            <option value="disabled">Disabled</option>
          </select>
        </header>

        <div className="overflow-x-auto">
          <table className="w-full min-w-[940px] text-left text-sm">
            <thead className="bg-slate-50 text-xs text-slate-500">
              <tr>
                <th className="px-5 py-3 font-semibold">Codename</th>
                <th className="px-5 py-3 font-semibold">Model</th>
                <th className="px-5 py-3 font-semibold">Status</th>
                <th className="px-5 py-3 font-semibold">Build Policies</th>
                <th className="px-5 py-3 font-semibold">Trust Anchor</th>
                <th className="px-5 py-3 font-semibold">Reports</th>
                <th className="px-5 py-3 font-semibold">Last Updated</th>
                <th className="px-5 py-3 text-right font-semibold">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {visibleFamilies.map((family) => (
                <tr key={family.id} className="hover:bg-slate-50/70">
                  <td className="px-5 py-3">
                    <div className="flex items-center gap-3">
                      <span className="flex h-9 w-9 items-center justify-center rounded-lg bg-blue-50 text-blue-700">
                        <Smartphone size={18} />
                      </span>
                      <span className="font-medium text-slate-900">
                        {family.codename || family.name}
                      </span>
                    </div>
                  </td>
                  <td className="px-5 py-3 text-slate-500">{family.model || "—"}</td>
                  <td className="px-5 py-3">
                    <span
                      className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium ${
                        family.enabled ? "bg-emerald-50 text-emerald-700" : "bg-red-50 text-red-700"
                      }`}
                    >
                      {family.enabled ? <CheckCircle2 size={15} /> : <X size={15} />}
                      {family.enabled ? "Enabled" : "Disabled"}
                    </span>
                  </td>
                  <td className="px-5 py-3 font-medium text-blue-700">{family.activeBuilds}</td>
                  <td className="px-5 py-3 font-medium text-blue-700">
                    {family.activeTrustAnchors}
                  </td>
                  <td className="px-5 py-3 font-medium text-blue-700">{family.reports}</td>
                  <td className="px-5 py-3 text-slate-500">{timeAgo(family.createdAt)}</td>
                  <td className="relative px-5 py-3 text-right">
                    <button
                      type="button"
                      aria-label={`Actions for ${family.codename || family.name}`}
                      onClick={(event) => {
                        if (actionMenu === family.id) {
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
                        setActionMenu(family.id);
                      }}
                      className="rounded-lg p-2 text-slate-500 hover:bg-slate-100"
                    >
                      <MoreVertical size={18} />
                    </button>
                    {actionMenu === family.id &&
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
                              onClick={() => toggleFamily(family)}
                              className="flex w-full items-center gap-2 px-3 py-2 text-sm text-slate-700 hover:bg-slate-50"
                            >
                              {family.enabled ? <X size={16} /> : <Check size={16} />}
                              {family.enabled ? "Disable" : "Enable"}
                            </button>
                            <button
                              type="button"
                              onClick={() => deleteFamily(family)}
                              className="flex w-full items-center gap-2 px-3 py-2 text-sm text-red-600 hover:bg-red-50"
                            >
                              <Trash2 size={16} />
                              Delete
                            </button>
                          </div>
                        </>,
                        document.body,
                      )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {loading && (
            <div className="flex items-center justify-center gap-2 px-5 py-14 text-sm text-slate-500">
              <Loader2 size={18} className="animate-spin" />
              Loading device families...
            </div>
          )}
          {!loading && visibleFamilies.length === 0 && (
            <div className="px-5 py-14 text-center text-sm text-slate-500">
              No device families found.
            </div>
          )}
        </div>

        <footer className="flex flex-col gap-3 border-t border-slate-200 px-5 py-4 text-xs text-slate-500 sm:flex-row sm:items-center sm:justify-between">
          <span>
            Showing {filteredFamilies.length ? (page - 1) * pageSize + 1 : 0} to{" "}
            {Math.min(page * pageSize, filteredFamilies.length)} of {filteredFamilies.length}{" "}
            results
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
            <select
              value={pageSize}
              onChange={(event) => setPageSize(Number(event.target.value))}
              className="h-8 rounded-lg border border-slate-200 bg-white px-2"
            >
              <option value={10}>10 per page</option>
              <option value={20}>20 per page</option>
              <option value={50}>50 per page</option>
            </select>
          </div>
        </footer>
      </section>

      <OemFooter />

      {drawerOpen &&
        typeof document !== "undefined" &&
        createPortal(
          <>
            <button
              type="button"
              aria-label="Close drawer"
              onClick={() => setDrawerOpen(false)}
              className="fixed inset-0 z-[9998] bg-[#071226]/55 backdrop-blur-sm"
            />
            <aside className="fixed inset-y-0 right-0 z-[9999] flex w-full max-w-md flex-col bg-white shadow-2xl">
              <header className="flex items-center justify-between border-b border-slate-200 px-6 py-5">
                <h2 className="text-lg font-semibold text-[#071226]">Register Device Family</h2>
                <button
                  type="button"
                  onClick={() => setDrawerOpen(false)}
                  className="rounded-lg p-2 text-slate-500 hover:bg-slate-100"
                >
                  <X size={20} />
                </button>
              </header>

              <div className="flex border-b border-slate-200 px-6">
                {[
                  ["register", "Register Device"],
                  ["import", "Import Device JSON"],
                ].map(([id, label]) => (
                  <button
                    key={id}
                    type="button"
                    onClick={() => {
                      setDrawerTab(id as DrawerTab);
                      setError(null);
                    }}
                    className={`border-b-2 px-2 py-4 text-sm font-medium ${
                      drawerTab === id
                        ? "border-blue-700 text-blue-700"
                        : "border-transparent text-slate-500"
                    }`}
                  >
                    {label}
                  </button>
                ))}
              </div>

              <div className="flex-1 space-y-5 overflow-y-auto p-6">
                {drawerTab === "register" ? (
                  <>
                    <p className="text-sm leading-6 text-slate-500">
                      Register a new device family to manage its builds, policies, and trust
                      configuration.
                    </p>
                    <label className="block text-sm font-medium text-slate-700">
                      <span className="flex items-center gap-2">
                        Device Codename <Info size={14} className="text-slate-400" />
                      </span>
                      <input
                        value={form.codename}
                        onChange={(event) =>
                          setForm((current) => ({
                            ...current,
                            codename: event.target.value.toLowerCase(),
                          }))
                        }
                        placeholder="Enter unique codename (e.g., algiz)"
                        className="mt-2 h-11 w-full rounded-lg border border-slate-200 px-3 text-sm outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-100"
                      />
                      <span className="mt-2 block text-xs font-normal text-slate-500">
                        Lowercase letters, numbers, and hyphens only.
                      </span>
                    </label>
                    <label className="block text-sm font-medium text-slate-700">
                      <span className="flex items-center gap-2">
                        Model Name <span className="font-normal text-slate-400">(optional)</span>
                      </span>
                      <input
                        value={form.model}
                        onChange={(event) =>
                          setForm((current) => ({ ...current, model: event.target.value }))
                        }
                        placeholder="Enter model name"
                        className="mt-2 h-11 w-full rounded-lg border border-slate-200 px-3 text-sm outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-100"
                      />
                    </label>
                    <label className="flex items-center justify-between gap-4">
                      <div>
                        <p className="text-sm font-medium text-slate-700">Enabled</p>
                        <p className="mt-1 text-xs text-slate-500">
                          Enabled families can be used in build policies and attestations.
                        </p>
                      </div>
                      <input
                        type="checkbox"
                        checked={form.enabled}
                        onChange={(event) =>
                          setForm((current) => ({ ...current, enabled: event.target.checked }))
                        }
                        className="h-5 w-5 accent-emerald-600"
                      />
                    </label>
                    <div className="rounded-xl border border-blue-200 bg-blue-50 p-4">
                      <div className="flex gap-3">
                        <Info size={20} className="shrink-0 text-blue-700" />
                        <div>
                          <p className="text-sm font-semibold text-[#071226]">Naming Guidance</p>
                          <p className="mt-2 text-xs leading-5 text-slate-600">
                            The codename is a unique identifier and cannot be changed after
                            creation.
                          </p>
                        </div>
                      </div>
                    </div>
                  </>
                ) : (
                  <label className="block text-sm font-medium text-slate-700">
                    Device JSON
                    <textarea
                      value={importJson}
                      onChange={(event) => setImportJson(event.target.value)}
                      rows={14}
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
                  onClick={() => setDrawerOpen(false)}
                  className="h-11 rounded-lg border border-slate-200 text-sm font-medium text-slate-700 hover:bg-slate-50"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={drawerTab === "register" ? createFamily : importDevice}
                  disabled={
                    submitting ||
                    (drawerTab === "register" ? !form.codename.trim() : !importJson.trim())
                  }
                  className="flex h-11 items-center justify-center gap-2 rounded-lg bg-[#071226] text-sm font-medium text-white hover:bg-[#101f36] disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {submitting && <Loader2 size={17} className="animate-spin" />}
                  {drawerTab === "register" ? "Register Device" : "Import JSON"}
                </button>
              </footer>
            </aside>
          </>,
          document.body,
        )}
    </div>
  );
}
