import { useCallback, useEffect, useMemo, useState } from "react";
import { createPortal } from "react-dom";
import {
  AlertTriangle,
  AppWindow,
  ArrowLeft,
  ArrowRight,
  BarChart3,
  Check,
  CheckCircle2,
  Copy,
  FileText,
  KeyRound,
  Loader2,
  LockKeyhole,
  MoreVertical,
  Plus,
  RefreshCw,
  Search,
  Server,
  ShieldCheck,
  Trash2,
  UserRound,
  X,
} from "lucide-react";
import AppdevFooter from "../../components/appdev/Footer";
import { backendUrl } from "../../lib/config";

type DeveloperApp = {
  id: string;
  projectId: string;
  name: string;
  signerDigestSha256: string;
  createdAt?: string;
};

type DeviceReport = {
  id: string;
  scopedDeviceId: string;
  issuerBackendId: string;
  lastSeen: string;
  lastVerdict?: { isTrusted?: boolean; reasonCodes?: string[] } | null;
};

type FederationBackend = {
  id: string;
  backendId: string;
  name: string;
  status: string;
};

type Profile = { id: string; email: string; displayName?: string | null };

const documentationUrl = "https://github.com/unifiedAttestation/Website/wiki";

export default function AppdevApplications({
  onProfileLoaded,
}: {
  onProfileLoaded?: (name: string) => void;
}) {
  const [apps, setApps] = useState<DeveloperApp[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [reports, setReports] = useState<DeviceReport[]>([]);
  const [backends, setBackends] = useState<FederationBackend[]>([]);
  const [profile, setProfile] = useState<Profile | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const [activeTab, setActiveTab] = useState("Configuration");
  const [registerOpen, setRegisterOpen] = useState(false);
  const [appName, setAppName] = useState("");
  const [projectId, setProjectId] = useState("");
  const [signerDigest, setSignerDigest] = useState("");
  const [editName, setEditName] = useState("");
  const [editProjectId, setEditProjectId] = useState("");
  const [editSigner, setEditSigner] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [secret, setSecret] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [menuId, setMenuId] = useState<string | null>(null);
  const [menuPosition, setMenuPosition] = useState({ top: 0, left: 0 });
  const [page, setPage] = useState(1);
  const pageSize = 5;

  const selectedApp = apps.find((app) => app.id === selectedId) || null;

  const loadReports = useCallback(async (appId: string, token: string) => {
    const response = await fetch(`${backendUrl}/api/v1/apps/${appId}/reports`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    setReports(response.ok ? await response.json() : []);
  }, []);

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
        throw new Error("Unable to load applications.");
      }
      const appData: DeveloperApp[] = await appsResponse.json();
      const profileData: Profile = await profileResponse.json();
      setApps(appData);
      setProfile(profileData);
      setDisplayName(profileData.displayName || profileData.email.split("@")[0]);
      setBackends(federationResponse.ok ? await federationResponse.json() : []);
      onProfileLoaded?.(profileData.displayName || profileData.email.split("@")[0]);
      const nextSelected = appData.find((app) => app.id === selectedId) || appData[0] || null;
      setSelectedId(nextSelected?.id || null);
      if (nextSelected) {
        setEditName(nextSelected.name);
        setEditProjectId(nextSelected.projectId);
        setEditSigner(nextSelected.signerDigestSha256);
        await loadReports(nextSelected.id, token);
      } else {
        setReports([]);
      }
      setError(null);
    } catch (requestError) {
      setError(
        requestError instanceof Error ? requestError.message : "Unable to load applications.",
      );
    } finally {
      setLoading(false);
    }
  }, [loadReports, onProfileLoaded, selectedId]);

  useEffect(() => {
    load();
  }, [load]);

  const chooseApp = async (application: DeveloperApp) => {
    const token = localStorage.getItem("ua_access");
    setSelectedId(application.id);
    setEditName(application.name);
    setEditProjectId(application.projectId);
    setEditSigner(application.signerDigestSha256);
    setActiveTab("Configuration");
    if (token) await loadReports(application.id, token);
  };

  const filteredApps = useMemo(() => {
    const query = search.trim().toLowerCase();
    if (statusFilter === "inactive") return [];
    return apps.filter((app) => `${app.name} ${app.projectId}`.toLowerCase().includes(query));
  }, [apps, search, statusFilter]);
  const totalPages = Math.max(1, Math.ceil(filteredApps.length / pageSize));
  const visibleApps = filteredApps.slice((page - 1) * pageSize, page * pageSize);

  useEffect(() => setPage(1), [search, statusFilter]);

  const registerApp = async () => {
    if (!appName.trim() || !projectId.trim() || !/^[a-fA-F0-9]{64}$/.test(signerDigest.trim())) {
      setError("Enter an app name, unique project ID, and a valid 64-character SHA-256 digest.");
      return;
    }
    const token = localStorage.getItem("ua_access");
    setSaving(true);
    try {
      const response = await fetch(`${backendUrl}/api/v1/apps`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify({
          name: appName.trim(),
          projectId: projectId.trim(),
          signerDigestSha256: signerDigest.trim(),
        }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data?.message || "Unable to register application.");
      setRegisterOpen(false);
      setAppName("");
      setProjectId("");
      setSignerDigest("");
      setSecret(data.apiSecret);
      await load();
      setSelectedId(data.id);
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Unable to register app.");
    } finally {
      setSaving(false);
    }
  };

  const saveApp = async () => {
    if (!selectedApp) return;
    const token = localStorage.getItem("ua_access");
    setSaving(true);
    try {
      const response = await fetch(`${backendUrl}/api/v1/apps/${selectedApp.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify({
          name: editName.trim(),
          projectId: editProjectId.trim(),
          signerDigestSha256: editSigner.trim(),
        }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data?.message || "Unable to update application.");
      setNotice("Application configuration saved.");
      await load();
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Unable to update app.");
    } finally {
      setSaving(false);
    }
  };

  const rotateSecret = async (targetApp?: DeveloperApp) => {
    const application = targetApp || selectedApp;
    if (!application) return;
    const token = localStorage.getItem("ua_access");
    setSaving(true);
    try {
      const response = await fetch(`${backendUrl}/api/v1/apps/${application.id}/rotate-secret`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data?.message || "Unable to rotate server secret.");
      setSecret(data.apiSecret);
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Unable to rotate secret.");
    } finally {
      setSaving(false);
    }
  };

  const deleteApp = async (targetApp?: DeveloperApp) => {
    const application = targetApp || selectedApp;
    if (!application || !window.confirm(`Delete ${application.name} and all associated reports?`))
      return;
    const token = localStorage.getItem("ua_access");
    setSaving(true);
    try {
      const response = await fetch(`${backendUrl}/api/v1/apps/${application.id}`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!response.ok) throw new Error("Unable to delete application.");
      setSelectedId(null);
      setNotice("Application deleted.");
      await load();
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Unable to delete app.");
    } finally {
      setSaving(false);
    }
  };

  const saveProfile = async () => {
    const token = localStorage.getItem("ua_access");
    setSaving(true);
    try {
      const response = await fetch(`${backendUrl}/api/v1/profile`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify({ displayName: displayName.trim() }),
      });
      if (!response.ok) throw new Error("Unable to update profile.");
      setNotice("Profile saved.");
      await load();
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Unable to save profile.");
    } finally {
      setSaving(false);
    }
  };

  const changePassword = async () => {
    const token = localStorage.getItem("ua_access");
    setSaving(true);
    try {
      const response = await fetch(`${backendUrl}/api/v1/profile/password`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify({ currentPassword, newPassword }),
      });
      if (!response.ok) throw new Error("Unable to change password.");
      setCurrentPassword("");
      setNewPassword("");
      setNotice("Password changed.");
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Unable to change password.");
    } finally {
      setSaving(false);
    }
  };

  const allReportCount = reports.length;

  return (
    <div className="flex min-h-[calc(100vh-3rem)] flex-col gap-4">
      <header className="flex flex-col gap-4 border-b border-slate-200 pb-4 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-[#071226]">Applications</h1>
          <p className="mt-1 text-sm text-slate-500">
            Register applications and manage their attestation identity.
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
            Developer Guide
          </a>
          <button
            type="button"
            onClick={() => setRegisterOpen(true)}
            className="flex h-10 items-center justify-center gap-2 rounded-lg bg-[#071226] px-4 text-sm font-medium text-white hover:bg-[#101f36]"
          >
            <Plus size={17} />
            Register App
          </button>
        </div>
      </header>
      {error && <Notice tone="error" text={error} onClose={() => setError(null)} />}
      {notice && <Notice tone="success" text={notice} onClose={() => setNotice(null)} />}

      <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard label="Registered Apps" value={apps.length} icon={<AppWindow />} tone="blue" />
        <StatCard label="Active Apps" value={apps.length} icon={<CheckCircle2 />} tone="green" />
        <StatCard
          label="Federation Servers"
          value={backends.length}
          icon={<Server />}
          tone="slate"
        />
        <StatCard label="Device Reports" value={allReportCount} icon={<BarChart3 />} tone="slate" />
      </section>

      <section className="grid min-w-0 items-stretch gap-4 xl:grid-cols-[360px_minmax(0,1fr)]">
        <div className="flex min-w-0 flex-col gap-4">
          <article className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
            <header className="border-b border-slate-200 p-4">
              <h2 className="text-lg font-semibold text-[#071226]">Registered Apps</h2>
              <p className="text-xs text-slate-500">
                Applications linked to this developer account.
              </p>
              <div className="mt-4 grid grid-cols-[1fr_130px] gap-2">
                <label className="relative">
                  <Search
                    size={16}
                    className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400"
                  />
                  <input
                    value={search}
                    onChange={(event) => setSearch(event.target.value)}
                    placeholder="Search applications..."
                    className="h-10 w-full rounded-lg border border-slate-200 pl-9 pr-3 text-sm outline-none focus:border-blue-600"
                  />
                </label>
                <select
                  value={statusFilter}
                  onChange={(event) => setStatusFilter(event.target.value)}
                  className="h-10 rounded-lg border border-slate-200 bg-white px-3 text-sm"
                >
                  <option value="all">All status</option>
                  <option value="active">Active</option>
                  <option value="inactive">Inactive</option>
                </select>
              </div>
            </header>
            <div className="space-y-2 p-3">
              {visibleApps.map((application) => (
                <AppListItem
                  key={application.id}
                  application={application}
                  active={application.id === selectedId}
                  onSelect={() => chooseApp(application)}
                  menuOpen={menuId === application.id}
                  onMenu={(event) => {
                    event.stopPropagation();
                    const rect = event.currentTarget.getBoundingClientRect();
                    setMenuPosition({ top: rect.bottom + 6, left: Math.max(12, rect.right - 180) });
                    setMenuId(menuId === application.id ? null : application.id);
                  }}
                  menuPosition={menuPosition}
                  closeMenu={() => setMenuId(null)}
                  onRotate={() => {
                    setMenuId(null);
                    rotateSecret(application);
                  }}
                  onDelete={() => {
                    setMenuId(null);
                    deleteApp(application);
                  }}
                />
              ))}
              {loading && (
                <div className="flex items-center justify-center gap-2 py-12 text-sm text-slate-500">
                  <Loader2 size={18} className="animate-spin" />
                  Loading...
                </div>
              )}
              {!loading && visibleApps.length === 0 && (
                <p className="py-12 text-center text-sm text-slate-500">No applications found.</p>
              )}
            </div>
            <footer className="flex items-center justify-between border-t border-slate-200 px-4 py-3 text-xs text-slate-500">
              <span>
                {filteredApps.length} application{filteredApps.length === 1 ? "" : "s"}
              </span>
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

          <ServerSecret onRotate={() => rotateSecret()} saving={saving} compact />
        </div>

        <article className="h-full min-w-0 rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
          {selectedApp ? (
            <>
              <h2 className="text-xl font-semibold text-[#071226]">{selectedApp.name}</h2>
              <nav className="mt-3 flex gap-1 overflow-x-auto border-b border-slate-200">
                {["Overview", "Configuration", "Device Reports"].map((tab) => (
                  <button
                    key={tab}
                    type="button"
                    onClick={() => setActiveTab(tab)}
                    className={`whitespace-nowrap border-b-2 px-4 py-3 text-sm ${activeTab === tab ? "border-blue-700 text-blue-700" : "border-transparent text-slate-500"}`}
                  >
                    {tab}
                  </button>
                ))}
              </nav>
              <div className="pt-5">
                {activeTab === "Overview" && (
                  <AppOverview application={selectedApp} reports={reports} backends={backends} />
                )}
                {activeTab === "Configuration" && (
                  <ConfigurationForm
                    name={editName}
                    setName={setEditName}
                    projectId={editProjectId}
                    setProjectId={setEditProjectId}
                    signer={editSigner}
                    setSigner={setEditSigner}
                    saving={saving}
                    onReset={() => {
                      setEditName(selectedApp.name);
                      setEditProjectId(selectedApp.projectId);
                      setEditSigner(selectedApp.signerDigestSha256);
                    }}
                    onSave={saveApp}
                    onDelete={deleteApp}
                  />
                )}
                {activeTab === "Device Reports" && <ReportsTable reports={reports} />}
              </div>
            </>
          ) : (
            <div className="flex min-h-96 flex-col items-center justify-center text-center">
              <AppWindow size={36} className="text-slate-300" />
              <h2 className="mt-3 font-semibold text-[#071226]">Select an application</h2>
              <p className="mt-1 text-sm text-slate-500">
                Choose an application to view its configuration.
              </p>
            </div>
          )}
        </article>
      </section>

      <AppdevFooter />

      {registerOpen &&
        typeof document !== "undefined" &&
        createPortal(
          <>
            <button
              type="button"
              aria-label="Close register app"
              onClick={() => setRegisterOpen(false)}
              className="fixed inset-0 z-[9998] bg-[#071226]/55 backdrop-blur-sm"
            />
            <aside className="fixed inset-y-0 right-0 z-[9999] flex w-full max-w-md flex-col bg-white shadow-2xl">
              <header className="flex items-center justify-between border-b border-slate-200 px-6 py-5">
                <h2 className="text-lg font-semibold text-[#071226]">Register App</h2>
                <button type="button" onClick={() => setRegisterOpen(false)}>
                  <X size={20} />
                </button>
              </header>
              <div className="flex-1 space-y-5 overflow-y-auto p-6">
                <Field
                  label="App Name"
                  value={appName}
                  onChange={setAppName}
                  placeholder="Volla Notes"
                />
                <Field
                  label="Project ID (package name)"
                  value={projectId}
                  onChange={setProjectId}
                  placeholder="com.example.notes"
                />
                <Field
                  label="Signing Cert SHA-256 (hex)"
                  value={signerDigest}
                  onChange={setSignerDigest}
                  placeholder="Enter 64-character hexadecimal digest"
                />
                <ValidationChecklist
                  unique={
                    !apps.some((app) => app.projectId === projectId.trim()) &&
                    Boolean(projectId.trim())
                  }
                  validDigest={/^[a-fA-F0-9]{64}$/.test(signerDigest.trim())}
                />
                <div className="rounded-lg border border-blue-200 bg-blue-50 p-4 text-sm text-blue-700">
                  The application can be edited after registration.
                </div>
              </div>
              <footer className="grid grid-cols-2 gap-3 border-t border-slate-200 p-6">
                <button
                  type="button"
                  onClick={() => setRegisterOpen(false)}
                  className="h-11 rounded-lg border border-slate-300 text-sm"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  disabled={saving}
                  onClick={registerApp}
                  className="flex h-11 items-center justify-center gap-2 rounded-lg bg-[#071226] text-sm font-medium text-white disabled:opacity-50"
                >
                  {saving && <Loader2 size={17} className="animate-spin" />}Register App
                </button>
              </footer>
            </aside>
          </>,
          document.body,
        )}

      {secret &&
        typeof document !== "undefined" &&
        createPortal(
          <>
            <button
              type="button"
              aria-label="Close secret dialog"
              className="fixed inset-0 z-[10000] bg-[#071226]/60 backdrop-blur-sm"
            />
            <div className="fixed left-1/2 top-1/2 z-[10001] w-[min(92vw,560px)] -translate-x-1/2 -translate-y-1/2 rounded-2xl bg-white p-6 shadow-2xl">
              <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-full bg-emerald-50 text-emerald-600">
                <CheckCircle2 size={28} />
              </div>
              <h2 className="mt-4 text-center text-xl font-semibold text-[#071226]">
                Server Secret Ready
              </h2>
              <p className="mt-2 text-center text-sm text-slate-500">
                Copy this secret now. It will not be shown again.
              </p>
              <div className="mt-5 flex items-center gap-2 rounded-lg border border-slate-200 bg-slate-50 p-3">
                <code className="min-w-0 flex-1 break-all text-xs text-slate-700">{secret}</code>
                <button
                  type="button"
                  onClick={async () => {
                    await navigator.clipboard.writeText(secret);
                    setCopied(true);
                  }}
                  className="rounded-lg p-2 text-blue-700"
                >
                  {copied ? <Check size={18} /> : <Copy size={18} />}
                </button>
              </div>
              <button
                type="button"
                onClick={() => {
                  setSecret(null);
                  setCopied(false);
                }}
                className="mt-5 h-11 w-full rounded-lg bg-[#071226] text-sm font-medium text-white"
              >
                I Have Saved It
              </button>
            </div>
          </>,
          document.body,
        )}
    </div>
  );
}

function StatCard({
  label,
  value,
  icon,
  tone,
}: {
  label: string;
  value: number;
  icon: React.ReactNode;
  tone: "blue" | "green" | "slate";
}) {
  const colors = {
    blue: "bg-blue-50 text-blue-700",
    green: "bg-emerald-50 text-emerald-700",
    slate: "bg-slate-50 text-slate-700",
  };
  return (
    <article className="flex min-h-24 items-center gap-4 rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
      <div className={`flex h-12 w-12 items-center justify-center rounded-xl ${colors[tone]}`}>
        {icon}
      </div>
      <div>
        <p className="text-xs text-slate-500">{label}</p>
        <strong className="mt-1 block text-2xl text-[#071226]">{value}</strong>
      </div>
    </article>
  );
}

function AppListItem({
  application,
  active,
  onSelect,
  menuOpen,
  onMenu,
  menuPosition,
  closeMenu,
  onRotate,
  onDelete,
}: {
  application: DeveloperApp;
  active: boolean;
  onSelect: () => void;
  menuOpen: boolean;
  onMenu: (event: React.MouseEvent<HTMLButtonElement>) => void;
  menuPosition: { top: number; left: number };
  closeMenu: () => void;
  onRotate: () => void;
  onDelete: () => void;
}) {
  return (
    <div
      role="button"
      tabIndex={0}
      onClick={onSelect}
      onKeyDown={(event) => {
        if (event.key === "Enter" || event.key === " ") onSelect();
      }}
      className={`w-full rounded-xl border p-3 text-left transition ${active ? "border-blue-600 bg-blue-50/40" : "border-slate-200 hover:border-slate-300"}`}
    >
      <div className="flex gap-3">
        <span className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl bg-violet-50 text-xl font-semibold text-violet-700">
          {application.name.charAt(0).toUpperCase()}
        </span>
        <div className="min-w-0 flex-1">
          <p className="font-semibold text-[#071226]">{application.name}</p>
          <p className="truncate text-xs text-slate-500">Project ID: {application.projectId}</p>
          <p className="truncate font-mono text-[10px] text-slate-400">
            Signer: {application.signerDigestSha256}
          </p>
          <div className="mt-2 flex items-center justify-between">
            <Status active />
            <span className="text-[10px] text-slate-400">
              {application.createdAt
                ? new Date(application.createdAt).toLocaleDateString()
                : "Registered"}
            </span>
          </div>
        </div>
        <button
          type="button"
          onClick={onMenu}
          className="rounded-lg p-1.5 text-slate-500 hover:bg-slate-100"
        >
          <MoreVertical size={17} />
        </button>
      </div>
      {menuOpen &&
        typeof document !== "undefined" &&
        createPortal(
          <>
            <button
              type="button"
              aria-label="Close app menu"
              onClick={closeMenu}
              className="fixed inset-0 z-[9990]"
            />
            <div
              className="fixed z-[9991] w-44 overflow-hidden rounded-lg border border-slate-200 bg-white py-1 shadow-xl"
              style={menuPosition}
            >
              <button
                type="button"
                onClick={onRotate}
                className="flex w-full items-center gap-2 px-4 py-2.5 text-sm text-slate-700 hover:bg-slate-50"
              >
                <RefreshCw size={16} />
                Rotate Secret
              </button>
              <button
                type="button"
                onClick={onDelete}
                className="flex w-full items-center gap-2 px-4 py-2.5 text-sm text-red-600 hover:bg-red-50"
              >
                <Trash2 size={16} />
                Delete
              </button>
            </div>
          </>,
          document.body,
        )}
    </div>
  );
}

function ConfigurationForm({
  name,
  setName,
  projectId,
  setProjectId,
  signer,
  setSigner,
  saving,
  onReset,
  onSave,
  onDelete,
}: {
  name: string;
  setName: (value: string) => void;
  projectId: string;
  setProjectId: (value: string) => void;
  signer: string;
  setSigner: (value: string) => void;
  saving: boolean;
  onReset: () => void;
  onSave: () => void;
  onDelete: () => void;
}) {
  return (
    <div>
      <h3 className="font-semibold text-[#071226]">Application Identity</h3>
      <div className="mt-4 space-y-4">
        <Field label="App Name" value={name} onChange={setName} placeholder="App name" />
        <Field
          label="Project ID (package name)"
          value={projectId}
          onChange={setProjectId}
          placeholder="Project ID"
        />
        <Field
          label="Signing Certificate SHA-256"
          value={signer}
          onChange={setSigner}
          placeholder="64-character SHA-256"
        />
      </div>
      <div className="mt-5 flex justify-end gap-2">
        <button
          type="button"
          onClick={onReset}
          className="h-10 rounded-lg border border-slate-300 px-4 text-sm"
        >
          Discard Changes
        </button>
        <button
          type="button"
          disabled={saving}
          onClick={onSave}
          className="h-10 rounded-lg bg-[#071226] px-4 text-sm font-medium text-white disabled:opacity-50"
        >
          Save Changes
        </button>
      </div>
      <div className="mt-5 flex flex-col gap-3 rounded-xl border border-red-300 bg-red-50/30 p-4 sm:flex-row sm:items-center">
        <div className="flex-1">
          <h3 className="font-semibold text-red-600">Danger Zone</h3>
          <p className="mt-1 text-sm text-red-700">Delete Application</p>
          <p className="text-xs text-slate-500">
            All credentials and report history will be permanently removed.
          </p>
        </div>
        <button
          type="button"
          onClick={onDelete}
          className="h-10 rounded-lg border border-red-500 px-4 text-sm text-red-600"
        >
          Delete
        </button>
      </div>
    </div>
  );
}

function AppOverview({
  application,
  reports,
  backends,
}: {
  application: DeveloperApp;
  reports: DeviceReport[];
  backends: FederationBackend[];
}) {
  return (
    <dl className="grid gap-4 sm:grid-cols-2">
      <Info label="Application Name" value={application.name} />
      <Info label="Project ID" value={application.projectId} />
      <Info label="Signer Digest" value={application.signerDigestSha256} mono />
      <Info label="Device Reports" value={reports.length.toString()} />
      <Info label="Federation Servers" value={backends.length.toString()} />
      <Info label="Status" value="Active" success />
    </dl>
  );
}

function ServerSecret({
  onRotate,
  saving,
  compact = false,
}: {
  onRotate: () => void;
  saving: boolean;
  compact?: boolean;
}) {
  const content = (
    <>
      <div className="mt-4 flex items-center justify-between rounded-lg border border-slate-200 bg-slate-50 p-3">
        <span className="font-mono text-xs text-slate-500">••••••••••••••••••••</span>
        <Status active label="Configured" />
      </div>
      <button
        type="button"
        disabled={saving}
        onClick={onRotate}
        className="mt-4 flex h-10 w-full items-center justify-center gap-2 rounded-lg border border-amber-500 text-sm text-amber-700 disabled:opacity-50"
      >
        <RefreshCw size={16} />
        Rotate Secret
      </button>
      <p className="mt-3 flex gap-2 text-xs text-amber-700">
        <AlertTriangle size={15} />
        Rotating invalidates the current secret immediately.
      </p>
    </>
  );
  if (compact)
    return (
      <article className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
        <h2 className="text-lg font-semibold text-[#071226]">App Server Secret</h2>
        <p className="text-xs text-slate-500">
          Authenticate requests sent by your application server.
        </p>
        {content}
      </article>
    );
  return (
    <div>
      <h3 className="font-semibold text-[#071226]">Server Secret</h3>
      <p className="mt-1 text-sm text-slate-500">
        Use this secret to authenticate your application server.
      </p>
      {content}
    </div>
  );
}

function ProfileSecurity({
  profile,
  displayName,
  setDisplayName,
  currentPassword,
  setCurrentPassword,
  newPassword,
  setNewPassword,
  saving,
  onSave,
  onPassword,
}: {
  profile: Profile | null;
  displayName: string;
  setDisplayName: (value: string) => void;
  currentPassword: string;
  setCurrentPassword: (value: string) => void;
  newPassword: string;
  setNewPassword: (value: string) => void;
  saving: boolean;
  onSave: () => void;
  onPassword: () => void;
}) {
  return (
    <article className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
      <h2 className="text-lg font-semibold text-[#071226]">Profile & Security</h2>
      <p className="mt-2 text-xs text-slate-500">Signed in as {profile?.email || "—"}</p>
      <div className="mt-3 flex gap-2">
        <input
          value={displayName}
          onChange={(event) => setDisplayName(event.target.value)}
          placeholder="Display name"
          className="h-10 min-w-0 flex-1 rounded-lg border border-slate-200 px-3 text-sm"
        />
        <button
          type="button"
          disabled={saving}
          onClick={onSave}
          className="rounded-lg border border-blue-600 px-3 text-sm text-blue-700"
        >
          Save
        </button>
      </div>
      <div className="mt-4 space-y-2">
        <input
          type="password"
          value={currentPassword}
          onChange={(event) => setCurrentPassword(event.target.value)}
          placeholder="Current password"
          className="h-10 w-full rounded-lg border border-slate-200 px-3 text-sm"
        />
        <input
          type="password"
          value={newPassword}
          onChange={(event) => setNewPassword(event.target.value)}
          placeholder="New password"
          className="h-10 w-full rounded-lg border border-slate-200 px-3 text-sm"
        />
        <button
          type="button"
          disabled={saving || !currentPassword || !newPassword}
          onClick={onPassword}
          className="h-9 rounded-lg border border-blue-600 px-3 text-sm text-blue-700 disabled:opacity-40"
        >
          Change Password
        </button>
      </div>
    </article>
  );
}

function FederationPanel({ backends }: { backends: FederationBackend[] }) {
  return (
    <article className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-[#071226]">Federation</h2>
        <LockKeyhole size={16} className="text-slate-500" />
      </div>
      <p className="text-xs text-slate-500">Read-only servers managed by the administrator.</p>
      <div className="mt-3 divide-y divide-slate-100">
        {backends.map((backend) => (
          <div key={backend.id} className="flex items-center gap-2 py-3">
            <div className="min-w-0 flex-1">
              <p className="text-sm font-medium">{backend.name}</p>
              <p className="truncate text-[10px] text-slate-500">ID: {backend.backendId}</p>
            </div>
            <Status active={backend.status === "active"} />
          </div>
        ))}
        {backends.length === 0 && (
          <p className="py-8 text-center text-xs text-slate-500">No servers configured.</p>
        )}
      </div>
    </article>
  );
}

function ReportsTable({ reports, card = false }: { reports: DeviceReport[]; card?: boolean }) {
  const content = (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[520px] text-left text-xs">
        <thead className="border-y border-slate-200 bg-slate-50 text-slate-500">
          <tr>
            <th className="px-3 py-2">Device</th>
            <th className="px-3 py-2">Verdict</th>
            <th className="px-3 py-2">Last Seen</th>
            <th className="px-3 py-2">Reason</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100">
          {reports.slice(0, 6).map((report) => (
            <tr key={report.id}>
              <td className="max-w-36 truncate px-3 py-2 font-mono">{report.scopedDeviceId}</td>
              <td className="px-3 py-2">
                <Verdict trusted={report.lastVerdict?.isTrusted === true} />
              </td>
              <td className="px-3 py-2 text-slate-500">
                {new Date(report.lastSeen).toLocaleString()}
              </td>
              <td className="px-3 py-2 text-slate-500">
                {report.lastVerdict?.reasonCodes?.[0] || "—"}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {reports.length === 0 && (
        <p className="py-14 text-center text-sm text-slate-500">No device reports yet.</p>
      )}
    </div>
  );
  if (card)
    return (
      <article className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
        <header className="p-4">
          <h2 className="text-lg font-semibold text-[#071226]">Device Reports</h2>
          <p className="text-xs text-slate-500">
            Attestation reports associated with this application.
          </p>
        </header>
        {content}
      </article>
    );
  return (
    <div>
      <h3 className="mb-4 font-semibold text-[#071226]">Device Reports</h3>
      {content}
    </div>
  );
}

function ValidationChecklist({ unique, validDigest }: { unique: boolean; validDigest: boolean }) {
  return (
    <div>
      <h3 className="font-semibold text-[#071226]">Validation Checklist</h3>
      <div className="mt-3 space-y-3">
        <Validation label="Unique Project ID" valid={unique} />
        <Validation label="Valid Hexadecimal Digest" valid={validDigest} />
      </div>
    </div>
  );
}

function Validation({ label, valid }: { label: string; valid: boolean }) {
  return (
    <div className="flex items-center gap-3 text-sm">
      <span
        className={`flex h-5 w-5 items-center justify-center rounded-full border ${valid ? "border-emerald-600 text-emerald-600" : "border-slate-400 text-slate-400"}`}
      >
        {valid && <Check size={13} />}
      </span>
      <span className="text-slate-600">{label}</span>
    </div>
  );
}

function Field({
  label,
  value,
  onChange,
  placeholder,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  placeholder: string;
}) {
  return (
    <label className="block">
      <span className="text-sm font-medium text-slate-700">{label}</span>
      <input
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        className="mt-2 h-11 w-full rounded-lg border border-slate-200 px-3 text-sm outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-100"
      />
    </label>
  );
}

function Info({
  label,
  value,
  mono = false,
  success = false,
}: {
  label: string;
  value: string;
  mono?: boolean;
  success?: boolean;
}) {
  return (
    <div className="rounded-lg border border-slate-200 bg-slate-50 p-4">
      <dt className="text-xs text-slate-500">{label}</dt>
      <dd
        className={`mt-2 break-all text-sm ${mono ? "font-mono" : "font-medium"} ${success ? "text-emerald-600" : "text-slate-700"}`}
      >
        {value}
      </dd>
    </div>
  );
}

function Status({ active, label }: { active: boolean; label?: string }) {
  return (
    <span
      className={`rounded border px-2 py-1 text-[10px] ${active ? "border-emerald-200 bg-emerald-50 text-emerald-700" : "border-red-200 bg-red-50 text-red-700"}`}
    >
      {label || (active ? "Active" : "Inactive")}
    </span>
  );
}

function Verdict({ trusted }: { trusted: boolean }) {
  return (
    <span
      className={`rounded border px-2 py-1 text-[10px] ${trusted ? "border-emerald-200 bg-emerald-50 text-emerald-700" : "border-red-200 bg-red-50 text-red-700"}`}
    >
      {trusted ? "Trusted" : "Rejected"}
    </span>
  );
}

function Notice({
  tone,
  text,
  onClose,
}: {
  tone: "error" | "success";
  text: string;
  onClose: () => void;
}) {
  return (
    <div
      className={`flex items-center justify-between rounded-xl border px-4 py-3 text-sm ${tone === "error" ? "border-red-200 bg-red-50 text-red-700" : "border-emerald-200 bg-emerald-50 text-emerald-700"}`}
    >
      <span className="flex items-center gap-2">
        {tone === "success" && <Check size={17} />}
        {text}
      </span>
      <button type="button" onClick={onClose}>
        <X size={17} />
      </button>
    </div>
  );
}
