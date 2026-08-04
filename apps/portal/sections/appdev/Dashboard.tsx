import { useCallback, useEffect, useMemo, useState } from "react";
import { createPortal } from "react-dom";
import {
  AppWindow,
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

type ReportWithApp = DeviceReport & { application: DeveloperApp };

type FederationBackend = {
  id: string;
  backendId: string;
  name: string;
  status: string;
};

type Profile = {
  id: string;
  email: string;
  displayName?: string | null;
};

export default function AppdevDashboard({
  onProfileLoaded,
}: {
  onProfileLoaded?: (name: string) => void;
}) {
  const [apps, setApps] = useState<DeveloperApp[]>([]);
  const [reports, setReports] = useState<ReportWithApp[]>([]);
  const [backends, setBackends] = useState<FederationBackend[]>([]);
  const [profile, setProfile] = useState<Profile | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [registerOpen, setRegisterOpen] = useState(false);
  const [profileOpen, setProfileOpen] = useState(false);
  const [appName, setAppName] = useState("");
  const [projectId, setProjectId] = useState("");
  const [signerDigest, setSignerDigest] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [secret, setSecret] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [actionApp, setActionApp] = useState<DeveloperApp | null>(null);
  const [actionPosition, setActionPosition] = useState({ top: 0, left: 0 });

  const loadDashboard = useCallback(async () => {
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
        throw new Error("Unable to load the application developer dashboard.");
      }
      const appData: DeveloperApp[] = await appsResponse.json();
      const profileData: Profile = await profileResponse.json();
      const reportGroups = await Promise.all(
        appData.map(async (application) => {
          const response = await fetch(`${backendUrl}/api/v1/apps/${application.id}/reports`, {
            headers,
          });
          if (!response.ok) return [];
          const data: DeviceReport[] = await response.json();
          return data.map((report) => ({ ...report, application }));
        }),
      );
      setApps(appData);
      setReports(reportGroups.flat().sort((a, b) => +new Date(b.lastSeen) - +new Date(a.lastSeen)));
      setBackends(federationResponse.ok ? await federationResponse.json() : []);
      setProfile(profileData);
      setDisplayName(profileData.displayName || profileData.email.split("@")[0]);
      onProfileLoaded?.(profileData.displayName || profileData.email.split("@")[0]);
      setError(null);
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Unable to load dashboard.");
    } finally {
      setLoading(false);
    }
  }, [onProfileLoaded]);

  useEffect(() => {
    loadDashboard();
  }, [loadDashboard]);

  const filteredApps = useMemo(() => {
    const query = search.trim().toLowerCase();
    return apps.filter((app) => `${app.name} ${app.projectId}`.toLowerCase().includes(query));
  }, [apps, search]);

  const filteredReports = useMemo(() => {
    const query = search.trim().toLowerCase();
    return reports.filter((report) =>
      `${report.scopedDeviceId} ${report.application.name} ${report.issuerBackendId}`
        .toLowerCase()
        .includes(query),
    );
  }, [reports, search]);

  const registerApp = async () => {
    if (!appName.trim() || !projectId.trim() || !/^[a-fA-F0-9]{64}$/.test(signerDigest.trim())) {
      setError("Enter an app name, project ID, and a valid 64-character SHA-256 digest.");
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
      await loadDashboard();
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Unable to register app.");
    } finally {
      setSaving(false);
    }
  };

  const rotateSecret = async (application: DeveloperApp) => {
    const token = localStorage.getItem("ua_access");
    setSaving(true);
    try {
      const response = await fetch(`${backendUrl}/api/v1/apps/${application.id}/rotate-secret`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data?.message || "Unable to rotate server secret.");
      setActionApp(null);
      setSecret(data.apiSecret);
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Unable to rotate secret.");
    } finally {
      setSaving(false);
    }
  };

  const deleteApp = async (application: DeveloperApp) => {
    if (!window.confirm(`Delete ${application.name} and all of its reports?`)) return;
    const token = localStorage.getItem("ua_access");
    setSaving(true);
    try {
      const response = await fetch(`${backendUrl}/api/v1/apps/${application.id}`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!response.ok) throw new Error("Unable to delete application.");
      setActionApp(null);
      setNotice("Application deleted.");
      await loadDashboard();
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
      if (displayName.trim()) {
        const response = await fetch(`${backendUrl}/api/v1/profile`, {
          method: "PATCH",
          headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
          body: JSON.stringify({ displayName: displayName.trim() }),
        });
        if (!response.ok) throw new Error("Unable to update profile.");
      }
      if (currentPassword && newPassword) {
        const passwordResponse = await fetch(`${backendUrl}/api/v1/profile/password`, {
          method: "POST",
          headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
          body: JSON.stringify({ currentPassword, newPassword }),
        });
        if (!passwordResponse.ok) throw new Error("Unable to update password.");
      }
      setCurrentPassword("");
      setNewPassword("");
      setProfileOpen(false);
      setNotice("Profile updated.");
      await loadDashboard();
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Unable to save profile.");
    } finally {
      setSaving(false);
    }
  };

  const trustedReports = reports.filter((report) => report.lastVerdict?.isTrusted === true).length;
  const configurationReady =
    apps.length > 0 && backends.some((backend) => backend.status === "active");

  return (
    <div className="flex min-h-[calc(100vh-3rem)] flex-col gap-4">
      <header className="flex flex-col gap-4 border-b border-slate-200 pb-4 xl:flex-row xl:items-start xl:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-[#071226]">Dashboard</h1>
          <p className="mt-1 text-sm text-slate-500">
            Overview of your applications and attestation configuration.
          </p>
        </div>
        <div className="flex flex-col gap-2 sm:flex-row">
          <label className="relative sm:w-72">
            <Search size={17} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
            <input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Search applications or reports..."
              className="h-10 w-full rounded-lg border border-slate-200 bg-white pl-10 pr-3 text-sm outline-none focus:border-blue-600"
            />
          </label>
          <a
            href="https://github.com/unifiedAttestation/Website/wiki"
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
        <MetricCard
          label="Registered Apps"
          value={apps.length.toString()}
          subtitle={`${apps.length} active`}
          icon={<AppWindow />}
          tone="blue"
        />
        <MetricCard
          label="Device Reports"
          value={reports.length.toLocaleString()}
          subtitle={reports.length ? `${trustedReports} trusted` : "No reports yet"}
          icon={<BarChart3 />}
          tone="slate"
        />
        <MetricCard
          label="Federation Servers"
          value={backends.length.toString()}
          subtitle={`${backends.filter((item) => item.status === "active").length} active`}
          icon={<Server />}
          tone="slate"
        />
        <MetricCard
          label="Server Secret"
          value={apps.length ? "Configured" : "Not set"}
          subtitle={apps.length ? "Available per application" : "Register an app first"}
          icon={<KeyRound />}
          tone="slate"
        />
      </section>

      <section className="grid gap-4 xl:grid-cols-[minmax(0,1.35fr)_minmax(380px,1fr)]">
        <article
          id="applications"
          className="scroll-mt-5 rounded-xl border border-slate-200 bg-white p-4 shadow-sm"
        >
          <div className="flex items-start justify-between">
            <div>
              <h2 className="text-lg font-semibold text-[#071226]">Applications</h2>
              <p className="text-xs text-slate-500">
                Applications registered to this developer account.
              </p>
            </div>
            <a href="/appdev/applications" className="text-xs font-medium text-blue-700">
              View all applications
            </a>
          </div>
          <div className="mt-4 space-y-3">
            {filteredApps.slice(0, 4).map((application) => (
              <ApplicationRow
                key={application.id}
                application={application}
                onReports={() => {
                  document.getElementById("device-reports")?.scrollIntoView({ behavior: "smooth" });
                }}
                onMenu={(event) => {
                  const rect = event.currentTarget.getBoundingClientRect();
                  setActionPosition({
                    top: Math.min(rect.bottom + 6, window.innerHeight - 120),
                    left: Math.max(12, rect.right - 190),
                  });
                  setActionApp(application);
                }}
              />
            ))}
            {!loading && filteredApps.length === 0 && (
              <EmptyState
                text="No applications registered yet."
                button="Register App"
                onClick={() => setRegisterOpen(true)}
              />
            )}
            {loading && (
              <div className="flex items-center justify-center gap-2 py-10 text-sm text-slate-500">
                <Loader2 size={18} className="animate-spin" />
                Loading applications...
              </div>
            )}
          </div>
          {apps.length > 0 && (
            <div className="mt-4 border-t border-dashed border-slate-200 pt-4 text-center">
              <p className="text-xs text-slate-500">Need another application?</p>
              <button
                type="button"
                onClick={() => setRegisterOpen(true)}
                className="mt-2 inline-flex h-9 items-center gap-2 rounded-lg border border-blue-600 px-4 text-sm text-blue-700"
              >
                <Plus size={16} />
                Register App
              </button>
            </div>
          )}
        </article>
        <ConfigurationStatus
          apps={apps}
          reports={reports}
          backends={backends}
          ready={configurationReady}
          onReview={() =>
            document.getElementById("profile")?.scrollIntoView({ behavior: "smooth" })
          }
        />
      </section>

      <section className="grid gap-4 xl:grid-cols-[minmax(0,1.35fr)_minmax(380px,1fr)]">
        <article
          id="device-reports"
          className="scroll-mt-5 overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm"
        >
          <header className="flex items-start justify-between p-4">
            <div>
              <h2 className="text-lg font-semibold text-[#071226]">Device Reports</h2>
              <p className="text-xs text-slate-500">
                Latest attestation results associated with your applications.
              </p>
            </div>
            <a href="#device-reports" className="text-xs font-medium text-blue-700">
              View reports
            </a>
          </header>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[680px] text-left text-xs">
              <thead className="border-y border-slate-200 bg-slate-50 text-slate-500">
                <tr>
                  <th className="px-4 py-3">Device</th>
                  <th className="px-4 py-3">Application</th>
                  <th className="px-4 py-3">Verdict</th>
                  <th className="px-4 py-3">Last Seen</th>
                  <th className="px-4 py-3">Reason</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {filteredReports.slice(0, 5).map((report) => (
                  <tr key={report.id}>
                    <td className="max-w-40 truncate px-4 py-3 font-mono">
                      {report.scopedDeviceId}
                    </td>
                    <td className="px-4 py-3">{report.application.name}</td>
                    <td className="px-4 py-3">
                      <Verdict trusted={report.lastVerdict?.isTrusted === true} />
                    </td>
                    <td className="px-4 py-3 text-slate-500">
                      {new Date(report.lastSeen).toLocaleString()}
                    </td>
                    <td className="px-4 py-3 text-slate-500">
                      {report.lastVerdict?.reasonCodes?.[0] || "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {!loading && filteredReports.length === 0 && (
              <EmptyState
                text="No device reports yet. Reports appear after a device attests with a registered application."
                button="View Integration Guide"
                href="https://github.com/unifiedAttestation/Website/wiki"
              />
            )}
          </div>
        </article>
        <article
          id="federation"
          className="scroll-mt-5 rounded-xl border border-slate-200 bg-white p-4 shadow-sm"
        >
          <h2 className="text-lg font-semibold text-[#071226]">Federation</h2>
          <p className="text-xs text-slate-500">
            Read-only federation servers available to this account.
          </p>
          <div className="mt-3 divide-y divide-slate-100">
            {backends.map((backend) => (
              <div key={backend.id} className="flex items-center gap-3 py-3">
                <div className="min-w-0 flex-1">
                  <p className="font-medium text-slate-700">{backend.name}</p>
                  <p className="truncate text-xs text-slate-500">ID {backend.backendId}</p>
                </div>
                <Status active={backend.status === "active"} />
              </div>
            ))}
            {backends.length === 0 && (
              <p className="py-8 text-center text-sm text-slate-500">
                No federation servers configured.
              </p>
            )}
          </div>
          <div className="mt-2 flex items-center justify-between border-t border-slate-200 pt-3 text-xs">
            <span className="flex items-center gap-2 text-slate-500">
              <LockKeyhole size={14} />
              Managed by platform administrator
            </span>
            <a href="#federation" className="text-blue-700">
              View federation
            </a>
          </div>
        </article>
      </section>

      <section className="grid gap-4 xl:grid-cols-3">
        <QuickActions
          onRegister={() => setRegisterOpen(true)}
          onRotate={() => (apps[0] ? rotateSecret(apps[0]) : setRegisterOpen(true))}
          onProfile={() => setProfileOpen(true)}
        />
        <article
          id="profile"
          className="scroll-mt-5 rounded-xl border border-slate-200 bg-white p-4 shadow-sm"
        >
          <h2 className="text-lg font-semibold text-[#071226]">Account Security</h2>
          <dl className="mt-3 divide-y divide-slate-100 text-sm">
            <InfoRow label="Display Name" value={profile?.displayName || profile?.email || "—"} />
            <InfoRow label="Password" value="Set" accent />
            <InfoRow
              label="Server Secret"
              value={apps.length ? "Configured" : "Not configured"}
              success={apps.length > 0}
            />
          </dl>
          <div className="mt-3 flex gap-2 rounded-lg border border-blue-200 bg-blue-50 p-3 text-xs text-blue-700">
            <ShieldCheck size={17} className="shrink-0" />
            Keep your account password and app server secret secure.
          </div>
          <div className="mt-3 grid grid-cols-2 gap-2">
            <button
              type="button"
              onClick={() => setProfileOpen(true)}
              className="h-10 rounded-lg border border-slate-300 text-sm"
            >
              Manage Profile
            </button>
            <button
              type="button"
              onClick={() => (apps[0] ? rotateSecret(apps[0]) : setRegisterOpen(true))}
              className="h-10 rounded-lg bg-[#071226] text-sm font-medium text-white"
            >
              Rotate Secret
            </button>
          </div>
        </article>
        <GettingStarted apps={apps} reports={reports} backends={backends} />
      </section>

      <AppdevFooter />

      {actionApp &&
        typeof document !== "undefined" &&
        createPortal(
          <>
            <button
              type="button"
              aria-label="Close application actions"
              onClick={() => setActionApp(null)}
              className="fixed inset-0 z-[9990]"
            />
            <div
              className="fixed z-[9991] w-48 overflow-hidden rounded-lg border border-slate-200 bg-white py-1 shadow-xl"
              style={actionPosition}
            >
              <button
                type="button"
                onClick={() => rotateSecret(actionApp)}
                className="flex w-full items-center gap-2 px-4 py-2.5 text-sm text-slate-700 hover:bg-slate-50"
              >
                <RefreshCw size={16} />
                Rotate Secret
              </button>
              <button
                type="button"
                onClick={() => deleteApp(actionApp)}
                className="flex w-full items-center gap-2 px-4 py-2.5 text-sm text-red-600 hover:bg-red-50"
              >
                <Trash2 size={16} />
                Delete Application
              </button>
            </div>
          </>,
          document.body,
        )}

      {registerOpen &&
        typeof document !== "undefined" &&
        createPortal(
          <Drawer
            title="Register Application"
            onClose={() => setRegisterOpen(false)}
            footer={
              <>
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
              </>
            }
          >
            <p className="text-sm text-slate-500">
              Register an application and configure its signing identity.
            </p>
            <Field
              label="Application Name"
              value={appName}
              onChange={setAppName}
              placeholder="Example"
            />
            <Field
              label="Project ID"
              value={projectId}
              onChange={setProjectId}
              placeholder="net.example.app"
            />
            <Field
              label="Signer Digest SHA-256"
              value={signerDigest}
              onChange={setSignerDigest}
              placeholder="64-character hexadecimal digest"
            />
            <div className="rounded-lg border border-blue-200 bg-blue-50 p-4 text-sm text-blue-700">
              The server secret is displayed once after registration.
            </div>
          </Drawer>,
          document.body,
        )}

      {profileOpen &&
        typeof document !== "undefined" &&
        createPortal(
          <Drawer
            title="Manage Profile"
            onClose={() => setProfileOpen(false)}
            footer={
              <>
                <button
                  type="button"
                  onClick={() => setProfileOpen(false)}
                  className="h-11 rounded-lg border border-slate-300 text-sm"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  disabled={saving}
                  onClick={saveProfile}
                  className="flex h-11 items-center justify-center gap-2 rounded-lg bg-[#071226] text-sm font-medium text-white disabled:opacity-50"
                >
                  {saving && <Loader2 size={17} className="animate-spin" />}Save Changes
                </button>
              </>
            }
          >
            <Field
              label="Display Name"
              value={displayName}
              onChange={setDisplayName}
              placeholder="Display name"
            />
            <div className="border-t border-slate-200 pt-5">
              <h3 className="font-semibold text-[#071226]">Change Password</h3>
              <div className="mt-4 space-y-4">
                <Field
                  label="Current Password"
                  value={currentPassword}
                  onChange={setCurrentPassword}
                  placeholder="Current password"
                  type="password"
                />
                <Field
                  label="New Password"
                  value={newPassword}
                  onChange={setNewPassword}
                  placeholder="At least 5 characters"
                  type="password"
                />
              </div>
            </div>
          </Drawer>,
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

function MetricCard({
  label,
  value,
  subtitle,
  icon,
  tone,
}: {
  label: string;
  value: string;
  subtitle: string;
  icon: React.ReactNode;
  tone: "blue" | "slate";
}) {
  return (
    <article className="flex min-h-24 items-center gap-4 rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
      <div
        className={`flex h-12 w-12 shrink-0 items-center justify-center rounded-xl ${tone === "blue" ? "bg-blue-50 text-blue-700" : "bg-slate-50 text-slate-700"}`}
      >
        {icon}
      </div>
      <div className="min-w-0">
        <p className="text-xs text-slate-500">{label}</p>
        <strong className="mt-0.5 block truncate text-2xl text-[#071226]">{value}</strong>
        <p
          className={`truncate text-xs ${tone === "blue" ? "text-emerald-600" : "text-slate-400"}`}
        >
          {subtitle}
        </p>
      </div>
    </article>
  );
}

function ApplicationRow({
  application,
  onReports,
  onMenu,
}: {
  application: DeveloperApp;
  onReports: () => void;
  onMenu: (event: React.MouseEvent<HTMLButtonElement>) => void;
}) {
  return (
    <div className="flex flex-col gap-3 rounded-xl border border-slate-200 p-3 sm:flex-row sm:items-center">
      <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-violet-50 text-xl font-semibold text-violet-700">
        {application.name.charAt(0).toUpperCase()}
      </div>
      <div className="min-w-0 flex-1">
        <p className="font-semibold text-[#071226]">{application.name}</p>
        <p className="truncate text-xs text-slate-500">Project ID: {application.projectId}</p>
        <p className="truncate font-mono text-[10px] text-slate-400">
          Signer: {application.signerDigestSha256}
        </p>
      </div>
      <Status active />
      <span className="text-xs text-slate-500">
        Registered
        <br />
        {application.createdAt ? new Date(application.createdAt).toLocaleDateString() : "—"}
      </span>
      <button
        type="button"
        onClick={onReports}
        className="h-9 rounded-lg border border-blue-600 px-4 text-xs text-blue-700"
      >
        Open Application
      </button>
      <button
        type="button"
        onClick={onMenu}
        className="self-end rounded-lg p-2 text-slate-500 hover:bg-slate-100 sm:self-auto"
      >
        <MoreVertical size={18} />
      </button>
    </div>
  );
}

function ConfigurationStatus({
  apps,
  reports,
  backends,
  ready,
  onReview,
}: {
  apps: DeveloperApp[];
  reports: ReportWithApp[];
  backends: FederationBackend[];
  ready: boolean;
  onReview: () => void;
}) {
  const rows = [
    ["Application registered", apps.length > 0, apps.length ? "Complete" : "Required"],
    [
      "Signing digest configured",
      apps.some((app) => app.signerDigestSha256.length === 64),
      apps.length ? "Complete" : "Required",
    ],
    ["Server secret configured", apps.length > 0, apps.length ? "Complete" : "Required"],
    [
      "Federation available",
      backends.some((backend) => backend.status === "active"),
      `${backends.filter((item) => item.status === "active").length} active`,
    ],
    [
      "Device attestation",
      reports.length > 0,
      reports.length ? `${reports.length} reports` : "Waiting for first report",
    ],
  ] as const;
  return (
    <article className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
      <h2 className="text-lg font-semibold text-[#071226]">Configuration Status</h2>
      <div className="mt-3 space-y-3">
        {rows.map(([label, complete, value]) => (
          <div key={label} className="flex items-center gap-2 text-sm">
            {complete ? <CheckCircle2 size={17} className="text-emerald-600" /> : <AlertIcon />}
            <span className="flex-1 text-slate-600 sm:whitespace-nowrap">{label}</span>
            <span
              className={`sm:whitespace-nowrap ${complete ? "text-emerald-600" : "text-amber-600"}`}
            >
              {value}
            </span>
          </div>
        ))}
      </div>
      <div className="mt-4 flex items-center justify-between border-t border-slate-200 pt-3">
        <strong className="text-sm">Overall</strong>
        <Status active={ready} label={ready ? "Ready" : "Pending"} />
      </div>
      <button
        type="button"
        onClick={onReview}
        className="mx-auto mt-3 block h-9 rounded-lg border border-blue-600 px-5 text-sm text-blue-700"
      >
        Review Configuration
      </button>
    </article>
  );
}

function QuickActions({
  onRegister,
  onRotate,
  onProfile,
}: {
  onRegister: () => void;
  onRotate: () => void;
  onProfile: () => void;
}) {
  const actions = [
    ["Register an application", Plus, onRegister],
    ["Rotate server secret", RefreshCw, onRotate],
    ["Update profile", UserRound, onProfile],
    ["Change password", LockKeyhole, onProfile],
  ] as const;
  return (
    <article className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
      <h2 className="text-lg font-semibold text-[#071226]">Quick Actions</h2>
      <div className="mt-2 divide-y divide-slate-100">
        {actions.map(([label, Icon, action]) => (
          <button
            key={label}
            type="button"
            onClick={action}
            className="flex w-full items-center gap-3 py-3 text-left text-sm text-slate-700 hover:text-blue-700"
          >
            <Icon size={17} />
            <span className="flex-1">{label}</span>
            <ArrowRight size={15} />
          </button>
        ))}
      </div>
    </article>
  );
}

function GettingStarted({
  apps,
  reports,
  backends,
}: {
  apps: DeveloperApp[];
  reports: ReportWithApp[];
  backends: FederationBackend[];
}) {
  const steps = [
    ["Register application", apps.length > 0],
    ["Configure signing digest", apps.some((app) => app.signerDigestSha256.length === 64)],
    ["Configure app server", backends.some((backend) => backend.status === "active")],
    ["Receive first device report", reports.length > 0],
  ] as const;
  const complete = steps.filter(([, done]) => done).length;
  return (
    <article className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
      <h2 className="text-lg font-semibold text-[#071226]">Getting Started</h2>
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
        <span className="text-slate-500">{complete} of 4 complete</span>
        <a
          href="https://github.com/unifiedAttestation/Website/wiki"
          target="_blank"
          rel="noreferrer"
          className="rounded-lg border border-blue-600 px-3 py-2 text-blue-700"
        >
          View Integration Guide
        </a>
      </div>
    </article>
  );
}

function Drawer({
  title,
  children,
  footer,
  onClose,
}: {
  title: string;
  children: React.ReactNode;
  footer: React.ReactNode;
  onClose: () => void;
}) {
  return (
    <>
      <button
        type="button"
        aria-label={`Close ${title}`}
        onClick={onClose}
        className="fixed inset-0 z-[9998] bg-[#071226]/55 backdrop-blur-sm"
      />
      <aside className="fixed inset-y-0 right-0 z-[9999] flex w-full max-w-md flex-col bg-white shadow-2xl">
        <header className="flex items-center justify-between border-b border-slate-200 px-6 py-5">
          <h2 className="text-lg font-semibold text-[#071226]">{title}</h2>
          <button type="button" onClick={onClose}>
            <X size={20} />
          </button>
        </header>
        <div className="flex-1 space-y-5 overflow-y-auto p-6">{children}</div>
        <footer className="grid grid-cols-2 gap-3 border-t border-slate-200 p-6">{footer}</footer>
      </aside>
    </>
  );
}

function Field({
  label,
  value,
  onChange,
  placeholder,
  type = "text",
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  placeholder: string;
  type?: string;
}) {
  return (
    <label className="block">
      <span className="text-sm font-medium text-slate-700">{label}</span>
      <input
        type={type}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        className="mt-2 h-11 w-full rounded-lg border border-slate-200 px-3 text-sm outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-100"
      />
    </label>
  );
}

function EmptyState({
  text,
  button,
  onClick,
  href,
}: {
  text: string;
  button: string;
  onClick?: () => void;
  href?: string;
}) {
  return (
    <div className="px-5 py-10 text-center">
      <p className="mx-auto max-w-xl text-sm text-slate-500">{text}</p>
      {href ? (
        <a
          href={href}
          target="_blank"
          rel="noreferrer"
          className="mt-3 inline-flex h-9 items-center rounded-lg border border-blue-600 px-4 text-sm text-blue-700"
        >
          {button}
        </a>
      ) : (
        <button
          type="button"
          onClick={onClick}
          className="mt-3 h-9 rounded-lg border border-blue-600 px-4 text-sm text-blue-700"
        >
          {button}
        </button>
      )}
    </div>
  );
}

function Status({ active, label }: { active: boolean; label?: string }) {
  return (
    <span
      className={`rounded border px-2 py-1 text-xs ${active ? "border-emerald-200 bg-emerald-50 text-emerald-700" : "border-amber-200 bg-amber-50 text-amber-700"}`}
    >
      {label || (active ? "Active" : "Inactive")}
    </span>
  );
}

function Verdict({ trusted }: { trusted: boolean }) {
  return (
    <span
      className={`rounded border px-2 py-1 ${trusted ? "border-emerald-200 bg-emerald-50 text-emerald-700" : "border-red-200 bg-red-50 text-red-700"}`}
    >
      {trusted ? "Trusted" : "Rejected"}
    </span>
  );
}

function InfoRow({
  label,
  value,
  accent = false,
  success = false,
}: {
  label: string;
  value: string;
  accent?: boolean;
  success?: boolean;
}) {
  return (
    <div className="flex justify-between gap-4 py-2">
      <dt className="text-slate-500">{label}</dt>
      <dd className={success ? "text-emerald-600" : accent ? "text-blue-700" : "text-slate-700"}>
        {value}
      </dd>
    </div>
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

function AlertIcon() {
  return (
    <span className="flex h-[17px] w-[17px] items-center justify-center rounded-full border border-amber-500 text-[10px] text-amber-600">
      !
    </span>
  );
}
