import { useCallback, useEffect, useMemo, useState } from "react";
import { createPortal } from "react-dom";
import {
  Bell,
  Check,
  CheckCircle2,
  ClipboardList,
  Copy,
  Info,
  KeyRound,
  Loader2,
  LockKeyhole,
  RotateCw,
  Search,
  Settings,
  ShieldCheck,
  X,
} from "lucide-react";
import Footer from "../../components/Footer";
import { backendUrl } from "../../lib/config";

type SettingsTab = "general" | "security" | "notifications" | "audit";

type PlatformSettings = {
  backendId?: string | null;
  publicKey?: string | null;
  signingKey?: {
    kid?: string | null;
    algorithm?: string | null;
    createdAt?: string | null;
    updatedAt?: string | null;
  };
  sessionSecurity?: {
    accessTokenLifetimeMinutes: number;
    refreshTokenLifetimeDays: number;
    failedLoginProtection: boolean;
  };
  apiSecretHeader?: string;
};

type AuditLog = {
  id: string;
  action: string;
  details: Record<string, unknown>;
  createdAt: string;
  actor?: { email: string; displayName?: string | null };
};

const tabs = [
  { id: "general" as const, label: "General", icon: Settings },
  { id: "security" as const, label: "Security", icon: ShieldCheck },
  { id: "notifications" as const, label: "Notifications", icon: Bell },
  { id: "audit" as const, label: "Audit Log", icon: ClipboardList },
];

function ValueRow({
  label,
  value,
  copyValue,
  status,
}: {
  label: string;
  value: string;
  copyValue?: string;
  status?: string;
}) {
  const [copied, setCopied] = useState(false);

  const copy = async () => {
    if (!copyValue) return;
    await navigator.clipboard.writeText(copyValue);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div className="grid gap-3 border-b border-slate-100 py-3 last:border-0 sm:grid-cols-[180px_1fr_auto] sm:items-center">
      <span className="inline-flex items-center gap-2 text-sm font-medium text-slate-700">
        {label}
        <Info size={14} className="text-slate-400" />
      </span>
      <span className="min-w-0 truncate font-mono text-sm text-slate-600">{value}</span>
      <div className="flex items-center gap-4">
        {copyValue && (
          <button
            type="button"
            onClick={copy}
            className="inline-flex h-9 items-center gap-2 rounded-lg border border-slate-200 px-3 text-xs text-slate-700 hover:bg-slate-50"
          >
            {copied ? <Check size={15} className="text-emerald-600" /> : <Copy size={15} />}
            {copied ? "Copied" : "Copy"}
          </button>
        )}
        {status && (
          <span className="inline-flex items-center gap-1.5 text-xs text-slate-600">
            <CheckCircle2 size={15} className="text-emerald-600" />
            {status}
          </span>
        )}
      </div>
    </div>
  );
}

export default function AdminSettings() {
  const [activeTab, setActiveTab] = useState<SettingsTab>("security");
  const [settings, setSettings] = useState<PlatformSettings | null>(null);
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [rotating, setRotating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [rotateModalOpen, setRotateModalOpen] = useState(false);
  const [rotateConfirmation, setRotateConfirmation] = useState("");
  const [notificationPreferences, setNotificationPreferences] = useState({
    securityEvents: true,
    federationIssues: true,
    authorityHealth: true,
    browserNotifications: false,
  });

  const loadSettings = useCallback(async () => {
    const accessToken = localStorage.getItem("ua_access");
    if (!accessToken) {
      window.location.href = "/login";
      return;
    }

    setLoading(true);
    try {
      const headers = { Authorization: `Bearer ${accessToken}` };
      const [settingsResponse, auditResponse] = await Promise.all([
        fetch(`${backendUrl}/api/v1/admin/settings`, { headers }),
        fetch(`${backendUrl}/api/v1/admin/audit-logs`, { headers }),
      ]);

      if (settingsResponse.status === 401 || auditResponse.status === 401) {
        localStorage.removeItem("ua_access");
        localStorage.removeItem("ua_refresh");
        window.location.href = "/login";
        return;
      }
      if (!settingsResponse.ok) throw new Error("Unable to load platform settings.");

      setSettings(await settingsResponse.json());
      if (auditResponse.ok) setAuditLogs(await auditResponse.json());
      setError(null);
    } catch (requestError) {
      setError(
        requestError instanceof Error ? requestError.message : "Unable to load platform settings.",
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadSettings();
    const stored = localStorage.getItem("ua_notification_preferences");
    if (!stored) return;
    try {
      setNotificationPreferences(JSON.parse(stored));
    } catch {
      localStorage.removeItem("ua_notification_preferences");
    }
  }, [loadSettings]);

  const rotateSigningKey = async () => {
    const accessToken = localStorage.getItem("ua_access");
    if (!accessToken || rotateConfirmation !== "ROTATE") return;

    setRotating(true);
    setError(null);
    try {
      const response = await fetch(`${backendUrl}/api/v1/admin/settings/rotate-key`, {
        method: "POST",
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      if (!response.ok) throw new Error((await response.text()) || "Unable to rotate signing key.");
      setRotateModalOpen(false);
      setRotateConfirmation("");
      setNotice("Signing key rotated successfully.");
      await loadSettings();
    } catch (requestError) {
      setError(
        requestError instanceof Error ? requestError.message : "Unable to rotate signing key.",
      );
    } finally {
      setRotating(false);
    }
  };

  const saveNotificationPreferences = async () => {
    let nextPreferences = notificationPreferences;
    if (notificationPreferences.browserNotifications && "Notification" in window) {
      const permission = await Notification.requestPermission();
      if (permission !== "granted") {
        nextPreferences = { ...notificationPreferences, browserNotifications: false };
        setNotificationPreferences(nextPreferences);
      }
    }
    localStorage.setItem("ua_notification_preferences", JSON.stringify(nextPreferences));
    setNotice("Notification preferences saved.");
  };

  const filteredLogs = useMemo(() => {
    const query = search.trim().toLowerCase();
    if (!query) return auditLogs;
    return auditLogs.filter(
      (log) =>
        log.action.toLowerCase().includes(query) ||
        log.actor?.email.toLowerCase().includes(query) ||
        log.actor?.displayName?.toLowerCase().includes(query),
    );
  }, [auditLogs, search]);

  const publicKeyPreview = settings?.publicKey
    ? `${settings.publicKey.slice(0, 28)}••••${settings.publicKey.slice(-18)}`
    : "Not configured";

  return (
    <div className="flex min-h-[calc(100vh-3rem)] flex-col gap-5">
      <header className="flex flex-col gap-4 border-b border-slate-200 pb-4 sm:flex-row sm:items-center sm:justify-between">
        <h1 className="text-2xl font-bold tracking-tight text-[#071226]">Platform Settings</h1>
        <label className="relative w-full sm:w-80">
          <Search
            size={18}
            className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-400"
          />
          <input
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Search settings..."
            className="h-10 w-full rounded-lg border border-slate-200 bg-white pl-10 pr-3 text-sm outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-100"
          />
        </label>
      </header>

      <section className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <p className="text-sm text-slate-500">
          Configure backend identity, signing security, and portal preferences.
        </p>
        {activeTab === "notifications" && (
          <button
            type="button"
            onClick={saveNotificationPreferences}
            className="h-10 rounded-lg bg-[#071226] px-4 text-sm font-medium text-white hover:bg-[#101f36]"
          >
            Save Preferences
          </button>
        )}
      </section>

      <nav className="flex gap-1 overflow-x-auto border-b border-slate-200">
        {tabs.map((tab) => {
          const Icon = tab.icon;
          return (
            <button
              key={tab.id}
              type="button"
              onClick={() => setActiveTab(tab.id)}
              className={`flex shrink-0 items-center gap-2 border-b-2 px-4 py-3 text-sm font-medium ${
                activeTab === tab.id
                  ? "border-blue-700 text-blue-700"
                  : "border-transparent text-slate-500 hover:text-slate-800"
              }`}
            >
              <Icon size={17} />
              {tab.label}
            </button>
          );
        })}
      </nav>

      {error && !rotateModalOpen && (
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
      {loading && (
        <div className="flex items-center justify-center gap-2 rounded-xl border border-slate-200 bg-white py-16 text-sm text-slate-500">
          <Loader2 size={18} className="animate-spin" />
          Loading platform settings...
        </div>
      )}

      {!loading && activeTab === "general" && (
        <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
          <h2 className="font-semibold text-[#071226]">Platform Information</h2>
          <div className="mt-3">
            <ValueRow label="Environment" value="UAT" status="Active" />
            <ValueRow
              label="Backend ID"
              value={settings?.backendId || "Not configured"}
              copyValue={settings?.backendId || undefined}
              status={settings?.backendId ? "Configured" : undefined}
            />
            <ValueRow
              label="API Secret Header"
              value={settings?.apiSecretHeader || "x-api-secret"}
            />
          </div>
        </section>
      )}

      {!loading && activeTab === "security" && (
        <div className="space-y-4">
          <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
            <h2 className="font-semibold text-[#071226]">Backend Identity</h2>
            <div className="mt-3">
              <ValueRow
                label="Backend ID"
                value={settings?.backendId || "Not configured"}
                copyValue={settings?.backendId || undefined}
                status={settings?.backendId ? "Configured" : undefined}
              />
              <ValueRow
                label="Public Key"
                value={publicKeyPreview}
                copyValue={settings?.publicKey || undefined}
                status={settings?.publicKey ? "Configured" : undefined}
              />
            </div>
          </section>

          <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
            <div className="flex flex-col gap-5 sm:flex-row sm:items-start sm:justify-between">
              <div>
                <h2 className="font-semibold text-[#071226]">Signing Key</h2>
                <div className="mt-4 grid gap-x-12 gap-y-3 text-sm sm:grid-cols-[150px_1fr]">
                  <span className="text-slate-500">Algorithm</span>
                  <span className="text-slate-700">
                    {settings?.signingKey?.algorithm || "Unknown"}
                  </span>
                  <span className="text-slate-500">Key ID</span>
                  <span className="font-mono text-slate-700">
                    {settings?.signingKey?.kid || "Unknown"}
                  </span>
                  <span className="text-slate-500">Last Rotation</span>
                  <span className="text-slate-700">
                    {settings?.signingKey?.updatedAt
                      ? new Date(settings.signingKey.updatedAt).toLocaleString()
                      : "Unknown"}
                  </span>
                  <span className="text-slate-500">Key Status</span>
                  <span className="inline-flex items-center gap-2 text-slate-700">
                    <span className="h-2 w-2 rounded-full bg-emerald-600" />
                    Active
                  </span>
                </div>
              </div>
              <button
                type="button"
                onClick={() => {
                  setError(null);
                  setRotateConfirmation("");
                  setRotateModalOpen(true);
                }}
                className="flex h-10 items-center justify-center gap-2 rounded-lg border border-blue-700 px-4 text-sm font-medium text-blue-700 hover:bg-blue-50"
              >
                <RotateCw size={17} />
                Rotate Signing Key
              </button>
            </div>
          </section>

          <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
            <h2 className="font-semibold text-[#071226]">Session Security</h2>
            <div className="mt-4 grid gap-x-12 gap-y-3 text-sm sm:grid-cols-[190px_1fr]">
              <span className="text-slate-500">Access Token Lifetime</span>
              <span className="text-slate-700">
                {settings?.sessionSecurity?.accessTokenLifetimeMinutes ?? "—"} minutes
              </span>
              <span className="text-slate-500">Refresh Token Lifetime</span>
              <span className="text-slate-700">
                {settings?.sessionSecurity?.refreshTokenLifetimeDays ?? "—"} days
              </span>
              <span className="text-slate-500">Failed Login Protection</span>
              <span className="inline-flex items-center gap-2 text-slate-700">
                <span
                  className={`h-2 w-2 rounded-full ${
                    settings?.sessionSecurity?.failedLoginProtection
                      ? "bg-emerald-600"
                      : "bg-red-500"
                  }`}
                />
                {settings?.sessionSecurity?.failedLoginProtection ? "Enabled" : "Disabled"}
              </span>
            </div>
          </section>

          <section className="rounded-xl border border-red-200 bg-red-50/30 p-5">
            <h2 className="font-semibold text-red-700">Danger Zone</h2>
            <div className="mt-3 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <p className="text-sm font-medium text-slate-800">Reset backend identity</p>
                <p className="mt-1 text-xs text-slate-500">
                  Backend identity reset is not available through the current API.
                </p>
              </div>
              <button
                type="button"
                disabled
                className="flex h-10 items-center justify-center gap-2 rounded-lg border border-slate-200 px-4 text-sm text-slate-400"
              >
                <LockKeyhole size={16} />
                Reset Backend Identity
              </button>
            </div>
          </section>
        </div>
      )}

      {!loading && activeTab === "notifications" && (
        <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
          <h2 className="font-semibold text-[#071226]">Notification Preferences</h2>
          <p className="mt-1 text-sm text-slate-500">
            Choose which administrative events should create notifications in this browser.
          </p>
          <div className="mt-5 divide-y divide-slate-100">
            {[
              ["securityEvents", "Security Events", "Signing-key rotation and root-anchor changes"],
              [
                "federationIssues",
                "Federation Issues",
                "Backend connectivity or verification-key failures",
              ],
              ["authorityHealth", "Authority Health", "RSA or ECDSA availability changes"],
              [
                "browserNotifications",
                "Browser Notifications",
                "Allow system notifications outside the portal",
              ],
            ].map(([key, title, description]) => (
              <label
                key={key}
                className="flex cursor-pointer items-center justify-between gap-4 py-4"
              >
                <div>
                  <p className="text-sm font-medium text-slate-800">{title}</p>
                  <p className="mt-1 text-xs text-slate-500">{description}</p>
                </div>
                <input
                  type="checkbox"
                  checked={notificationPreferences[key as keyof typeof notificationPreferences]}
                  onChange={(event) =>
                    setNotificationPreferences((current) => ({
                      ...current,
                      [key]: event.target.checked,
                    }))
                  }
                  className="h-4 w-4 accent-blue-700"
                />
              </label>
            ))}
          </div>
        </section>
      )}

      {!loading && activeTab === "audit" && (
        <section className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
          <header className="border-b border-slate-200 px-5 py-4">
            <h2 className="font-semibold text-[#071226]">Administrative Audit Log</h2>
          </header>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[700px] text-left text-sm">
              <thead className="bg-slate-50 text-xs text-slate-500">
                <tr>
                  <th className="px-5 py-3 font-semibold">Action</th>
                  <th className="px-5 py-3 font-semibold">Actor</th>
                  <th className="px-5 py-3 font-semibold">Details</th>
                  <th className="px-5 py-3 font-semibold">Date</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {filteredLogs.map((log) => (
                  <tr key={log.id}>
                    <td className="px-5 py-3 font-medium text-slate-800">{log.action}</td>
                    <td className="px-5 py-3 text-slate-600">
                      {log.actor?.displayName || log.actor?.email || "Unknown"}
                    </td>
                    <td className="max-w-80 truncate px-5 py-3 font-mono text-xs text-slate-500">
                      {JSON.stringify(log.details)}
                    </td>
                    <td className="px-5 py-3 text-xs text-slate-500">
                      {new Date(log.createdAt).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {filteredLogs.length === 0 && (
              <div className="px-5 py-12 text-center text-sm text-slate-500">
                No audit activity found.
              </div>
            )}
          </div>
        </section>
      )}

      <Footer pushToBottom />

      {rotateModalOpen &&
        typeof document !== "undefined" &&
        createPortal(
          <>
            <button
              type="button"
              aria-label="Close rotate key dialog"
              onClick={() => setRotateModalOpen(false)}
              className="fixed left-0 top-0 z-[9998] h-[100dvh] w-screen bg-[#071226]/60 backdrop-blur-sm"
            />
            <div
              role="dialog"
              aria-modal="true"
              className="fixed left-1/2 top-1/2 z-[9999] w-[calc(100%-2rem)] max-w-md -translate-x-1/2 -translate-y-1/2 rounded-2xl bg-white shadow-2xl"
            >
              <header className="flex items-center justify-between border-b border-slate-200 px-6 py-5">
                <h2 className="text-lg font-semibold text-[#071226]">Rotate signing key?</h2>
                <button
                  type="button"
                  onClick={() => setRotateModalOpen(false)}
                  className="rounded-lg p-2 text-slate-500 hover:bg-slate-100"
                >
                  <X size={20} />
                </button>
              </header>
              <div className="p-6">
                <div className="flex h-14 w-14 items-center justify-center rounded-full bg-blue-50 text-blue-700">
                  <KeyRound size={25} />
                </div>
                <p className="mt-4 text-sm leading-6 text-slate-600">
                  A new signing key pair will be generated. Federation backends must receive the new
                  public key to avoid verification failures. Existing signatures remain verifiable.
                </p>
                <label className="mt-5 block text-sm font-medium text-slate-700">
                  To confirm, type <strong>ROTATE</strong> below.
                </label>
                <input
                  value={rotateConfirmation}
                  onChange={(event) => setRotateConfirmation(event.target.value)}
                  className="mt-2 h-11 w-full rounded-lg border border-slate-200 px-3 text-sm outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-100"
                  placeholder="ROTATE"
                />
                {error && (
                  <div className="mt-4 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
                    {error}
                  </div>
                )}
              </div>
              <footer className="grid grid-cols-2 gap-3 border-t border-slate-200 p-6">
                <button
                  type="button"
                  onClick={() => setRotateModalOpen(false)}
                  className="h-11 rounded-lg border border-slate-200 text-sm font-medium text-slate-700 hover:bg-slate-50"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={rotateSigningKey}
                  disabled={rotating || rotateConfirmation !== "ROTATE"}
                  className="flex h-11 items-center justify-center gap-2 rounded-lg bg-[#071226] text-sm font-medium text-white hover:bg-[#101f36] disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {rotating && <Loader2 size={17} className="animate-spin" />}
                  Rotate Key
                </button>
              </footer>
            </div>
          </>,
          document.body,
        )}
    </div>
  );
}
