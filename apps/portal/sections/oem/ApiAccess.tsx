import { useCallback, useEffect, useMemo, useState } from "react";
import { createPortal } from "react-dom";
import {
  Activity,
  AlertTriangle,
  BarChart3,
  Check,
  CheckCircle2,
  Clipboard,
  Code2,
  Copy,
  ExternalLink,
  Filter,
  Gauge,
  KeyRound,
  Loader2,
  MoreVertical,
  RefreshCw,
  RotateCw,
  Search,
  ShieldCheck,
  Trash2,
  X,
} from "lucide-react";
import OemFooter from "../../components/oem/Footer";
import { backendUrl } from "../../lib/config";

type Credential = {
  id: string;
  name: string;
  clientId: string;
  prefix: string | null;
  environment: string;
  description: string;
  scopes: string[];
  expiration: string;
  createdAt: string;
  lastUsed: string | null;
  status: "active" | "revoked";
};

type Metrics = {
  requestsThisMonth: number;
  successful: number;
  errors: number;
  successRate: number;
  rateLimitUsed: number;
  averageLatencyMs: number;
};

type UsagePoint = { date: string; successful: number; errors: number };

type ApiAccessResponse = {
  credential: Credential | null;
  metrics: Metrics;
  usage: UsagePoint[];
};

const scopes = [
  ["devices:read", "View enrolled devices"],
  ["reports:read", "View attestation reports"],
  ["policies:read", "View build policies"],
  ["builds:write", "Submit build metadata"],
];

const emptyMetrics: Metrics = {
  requestsThisMonth: 0,
  successful: 0,
  errors: 0,
  successRate: 100,
  rateLimitUsed: 0,
  averageLatencyMs: 0,
};

export default function OemApiAccess({
  onOrganizationLoaded,
}: {
  onOrganizationLoaded?: (name: string) => void;
}) {
  const [credential, setCredential] = useState<Credential | null>(null);
  const [metrics, setMetrics] = useState<Metrics>(emptyMetrics);
  const [usage, setUsage] = useState<UsagePoint[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [secret, setSecret] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);
  const [menuOpen, setMenuOpen] = useState(false);
  const [menuPosition, setMenuPosition] = useState({ top: 0, left: 0 });
  const [search, setSearch] = useState("");
  const [status, setStatus] = useState("all");
  const [name, setName] = useState("");
  const [environment, setEnvironment] = useState("production");
  const [description, setDescription] = useState("");
  const [selectedScopes, setSelectedScopes] = useState(["devices:read", "reports:read"]);
  const [expiration, setExpiration] = useState("90");
  const apiBase = `${backendUrl || windowOrigin()}/api/v1/oem`;

  const load = useCallback(async () => {
    const token = localStorage.getItem("ua_access");
    if (!token) {
      window.location.href = "/login";
      return;
    }
    setLoading(true);
    try {
      const headers = { Authorization: `Bearer ${token}` };
      const [accessResponse, profileResponse] = await Promise.all([
        fetch(`${backendUrl}/api/v1/oem/profile/api-access`, { headers }),
        fetch(`${backendUrl}/api/v1/oem/profile`, { headers }),
      ]);
      if (accessResponse.status === 401) {
        localStorage.removeItem("ua_access");
        localStorage.removeItem("ua_refresh");
        window.location.href = "/login";
        return;
      }
      let data: ApiAccessResponse;
      if (accessResponse.ok) {
        data = await accessResponse.json();
      } else if (profileResponse.ok) {
        const profile = await profileResponse.clone().json();
        data = {
          credential: profile.apiTokenPrefix
            ? {
                id: profile.id,
                name: "OEM API Credential",
                clientId: `oem_${String(profile.id).slice(-8)}`,
                prefix: profile.apiTokenPrefix,
                environment: "production",
                description: "",
                scopes: ["devices:read"],
                expiration: "never",
                createdAt: profile.createdAt,
                lastUsed: null,
                status: "active",
              }
            : null,
          metrics: emptyMetrics,
          usage: [],
        };
      } else {
        throw new Error("Unable to connect to the backend.");
      }
      setCredential(data.credential);
      setMetrics(data.metrics || emptyMetrics);
      setUsage(data.usage || []);
      if (profileResponse.ok) {
        const profile = await profileResponse.json();
        onOrganizationLoaded?.(profile.name || "OEM Portal");
      }
      setError(null);
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Unable to load API access.");
    } finally {
      setLoading(false);
    }
  }, [onOrganizationLoaded]);

  useEffect(() => {
    load();
  }, [load]);

  const visibleCredential = useMemo(() => {
    if (!credential) return null;
    const query = search.trim().toLowerCase();
    if (status !== "all" && credential.status !== status) return null;
    if (query && !`${credential.name} ${credential.clientId}`.toLowerCase().includes(query)) {
      return null;
    }
    return credential;
  }, [credential, search, status]);

  const createCredential = async () => {
    if (!name.trim() || selectedScopes.length === 0) {
      setError("Credential name and at least one permission are required.");
      return;
    }
    const token = localStorage.getItem("ua_access");
    setSaving(true);
    try {
      const response = await fetch(`${backendUrl}/api/v1/oem/profile/token`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify({
          name: name.trim(),
          environment,
          description: description.trim(),
          scopes: selectedScopes,
          expiration,
        }),
      });
      if (!response.ok) throw new Error("Unable to create API credential.");
      const data = await response.json();
      setSecret(data.token);
      setDrawerOpen(false);
      setName("");
      setDescription("");
      await load();
    } catch (requestError) {
      setError(
        requestError instanceof Error ? requestError.message : "Unable to create credential.",
      );
    } finally {
      setSaving(false);
    }
  };

  const revokeCredential = async () => {
    const token = localStorage.getItem("ua_access");
    setSaving(true);
    try {
      const response = await fetch(`${backendUrl}/api/v1/oem/profile/token`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!response.ok) throw new Error("Unable to revoke API credential.");
      setMenuOpen(false);
      await load();
    } catch (requestError) {
      setError(
        requestError instanceof Error ? requestError.message : "Unable to revoke credential.",
      );
    } finally {
      setSaving(false);
    }
  };

  const copyText = async (key: string, value: string) => {
    await navigator.clipboard.writeText(value);
    setCopied(key);
    window.setTimeout(() => setCopied(null), 1300);
  };

  return (
    <div className="flex min-h-[calc(100vh-3rem)] flex-col gap-5">
      <header className="flex flex-col gap-4 border-b border-slate-200 pb-4 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-[#071226]">API Access</h1>
          <p className="mt-1 text-sm text-slate-500">
            Manage credentials, permissions, and integrations for your organization.
          </p>
        </div>
        <div className="flex flex-col gap-2 sm:flex-row">
          <a
            href="https://github.com/unifiedAttestation/Website/wiki"
            target="_blank"
            rel="noreferrer"
            className="flex h-10 items-center justify-center gap-2 rounded-lg border border-slate-300 bg-white px-4 text-sm text-slate-700 hover:bg-slate-50"
          >
            <Clipboard size={17} /> API Documentation
          </a>
          <button
            type="button"
            onClick={() => setDrawerOpen(true)}
            className="flex h-10 items-center justify-center gap-2 rounded-lg bg-[#071226] px-4 text-sm font-medium text-white hover:bg-[#101f36]"
          >
            <KeyRound size={17} /> Create Credential
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
        <MetricCard
          label="Active Credentials"
          value={credential ? "1" : "0"}
          icon={<KeyRound />}
          tone="blue"
        />
        <MetricCard
          label="Requests This Month"
          value={metrics.requestsThisMonth.toLocaleString()}
          icon={<BarChart3 />}
          tone="violet"
        />
        <MetricCard
          label="Success Rate"
          value={`${metrics.successRate.toFixed(2)}%`}
          icon={<ShieldCheck />}
          tone="green"
        />
        <MetricCard
          label="Rate Limit"
          value={`${metrics.rateLimitUsed.toFixed(1)}% used`}
          icon={<Gauge />}
          tone="amber"
        />
      </section>

      <section className="grid min-w-0 gap-4 xl:grid-cols-[minmax(0,1.7fr)_minmax(300px,0.8fr)]">
        <div className="overflow-visible rounded-xl border border-slate-200 bg-white shadow-sm">
          <header className="border-b border-slate-200 p-4">
            <h2 className="text-lg font-semibold text-[#071226]">API Credentials</h2>
            <p className="mt-1 text-xs text-slate-500">
              Credentials used by services and automation.
            </p>
            <div className="mt-4 grid gap-3 sm:grid-cols-[1fr_180px_auto]">
              <label className="relative">
                <Search
                  size={17}
                  className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400"
                />
                <input
                  value={search}
                  onChange={(event) => setSearch(event.target.value)}
                  placeholder="Search credentials"
                  className="h-10 w-full rounded-lg border border-slate-200 pl-10 pr-3 text-sm outline-none focus:border-blue-600"
                />
              </label>
              <select
                value={status}
                onChange={(event) => setStatus(event.target.value)}
                className="h-10 rounded-lg border border-slate-200 bg-white px-3 text-sm outline-none"
              >
                <option value="all">All statuses</option>
                <option value="active">Active</option>
                <option value="revoked">Revoked</option>
              </select>
              <button
                type="button"
                onClick={load}
                className="flex h-10 items-center justify-center rounded-lg border border-slate-200 px-3 text-slate-600 hover:bg-slate-50"
              >
                {loading ? <Loader2 size={17} className="animate-spin" /> : <Filter size={17} />}
              </button>
            </div>
          </header>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[760px] text-left text-sm">
              <thead className="bg-slate-50 text-xs text-slate-500">
                <tr>
                  <th className="px-4 py-3">Name</th>
                  <th className="px-4 py-3">Client ID</th>
                  <th className="px-4 py-3">Permissions</th>
                  <th className="px-4 py-3">Created</th>
                  <th className="px-4 py-3">Last Used</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {visibleCredential && (
                  <tr className="border-t border-slate-100 hover:bg-slate-50/70">
                    <td className="px-4 py-4 font-medium text-blue-700">
                      {visibleCredential.name}
                    </td>
                    <td className="px-4 py-4 font-mono text-xs text-slate-500">
                      {visibleCredential.clientId}
                    </td>
                    <td className="px-4 py-4">
                      <div className="flex max-w-56 flex-wrap gap-1">
                        {visibleCredential.scopes.map((scope) => (
                          <span
                            key={scope}
                            className="rounded border border-slate-200 bg-slate-50 px-1.5 py-1 text-[10px] text-slate-600"
                          >
                            {scope}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="px-4 py-4 text-xs text-slate-500">
                      {formatDate(visibleCredential.createdAt)}
                    </td>
                    <td className="px-4 py-4 text-xs text-slate-500">
                      {visibleCredential.lastUsed
                        ? formatDate(visibleCredential.lastUsed)
                        : "Never"}
                    </td>
                    <td className="px-4 py-4">
                      <StatusBadge status={visibleCredential.status} />
                    </td>
                    <td className="px-4 py-4 text-right">
                      <button
                        type="button"
                        onClick={(event) => {
                          const rect = event.currentTarget.getBoundingClientRect();
                          setMenuPosition({
                            top: rect.bottom + 6,
                            left: Math.max(12, rect.right - 190),
                          });
                          setMenuOpen((value) => !value);
                        }}
                        className="rounded-lg p-2 text-slate-500 hover:bg-slate-100"
                      >
                        <MoreVertical size={18} />
                      </button>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
            {!loading && !visibleCredential && (
              <div className="px-5 py-16 text-center text-sm text-slate-500">
                No API credentials found.
              </div>
            )}
          </div>
        </div>

        <div className="grid gap-4">
          <article className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
            <h2 className="text-lg font-semibold text-[#071226]">Quick Start</h2>
            <p className="mt-3 text-xs text-slate-500">Base URL for all API requests</p>
            <CopyField
              value={apiBase}
              copied={copied === "base"}
              onCopy={() => copyText("base", apiBase)}
            />
            <p className="mt-4 text-xs text-slate-500">Example request</p>
            <pre className="mt-2 overflow-x-auto rounded-lg border border-slate-200 bg-slate-50 p-3 text-xs leading-6 text-slate-700">{`Authorization: Bearer ${credential?.prefix || "your_token"}••••••••\nGET /reports`}</pre>
          </article>
          <article className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
            <h2 className="text-lg font-semibold text-[#071226]">Rate Limits</h2>
            <Rate
              label="Standard API"
              detail="10,000 requests/hour"
              value={metrics.rateLimitUsed}
            />
            <Rate
              label="Report Exports"
              detail="100 requests/hour"
              value={Math.min(metrics.rateLimitUsed / 2, 100)}
            />
            <Rate
              label="Concurrent Requests"
              detail="50"
              value={Math.min(metrics.rateLimitUsed / 4, 100)}
            />
          </article>
        </div>
      </section>

      <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h2 className="text-lg font-semibold text-[#071226]">API Usage</h2>
            <p className="text-xs text-slate-500">Request activity over the current month.</p>
          </div>
          <div className="flex gap-4 text-xs text-slate-500">
            <span className="flex items-center gap-2">
              <i className="h-2 w-2 rounded-full bg-emerald-600" />
              Successful
            </span>
            <span className="flex items-center gap-2">
              <i className="h-2 w-2 rounded-full bg-red-600" />
              Errors
            </span>
          </div>
        </div>
        <div className="mt-4 grid gap-4 md:grid-cols-[150px_1fr]">
          <dl className="grid grid-cols-3 gap-3 border-b border-slate-200 pb-4 md:grid-cols-1 md:border-b-0 md:border-r md:pb-0">
            <UsageValue value={metrics.requestsThisMonth.toLocaleString()} label="Total requests" />
            <UsageValue value={metrics.errors.toLocaleString()} label="Errors" />
            <UsageValue value={`${metrics.averageLatencyMs} ms`} label="Average latency" />
          </dl>
          <UsageChart data={usage} />
        </div>
      </section>

      <OemFooter />

      {menuOpen &&
        typeof document !== "undefined" &&
        createPortal(
          <>
            <button
              type="button"
              aria-label="Close actions"
              onClick={() => setMenuOpen(false)}
              className="fixed inset-0 z-[9990]"
            />
            <div
              className="fixed z-[9991] w-48 overflow-hidden rounded-lg border border-slate-200 bg-white py-1 shadow-xl"
              style={menuPosition}
            >
              <button
                type="button"
                onClick={() => {
                  setMenuOpen(false);
                  setDrawerOpen(true);
                }}
                className="flex w-full items-center gap-2 px-4 py-2.5 text-sm text-slate-700 hover:bg-slate-50"
              >
                <RotateCw size={16} />
                Rotate Credential
              </button>
              <button
                type="button"
                onClick={revokeCredential}
                className="flex w-full items-center gap-2 px-4 py-2.5 text-sm text-red-600 hover:bg-red-50"
              >
                <Trash2 size={16} />
                Revoke
              </button>
            </div>
          </>,
          document.body,
        )}

      {drawerOpen &&
        typeof document !== "undefined" &&
        createPortal(
          <>
            <button
              type="button"
              aria-label="Close credential drawer"
              onClick={() => setDrawerOpen(false)}
              className="fixed inset-0 z-[9998] bg-[#071226]/55 backdrop-blur-sm"
            />
            <aside className="fixed inset-y-0 right-0 z-[9999] flex w-full max-w-md flex-col bg-white shadow-2xl">
              <header className="flex items-center justify-between border-b border-slate-200 px-6 py-5">
                <h2 className="text-lg font-semibold text-[#071226]">Create API Credential</h2>
                <button type="button" onClick={() => setDrawerOpen(false)}>
                  <X size={20} />
                </button>
              </header>
              <div className="flex-1 space-y-5 overflow-y-auto p-6">
                <Field
                  label="Credential Name"
                  value={name}
                  onChange={setName}
                  placeholder="Device Compliance Service"
                />
                <div>
                  <p className="mb-2 text-sm font-medium text-slate-700">Environment</p>
                  <div className="grid grid-cols-2 overflow-hidden rounded-lg border border-slate-200">
                    <EnvironmentButton
                      active={environment === "production"}
                      onClick={() => setEnvironment("production")}
                    >
                      Production
                    </EnvironmentButton>
                    <EnvironmentButton
                      active={environment === "sandbox"}
                      onClick={() => setEnvironment("sandbox")}
                    >
                      Sandbox
                    </EnvironmentButton>
                  </div>
                </div>
                <label className="block">
                  <span className="text-sm font-medium text-slate-700">
                    Description <span className="font-normal text-slate-400">(optional)</span>
                  </span>
                  <textarea
                    value={description}
                    onChange={(event) => setDescription(event.target.value)}
                    rows={4}
                    className="mt-2 w-full resize-none rounded-lg border border-slate-200 p-3 text-sm outline-none focus:border-blue-600"
                    placeholder="Reads device status for compliance checks"
                  />
                </label>
                <div>
                  <h3 className="font-semibold text-[#071226]">Permissions</h3>
                  <p className="mt-1 text-xs text-slate-500">
                    Select the scopes this credential should have.
                  </p>
                  <div className="mt-3 space-y-3">
                    {scopes.map(([scope, help]) => (
                      <label key={scope} className="flex cursor-pointer items-start gap-3">
                        <input
                          type="checkbox"
                          checked={selectedScopes.includes(scope)}
                          onChange={() =>
                            setSelectedScopes((current) =>
                              current.includes(scope)
                                ? current.filter((item) => item !== scope)
                                : [...current, scope],
                            )
                          }
                          className="mt-1 h-4 w-4 accent-blue-700"
                        />
                        <span>
                          <strong className="block text-sm text-slate-700">{scope}</strong>
                          <span className="text-xs text-slate-500">{help}</span>
                        </span>
                      </label>
                    ))}
                  </div>
                </div>
                <label className="block">
                  <span className="text-sm font-medium text-slate-700">Expiration</span>
                  <select
                    value={expiration}
                    onChange={(event) => setExpiration(event.target.value)}
                    className="mt-2 h-11 w-full rounded-lg border border-slate-200 bg-white px-3 text-sm"
                  >
                    <option value="30">30 days</option>
                    <option value="90">90 days</option>
                    <option value="365">1 year</option>
                    <option value="never">Never</option>
                  </select>
                </label>
                <div className="flex gap-3 rounded-lg border border-amber-300 bg-amber-50 p-4 text-sm text-amber-800">
                  <AlertTriangle size={19} className="shrink-0" />
                  <p>The secret is shown only once after creation. Store it securely.</p>
                </div>
              </div>
              <footer className="grid grid-cols-2 gap-3 border-t border-slate-200 p-6">
                <button
                  type="button"
                  onClick={() => setDrawerOpen(false)}
                  className="h-11 rounded-lg border border-slate-300 text-sm"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  disabled={saving}
                  onClick={createCredential}
                  className="flex h-11 items-center justify-center gap-2 rounded-lg bg-[#071226] text-sm font-medium text-white disabled:opacity-50"
                >
                  {saving && <Loader2 size={17} className="animate-spin" />}Create Credential
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
                Credential Created
              </h2>
              <p className="mt-2 text-center text-sm text-slate-500">
                Copy this secret now. It will not be shown again.
              </p>
              <div className="mt-5 flex items-center gap-2 rounded-lg border border-slate-200 bg-slate-50 p-3">
                <code className="min-w-0 flex-1 break-all text-xs text-slate-700">{secret}</code>
                <button
                  type="button"
                  onClick={() => copyText("secret", secret)}
                  className="rounded-lg p-2 text-blue-700 hover:bg-blue-50"
                >
                  {copied === "secret" ? <Check size={18} /> : <Copy size={18} />}
                </button>
              </div>
              <button
                type="button"
                onClick={() => setSecret(null)}
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

function windowOrigin() {
  return typeof window === "undefined" ? "" : window.location.origin;
}

function MetricCard({
  label,
  value,
  icon,
  tone,
}: {
  label: string;
  value: string;
  icon: React.ReactNode;
  tone: "blue" | "violet" | "green" | "amber";
}) {
  const colors = {
    blue: "bg-blue-50 text-blue-700",
    violet: "bg-violet-50 text-violet-700",
    green: "bg-emerald-50 text-emerald-700",
    amber: "bg-amber-50 text-amber-600",
  };
  return (
    <article className="flex min-h-28 items-center gap-4 rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
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

function StatusBadge({ status }: { status: Credential["status"] }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-md border px-2 py-1 text-xs ${status === "active" ? "border-emerald-200 bg-emerald-50 text-emerald-700" : "border-red-200 bg-red-50 text-red-700"}`}
    >
      <i
        className={`h-1.5 w-1.5 rounded-full ${status === "active" ? "bg-emerald-600" : "bg-red-600"}`}
      />
      {status === "active" ? "Active" : "Revoked"}
    </span>
  );
}

function CopyField({
  value,
  copied,
  onCopy,
}: {
  value: string;
  copied: boolean;
  onCopy: () => void;
}) {
  return (
    <div className="mt-2 flex h-11 items-center gap-2 rounded-lg border border-slate-200 px-3">
      <code className="min-w-0 flex-1 truncate text-xs text-slate-700">{value}</code>
      <button type="button" onClick={onCopy}>
        {copied ? (
          <Check size={17} className="text-emerald-600" />
        ) : (
          <Copy size={17} className="text-slate-500" />
        )}
      </button>
    </div>
  );
}

function Rate({ label, detail, value }: { label: string; detail: string; value: number }) {
  return (
    <div className="mt-4">
      <div className="flex justify-between gap-3 text-xs">
        <span className="text-slate-700">{label}</span>
        <span className="text-slate-500">{detail}</span>
        <span className="font-medium text-slate-700">{value.toFixed(1)}%</span>
      </div>
      <div className="mt-2 h-2 overflow-hidden rounded-full bg-slate-100">
        <div
          className="h-full rounded-full bg-blue-700"
          style={{ width: `${Math.max(1, value)}%` }}
        />
      </div>
    </div>
  );
}

function UsageValue({ value, label }: { value: string; label: string }) {
  return (
    <div>
      <strong className="text-lg text-[#071226]">{value}</strong>
      <p className="text-[11px] text-slate-500">{label}</p>
    </div>
  );
}

function UsageChart({ data }: { data: UsagePoint[] }) {
  const points = data.length
    ? data
    : [{ date: new Date().toISOString(), successful: 0, errors: 0 }];
  const width = 900;
  const height = 180;
  const max = Math.max(1, ...points.flatMap((item) => [item.successful, item.errors]));
  const path = (key: "successful" | "errors") =>
    points
      .map(
        (item, index) =>
          `${24 + (index / Math.max(1, points.length - 1)) * (width - 48)},${height - 24 - (item[key] / max) * (height - 48)}`,
      )
      .join(" ");
  return (
    <div className="min-w-0 overflow-hidden">
      <svg viewBox={`0 0 ${width} ${height}`} className="h-44 w-full">
        {[0.25, 0.5, 0.75].map((value) => (
          <line
            key={value}
            x1="24"
            x2={width - 24}
            y1={height * value}
            y2={height * value}
            stroke="#e2e8f0"
            strokeDasharray="4 4"
          />
        ))}
        <polyline points={path("successful")} fill="none" stroke="#16a34a" strokeWidth="3" />
        <polyline points={path("errors")} fill="none" stroke="#dc2626" strokeWidth="3" />
      </svg>
      <div className="flex justify-between text-[10px] text-slate-400">
        <span>{formatShortDate(points[0].date)}</span>
        <span>{formatShortDate(points[points.length - 1].date)}</span>
      </div>
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

function EnvironmentButton({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`h-10 text-sm ${active ? "border border-blue-600 bg-blue-50 text-blue-700" : "text-slate-600"}`}
    >
      {children}
    </button>
  );
}

function formatDate(value: string) {
  return new Date(value).toLocaleString();
}

function formatShortDate(value: string) {
  return new Date(value).toLocaleDateString(undefined, { month: "short", day: "numeric" });
}
