import { useCallback, useEffect, useMemo, useState } from "react";
import { createPortal } from "react-dom";
import {
  AlertTriangle,
  Check,
  CheckCircle2,
  ExternalLink,
  Globe2,
  KeyRound,
  Loader2,
  MoreVertical,
  Plus,
  RefreshCw,
  Search,
  Server,
  ShieldCheck,
  Trash2,
  X,
} from "lucide-react";
import Footer from "../../components/Footer";
import { backendUrl } from "../../lib/config";

type VerificationKey = {
  kid?: string;
  alg?: string;
  publicKey?: string;
};

type FederationBackend = {
  id: string;
  backendId: string;
  name: string;
  url?: string | null;
  publicKeys?: VerificationKey[];
  status: "active" | "disabled";
  createdAt: string;
};

type Activity = {
  id: string;
  title: string;
  description: string;
  date: string;
  type: "added" | "refresh" | "status" | "delete";
};

function StatusBadge({ active }: { active: boolean }) {
  return (
    <span
      className={[
        "inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium",
        active ? "bg-emerald-50 text-emerald-700" : "bg-red-50 text-red-700",
      ].join(" ")}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${active ? "bg-emerald-600" : "bg-red-600"}`} />
      {active ? "Active" : "Disabled"}
    </span>
  );
}

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

export default function AdminFederation() {
  const [backends, setBackends] = useState<FederationBackend[]>([]);
  const [activities, setActivities] = useState<Activity[]>([]);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [refreshingId, setRefreshingId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState<"all" | "active" | "disabled">("all");
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [actionMenu, setActionMenu] = useState<string | null>(null);
  const [actionMenuPosition, setActionMenuPosition] = useState({ top: 0, left: 0 });
  const [newBackend, setNewBackend] = useState({ url: "", name: "" });

  const getAccessToken = () => localStorage.getItem("ua_access");

  const loadBackends = useCallback(async () => {
    setLoading(true);
    try {
      const response = await fetch(`${backendUrl}/api/v1/federation/backends`);
      if (!response.ok) throw new Error("Unable to load federated backends.");
      const data: FederationBackend[] = await response.json();
      setBackends(data);
      setActivities((current) => {
        if (current.length > 0) return current;
        return data.slice(0, 5).map((backend) => ({
          id: `added-${backend.id}`,
          title: "Backend added",
          description: `${backend.name} was added to the federation`,
          date: backend.createdAt,
          type: "added",
        }));
      });
      setError(null);
    } catch (requestError) {
      setError(
        requestError instanceof Error ? requestError.message : "Unable to load federated backends.",
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadBackends();
  }, [loadBackends]);

  const filteredBackends = useMemo(() => {
    const query = search.trim().toLowerCase();
    return backends.filter((backend) => {
      const matchesSearch =
        !query ||
        backend.name.toLowerCase().includes(query) ||
        backend.backendId.toLowerCase().includes(query) ||
        backend.url?.toLowerCase().includes(query);
      const matchesStatus = statusFilter === "all" || backend.status === statusFilter;
      return matchesSearch && matchesStatus;
    });
  }, [backends, search, statusFilter]);

  const addActivity = (
    backend: FederationBackend,
    type: Activity["type"],
    title: string,
    description: string,
  ) => {
    setActivities((current) =>
      [
        {
          id: `${type}-${backend.id}-${Date.now()}`,
          title,
          description,
          date: new Date().toISOString(),
          type,
        },
        ...current,
      ].slice(0, 8),
    );
  };

  const createBackend = async () => {
    const accessToken = getAccessToken();
    if (!accessToken) {
      window.location.href = "/login";
      return;
    }
    if (!newBackend.url.trim()) {
      setError("Backend URL is required.");
      return;
    }
    try {
      new URL(newBackend.url);
    } catch {
      setError("Enter a valid absolute URL.");
      return;
    }

    setSubmitting(true);
    setError(null);
    try {
      const response = await fetch(`${backendUrl}/api/v1/federation/backends`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${accessToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          url: newBackend.url,
          name: newBackend.name.trim() || undefined,
        }),
      });
      if (!response.ok) {
        const message = await response.text();
        throw new Error(message || "Unable to add federated backend.");
      }
      const created: FederationBackend = await response.json();
      addActivity(created, "added", "Backend added", `${created.name} was added to the federation`);
      setDrawerOpen(false);
      setNewBackend({ url: "", name: "" });
      setNotice("Federated backend verified and added successfully.");
      await loadBackends();
    } catch (requestError) {
      setError(
        requestError instanceof Error ? requestError.message : "Unable to add federated backend.",
      );
    } finally {
      setSubmitting(false);
    }
  };

  const refreshBackend = async (backend: FederationBackend) => {
    const accessToken = getAccessToken();
    if (!accessToken) return;
    setRefreshingId(backend.id);
    setError(null);
    try {
      const response = await fetch(
        `${backendUrl}/api/v1/federation/backends/${backend.id}/refresh`,
        {
          method: "POST",
          headers: { Authorization: `Bearer ${accessToken}` },
        },
      );
      if (!response.ok) {
        const message = await response.text();
        throw new Error(message || `Unable to refresh ${backend.name}.`);
      }
      addActivity(
        backend,
        "refresh",
        "Keys refreshed",
        `Verification keys refreshed for ${backend.name}`,
      );
      setNotice(`${backend.name} verification keys refreshed.`);
      await loadBackends();
    } catch (requestError) {
      setError(
        requestError instanceof Error ? requestError.message : `Unable to refresh ${backend.name}.`,
      );
    } finally {
      setRefreshingId(null);
    }
  };

  const refreshAll = async () => {
    for (const backend of backends.filter((item) => item.url)) {
      await refreshBackend(backend);
    }
  };

  const toggleBackendStatus = async (backend: FederationBackend) => {
    const accessToken = getAccessToken();
    if (!accessToken) return;
    const nextStatus = backend.status === "active" ? "disabled" : "active";
    setActionMenu(null);
    setError(null);
    try {
      const response = await fetch(`${backendUrl}/api/v1/federation/backends/${backend.id}`, {
        method: "PATCH",
        headers: {
          Authorization: `Bearer ${accessToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ status: nextStatus }),
      });
      if (!response.ok) throw new Error(`Unable to ${nextStatus} backend.`);
      addActivity(
        backend,
        "status",
        "Backend status changed",
        `${backend.name} is now ${nextStatus}`,
      );
      setNotice(`${backend.name} is now ${nextStatus}.`);
      await loadBackends();
    } catch (requestError) {
      setError(
        requestError instanceof Error ? requestError.message : "Unable to update backend status.",
      );
    }
  };

  const deleteBackend = async (backend: FederationBackend) => {
    if (!window.confirm(`Delete ${backend.name} from the federation?`)) return;
    const accessToken = getAccessToken();
    if (!accessToken) return;
    setActionMenu(null);
    setError(null);
    try {
      const response = await fetch(`${backendUrl}/api/v1/federation/backends/${backend.id}`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      if (!response.ok) {
        const message = await response.text();
        throw new Error(message || "Unable to delete backend.");
      }
      addActivity(
        backend,
        "delete",
        "Backend removed",
        `${backend.name} was removed from the federation`,
      );
      setNotice("Federated backend removed successfully.");
      await loadBackends();
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Unable to delete backend.");
    }
  };

  const activeCount = backends.filter((backend) => backend.status === "active").length;
  const verificationKeyCount = backends.reduce(
    (total, backend) => total + (Array.isArray(backend.publicKeys) ? backend.publicKeys.length : 0),
    0,
  );
  const issueCount = backends.length - activeCount;

  return (
    <div className="flex min-h-[calc(100vh-3rem)] flex-col gap-5">
      <header className="flex flex-col gap-4 border-b border-slate-200 pb-4 sm:flex-row sm:items-center sm:justify-between">
        <h1 className="text-2xl font-bold tracking-tight text-[#071226]">Federation Management</h1>
        <label className="relative w-full sm:w-80">
          <Search
            size={18}
            className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-400"
          />
          <input
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Search backends..."
            className="h-10 w-full rounded-lg border border-slate-200 bg-white pl-10 pr-3 text-sm outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-100"
          />
        </label>
      </header>

      <section className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <p className="text-sm text-slate-500">
          Connect trusted attestation backends and monitor the federation.
        </p>
        <button
          type="button"
          onClick={() => {
            setError(null);
            setDrawerOpen(true);
          }}
          className="flex h-10 items-center justify-center gap-2 rounded-lg bg-[#071226] px-4 text-sm font-medium text-white hover:bg-[#101f36]"
        >
          <Plus size={18} />
          Add Backend
        </button>
      </section>

      <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          label="Trusted Backends"
          value={backends.length}
          icon={<ShieldCheck size={23} />}
          color="bg-blue-50 text-blue-700"
        />
        <StatCard
          label="Active"
          value={activeCount}
          icon={<CheckCircle2 size={23} />}
          color="bg-emerald-50 text-emerald-700"
        />
        <StatCard
          label="Verification Keys"
          value={verificationKeyCount}
          icon={<KeyRound size={23} />}
          color="bg-sky-50 text-sky-700"
        />
        <StatCard
          label="Issues"
          value={issueCount}
          icon={<AlertTriangle size={23} />}
          color="bg-violet-50 text-violet-700"
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
        <header className="flex flex-col gap-3 border-b border-slate-200 p-4 sm:flex-row sm:items-center sm:justify-between">
          <h2 className="font-semibold text-[#071226]">Federated Backends</h2>
          <div className="flex flex-col gap-2 sm:flex-row">
            <label className="relative">
              <Search
                size={16}
                className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400"
              />
              <input
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                placeholder="Search backends..."
                className="h-9 rounded-lg border border-slate-200 pl-9 pr-3 text-sm outline-none focus:border-blue-600"
              />
            </label>
            <select
              value={statusFilter}
              onChange={(event) =>
                setStatusFilter(event.target.value as "all" | "active" | "disabled")
              }
              className="h-9 rounded-lg border border-slate-200 bg-white px-3 text-sm outline-none"
            >
              <option value="all">All Statuses</option>
              <option value="active">Active</option>
              <option value="disabled">Disabled</option>
            </select>
            <button
              type="button"
              onClick={refreshAll}
              disabled={Boolean(refreshingId) || backends.length === 0}
              className="flex h-9 items-center justify-center gap-2 rounded-lg border border-slate-200 px-3 text-sm text-slate-700 hover:bg-slate-50 disabled:opacity-50"
            >
              <RefreshCw size={16} className={refreshingId ? "animate-spin" : ""} />
              Refresh Keys
            </button>
          </div>
        </header>

        <div className="overflow-x-auto">
          <table className="w-full min-w-[820px] text-left text-sm">
            <thead className="bg-slate-50 text-xs text-slate-500">
              <tr>
                <th className="px-5 py-3 font-semibold">Backend</th>
                <th className="px-5 py-3 font-semibold">URL</th>
                <th className="px-5 py-3 font-semibold">Status</th>
                <th className="px-5 py-3 font-semibold">Verification Keys</th>
                <th className="px-5 py-3 font-semibold">Added</th>
                <th className="px-5 py-3 text-right font-semibold">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {filteredBackends.map((backend) => (
                <tr key={backend.id} className="hover:bg-slate-50/70">
                  <td className="px-5 py-3">
                    <div className="flex items-center gap-3">
                      <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-blue-50 text-blue-700">
                        <Server size={18} />
                      </div>
                      <div>
                        <p className="font-medium text-slate-900">{backend.name}</p>
                        <p className="max-w-48 truncate text-xs text-slate-500">
                          {backend.backendId}
                        </p>
                      </div>
                    </div>
                  </td>
                  <td className="px-5 py-3">
                    {backend.url ? (
                      <a
                        href={backend.url}
                        target="_blank"
                        rel="noreferrer"
                        className="inline-flex max-w-52 items-center gap-1 truncate text-xs text-blue-700 hover:underline"
                      >
                        {backend.url}
                        <ExternalLink size={12} className="shrink-0" />
                      </a>
                    ) : (
                      <span className="text-xs text-slate-400">Manual configuration</span>
                    )}
                  </td>
                  <td className="px-5 py-3">
                    <StatusBadge active={backend.status === "active"} />
                  </td>
                  <td className="px-5 py-3 text-slate-600">
                    {Array.isArray(backend.publicKeys) ? backend.publicKeys.length : 0}
                  </td>
                  <td className="px-5 py-3 text-xs text-slate-500">
                    {new Date(backend.createdAt).toLocaleString()}
                  </td>
                  <td className="relative px-5 py-3 text-right">
                    <div className="inline-flex items-center gap-1">
                      {backend.url && (
                        <button
                          type="button"
                          onClick={() => refreshBackend(backend)}
                          disabled={refreshingId === backend.id}
                          className="rounded-lg border border-slate-200 p-2 text-slate-600 hover:bg-slate-50 disabled:opacity-50"
                        >
                          <RefreshCw
                            size={17}
                            className={refreshingId === backend.id ? "animate-spin" : ""}
                          />
                        </button>
                      )}
                      <button
                        type="button"
                        onClick={(event) => {
                          if (actionMenu === backend.id) {
                            setActionMenu(null);
                            return;
                          }
                          const rect = event.currentTarget.getBoundingClientRect();
                          const menuHeight = 88;
                          setActionMenuPosition({
                            top:
                              rect.bottom + menuHeight + 8 <= window.innerHeight
                                ? rect.bottom + 6
                                : rect.top - menuHeight - 6,
                            left: Math.max(12, rect.right - 176),
                          });
                          setActionMenu(backend.id);
                        }}
                        className="rounded-lg border border-slate-200 p-2 text-slate-600 hover:bg-slate-50"
                      >
                        <MoreVertical size={17} />
                      </button>
                    </div>
                    {actionMenu === backend.id &&
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
                            style={{
                              top: actionMenuPosition.top,
                              left: actionMenuPosition.left,
                            }}
                          >
                            <button
                              type="button"
                              onClick={() => toggleBackendStatus(backend)}
                              className="flex w-full items-center gap-2 px-3 py-2 text-sm text-slate-700 hover:bg-slate-50"
                            >
                              {backend.status === "active" ? <X size={16} /> : <Check size={16} />}
                              {backend.status === "active" ? "Disable" : "Enable"}
                            </button>
                            <button
                              type="button"
                              onClick={() => deleteBackend(backend)}
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
          {!loading && filteredBackends.length === 0 && (
            <div className="px-5 py-12 text-center text-sm text-slate-500">
              No federated backends found.
            </div>
          )}
          {loading && (
            <div className="flex items-center justify-center gap-2 px-5 py-12 text-sm text-slate-500">
              <Loader2 size={18} className="animate-spin" />
              Loading federated backends...
            </div>
          )}
        </div>
        <div className="border-t border-slate-200 px-5 py-4 text-xs text-slate-500">
          Showing {filteredBackends.length} of {backends.length} backends
        </div>
      </section>

      <section className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
        <header className="border-b border-slate-200 px-5 py-4">
          <h2 className="font-semibold text-[#071226]">Audit Activity</h2>
        </header>
        <div className="divide-y divide-slate-100">
          {activities.slice(0, 5).map((activity) => (
            <div key={activity.id} className="flex items-center gap-3 px-5 py-3">
              <div
                className={[
                  "flex h-9 w-9 shrink-0 items-center justify-center rounded-lg",
                  activity.type === "delete"
                    ? "bg-red-50 text-red-700"
                    : activity.type === "refresh"
                      ? "bg-emerald-50 text-emerald-700"
                      : "bg-blue-50 text-blue-700",
                ].join(" ")}
              >
                {activity.type === "refresh" ? <KeyRound size={17} /> : <Server size={17} />}
              </div>
              <div className="min-w-0 flex-1">
                <p className="text-sm font-medium text-slate-800">{activity.title}</p>
                <p className="truncate text-xs text-slate-500">{activity.description}</p>
              </div>
              <time className="shrink-0 text-xs text-slate-500">
                {new Date(activity.date).toLocaleString()}
              </time>
            </div>
          ))}
          {activities.length === 0 && (
            <div className="px-5 py-10 text-center text-sm text-slate-500">
              No federation activity.
            </div>
          )}
        </div>
      </section>

      <Footer />

      {drawerOpen &&
        typeof document !== "undefined" &&
        createPortal(
          <>
            <button
              type="button"
              aria-label="Close backend drawer"
              onClick={() => setDrawerOpen(false)}
              className="fixed left-0 top-0 z-[9998] h-[100dvh] w-screen bg-[#071226]/55 backdrop-blur-sm"
            />
            <aside className="fixed inset-y-0 right-0 z-[9999] flex w-full max-w-md flex-col bg-white shadow-2xl">
              <header className="flex items-center justify-between border-b border-slate-200 px-6 py-5">
                <h2 className="text-lg font-semibold text-[#071226]">Add Federated Backend</h2>
                <button
                  type="button"
                  onClick={() => setDrawerOpen(false)}
                  className="rounded-lg p-2 text-slate-500 hover:bg-slate-100"
                >
                  <X size={20} />
                </button>
              </header>

              <div className="flex-1 space-y-5 overflow-y-auto p-6">
                <div>
                  <label className="text-sm font-medium text-slate-700">Backend URL</label>
                  <div className="relative mt-2">
                    <Globe2
                      size={18}
                      className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400"
                    />
                    <input
                      value={newBackend.url}
                      onChange={(event) =>
                        setNewBackend((current) => ({ ...current, url: event.target.value }))
                      }
                      placeholder="https://backend.example.com"
                      className="h-11 w-full rounded-lg border border-slate-200 pl-10 pr-3 text-sm outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-100"
                    />
                  </div>
                  <p className="mt-2 text-xs text-slate-500">
                    Enter the base URL of the federated backend.
                  </p>
                </div>

                <div>
                  <label className="text-sm font-medium text-slate-700">
                    Display Name <span className="font-normal text-slate-400">(optional)</span>
                  </label>
                  <div className="relative mt-2">
                    <Server
                      size={18}
                      className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400"
                    />
                    <input
                      value={newBackend.name}
                      onChange={(event) =>
                        setNewBackend((current) => ({ ...current, name: event.target.value }))
                      }
                      placeholder="e.g., Partner Backend"
                      className="h-11 w-full rounded-lg border border-slate-200 pl-10 pr-3 text-sm outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-100"
                    />
                  </div>
                </div>

                <div>
                  <h3 className="text-sm font-semibold text-slate-800">Trust Verification</h3>
                  <div className="mt-3 space-y-3">
                    {[
                      "Backend is reachable",
                      "Backend identity is retrieved",
                      "Verification keys are available",
                      "Attestation endpoint is supported",
                    ].map((item) => (
                      <div key={item} className="flex items-center gap-2 text-xs text-slate-600">
                        <CheckCircle2 size={16} className="text-emerald-600" />
                        {item}
                      </div>
                    ))}
                  </div>
                </div>

                <div className="rounded-xl border border-blue-200 bg-blue-50 p-4">
                  <div className="flex gap-3">
                    <ShieldCheck className="shrink-0 text-blue-700" size={22} />
                    <p className="text-xs leading-5 text-slate-600">
                      The backend will retrieve and validate verification keys before establishing
                      trust. The backend will not be added if validation fails.
                    </p>
                  </div>
                </div>

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
                  onClick={createBackend}
                  disabled={submitting}
                  className="flex h-11 items-center justify-center gap-2 rounded-lg bg-[#071226] text-sm font-medium text-white hover:bg-[#101f36] disabled:opacity-60"
                >
                  {submitting && <Loader2 size={17} className="animate-spin" />}
                  Verify & Add
                </button>
              </footer>
            </aside>
          </>,
          document.body,
        )}
    </div>
  );
}
