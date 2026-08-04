import { useCallback, useEffect, useMemo, useState } from "react";
import { createPortal } from "react-dom";
import {
  Building2,
  Check,
  CheckCircle2,
  Clock3,
  Globe2,
  KeyRound,
  Loader2,
  MoreVertical,
  Plus,
  RefreshCw,
  Search,
  ShieldCheck,
  Trash2,
  X,
  XCircle,
} from "lucide-react";
import Footer from "../../components/Footer";
import { backendUrl } from "../../lib/config";

type Authority = {
  id: string;
  name: string;
  baseUrl: string;
  enabled: boolean;
  isLocal: boolean;
  createdAt?: string;
  statusCachedAt?: string | null;
  keyAvailability?: {
    rsa: boolean;
    ecdsa: boolean;
  };
};

function StatusBadge({ healthy }: { healthy: boolean }) {
  return (
    <span
      className={[
        "inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium",
        healthy ? "bg-emerald-50 text-emerald-700" : "bg-red-50 text-red-700",
      ].join(" ")}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${healthy ? "bg-emerald-600" : "bg-red-600"}`} />
      {healthy ? "Healthy" : "Unavailable"}
    </span>
  );
}

function AvailabilityIcon({ available }: { available: boolean }) {
  return available ? (
    <CheckCircle2 size={19} className="text-emerald-600" />
  ) : (
    <XCircle size={19} className="text-red-600" />
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

export default function AdminAuthorities() {
  const [authorities, setAuthorities] = useState<Authority[]>([]);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [refreshingId, setRefreshingId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [actionMenu, setActionMenu] = useState<string | null>(null);
  const [actionMenuPosition, setActionMenuPosition] = useState({ top: 0, left: 0 });
  const [newAuthority, setNewAuthority] = useState({ name: "", baseUrl: "" });

  const getAccessToken = () => localStorage.getItem("ua_access");

  const loadAuthorities = useCallback(async () => {
    const accessToken = getAccessToken();
    if (!accessToken) {
      window.location.href = "/login";
      return;
    }
    setLoading(true);
    try {
      const response = await fetch(`${backendUrl}/api/v1/admin/attestation-authorities`, {
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      if (response.status === 401) {
        localStorage.removeItem("ua_access");
        localStorage.removeItem("ua_refresh");
        window.location.href = "/login";
        return;
      }
      if (!response.ok) throw new Error("Unable to load attestation authorities.");
      setAuthorities(await response.json());
      setError(null);
    } catch (requestError) {
      setError(
        requestError instanceof Error
          ? requestError.message
          : "Unable to load attestation authorities.",
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadAuthorities();
  }, [loadAuthorities]);

  const isHealthy = (authority: Authority) =>
    authority.enabled &&
    Boolean(authority.keyAvailability?.rsa) &&
    Boolean(authority.keyAvailability?.ecdsa);

  const filteredAuthorities = useMemo(() => {
    const query = search.trim().toLowerCase();
    if (!query) return authorities;
    return authorities.filter(
      (authority) =>
        authority.name.toLowerCase().includes(query) ||
        authority.baseUrl.toLowerCase().includes(query),
    );
  }, [authorities, search]);

  const createAuthority = async () => {
    const accessToken = getAccessToken();
    if (!accessToken) return;
    if (!newAuthority.name.trim() || !newAuthority.baseUrl.trim()) {
      setError("Authority name and base URL are required.");
      return;
    }
    try {
      new URL(newAuthority.baseUrl);
    } catch {
      setError("Enter a valid absolute URL.");
      return;
    }

    setSubmitting(true);
    setError(null);
    try {
      const response = await fetch(`${backendUrl}/api/v1/admin/attestation-authorities`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${accessToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(newAuthority),
      });
      if (!response.ok) {
        const message = await response.text();
        throw new Error(message || "Unable to add authority.");
      }
      setDrawerOpen(false);
      setNewAuthority({ name: "", baseUrl: "" });
      setNotice("Attestation authority added successfully.");
      await loadAuthorities();
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Unable to add authority.");
    } finally {
      setSubmitting(false);
    }
  };

  const refreshAuthority = async (authority: Authority) => {
    const accessToken = getAccessToken();
    if (!accessToken) return;
    setRefreshingId(authority.id);
    setActionMenu(null);
    setError(null);
    try {
      const response = await fetch(
        `${backendUrl}/api/v1/admin/attestation-authorities/${authority.id}/refresh`,
        {
          method: "POST",
          headers: { Authorization: `Bearer ${accessToken}` },
        },
      );
      if (!response.ok) {
        const message = await response.text();
        throw new Error(message || `Unable to refresh ${authority.name}.`);
      }
      setNotice(`${authority.name} refreshed successfully.`);
      await loadAuthorities();
    } catch (requestError) {
      setError(
        requestError instanceof Error
          ? requestError.message
          : `Unable to refresh ${authority.name}.`,
      );
    } finally {
      setRefreshingId(null);
    }
  };

  const refreshAll = async () => {
    for (const authority of authorities) {
      await refreshAuthority(authority);
    }
  };

  const deleteAuthority = async (authority: Authority) => {
    if (!window.confirm(`Delete ${authority.name}?`)) return;
    const accessToken = getAccessToken();
    if (!accessToken) return;
    setActionMenu(null);
    setError(null);
    try {
      const response = await fetch(
        `${backendUrl}/api/v1/admin/attestation-authorities/${authority.id}`,
        {
          method: "DELETE",
          headers: { Authorization: `Bearer ${accessToken}` },
        },
      );
      if (!response.ok) {
        const message = await response.text();
        throw new Error(message || "Unable to delete authority.");
      }
      setNotice("Attestation authority deleted successfully.");
      await loadAuthorities();
    } catch (requestError) {
      setError(
        requestError instanceof Error ? requestError.message : "Unable to delete authority.",
      );
    }
  };

  const healthyCount = authorities.filter(isHealthy).length;
  const rsaCount = authorities.filter((authority) => authority.keyAvailability?.rsa).length;
  const ecdsaCount = authorities.filter((authority) => authority.keyAvailability?.ecdsa).length;

  return (
    <div className="flex min-h-[calc(100vh-3rem)] flex-col gap-5">
      <header className="flex flex-col gap-4 border-b border-slate-200 pb-4 sm:flex-row sm:items-center sm:justify-between">
        <h1 className="text-2xl font-bold tracking-tight text-[#071226]">
          Attestation Authorities
        </h1>
        <label className="relative w-full sm:w-80">
          <Search
            size={18}
            className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-400"
          />
          <input
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Search authorities..."
            className="h-10 w-full rounded-lg border border-slate-200 bg-white pl-10 pr-3 text-sm outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-100"
          />
        </label>
      </header>

      <section className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <p className="text-sm text-slate-500">
          Manage trusted attestation providers and monitor key availability.
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
          Add Authority
        </button>
      </section>

      <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          label="Total Authorities"
          value={authorities.length}
          icon={<ShieldCheck size={23} />}
          color="bg-blue-50 text-blue-700"
        />
        <StatCard
          label="Healthy"
          value={healthyCount}
          icon={<CheckCircle2 size={23} />}
          color="bg-emerald-50 text-emerald-700"
        />
        <StatCard
          label="RSA Available"
          value={rsaCount}
          icon={<KeyRound size={23} />}
          color="bg-sky-50 text-sky-700"
        />
        <StatCard
          label="ECDSA Available"
          value={ecdsaCount}
          icon={<KeyRound size={23} />}
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
        <div className="overflow-x-auto">
          <table className="w-full min-w-[940px] text-left text-sm">
            <thead className="bg-slate-50 text-xs text-slate-500">
              <tr>
                <th className="px-5 py-3 font-semibold">Authority</th>
                <th className="px-5 py-3 font-semibold">Type</th>
                <th className="px-5 py-3 font-semibold">Endpoint</th>
                <th className="px-5 py-3 text-center font-semibold">RSA</th>
                <th className="px-5 py-3 text-center font-semibold">ECDSA</th>
                <th className="px-5 py-3 font-semibold">Last Checked</th>
                <th className="px-5 py-3 font-semibold">Status</th>
                <th className="px-5 py-3 text-right font-semibold">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {filteredAuthorities.map((authority) => (
                <tr key={authority.id} className="hover:bg-slate-50/70">
                  <td className="px-5 py-3">
                    <div className="flex items-center gap-3">
                      <div
                        className={[
                          "flex h-9 w-9 shrink-0 items-center justify-center rounded-lg",
                          authority.isLocal
                            ? "bg-blue-50 text-blue-700"
                            : "bg-slate-100 text-slate-600",
                        ].join(" ")}
                      >
                        {authority.isLocal ? <ShieldCheck size={19} /> : <Globe2 size={19} />}
                      </div>
                      <div className="min-w-0">
                        <p className="font-medium text-slate-900">{authority.name}</p>
                        <p className="max-w-52 truncate text-xs text-slate-500">
                          {authority.baseUrl}
                        </p>
                      </div>
                    </div>
                  </td>
                  <td className="px-5 py-3">
                    <span
                      className={[
                        "rounded-md px-2 py-1 text-xs font-medium",
                        authority.isLocal
                          ? "bg-violet-50 text-violet-700"
                          : "bg-blue-50 text-blue-700",
                      ].join(" ")}
                    >
                      {authority.isLocal ? "Local" : "External"}
                    </span>
                  </td>
                  <td className="max-w-52 truncate px-5 py-3 text-xs text-slate-600">
                    {authority.baseUrl}
                  </td>
                  <td className="px-5 py-3">
                    <div className="flex justify-center">
                      <AvailabilityIcon available={Boolean(authority.keyAvailability?.rsa)} />
                    </div>
                  </td>
                  <td className="px-5 py-3">
                    <div className="flex justify-center">
                      <AvailabilityIcon available={Boolean(authority.keyAvailability?.ecdsa)} />
                    </div>
                  </td>
                  <td className="px-5 py-3 text-xs text-slate-500">
                    {authority.statusCachedAt
                      ? new Date(authority.statusCachedAt).toLocaleString()
                      : "Never"}
                  </td>
                  <td className="px-5 py-3">
                    <StatusBadge healthy={isHealthy(authority)} />
                  </td>
                  <td className="relative px-5 py-3 text-right">
                    <div className="inline-flex items-center gap-1">
                      <button
                        type="button"
                        onClick={() => refreshAuthority(authority)}
                        disabled={refreshingId === authority.id}
                        aria-label={`Refresh ${authority.name}`}
                        className="rounded-lg border border-slate-200 p-2 text-slate-600 hover:bg-slate-50 disabled:opacity-50"
                      >
                        <RefreshCw
                          size={17}
                          className={refreshingId === authority.id ? "animate-spin" : ""}
                        />
                      </button>
                      {!authority.isLocal && (
                        <button
                          type="button"
                          onClick={(event) => {
                            if (actionMenu === authority.id) {
                              setActionMenu(null);
                              return;
                            }
                            const rect = event.currentTarget.getBoundingClientRect();
                            const menuHeight = 48;
                            setActionMenuPosition({
                              top:
                                rect.bottom + menuHeight + 8 <= window.innerHeight
                                  ? rect.bottom + 6
                                  : rect.top - menuHeight - 6,
                              left: Math.max(12, rect.right - 160),
                            });
                            setActionMenu(authority.id);
                          }}
                          className="rounded-lg border border-slate-200 p-2 text-slate-600 hover:bg-slate-50"
                        >
                          <MoreVertical size={17} />
                        </button>
                      )}
                    </div>
                    {actionMenu === authority.id &&
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
                            className="fixed z-[9991] w-40 overflow-hidden rounded-lg border border-slate-200 bg-white py-1 text-left shadow-xl"
                            style={{
                              top: actionMenuPosition.top,
                              left: actionMenuPosition.left,
                            }}
                          >
                            <button
                              type="button"
                              onClick={() => deleteAuthority(authority)}
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
          {!loading && filteredAuthorities.length === 0 && (
            <div className="px-5 py-12 text-center text-sm text-slate-500">
              No authorities found.
            </div>
          )}
          {loading && (
            <div className="flex items-center justify-center gap-2 px-5 py-12 text-sm text-slate-500">
              <Loader2 size={18} className="animate-spin" />
              Loading authorities...
            </div>
          )}
        </div>
      </section>

      <section className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
        <header className="flex flex-col gap-3 border-b border-slate-200 p-4 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-full bg-slate-100 text-slate-600">
              <Clock3 size={18} />
            </div>
            <div>
              <h2 className="font-semibold text-[#071226]">Availability Monitoring</h2>
              <p className="text-xs text-slate-500">
                Authorities are checked when you request a refresh.
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={refreshAll}
            disabled={Boolean(refreshingId) || authorities.length === 0}
            className="flex h-9 items-center justify-center gap-2 rounded-lg border border-slate-200 px-3 text-sm text-slate-700 hover:bg-slate-50 disabled:opacity-50"
          >
            <RefreshCw size={16} className={refreshingId ? "animate-spin" : ""} />
            Refresh now
          </button>
        </header>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[680px] text-left text-sm">
            <thead className="bg-slate-50 text-xs text-slate-500">
              <tr>
                <th className="px-5 py-3 font-semibold">Authority</th>
                <th className="px-5 py-3 font-semibold">Status</th>
                <th className="px-5 py-3 font-semibold">Last Refresh</th>
                <th className="px-5 py-3 font-semibold">Keys</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {filteredAuthorities.map((authority) => (
                <tr key={authority.id}>
                  <td className="px-5 py-3">
                    <p className="font-medium text-slate-900">{authority.name}</p>
                    <p className="text-xs text-slate-500">{authority.baseUrl}</p>
                  </td>
                  <td className="px-5 py-3">
                    <StatusBadge healthy={isHealthy(authority)} />
                  </td>
                  <td className="px-5 py-3 text-xs text-slate-500">
                    {authority.statusCachedAt
                      ? new Date(authority.statusCachedAt).toLocaleString()
                      : "Never"}
                  </td>
                  <td className="px-5 py-3 text-xs text-slate-600">
                    RSA {authority.keyAvailability?.rsa ? "✓" : "✕"} · ECDSA{" "}
                    {authority.keyAvailability?.ecdsa ? "✓" : "✕"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="border-t border-slate-200 px-5 py-4 text-xs text-slate-500">
          Showing {filteredAuthorities.length} of {authorities.length} authorities
        </div>
      </section>

      <Footer />

      {drawerOpen &&
        typeof document !== "undefined" &&
        createPortal(
          <>
            <button
              type="button"
              aria-label="Close authority drawer"
              onClick={() => setDrawerOpen(false)}
              className="fixed left-0 top-0 z-[9998] h-[100dvh] w-screen bg-[#071226]/55 backdrop-blur-sm"
            />
            <aside className="fixed inset-y-0 right-0 z-[9999] flex w-full max-w-md flex-col bg-white shadow-2xl">
              <header className="flex items-center justify-between border-b border-slate-200 px-6 py-5">
                <h2 className="text-lg font-semibold text-[#071226]">Add Attestation Authority</h2>
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
                  <label className="text-sm font-medium text-slate-700">Authority Name</label>
                  <div className="relative mt-2">
                    <Building2
                      size={18}
                      className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400"
                    />
                    <input
                      value={newAuthority.name}
                      onChange={(event) =>
                        setNewAuthority((current) => ({ ...current, name: event.target.value }))
                      }
                      placeholder="e.g., Vendor Attestation Service"
                      className="h-11 w-full rounded-lg border border-slate-200 pl-10 pr-3 text-sm outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-100"
                    />
                  </div>
                </div>
                <div>
                  <label className="text-sm font-medium text-slate-700">Base URL</label>
                  <div className="relative mt-2">
                    <Globe2
                      size={18}
                      className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400"
                    />
                    <input
                      value={newAuthority.baseUrl}
                      onChange={(event) =>
                        setNewAuthority((current) => ({ ...current, baseUrl: event.target.value }))
                      }
                      placeholder="https://attestation.vendor.com"
                      className="h-11 w-full rounded-lg border border-slate-200 pl-10 pr-3 text-sm outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-100"
                    />
                  </div>
                  <p className="mt-2 text-xs leading-5 text-slate-500">
                    Enter the authority attestation information endpoint or its backend base URL.
                  </p>
                </div>

                <div className="rounded-xl border border-blue-200 bg-blue-50 p-4">
                  <div className="flex gap-3">
                    <ShieldCheck className="shrink-0 text-blue-700" size={22} />
                    <p className="text-xs leading-5 text-slate-600">
                      The backend will discover the supported roots, verify RSA and ECDSA
                      availability, and cache the authority status.
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
                  onClick={createAuthority}
                  disabled={submitting}
                  className="flex h-11 items-center justify-center gap-2 rounded-lg bg-[#071226] text-sm font-medium text-white hover:bg-[#101f36] disabled:opacity-60"
                >
                  {submitting && <Loader2 size={17} className="animate-spin" />}
                  Add Authority
                </button>
              </footer>
            </aside>
          </>,
          document.body,
        )}
    </div>
  );
}
