import { useCallback, useEffect, useMemo, useState } from "react";
import { createPortal } from "react-dom";
import {
  ArrowLeft,
  ArrowRight,
  Building2,
  Check,
  Copy,
  Cpu,
  Download,
  KeyRound,
  Loader2,
  MoreVertical,
  Plus,
  RefreshCw,
  Search,
  ShieldCheck,
  ShieldX,
  Trash2,
  X,
} from "lucide-react";
import Footer from "../../components/Footer";
import { backendUrl } from "../../lib/config";

type BackendRoot = {
  id: string;
  name?: string | null;
  rsaSerialHex: string;
  ecdsaSerialHex: string;
  rsaSubject: string;
  ecdsaSubject: string;
  createdAt: string;
  revokedAt?: string | null;
  linkedOemCount?: number;
};

const pageSize = 6;

function shortSerial(serial: string) {
  return serial.length <= 18 ? serial : `${serial.slice(0, 8)}••••${serial.slice(-6)}`;
}

function StatusBadge({ active }: { active: boolean }) {
  return (
    <span
      className={[
        "inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium",
        active ? "bg-emerald-50 text-emerald-700" : "bg-red-50 text-red-700",
      ].join(" ")}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${active ? "bg-emerald-600" : "bg-red-600"}`} />
      {active ? "Active" : "Revoked"}
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

function SerialRow({
  algorithm,
  serial,
  subject,
  color,
}: {
  algorithm: string;
  serial: string;
  subject: string;
  color: string;
}) {
  const [copied, setCopied] = useState(false);

  const copySerial = async () => {
    await navigator.clipboard.writeText(serial);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div className="flex flex-col gap-3 rounded-xl border border-slate-200 p-3 sm:flex-row sm:items-center">
      <span
        className={`flex h-12 w-16 shrink-0 items-center justify-center rounded-lg text-xs font-bold ${color}`}
      >
        {algorithm}
      </span>
      <div className="min-w-0 flex-1">
        <p className="text-xs text-slate-500">Serial (Fingerprint)</p>
        <p className="mt-1 font-mono text-sm font-medium text-slate-800">{shortSerial(serial)}</p>
        <p className="mt-1 truncate text-xs text-slate-500">{subject}</p>
      </div>
      <button
        type="button"
        onClick={copySerial}
        aria-label={`Copy ${algorithm} serial`}
        className="self-end rounded-lg p-2 text-slate-500 hover:bg-slate-100 sm:self-auto"
      >
        {copied ? <Check size={17} className="text-emerald-600" /> : <Copy size={17} />}
      </button>
    </div>
  );
}

export default function AdminRootAnchors() {
  const [roots, setRoots] = useState<BackendRoot[]>([]);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState<"all" | "active" | "revoked">("all");
  const [page, setPage] = useState(1);
  const [generateModalOpen, setGenerateModalOpen] = useState(false);
  const [actionMenu, setActionMenu] = useState<string | null>(null);
  const [actionMenuPosition, setActionMenuPosition] = useState({ top: 0, left: 0 });

  const getAccessToken = () => localStorage.getItem("ua_access");

  const loadRoots = useCallback(async () => {
    const accessToken = getAccessToken();
    if (!accessToken) {
      window.location.href = "/login";
      return;
    }
    setLoading(true);
    try {
      const response = await fetch(`${backendUrl}/api/v1/admin/backend-roots`, {
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      if (response.status === 401) {
        localStorage.removeItem("ua_access");
        localStorage.removeItem("ua_refresh");
        window.location.href = "/login";
        return;
      }
      if (!response.ok) throw new Error("Unable to load root anchors.");
      setRoots(await response.json());
      setError(null);
    } catch (requestError) {
      setError(
        requestError instanceof Error ? requestError.message : "Unable to load root anchors.",
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadRoots();
  }, [loadRoots]);

  const activeRoots = roots.filter((root) => !root.revokedAt);
  const revokedRoots = roots.filter((root) => Boolean(root.revokedAt));
  const activeRoot = activeRoots[0] || null;
  const linkedOems = roots.reduce((total, root) => total + (root.linkedOemCount || 0), 0);

  const filteredRoots = useMemo(() => {
    const query = search.trim().toLowerCase();
    return roots.filter((root) => {
      const matchesSearch =
        !query ||
        root.name?.toLowerCase().includes(query) ||
        root.rsaSerialHex.toLowerCase().includes(query) ||
        root.ecdsaSerialHex.toLowerCase().includes(query) ||
        root.rsaSubject.toLowerCase().includes(query) ||
        root.ecdsaSubject.toLowerCase().includes(query);
      const matchesStatus =
        statusFilter === "all" ||
        (statusFilter === "active" && !root.revokedAt) ||
        (statusFilter === "revoked" && Boolean(root.revokedAt));
      return matchesSearch && matchesStatus;
    });
  }, [roots, search, statusFilter]);

  const totalPages = Math.max(1, Math.ceil(filteredRoots.length / pageSize));
  const visibleRoots = filteredRoots.slice((page - 1) * pageSize, page * pageSize);

  useEffect(() => setPage(1), [search, statusFilter]);
  useEffect(() => {
    if (page > totalPages) setPage(totalPages);
  }, [page, totalPages]);

  const generateRoot = async () => {
    const accessToken = getAccessToken();
    if (!accessToken || activeRoot) return;
    setGenerating(true);
    setError(null);
    try {
      const response = await fetch(`${backendUrl}/api/v1/admin/backend-roots/generate`, {
        method: "POST",
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      if (!response.ok) {
        const message = await response.text();
        throw new Error(message || "Unable to generate root anchor.");
      }
      const xml = await response.text();
      const blobUrl = URL.createObjectURL(new Blob([xml], { type: "application/xml" }));
      const link = document.createElement("a");
      link.href = blobUrl;
      link.download = "backend_root_anchor.xml";
      link.click();
      URL.revokeObjectURL(blobUrl);

      setGenerateModalOpen(false);
      setNotice("Root anchor generated and downloaded successfully.");
      await loadRoots();
    } catch (requestError) {
      setError(
        requestError instanceof Error ? requestError.message : "Unable to generate root anchor.",
      );
    } finally {
      setGenerating(false);
    }
  };

  const revokeRoot = async (root: BackendRoot) => {
    if (!window.confirm(`Revoke ${root.name || "this root anchor"}?`)) return;
    const accessToken = getAccessToken();
    if (!accessToken) return;
    setActionMenu(null);
    try {
      const response = await fetch(`${backendUrl}/api/v1/admin/backend-roots/${root.id}/revoke`, {
        method: "POST",
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      if (!response.ok) throw new Error("Unable to revoke root anchor.");
      setNotice("Root anchor revoked successfully.");
      await loadRoots();
    } catch (requestError) {
      setError(
        requestError instanceof Error ? requestError.message : "Unable to revoke root anchor.",
      );
    }
  };

  const deleteRoot = async (root: BackendRoot) => {
    if (!window.confirm(`Delete ${root.name || "this root anchor"}?`)) return;
    const accessToken = getAccessToken();
    if (!accessToken) return;
    setActionMenu(null);
    try {
      const response = await fetch(`${backendUrl}/api/v1/admin/backend-roots/${root.id}`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      if (!response.ok) {
        const message = await response.text();
        throw new Error(message || "Unable to delete root anchor.");
      }
      setNotice("Root anchor deleted successfully.");
      await loadRoots();
    } catch (requestError) {
      setError(
        requestError instanceof Error ? requestError.message : "Unable to delete root anchor.",
      );
    }
  };

  return (
    <div className="flex min-h-[calc(100vh-3rem)] flex-col gap-5">
      <header className="flex flex-col gap-4 border-b border-slate-200 pb-4 sm:flex-row sm:items-center sm:justify-between">
        <h1 className="text-2xl font-bold tracking-tight text-[#071226]">Root Anchors</h1>
        <label className="relative w-full sm:w-80">
          <Search
            size={18}
            className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-400"
          />
          <input
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Search root anchors..."
            className="h-10 w-full rounded-lg border border-slate-200 bg-white pl-10 pr-3 text-sm outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-100"
          />
        </label>
      </header>

      <section className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <h2 className="text-xl font-semibold text-[#071226]">Backend Root Anchors</h2>
          <p className="mt-1 text-sm text-slate-500">
            Manage RSA and ECDSA roots that establish trust for OEM and device anchors.
          </p>
        </div>
        <button
          type="button"
          onClick={() => {
            setError(null);
            setGenerateModalOpen(true);
          }}
          className="flex h-10 items-center justify-center gap-2 rounded-lg bg-[#071226] px-4 text-sm font-medium text-white hover:bg-[#101f36]"
        >
          <Plus size={18} />
          Generate Root Anchor
        </button>
      </section>
      <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          label="Active Roots"
          value={activeRoots.length}
          icon={<ShieldCheck size={23} />}
          color="bg-blue-50 text-blue-700"
        />
        <StatCard
          label="Algorithms"
          value={roots.length > 0 ? 2 : 0}
          icon={<KeyRound size={23} />}
          color="bg-sky-50 text-sky-700"
        />
        <StatCard
          label="Linked OEMs"
          value={linkedOems}
          icon={<Building2 size={23} />}
          color="bg-emerald-50 text-emerald-700"
        />
        <StatCard
          label="Revoked"
          value={revokedRoots.length}
          icon={<ShieldX size={23} />}
          color="bg-violet-50 text-violet-700"
        />
      </section>

      {error && !generateModalOpen && (
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
      <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
        {activeRoot ? (
          <>
            <header className="flex flex-wrap items-start justify-between gap-3 border-b border-slate-200 pb-4">
              <div>
                <div className="flex flex-wrap items-center gap-3">
                  <h2 className="text-lg font-semibold text-[#071226]">
                    {activeRoot.name || "UA Backend Root"}
                  </h2>
                  <StatusBadge active />
                </div>
                <p className="mt-1 text-xs text-slate-500">
                  Created {new Date(activeRoot.createdAt).toLocaleString()}
                </p>
              </div>
            </header>

            <div className="mt-5 grid gap-6 xl:grid-cols-[1.1fr_0.9fr]">
              <div>
                <h3 className="mb-3 text-sm font-semibold text-slate-700">Algorithms</h3>
                <div className="space-y-3">
                  <SerialRow
                    algorithm="RSA"
                    serial={activeRoot.rsaSerialHex}
                    subject={activeRoot.rsaSubject}
                    color="bg-blue-50 text-blue-700"
                  />
                  <SerialRow
                    algorithm="ECDSA"
                    serial={activeRoot.ecdsaSerialHex}
                    subject={activeRoot.ecdsaSubject}
                    color="bg-sky-50 text-sky-700"
                  />
                </div>
              </div>

              <div>
                <h3 className="mb-3 text-sm font-semibold text-slate-700">Certificate Chain</h3>
                <div className="flex flex-col items-stretch gap-2 sm:flex-row sm:items-center">
                  {[
                    {
                      title: "Backend Root",
                      caption: "This Root",
                      icon: <ShieldCheck size={23} />,
                      active: true,
                    },
                    {
                      title: "OEM Intermediate",
                      caption: "Issued by Root",
                      icon: <Building2 size={23} />,
                    },
                    {
                      title: "Device Anchor",
                      caption: "Issued by OEM",
                      icon: <Cpu size={23} />,
                    },
                  ].map((item, index) => (
                    <div key={item.title} className="contents">
                      {index > 0 && (
                        <ArrowRight className="hidden shrink-0 text-slate-400 sm:block" size={18} />
                      )}
                      <div
                        className={[
                          "flex flex-1 flex-col items-center rounded-xl border p-4 text-center",
                          item.active
                            ? "border-blue-200 bg-blue-50/50 text-blue-700"
                            : "border-slate-200 text-slate-600",
                        ].join(" ")}
                      >
                        {item.icon}
                        <p className="mt-2 text-xs font-semibold text-slate-800">{item.title}</p>
                        <p className="mt-1 text-[11px] text-slate-500">{item.caption}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </>
        ) : (
          <div className="flex flex-col items-center py-10 text-center">
            <div className="flex h-14 w-14 items-center justify-center rounded-full bg-slate-100 text-slate-500">
              <ShieldX size={26} />
            </div>
            <h2 className="mt-4 font-semibold text-[#071226]">No active root anchor</h2>
            <p className="mt-1 text-sm text-slate-500">
              Generate a root anchor to establish the trust chain.
            </p>
          </div>
        )}
      </section>

      {/* تاریخچه Root Anchorها */}
      <section className="overflow-visible rounded-xl border border-slate-200 bg-white shadow-sm">
        <header className="flex flex-col gap-3 border-b border-slate-200 p-4 sm:flex-row sm:items-center sm:justify-between">
          <h2 className="font-semibold text-[#071226]">Root Anchor History</h2>
          <div className="flex gap-2">
            <select
              value={statusFilter}
              onChange={(event) =>
                setStatusFilter(event.target.value as "all" | "active" | "revoked")
              }
              className="h-9 rounded-lg border border-slate-200 bg-white px-3 text-sm outline-none"
            >
              <option value="all">All Statuses</option>
              <option value="active">Active</option>
              <option value="revoked">Revoked</option>
            </select>
            <button
              type="button"
              onClick={loadRoots}
              className="flex h-9 w-9 items-center justify-center rounded-lg border border-slate-200 text-slate-600 hover:bg-slate-50"
            >
              <RefreshCw size={16} className={loading ? "animate-spin" : ""} />
            </button>
          </div>
        </header>

        <div className="overflow-x-auto">
          <table className="w-full min-w-[760px] text-left text-sm">
            <thead className="bg-slate-50 text-xs text-slate-500">
              <tr>
                <th className="px-5 py-3 font-semibold">Name</th>
                <th className="px-5 py-3 font-semibold">Algorithms</th>
                <th className="px-5 py-3 font-semibold">Created</th>
                <th className="px-5 py-3 font-semibold">Status</th>
                <th className="px-5 py-3 text-right font-semibold">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {visibleRoots.map((root) => (
                <tr key={root.id} className="hover:bg-slate-50/70">
                  <td className="px-5 py-3 font-medium text-slate-900">
                    {root.name || "UA Backend Root"}
                  </td>
                  <td className="px-5 py-3 text-slate-600">RSA, ECDSA</td>
                  <td className="px-5 py-3 text-slate-500">
                    {new Date(root.createdAt).toLocaleString()}
                  </td>
                  <td className="px-5 py-3">
                    <StatusBadge active={!root.revokedAt} />
                  </td>
                  <td className="relative px-5 py-3 text-right">
                    <button
                      type="button"
                      onClick={(event) => {
                        if (actionMenu === root.id) {
                          setActionMenu(null);
                          return;
                        }
                        const rect = event.currentTarget.getBoundingClientRect();
                        const menuHeight = root.revokedAt ? 48 : 88;
                        setActionMenuPosition({
                          top:
                            rect.bottom + menuHeight + 8 <= window.innerHeight
                              ? rect.bottom + 6
                              : rect.top - menuHeight - 6,
                          left: Math.max(12, rect.right - 160),
                        });
                        setActionMenu(root.id);
                      }}
                      className="rounded-lg p-2 text-slate-500 hover:bg-slate-100"
                    >
                      <MoreVertical size={18} />
                    </button>
                    {actionMenu === root.id &&
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
                            {!root.revokedAt && (
                              <button
                                type="button"
                                onClick={() => revokeRoot(root)}
                                className="flex w-full items-center gap-2 px-3 py-2 text-sm text-amber-700 hover:bg-amber-50"
                              >
                                <ShieldX size={16} /> Revoke
                              </button>
                            )}
                            <button
                              type="button"
                              onClick={() => deleteRoot(root)}
                              className="flex w-full items-center gap-2 px-3 py-2 text-sm text-red-600 hover:bg-red-50"
                            >
                              <Trash2 size={16} /> Delete
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
          {!loading && visibleRoots.length === 0 && (
            <div className="px-5 py-10 text-center text-sm text-slate-500">
              No root anchors found.
            </div>
          )}
          {loading && (
            <div className="flex items-center justify-center gap-2 px-5 py-10 text-sm text-slate-500">
              <Loader2 size={18} className="animate-spin" /> Loading root anchors...
            </div>
          )}
        </div>

        <footer className="flex flex-col gap-3 border-t border-slate-200 px-5 py-4 text-xs text-slate-500 sm:flex-row sm:items-center sm:justify-between">
          <span>
            Showing {filteredRoots.length === 0 ? 0 : (page - 1) * pageSize + 1} to{" "}
            {Math.min(page * pageSize, filteredRoots.length)} of {filteredRoots.length} root anchors
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
            <span className="flex h-8 min-w-8 items-center justify-center rounded-lg border border-slate-300 px-2 font-medium text-slate-700">
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
      <Footer />

      {generateModalOpen &&
        typeof document !== "undefined" &&
        createPortal(
          <>
            <button
              type="button"
              aria-label="Close generate dialog"
              onClick={() => setGenerateModalOpen(false)}
              className="fixed left-0 top-0 z-[9998] h-[100dvh] w-screen bg-[#071226]/60 backdrop-blur-sm"
            />
            <div
              role="dialog"
              aria-modal="true"
              className="fixed left-1/2 top-1/2 z-[9999] w-[calc(100%-2rem)] max-w-lg -translate-x-1/2 -translate-y-1/2 rounded-2xl bg-white p-6 shadow-2xl sm:p-8"
            >
              <button
                type="button"
                onClick={() => setGenerateModalOpen(false)}
                className="absolute right-4 top-4 rounded-lg p-2 text-slate-500 hover:bg-slate-100"
              >
                <X size={20} />
              </button>
              <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-full bg-blue-50 text-blue-700">
                <ShieldCheck size={30} />
              </div>
              <h2 className="mt-5 text-center text-xl font-semibold text-[#071226]">
                Generate new root anchor?
              </h2>
              <p className="mx-auto mt-3 max-w-sm text-center text-sm leading-6 text-slate-500">
                A new RSA + ECDSA root pair will be generated and downloaded as{" "}
                <code className="rounded bg-blue-50 px-1 text-blue-700">
                  backend_root_anchor.xml
                </code>
                .
              </p>
              <div
                className={[
                  "mt-5 rounded-xl border p-4 text-sm",
                  activeRoot
                    ? "border-amber-200 bg-amber-50 text-amber-800"
                    : "border-blue-200 bg-blue-50 text-blue-800",
                ].join(" ")}
              >
                {activeRoot
                  ? "Revoke the current active root before generating a replacement."
                  : "Store this file securely. It contains the private keys required for the trust chain."}
              </div>
              {error && (
                <div className="mt-4 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
                  {error}
                </div>
              )}
              <div className="mt-6 grid gap-3 sm:grid-cols-2">
                <button
                  type="button"
                  onClick={() => setGenerateModalOpen(false)}
                  className="h-11 rounded-lg border border-slate-200 text-sm font-medium text-slate-700 hover:bg-slate-50"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={generateRoot}
                  disabled={generating || Boolean(activeRoot)}
                  className="flex h-11 items-center justify-center gap-2 rounded-lg bg-[#071226] text-sm font-medium text-white hover:bg-[#101f36] disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {generating ? (
                    <Loader2 size={17} className="animate-spin" />
                  ) : (
                    <Download size={17} />
                  )}
                  Generate & Download
                </button>
              </div>
            </div>
          </>,
          document.body,
        )}
    </div>
  );
}
