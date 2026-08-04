import { useCallback, useEffect, useMemo, useState } from "react";
import { createPortal } from "react-dom";
import {
  ArrowLeft,
  ArrowRight,
  Building2,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Copy,
  Download,
  Info,
  KeyRound,
  Loader2,
  MoreVertical,
  RefreshCw,
  Search,
  ShieldCheck,
  ShieldX,
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
};

type Authority = {
  id: string;
  name: string;
  baseUrl: string;
  keyAvailability?: { rsa: boolean; ecdsa: boolean };
};

type TrustAnchor = {
  id: string;
  deviceFamilyId: string;
  deviceCodename?: string | null;
  authorityId: string;
  authorityName: string;
  rsaSerialHex: string;
  rsaIntermediateSerialHex?: string | null;
  ecdsaSerialHex: string;
  ecdsaIntermediateSerialHex?: string | null;
  revokedAt?: string | null;
  createdAt: string;
};

type Profile = {
  oemTrustAnchorReady?: boolean;
  oemTrustAnchor?: {
    rsa?: { subject: string; serialHex: string };
    ecdsa?: { subject: string; serialHex: string };
  } | null;
};

type AnchorForm = {
  deviceFamilyId: string;
  authorityId: string;
  rsaSerialHex: string;
  rsaIntermediateSerialHex: string;
  ecdsaSerialHex: string;
  ecdsaIntermediateSerialHex: string;
};

const emptyForm: AnchorForm = {
  deviceFamilyId: "",
  authorityId: "",
  rsaSerialHex: "",
  rsaIntermediateSerialHex: "",
  ecdsaSerialHex: "",
  ecdsaIntermediateSerialHex: "",
};

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

function masked(value?: string | null) {
  if (!value) return "—";
  if (value.length < 12) return value;
  return `${value.slice(0, 4)}••••••${value.slice(-4)}`;
}

export default function OemTrustAnchors({
  onOrganizationLoaded,
}: {
  onOrganizationLoaded?: (name: string) => void;
}) {
  const [families, setFamilies] = useState<DeviceFamily[]>([]);
  const [authorities, setAuthorities] = useState<Authority[]>([]);
  const [anchors, setAnchors] = useState<TrustAnchor[]>([]);
  const [profile, setProfile] = useState<Profile>({});
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [familyFilter, setFamilyFilter] = useState("all");
  const [authorityFilter, setAuthorityFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  const [page, setPage] = useState(1);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [form, setForm] = useState<AnchorForm>(emptyForm);
  const [expandedAnchor, setExpandedAnchor] = useState<string | null>(null);
  const [actionMenu, setActionMenu] = useState<string | null>(null);
  const [actionPosition, setActionPosition] = useState({ top: 0, left: 0 });
  const [revokeTarget, setRevokeTarget] = useState<TrustAnchor | null>(null);
  const [copied, setCopied] = useState<string | null>(null);
  const pageSize = 10;

  const loadData = useCallback(async () => {
    const token = localStorage.getItem("ua_access");
    if (!token) {
      window.location.href = "/login";
      return;
    }
    setLoading(true);
    try {
      const headers = { Authorization: `Bearer ${token}` };
      const [familiesResponse, authoritiesResponse, anchorsResponse, profileResponse, orgResponse] =
        await Promise.all([
          fetch(`${backendUrl}/api/v1/oem/device-families`, { headers }),
          fetch(`${backendUrl}/api/v1/oem/attestation-servers`, { headers }),
          fetch(`${backendUrl}/api/v1/oem/anchors`, { headers }),
          fetch(`${backendUrl}/api/v1/profile`, { headers }),
          fetch(`${backendUrl}/api/v1/oem/profile`, { headers }),
        ]);
      if (anchorsResponse.status === 401) {
        localStorage.removeItem("ua_access");
        localStorage.removeItem("ua_refresh");
        window.location.href = "/login";
        return;
      }
      if (!familiesResponse.ok || !anchorsResponse.ok) {
        throw new Error("Unable to load trust anchors.");
      }
      setFamilies(await familiesResponse.json());
      setAnchors(await anchorsResponse.json());
      setAuthorities(authoritiesResponse.ok ? await authoritiesResponse.json() : []);
      setProfile(profileResponse.ok ? await profileResponse.json() : {});
      if (orgResponse.ok) {
        const org = await orgResponse.json();
        onOrganizationLoaded?.(org.name || "OEM Portal");
      }
      setError(null);
    } catch (requestError) {
      setError(
        requestError instanceof Error ? requestError.message : "Unable to load trust anchors.",
      );
    } finally {
      setLoading(false);
    }
  }, [onOrganizationLoaded]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  useEffect(() => {
    setPage(1);
  }, [search, familyFilter, authorityFilter, statusFilter]);

  const openDrawer = () => {
    setForm({
      ...emptyForm,
      deviceFamilyId: families[0]?.id || "",
      authorityId: authorities[0]?.id || "",
    });
    setError(null);
    setDrawerOpen(true);
  };

  const registerAnchor = async () => {
    const token = localStorage.getItem("ua_access");
    if (!token) return;
    if (Object.values(form).some((value) => !value.trim())) {
      setError("All certificate serial fields are required.");
      return;
    }
    setSubmitting(true);
    setError(null);
    try {
      const response = await fetch(`${backendUrl}/api/v1/oem/anchors`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(form),
      });
      if (!response.ok) throw new Error((await response.text()) || "Unable to register anchor.");
      setDrawerOpen(false);
      setNotice("Trust anchor registered successfully.");
      setForm(emptyForm);
      await loadData();
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Unable to register anchor.");
    } finally {
      setSubmitting(false);
    }
  };

  const generateKeybox = async (familyId?: string) => {
    const selectedFamily = familyId || form.deviceFamilyId || families[0]?.id;
    const token = localStorage.getItem("ua_access");
    if (!token || !selectedFamily) {
      setError("Select a device family before generating keys.");
      return;
    }
    setSubmitting(true);
    setError(null);
    try {
      const response = await fetch(`${backendUrl}/api/v1/oem/anchors/generate-keybox`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ deviceFamilyId: selectedFamily }),
      });
      if (!response.ok) throw new Error((await response.text()) || "Unable to generate keys.");
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = "device_keybox.xml";
      link.click();
      window.URL.revokeObjectURL(url);
      setDrawerOpen(false);
      setNotice("Device keybox generated and downloaded.");
      await loadData();
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Unable to generate keys.");
    } finally {
      setSubmitting(false);
    }
  };

  const generateOemAnchor = async () => {
    const token = localStorage.getItem("ua_access");
    if (!token) return;
    setSubmitting(true);
    setError(null);
    try {
      const response = await fetch(`${backendUrl}/api/v1/oem/profile/generate-trust-anchor`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!response.ok)
        throw new Error((await response.text()) || "Unable to generate OEM anchor.");
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = "oem_trust_anchor.xml";
      link.click();
      window.URL.revokeObjectURL(url);
      setNotice("OEM trust anchor generated and downloaded.");
      await loadData();
    } catch (requestError) {
      setError(
        requestError instanceof Error ? requestError.message : "Unable to generate OEM anchor.",
      );
    } finally {
      setSubmitting(false);
    }
  };

  const revokeAnchor = async () => {
    if (!revokeTarget) return;
    const token = localStorage.getItem("ua_access");
    if (!token) return;
    setSubmitting(true);
    try {
      const response = await fetch(`${backendUrl}/api/v1/oem/anchors/${revokeTarget.id}/revoke`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!response.ok) throw new Error((await response.text()) || "Unable to revoke anchor.");
      setRevokeTarget(null);
      setNotice("Trust anchor revoked.");
      await loadData();
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Unable to revoke anchor.");
    } finally {
      setSubmitting(false);
    }
  };

  const removeAnchor = async (anchor: TrustAnchor) => {
    if (!window.confirm("Permanently remove this trust anchor?")) return;
    const token = localStorage.getItem("ua_access");
    if (!token) return;
    setActionMenu(null);
    try {
      const response = await fetch(`${backendUrl}/api/v1/oem/anchors/${anchor.id}`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!response.ok) throw new Error((await response.text()) || "Unable to remove anchor.");
      setNotice("Trust anchor removed.");
      await loadData();
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Unable to remove anchor.");
    }
  };

  const copyValue = async (id: string, value: string) => {
    await navigator.clipboard.writeText(value);
    setCopied(id);
    window.setTimeout(() => setCopied(null), 1400);
  };

  const filteredAnchors = useMemo(() => {
    const query = search.trim().toLowerCase();
    return anchors.filter((anchor) => {
      const family = families.find((item) => item.id === anchor.deviceFamilyId);
      const matchesSearch =
        !query ||
        anchor.deviceCodename?.toLowerCase().includes(query) ||
        family?.model?.toLowerCase().includes(query) ||
        anchor.authorityName.toLowerCase().includes(query) ||
        anchor.rsaSerialHex.toLowerCase().includes(query) ||
        anchor.ecdsaSerialHex.toLowerCase().includes(query);
      const matchesFamily = familyFilter === "all" || anchor.deviceFamilyId === familyFilter;
      const matchesAuthority = authorityFilter === "all" || anchor.authorityId === authorityFilter;
      const matchesStatus =
        statusFilter === "all" ||
        (statusFilter === "active" && !anchor.revokedAt) ||
        (statusFilter === "revoked" && Boolean(anchor.revokedAt));
      return matchesSearch && matchesFamily && matchesAuthority && matchesStatus;
    });
  }, [anchors, families, search, familyFilter, authorityFilter, statusFilter]);

  const totalPages = Math.max(1, Math.ceil(filteredAnchors.length / pageSize));
  const visibleAnchors = filteredAnchors.slice((page - 1) * pageSize, page * pageSize);
  const activeAnchors = anchors.filter((anchor) => !anchor.revokedAt).length;
  const revokedAnchors = anchors.length - activeAnchors;

  return (
    <div className="flex min-h-[calc(100vh-3rem)] flex-col gap-5">
      <header className="flex flex-col gap-4 border-b border-slate-200 pb-4 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-[#071226]">Trust Anchors</h1>
          <p className="mt-1 text-sm text-slate-500">
            Manage OEM and device certificate anchors used to establish attestation trust.
          </p>
        </div>
        <div className="flex flex-col gap-2 sm:flex-row">
          <button
            type="button"
            onClick={openDrawer}
            className="h-10 rounded-lg bg-[#071226] px-4 text-sm font-medium text-white hover:bg-[#101f36]"
          >
            Register Trust Anchor
          </button>
          <button
            type="button"
            onClick={() => generateKeybox()}
            disabled={submitting || families.length === 0}
            className="flex h-10 items-center justify-center gap-2 rounded-lg border border-slate-300 bg-white px-4 text-sm font-medium text-slate-700 hover:bg-slate-50 disabled:opacity-50"
          >
            <Download size={17} /> Generate Keys
          </button>
        </div>
      </header>

      <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          label="Total Anchors"
          value={anchors.length}
          icon={<KeyRound size={23} />}
          color="bg-blue-50 text-blue-700"
        />
        <StatCard
          label="Active Anchors"
          value={activeAnchors}
          icon={<ShieldCheck size={23} />}
          color="bg-emerald-50 text-emerald-700"
        />
        <StatCard
          label="Device Families"
          value={new Set(anchors.map((anchor) => anchor.deviceFamilyId)).size}
          icon={<Smartphone size={23} />}
          color="bg-indigo-50 text-indigo-700"
        />
        <StatCard
          label="Revoked"
          value={revokedAnchors}
          icon={<ShieldX size={23} />}
          color="bg-red-50 text-red-600"
        />
      </section>

      {error && !drawerOpen && !revokeTarget && (
        <div className="rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
          {error}
        </div>
      )}
      {notice && (
        <div className="flex items-center gap-2 rounded-xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-700">
          <Check size={17} /> {notice}
        </div>
      )}

      <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
        <h2 className="text-lg font-semibold text-[#071226]">OEM Trust Chain</h2>
        <div className="mt-5 grid items-center gap-5 lg:grid-cols-[1fr_auto]">
          <div className="grid items-center gap-3 sm:grid-cols-[1fr_auto_1fr_auto_1fr]">
            <ChainNode
              icon={<ShieldCheck size={21} />}
              title="Backend Root"
              ready
              subtitle="Verified"
            />
            <div className="hidden h-px w-10 bg-slate-300 sm:block" />
            <ChainNode
              icon={<Building2 size={21} />}
              title="OEM Intermediate"
              ready={Boolean(profile.oemTrustAnchorReady)}
              subtitle={profile.oemTrustAnchorReady ? "Generated" : "Missing"}
            />
            <div className="hidden h-px w-10 bg-slate-300 sm:block" />
            <ChainNode
              icon={<Smartphone size={21} />}
              title="Device Anchor"
              ready={activeAnchors > 0}
              subtitle={activeAnchors > 0 ? "Issued per device" : "Not issued"}
            />
          </div>
          <button
            type="button"
            onClick={generateOemAnchor}
            disabled={submitting}
            className="h-10 rounded-lg border border-blue-600 px-4 text-sm font-medium text-blue-700 hover:bg-blue-50 disabled:opacity-50"
          >
            Generate OEM Trust Anchor
          </button>
        </div>
      </section>

      <section className="overflow-visible rounded-xl border border-slate-200 bg-white shadow-sm">
        <header className="grid gap-3 border-b border-slate-200 p-4 md:grid-cols-2 xl:grid-cols-[1.4fr_1fr_1fr_1fr_auto]">
          <label className="relative">
            <Search
              size={18}
              className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-400"
            />
            <input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Search anchors..."
              className="h-10 w-full rounded-lg border border-slate-200 pl-10 pr-3 text-sm outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-100"
            />
          </label>
          <select
            value={familyFilter}
            onChange={(event) => setFamilyFilter(event.target.value)}
            className="h-10 rounded-lg border border-slate-200 bg-white px-3 text-sm outline-none"
          >
            <option value="all">All Device Families</option>
            {families.map((family) => (
              <option key={family.id} value={family.id}>
                {family.codename || family.name}
              </option>
            ))}
          </select>
          <select
            value={authorityFilter}
            onChange={(event) => setAuthorityFilter(event.target.value)}
            className="h-10 rounded-lg border border-slate-200 bg-white px-3 text-sm outline-none"
          >
            <option value="all">All Authorities</option>
            {authorities.map((authority) => (
              <option key={authority.id} value={authority.id}>
                {authority.name}
              </option>
            ))}
          </select>
          <select
            value={statusFilter}
            onChange={(event) => setStatusFilter(event.target.value)}
            className="h-10 rounded-lg border border-slate-200 bg-white px-3 text-sm outline-none"
          >
            <option value="all">All Statuses</option>
            <option value="active">Active</option>
            <option value="revoked">Revoked</option>
          </select>
          <button
            type="button"
            onClick={loadData}
            className="flex h-10 items-center justify-center gap-2 rounded-lg border border-slate-200 px-3 text-sm text-slate-700 hover:bg-slate-50"
          >
            <RefreshCw size={16} className={loading ? "animate-spin" : ""} /> Refresh
          </button>
        </header>

        <div className="overflow-x-auto">
          <table className="w-full min-w-[1150px] text-left text-sm">
            <thead className="bg-slate-50 text-xs text-slate-500">
              <tr>
                <th className="w-10 px-3 py-3" />
                <th className="px-3 py-3 font-semibold">Device Family</th>
                <th className="px-3 py-3 font-semibold">Model</th>
                <th className="px-3 py-3 font-semibold">Authority</th>
                <th className="px-3 py-3 font-semibold">RSA</th>
                <th className="px-3 py-3 font-semibold">RSA Intermediate</th>
                <th className="px-3 py-3 font-semibold">ECDSA</th>
                <th className="px-3 py-3 font-semibold">ECDSA Intermediate</th>
                <th className="px-3 py-3 font-semibold">Status</th>
                <th className="px-3 py-3 font-semibold">Created</th>
                <th className="px-3 py-3 text-right font-semibold">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {visibleAnchors.map((anchor) => {
                const family = families.find((item) => item.id === anchor.deviceFamilyId);
                return (
                  <AnchorRows
                    key={anchor.id}
                    anchor={anchor}
                    family={family}
                    expanded={expandedAnchor === anchor.id}
                    onExpand={() =>
                      setExpandedAnchor((current) => (current === anchor.id ? null : anchor.id))
                    }
                    onRevoke={() => {
                      setActionMenu(null);
                      setRevokeTarget(anchor);
                    }}
                    onRemove={() => removeAnchor(anchor)}
                    onCopy={copyValue}
                    copied={copied}
                    actionMenu={actionMenu}
                    actionPosition={actionPosition}
                    setActionMenu={setActionMenu}
                    setActionPosition={setActionPosition}
                  />
                );
              })}
            </tbody>
          </table>
          {loading && (
            <div className="flex items-center justify-center gap-2 px-5 py-14 text-sm text-slate-500">
              <Loader2 size={18} className="animate-spin" /> Loading trust anchors...
            </div>
          )}
          {!loading && visibleAnchors.length === 0 && (
            <div className="px-5 py-14 text-center text-sm text-slate-500">
              No trust anchors found.
            </div>
          )}
        </div>

        <footer className="flex items-center justify-between border-t border-slate-200 px-5 py-4 text-xs text-slate-500">
          <span>
            Showing {filteredAnchors.length ? (page - 1) * pageSize + 1 : 0} to{" "}
            {Math.min(page * pageSize, filteredAnchors.length)} of {filteredAnchors.length} anchors
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
                <h2 className="text-lg font-semibold text-[#071226]">Register Trust Anchor</h2>
                <button
                  type="button"
                  onClick={() => setDrawerOpen(false)}
                  className="rounded-lg p-2 text-slate-500 hover:bg-slate-100"
                >
                  <X size={20} />
                </button>
              </header>
              <div className="flex-1 space-y-5 overflow-y-auto p-6">
                <SelectField
                  label="Device Family"
                  value={form.deviceFamilyId}
                  onChange={(value) =>
                    setForm((current) => ({ ...current, deviceFamilyId: value }))
                  }
                  options={families.map((family) => ({
                    value: family.id,
                    label: `${family.codename || family.name} — ${family.model || "No model"}`,
                  }))}
                />
                <SelectField
                  label="Attestation Authority"
                  value={form.authorityId}
                  onChange={(value) => setForm((current) => ({ ...current, authorityId: value }))}
                  options={authorities.map((authority) => ({
                    value: authority.id,
                    label: authority.name,
                  }))}
                />
                <SerialField
                  label="RSA Leaf Serial Hex"
                  value={form.rsaSerialHex}
                  onChange={(value) => setForm((current) => ({ ...current, rsaSerialHex: value }))}
                />
                <SerialField
                  label="RSA Intermediate Serial Hex"
                  value={form.rsaIntermediateSerialHex}
                  onChange={(value) =>
                    setForm((current) => ({ ...current, rsaIntermediateSerialHex: value }))
                  }
                />
                <SerialField
                  label="ECDSA Leaf Serial Hex"
                  value={form.ecdsaSerialHex}
                  onChange={(value) =>
                    setForm((current) => ({ ...current, ecdsaSerialHex: value }))
                  }
                />
                <SerialField
                  label="ECDSA Intermediate Serial Hex"
                  value={form.ecdsaIntermediateSerialHex}
                  onChange={(value) =>
                    setForm((current) => ({ ...current, ecdsaIntermediateSerialHex: value }))
                  }
                />
                <div className="rounded-xl border border-blue-200 bg-blue-50 p-4">
                  <div className="flex gap-3">
                    <Info size={20} className="shrink-0 text-blue-700" />
                    <p className="text-xs leading-5 text-slate-600">
                      Serials must exactly match the issued certificate chain for successful
                      attestation.
                    </p>
                  </div>
                </div>
                {error && (
                  <div className="rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
                    {error}
                  </div>
                )}
              </div>
              <footer className="grid grid-cols-3 gap-3 border-t border-slate-200 p-6">
                <button
                  type="button"
                  onClick={() => generateKeybox(form.deviceFamilyId)}
                  disabled={submitting || !form.deviceFamilyId}
                  className="h-11 rounded-lg border border-slate-300 text-sm font-medium text-slate-700 disabled:opacity-50"
                >
                  Generate Keys
                </button>
                <button
                  type="button"
                  onClick={() => setDrawerOpen(false)}
                  className="h-11 rounded-lg border border-slate-200 text-sm font-medium text-slate-700"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={registerAnchor}
                  disabled={submitting}
                  className="flex h-11 items-center justify-center gap-2 rounded-lg bg-[#071226] text-sm font-medium text-white hover:bg-[#101f36] disabled:opacity-50"
                >
                  {submitting && <Loader2 size={16} className="animate-spin" />}
                  Register Anchor
                </button>
              </footer>
            </aside>
          </>,
          document.body,
        )}

      {revokeTarget &&
        typeof document !== "undefined" &&
        createPortal(
          <>
            <button
              type="button"
              aria-label="Close revoke dialog"
              onClick={() => setRevokeTarget(null)}
              className="fixed inset-0 z-[10000] bg-[#071226]/60 backdrop-blur-sm"
            />
            <section className="fixed left-1/2 top-1/2 z-[10001] w-[calc(100%-2rem)] max-w-md -translate-x-1/2 -translate-y-1/2 rounded-2xl bg-white shadow-2xl">
              <header className="flex items-center justify-between px-6 py-5">
                <div className="flex items-center gap-3">
                  <span className="flex h-10 w-10 items-center justify-center rounded-full bg-amber-50 text-amber-600">
                    <ShieldX size={21} />
                  </span>
                  <h2 className="text-lg font-semibold text-[#071226]">Revoke trust anchor?</h2>
                </div>
                <button type="button" onClick={() => setRevokeTarget(null)}>
                  <X size={20} className="text-slate-500" />
                </button>
              </header>
              <p className="px-6 pb-5 text-sm leading-6 text-slate-600">
                New attestations using this trust anchor will fail. Historical records remain
                unchanged.
              </p>
              <footer className="grid grid-cols-2 gap-3 border-t border-slate-200 p-6">
                <button
                  type="button"
                  onClick={() => setRevokeTarget(null)}
                  className="h-11 rounded-lg border border-slate-200 text-sm font-medium text-slate-700"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={revokeAnchor}
                  disabled={submitting}
                  className="flex h-11 items-center justify-center gap-2 rounded-lg bg-red-600 text-sm font-medium text-white hover:bg-red-700 disabled:opacity-50"
                >
                  {submitting && <Loader2 size={16} className="animate-spin" />}
                  Revoke Anchor
                </button>
              </footer>
            </section>
          </>,
          document.body,
        )}
    </div>
  );
}

function ChainNode({
  icon,
  title,
  subtitle,
  ready,
}: {
  icon: React.ReactNode;
  title: string;
  subtitle: string;
  ready: boolean;
}) {
  return (
    <div className="flex items-center gap-3">
      <span className="flex h-12 w-12 shrink-0 items-center justify-center rounded-full border border-blue-200 bg-blue-50 text-blue-700">
        {icon}
      </span>
      <div>
        <p className="text-sm font-medium text-slate-800">{title}</p>
        <span
          className={`mt-1 inline-block rounded-md px-2 py-0.5 text-xs ${
            ready ? "bg-emerald-50 text-emerald-700" : "bg-amber-50 text-amber-700"
          }`}
        >
          {subtitle}
        </span>
      </div>
    </div>
  );
}

function SelectField({
  label,
  value,
  onChange,
  options,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  options: Array<{ value: string; label: string }>;
}) {
  return (
    <label className="block text-sm font-medium text-slate-700">
      {label} <span className="text-red-500">*</span>
      <select
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="mt-2 h-11 w-full rounded-lg border border-slate-200 bg-white px-3 text-sm outline-none focus:border-blue-600"
      >
        <option value="">Select {label.toLowerCase()}</option>
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
    </label>
  );
}

function SerialField({
  label,
  value,
  onChange,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
}) {
  return (
    <label className="block text-sm font-medium text-slate-700">
      {label} <span className="text-red-500">*</span>
      <input
        value={value}
        onChange={(event) => onChange(event.target.value.replace(/[^a-fA-F0-9]/g, ""))}
        placeholder="Enter certificate serial hex"
        className="mt-2 h-11 w-full rounded-lg border border-slate-200 px-3 font-mono text-sm outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-100"
      />
    </label>
  );
}

function AnchorRows({
  anchor,
  family,
  expanded,
  onExpand,
  onRevoke,
  onRemove,
  onCopy,
  copied,
  actionMenu,
  actionPosition,
  setActionMenu,
  setActionPosition,
}: {
  anchor: TrustAnchor;
  family?: DeviceFamily;
  expanded: boolean;
  onExpand: () => void;
  onRevoke: () => void;
  onRemove: () => void;
  onCopy: (id: string, value: string) => void;
  copied: string | null;
  actionMenu: string | null;
  actionPosition: { top: number; left: number };
  setActionMenu: React.Dispatch<React.SetStateAction<string | null>>;
  setActionPosition: React.Dispatch<React.SetStateAction<{ top: number; left: number }>>;
}) {
  return (
    <>
      <tr className="hover:bg-slate-50/70">
        <td className="px-3 py-3">
          <button type="button" onClick={onExpand} className="rounded p-1 hover:bg-slate-100">
            {expanded ? <ChevronDown size={17} /> : <ChevronRight size={17} />}
          </button>
        </td>
        <td className="px-3 py-3 font-medium text-blue-700">
          {anchor.deviceCodename || family?.codename || family?.name || "Unknown"}
        </td>
        <td className="px-3 py-3 text-slate-500">{family?.model || "—"}</td>
        <td className="px-3 py-3 text-slate-600">{anchor.authorityName}</td>
        <td className="px-3 py-3 font-mono text-xs">{masked(anchor.rsaSerialHex)}</td>
        <td className="px-3 py-3 font-mono text-xs">{masked(anchor.rsaIntermediateSerialHex)}</td>
        <td className="px-3 py-3 font-mono text-xs">{masked(anchor.ecdsaSerialHex)}</td>
        <td className="px-3 py-3 font-mono text-xs">{masked(anchor.ecdsaIntermediateSerialHex)}</td>
        <td className="px-3 py-3">
          <span
            className={`rounded-md border px-2 py-1 text-xs ${
              anchor.revokedAt
                ? "border-red-200 bg-red-50 text-red-700"
                : "border-emerald-200 bg-emerald-50 text-emerald-700"
            }`}
          >
            {anchor.revokedAt ? "Revoked" : "Active"}
          </span>
        </td>
        <td className="px-3 py-3 text-xs text-slate-500">
          {new Date(anchor.createdAt).toLocaleString()}
        </td>
        <td className="relative px-3 py-3 text-right">
          <button
            type="button"
            onClick={(event) => {
              if (actionMenu === anchor.id) {
                setActionMenu(null);
                return;
              }
              const rect = event.currentTarget.getBoundingClientRect();
              const menuHeight = anchor.revokedAt ? 48 : 88;
              setActionPosition({
                top:
                  rect.bottom + menuHeight + 8 <= window.innerHeight
                    ? rect.bottom + 6
                    : rect.top - menuHeight - 6,
                left: Math.max(12, rect.right - 176),
              });
              setActionMenu(anchor.id);
            }}
            className="rounded-lg p-2 text-slate-500 hover:bg-slate-100"
          >
            <MoreVertical size={18} />
          </button>
          {actionMenu === anchor.id &&
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
                  {!anchor.revokedAt && (
                    <button
                      type="button"
                      onClick={onRevoke}
                      className="flex w-full items-center gap-2 px-3 py-2 text-sm text-amber-700 hover:bg-amber-50"
                    >
                      <ShieldX size={16} /> Revoke
                    </button>
                  )}
                  <button
                    type="button"
                    onClick={onRemove}
                    className="flex w-full items-center gap-2 px-3 py-2 text-sm text-red-600 hover:bg-red-50"
                  >
                    <Trash2 size={16} /> Remove
                  </button>
                </div>
              </>,
              document.body,
            )}
        </td>
      </tr>
      {expanded && (
        <tr>
          <td colSpan={11} className="bg-slate-50/60 px-5 py-4">
            <div className="grid gap-5 rounded-xl border border-slate-200 bg-white p-4 lg:grid-cols-[1fr_1fr_auto]">
              <div className="space-y-4">
                {[
                  ["RSA Leaf Serial Hex", anchor.rsaSerialHex],
                  ["RSA Intermediate Serial Hex", anchor.rsaIntermediateSerialHex || ""],
                  ["ECDSA Leaf Serial Hex", anchor.ecdsaSerialHex],
                  ["ECDSA Intermediate Serial Hex", anchor.ecdsaIntermediateSerialHex || ""],
                ].map(([label, value], index) => (
                  <div key={label}>
                    <p className="text-xs text-slate-500">{label}</p>
                    <div className="mt-1 flex items-center gap-2">
                      <p className="font-mono text-xs text-slate-700">{value || "—"}</p>
                      {value && (
                        <button
                          type="button"
                          onClick={() => onCopy(`${anchor.id}-${index}`, value)}
                          className="text-slate-500 hover:text-blue-700"
                        >
                          {copied === `${anchor.id}-${index}` ? (
                            <Check size={15} />
                          ) : (
                            <Copy size={15} />
                          )}
                        </button>
                      )}
                    </div>
                  </div>
                ))}
              </div>
              <dl className="grid grid-cols-2 gap-x-5 gap-y-3 text-sm">
                <dt className="text-slate-500">Authority</dt>
                <dd className="text-slate-700">{anchor.authorityName}</dd>
                <dt className="text-slate-500">Created</dt>
                <dd className="text-slate-700">{new Date(anchor.createdAt).toLocaleString()}</dd>
                <dt className="text-slate-500">Revoked</dt>
                <dd className="text-slate-700">
                  {anchor.revokedAt ? new Date(anchor.revokedAt).toLocaleString() : "—"}
                </dd>
              </dl>
              <div className="flex flex-col gap-2">
                {!anchor.revokedAt && (
                  <button
                    type="button"
                    onClick={onRevoke}
                    className="flex h-10 items-center justify-center gap-2 rounded-lg border border-amber-400 px-4 text-sm text-amber-700 hover:bg-amber-50"
                  >
                    <ShieldX size={16} /> Revoke
                  </button>
                )}
                <button
                  type="button"
                  onClick={onRemove}
                  className="flex h-10 items-center justify-center gap-2 rounded-lg border border-red-300 px-4 text-sm text-red-600 hover:bg-red-50"
                >
                  <Trash2 size={16} /> Remove
                </button>
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}
