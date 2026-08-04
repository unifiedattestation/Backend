import { useCallback, useEffect, useMemo, useState } from "react";
import { createPortal } from "react-dom";
import {
  ArrowLeft,
  ArrowRight,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  ClipboardList,
  Copy,
  Layers3,
  Loader2,
  LockKeyhole,
  MoreVertical,
  Pencil,
  Plus,
  RefreshCw,
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
};

type BuildPolicy = {
  id: string;
  deviceFamilyId: string;
  buildFingerprint: string;
  verifiedBootKeyHex: string;
  verifiedBootHashHex?: string | null;
  osVersionRaw?: number | null;
  minOsPatchLevelRaw?: number | null;
  enabled: boolean;
  createdAt: string;
  updatedAt?: string;
  family: DeviceFamily;
};

type PolicyForm = {
  id: string;
  deviceFamilyId: string;
  buildFingerprint: string;
  verifiedBootKeyHex: string;
  verifiedBootHashHex: string;
  osVersionRaw: string;
  minOsPatchLevelRaw: string;
  enabled: boolean;
};

const emptyForm: PolicyForm = {
  id: "",
  deviceFamilyId: "",
  buildFingerprint: "",
  verifiedBootKeyHex: "",
  verifiedBootHashHex: "",
  osVersionRaw: "",
  minOsPatchLevelRaw: "",
  enabled: true,
};

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

function androidVersion(value?: number | null) {
  if (!value) return "—";
  return value >= 10000 ? String(Math.floor(value / 10000)) : String(value);
}

function formatDate(value: string) {
  return new Date(value).toLocaleString();
}

function masked(value?: string | null) {
  if (!value) return "—";
  if (value.length < 16) return value;
  return `${value.slice(0, 4)}••••••••••••${value.slice(-4)}`;
}

export default function OemBuildPolicies({
  onOrganizationLoaded,
}: {
  onOrganizationLoaded?: (name: string) => void;
}) {
  const [families, setFamilies] = useState<DeviceFamily[]>([]);
  const [policies, setPolicies] = useState<BuildPolicy[]>([]);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [familyFilter, setFamilyFilter] = useState("all");
  const [versionFilter, setVersionFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  const [page, setPage] = useState(1);
  const [expandedPolicy, setExpandedPolicy] = useState<string | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [form, setForm] = useState<PolicyForm>(emptyForm);
  const [actionMenu, setActionMenu] = useState<string | null>(null);
  const [actionPosition, setActionPosition] = useState({ top: 0, left: 0 });
  const [copied, setCopied] = useState<string | null>(null);
  const pageSize = 10;

  const loadPolicies = useCallback(async () => {
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
      const buildResponses = await Promise.all(
        familyData.map((family) =>
          fetch(`${backendUrl}/api/v1/oem/device-families/${family.id}/builds`, { headers }),
        ),
      );
      const buildGroups = await Promise.all(
        buildResponses.map(async (response) => (response.ok ? await response.json() : [])),
      );
      const nextPolicies: BuildPolicy[] = buildGroups.flatMap((builds, index) =>
        (builds as Omit<BuildPolicy, "family">[]).map((build) => ({
          ...build,
          family: familyData[index],
          deviceFamilyId: familyData[index].id,
          enabled: build.enabled !== false,
        })),
      );
      setFamilies(familyData);
      setPolicies(nextPolicies);
      if (profileResponse.ok) {
        const profile = await profileResponse.json();
        onOrganizationLoaded?.(profile.name || "OEM Portal");
      }
      setError(null);
    } catch (requestError) {
      setError(
        requestError instanceof Error ? requestError.message : "Unable to load build policies.",
      );
    } finally {
      setLoading(false);
    }
  }, [onOrganizationLoaded]);

  useEffect(() => {
    loadPolicies();
  }, [loadPolicies]);

  useEffect(() => {
    setPage(1);
  }, [search, familyFilter, versionFilter, statusFilter]);

  const openCreate = () => {
    setForm({ ...emptyForm, deviceFamilyId: families[0]?.id || "" });
    setError(null);
    setDrawerOpen(true);
  };

  const openEdit = (policy: BuildPolicy) => {
    setActionMenu(null);
    setForm({
      id: policy.id,
      deviceFamilyId: policy.deviceFamilyId,
      buildFingerprint: policy.buildFingerprint,
      verifiedBootKeyHex: policy.verifiedBootKeyHex,
      verifiedBootHashHex: policy.verifiedBootHashHex || "",
      osVersionRaw: policy.osVersionRaw?.toString() || "",
      minOsPatchLevelRaw: policy.minOsPatchLevelRaw?.toString() || "",
      enabled: policy.enabled,
    });
    setError(null);
    setDrawerOpen(true);
  };

  const validateForm = () => {
    if (!form.deviceFamilyId || !form.buildFingerprint.trim()) {
      return "Device family and build fingerprint are required.";
    }
    if (!/^[a-fA-F0-9]{64}$/.test(form.verifiedBootKeyHex.trim())) {
      return "Verified Boot Key must contain exactly 64 hexadecimal characters.";
    }
    if (
      form.verifiedBootHashHex.trim() &&
      !/^[a-fA-F0-9]{64}$/.test(form.verifiedBootHashHex.trim())
    ) {
      return "Verified Boot Hash must contain exactly 64 hexadecimal characters.";
    }
    if (!form.osVersionRaw || !form.minOsPatchLevelRaw) {
      return "OS version and OS patch level are required.";
    }
    return null;
  };

  const savePolicy = async () => {
    const validationError = validateForm();
    if (validationError) {
      setError(validationError);
      return;
    }
    const token = localStorage.getItem("ua_access");
    if (!token) return;
    setSubmitting(true);
    setError(null);
    try {
      const editPolicy = policies.find((policy) => policy.id === form.id);
      const familyId = editPolicy?.deviceFamilyId || form.deviceFamilyId;
      const response = await fetch(
        form.id
          ? `${backendUrl}/api/v1/oem/device-families/${familyId}/builds/${form.id}`
          : `${backendUrl}/api/v1/oem/device-families/${form.deviceFamilyId}/builds`,
        {
          method: form.id ? "PUT" : "POST",
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            buildFingerprint: form.buildFingerprint.trim(),
            verifiedBootKeyHex: form.verifiedBootKeyHex.trim(),
            verifiedBootHashHex: form.verifiedBootHashHex.trim() || null,
            osVersionRaw: Number(form.osVersionRaw),
            minOsPatchLevelRaw: Number(form.minOsPatchLevelRaw),
            enabled: form.enabled,
          }),
        },
      );
      if (!response.ok) throw new Error((await response.text()) || "Unable to save build policy.");
      setDrawerOpen(false);
      setNotice(form.id ? "Build policy updated." : "Build policy added.");
      setForm(emptyForm);
      await loadPolicies();
    } catch (requestError) {
      setError(
        requestError instanceof Error ? requestError.message : "Unable to save build policy.",
      );
    } finally {
      setSubmitting(false);
    }
  };

  const deletePolicy = async (policy: BuildPolicy) => {
    if (!window.confirm("Delete this build policy?")) return;
    const token = localStorage.getItem("ua_access");
    if (!token) return;
    setActionMenu(null);
    try {
      const response = await fetch(
        `${backendUrl}/api/v1/oem/device-families/${policy.deviceFamilyId}/builds/${policy.id}`,
        { method: "DELETE", headers: { Authorization: `Bearer ${token}` } },
      );
      if (!response.ok) throw new Error((await response.text()) || "Unable to delete policy.");
      setNotice("Build policy deleted.");
      await loadPolicies();
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Unable to delete policy.");
    }
  };

  const copyValue = async (id: string, value: string) => {
    await navigator.clipboard.writeText(value);
    setCopied(id);
    window.setTimeout(() => setCopied(null), 1400);
  };

  const versions = useMemo(
    () => Array.from(new Set(policies.map((policy) => androidVersion(policy.osVersionRaw)))).sort(),
    [policies],
  );

  const filteredPolicies = useMemo(() => {
    const query = search.trim().toLowerCase();
    return policies.filter((policy) => {
      const matchesSearch =
        !query ||
        policy.buildFingerprint.toLowerCase().includes(query) ||
        policy.family.name.toLowerCase().includes(query) ||
        policy.family.codename?.toLowerCase().includes(query);
      const matchesFamily = familyFilter === "all" || policy.deviceFamilyId === familyFilter;
      const matchesVersion =
        versionFilter === "all" || androidVersion(policy.osVersionRaw) === versionFilter;
      const matchesStatus =
        statusFilter === "all" ||
        (statusFilter === "enabled" && policy.enabled) ||
        (statusFilter === "disabled" && !policy.enabled);
      return matchesSearch && matchesFamily && matchesVersion && matchesStatus;
    });
  }, [policies, search, familyFilter, versionFilter, statusFilter]);

  const totalPages = Math.max(1, Math.ceil(filteredPolicies.length / pageSize));
  const visiblePolicies = filteredPolicies.slice((page - 1) * pageSize, page * pageSize);
  const activePolicies = policies.filter((policy) => policy.enabled).length;
  const compliantPolicies = policies.filter(
    (policy) => policy.enabled && Number(policy.minOsPatchLevelRaw || 0) > 0,
  ).length;
  const compliance = activePolicies ? Math.round((compliantPolicies / activePolicies) * 100) : 0;

  return (
    <div className="flex min-h-[calc(100vh-3rem)] flex-col gap-5">
      <header className="flex flex-col gap-4 border-b border-slate-200 pb-4 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-[#071226]">Build Policies</h1>
          <p className="mt-1 text-sm text-slate-500">
            Manage approved Android builds and Verified Boot requirements across device families.
          </p>
        </div>
        <button
          type="button"
          onClick={openCreate}
          className="flex h-10 items-center justify-center gap-2 rounded-lg bg-[#071226] px-4 text-sm font-medium text-white hover:bg-[#101f36]"
        >
          <Plus size={18} />
          Add Build Policy
        </button>
      </header>

      <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          label="Total Policies"
          value={policies.length}
          icon={<ClipboardList size={23} />}
          color="bg-blue-50 text-blue-700"
        />
        <StatCard
          label="Active Policies"
          value={activePolicies}
          icon={<ShieldCheck size={23} />}
          color="bg-emerald-50 text-emerald-700"
        />
        <StatCard
          label="Device Families"
          value={new Set(policies.map((policy) => policy.deviceFamilyId)).size}
          icon={<Smartphone size={23} />}
          color="bg-indigo-50 text-indigo-700"
        />
        <StatCard
          label="Patch Compliance"
          value={`${compliance}%`}
          icon={<CheckCircle2 size={23} />}
          color="bg-emerald-50 text-emerald-700"
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
        <header className="grid gap-3 border-b border-slate-200 p-4 md:grid-cols-2 xl:grid-cols-[1.5fr_1fr_1fr_1fr_auto]">
          <label className="relative">
            <Search
              size={18}
              className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-400"
            />
            <input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Search by build fingerprint..."
              className="h-10 w-full rounded-lg border border-slate-200 pl-10 pr-3 text-sm outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-100"
            />
          </label>
          <select
            value={familyFilter}
            onChange={(event) => setFamilyFilter(event.target.value)}
            className="h-10 rounded-lg border border-slate-200 bg-white px-3 text-sm text-slate-700 outline-none"
          >
            <option value="all">All Device Families</option>
            {families.map((family) => (
              <option key={family.id} value={family.id}>
                {family.codename || family.name}
              </option>
            ))}
          </select>
          <select
            value={versionFilter}
            onChange={(event) => setVersionFilter(event.target.value)}
            className="h-10 rounded-lg border border-slate-200 bg-white px-3 text-sm text-slate-700 outline-none"
          >
            <option value="all">All Android Versions</option>
            {versions.map((version) => (
              <option key={version} value={version}>
                Android {version}
              </option>
            ))}
          </select>
          <select
            value={statusFilter}
            onChange={(event) => setStatusFilter(event.target.value)}
            className="h-10 rounded-lg border border-slate-200 bg-white px-3 text-sm text-slate-700 outline-none"
          >
            <option value="all">All Statuses</option>
            <option value="enabled">Enabled</option>
            <option value="disabled">Disabled</option>
          </select>
          <button
            type="button"
            onClick={loadPolicies}
            className="flex h-10 items-center justify-center gap-2 rounded-lg border border-slate-200 px-3 text-sm text-slate-700 hover:bg-slate-50"
          >
            <RefreshCw size={16} className={loading ? "animate-spin" : ""} />
            Refresh
          </button>
        </header>

        <div className="overflow-x-auto">
          <table className="w-full min-w-[1050px] text-left text-sm">
            <thead className="bg-slate-50 text-xs text-slate-500">
              <tr>
                <th className="w-10 px-3 py-3" />
                <th className="px-3 py-3 font-semibold">Device Family</th>
                <th className="px-3 py-3 font-semibold">Model</th>
                <th className="px-3 py-3 font-semibold">Build Fingerprint</th>
                <th className="px-3 py-3 font-semibold">Android Version</th>
                <th className="px-3 py-3 font-semibold">OS Patch Level</th>
                <th className="px-3 py-3 font-semibold">Verified Boot</th>
                <th className="px-3 py-3 font-semibold">Status</th>
                <th className="px-3 py-3 font-semibold">Updated</th>
                <th className="px-3 py-3 text-right font-semibold">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {visiblePolicies.map((policy) => (
                <PolicyRows
                  key={policy.id}
                  policy={policy}
                  expanded={expandedPolicy === policy.id}
                  onExpand={() =>
                    setExpandedPolicy((current) => (current === policy.id ? null : policy.id))
                  }
                  onEdit={() => openEdit(policy)}
                  onDelete={() => deletePolicy(policy)}
                  onCopy={copyValue}
                  copied={copied}
                  actionMenu={actionMenu}
                  actionPosition={actionPosition}
                  setActionMenu={setActionMenu}
                  setActionPosition={setActionPosition}
                />
              ))}
            </tbody>
          </table>
          {loading && (
            <div className="flex items-center justify-center gap-2 px-5 py-14 text-sm text-slate-500">
              <Loader2 size={18} className="animate-spin" />
              Loading build policies...
            </div>
          )}
          {!loading && visiblePolicies.length === 0 && (
            <div className="px-5 py-14 text-center text-sm text-slate-500">
              No build policies found.
            </div>
          )}
        </div>

        <footer className="flex items-center justify-between border-t border-slate-200 px-5 py-4 text-xs text-slate-500">
          <span>
            Showing {filteredPolicies.length ? (page - 1) * pageSize + 1 : 0} to{" "}
            {Math.min(page * pageSize, filteredPolicies.length)} of {filteredPolicies.length}{" "}
            policies
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
                <h2 className="text-lg font-semibold text-[#071226]">
                  {form.id ? "Edit Build Policy" : "Add Build Policy"}
                </h2>
                <button
                  type="button"
                  onClick={() => setDrawerOpen(false)}
                  className="rounded-lg p-2 text-slate-500 hover:bg-slate-100"
                >
                  <X size={20} />
                </button>
              </header>
              <div className="flex-1 space-y-5 overflow-y-auto p-6">
                <Field label="Device Family" required>
                  <select
                    value={form.deviceFamilyId}
                    disabled={Boolean(form.id)}
                    onChange={(event) =>
                      setForm((current) => ({ ...current, deviceFamilyId: event.target.value }))
                    }
                    className="mt-2 h-11 w-full rounded-lg border border-slate-200 bg-white px-3 text-sm outline-none focus:border-blue-600 disabled:bg-slate-50"
                  >
                    <option value="">Select a device family</option>
                    {families.map((family) => (
                      <option key={family.id} value={family.id}>
                        {family.codename || family.name} — {family.model || "No model"}
                      </option>
                    ))}
                  </select>
                </Field>
                <Field
                  label="Build Fingerprint"
                  required
                  hint="Exact match to the device fingerprint."
                >
                  <input
                    value={form.buildFingerprint}
                    onChange={(event) =>
                      setForm((current) => ({ ...current, buildFingerprint: event.target.value }))
                    }
                    placeholder="e.g. vendor/device/build:16/..."
                    className="mt-2 h-11 w-full rounded-lg border border-slate-200 px-3 text-sm outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-100"
                  />
                </Field>
                <Field
                  label="Verified Boot Key Hex"
                  required
                  hint="Exactly 64 hexadecimal characters."
                >
                  <input
                    value={form.verifiedBootKeyHex}
                    onChange={(event) =>
                      setForm((current) => ({
                        ...current,
                        verifiedBootKeyHex: event.target.value,
                      }))
                    }
                    placeholder="64-character hex string"
                    className="mt-2 h-11 w-full rounded-lg border border-slate-200 px-3 font-mono text-sm outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-100"
                  />
                </Field>
                <Field
                  label="Verified Boot Hash Hex"
                  hint="Optional 64-character hexadecimal value."
                >
                  <input
                    value={form.verifiedBootHashHex}
                    onChange={(event) =>
                      setForm((current) => ({
                        ...current,
                        verifiedBootHashHex: event.target.value,
                      }))
                    }
                    placeholder="64-character hex string"
                    className="mt-2 h-11 w-full rounded-lg border border-slate-200 px-3 font-mono text-sm outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-100"
                  />
                </Field>
                <div className="grid grid-cols-2 gap-3">
                  <Field label="OS Version Raw" required>
                    <input
                      type="number"
                      value={form.osVersionRaw}
                      onChange={(event) =>
                        setForm((current) => ({ ...current, osVersionRaw: event.target.value }))
                      }
                      placeholder="e.g. 160000"
                      className="mt-2 h-11 w-full rounded-lg border border-slate-200 px-3 text-sm outline-none focus:border-blue-600"
                    />
                  </Field>
                  <Field label="OS Patch Level" required>
                    <input
                      type="number"
                      value={form.minOsPatchLevelRaw}
                      onChange={(event) =>
                        setForm((current) => ({
                          ...current,
                          minOsPatchLevelRaw: event.target.value,
                        }))
                      }
                      placeholder="e.g. 202605"
                      className="mt-2 h-11 w-full rounded-lg border border-slate-200 px-3 text-sm outline-none focus:border-blue-600"
                    />
                  </Field>
                </div>
                <div className="flex items-center justify-between gap-4">
                  <div>
                    <p className="text-sm font-medium text-slate-700">Enabled</p>
                    <p className="mt-1 text-xs text-slate-500">Policy is active and enforced.</p>
                  </div>
                  <button
                    type="button"
                    role="switch"
                    aria-checked={form.enabled}
                    onClick={() =>
                      setForm((current) => ({ ...current, enabled: !current.enabled }))
                    }
                    className={`relative h-6 w-11 rounded-full transition ${
                      form.enabled ? "bg-blue-700" : "bg-slate-300"
                    }`}
                  >
                    <span
                      className={`absolute top-0.5 h-5 w-5 rounded-full bg-white shadow transition ${
                        form.enabled ? "left-[22px]" : "left-0.5"
                      }`}
                    />
                  </button>
                </div>
                <div className="rounded-xl border border-blue-200 bg-blue-50 p-4">
                  <div className="flex gap-3">
                    <LockKeyhole size={21} className="shrink-0 text-blue-700" />
                    <p className="text-xs leading-5 text-slate-600">
                      This policy validates the device against the approved build fingerprint and
                      Verified Boot key during attestation.
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
                  onClick={savePolicy}
                  disabled={submitting}
                  className="flex h-11 items-center justify-center gap-2 rounded-lg bg-[#071226] text-sm font-medium text-white hover:bg-[#101f36] disabled:opacity-50"
                >
                  {submitting && <Loader2 size={17} className="animate-spin" />}
                  {form.id ? "Save Changes" : "Add Build Policy"}
                </button>
              </footer>
            </aside>
          </>,
          document.body,
        )}
    </div>
  );
}

function Field({
  label,
  required,
  hint,
  children,
}: {
  label: string;
  required?: boolean;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <label className="block text-sm font-medium text-slate-700">
      {label} {required && <span className="text-red-500">*</span>}
      {children}
      {hint && <span className="mt-2 block text-xs font-normal text-slate-500">{hint}</span>}
    </label>
  );
}

function PolicyRows({
  policy,
  expanded,
  onExpand,
  onEdit,
  onDelete,
  onCopy,
  copied,
  actionMenu,
  actionPosition,
  setActionMenu,
  setActionPosition,
}: {
  policy: BuildPolicy;
  expanded: boolean;
  onExpand: () => void;
  onEdit: () => void;
  onDelete: () => void;
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
          {policy.family.codename || policy.family.name}
        </td>
        <td className="px-3 py-3 text-slate-500">{policy.family.model || "—"}</td>
        <td className="max-w-52 truncate px-3 py-3 font-mono text-xs text-slate-600">
          {policy.buildFingerprint}
        </td>
        <td className="px-3 py-3 text-slate-600">Android {androidVersion(policy.osVersionRaw)}</td>
        <td className="px-3 py-3 text-slate-600">{policy.minOsPatchLevelRaw || "—"}</td>
        <td className="px-3 py-3">
          <span className="rounded-md border border-emerald-200 bg-emerald-50 px-2 py-1 text-xs text-emerald-700">
            Verified
          </span>
        </td>
        <td className="px-3 py-3">
          <span
            className={`rounded-md border px-2 py-1 text-xs ${
              policy.enabled
                ? "border-emerald-200 bg-emerald-50 text-emerald-700"
                : "border-red-200 bg-red-50 text-red-700"
            }`}
          >
            {policy.enabled ? "Enabled" : "Disabled"}
          </span>
        </td>
        <td className="px-3 py-3 text-xs text-slate-500">
          {formatDate(policy.updatedAt || policy.createdAt)}
        </td>
        <td className="relative px-3 py-3 text-right">
          <button
            type="button"
            onClick={(event) => {
              if (actionMenu === policy.id) {
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
              setActionMenu(policy.id);
            }}
            className="rounded-lg p-2 text-slate-500 hover:bg-slate-100"
          >
            <MoreVertical size={18} />
          </button>
          {actionMenu === policy.id &&
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
                    onClick={onEdit}
                    className="flex w-full items-center gap-2 px-3 py-2 text-sm text-slate-700 hover:bg-slate-50"
                  >
                    <Pencil size={16} /> Edit Policy
                  </button>
                  <button
                    type="button"
                    onClick={onDelete}
                    className="flex w-full items-center gap-2 px-3 py-2 text-sm text-red-600 hover:bg-red-50"
                  >
                    <Trash2 size={16} /> Delete Policy
                  </button>
                </div>
              </>,
              document.body,
            )}
        </td>
      </tr>
      {expanded && (
        <tr>
          <td colSpan={10} className="bg-slate-50/60 px-5 py-4">
            <div className="grid gap-5 rounded-xl border border-slate-200 bg-white p-4 lg:grid-cols-[1fr_1fr_auto]">
              <div className="space-y-4">
                <Detail
                  label="Build Fingerprint"
                  value={policy.buildFingerprint}
                  onCopy={() => onCopy(`${policy.id}-fingerprint`, policy.buildFingerprint)}
                  copied={copied === `${policy.id}-fingerprint`}
                />
                <Detail
                  label="Verified Boot Key Hex"
                  value={masked(policy.verifiedBootKeyHex)}
                  onCopy={() => onCopy(`${policy.id}-key`, policy.verifiedBootKeyHex)}
                  copied={copied === `${policy.id}-key`}
                />
                <Detail
                  label="Verified Boot Hash Hex"
                  value={masked(policy.verifiedBootHashHex)}
                  onCopy={
                    policy.verifiedBootHashHex
                      ? () => onCopy(`${policy.id}-hash`, policy.verifiedBootHashHex || "")
                      : undefined
                  }
                  copied={copied === `${policy.id}-hash`}
                />
              </div>
              <dl className="grid grid-cols-2 gap-x-5 gap-y-3 text-sm">
                <dt className="text-slate-500">OS Version Raw</dt>
                <dd className="text-slate-700">{policy.osVersionRaw || "—"}</dd>
                <dt className="text-slate-500">OS Patch Level</dt>
                <dd className="text-slate-700">{policy.minOsPatchLevelRaw || "—"}</dd>
                <dt className="text-slate-500">Enabled</dt>
                <dd className="text-slate-700">{policy.enabled ? "Yes" : "No"}</dd>
                <dt className="text-slate-500">Created At</dt>
                <dd className="text-slate-700">{formatDate(policy.createdAt)}</dd>
              </dl>
              <div className="flex flex-col gap-2">
                <button
                  type="button"
                  onClick={onEdit}
                  className="flex h-10 items-center justify-center gap-2 rounded-lg border border-blue-600 px-4 text-sm text-blue-700 hover:bg-blue-50"
                >
                  <Pencil size={16} /> Edit Policy
                </button>
                <button
                  type="button"
                  onClick={onDelete}
                  className="flex h-10 items-center justify-center gap-2 rounded-lg border border-red-300 px-4 text-sm text-red-600 hover:bg-red-50"
                >
                  <Trash2 size={16} /> Delete Policy
                </button>
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

function Detail({
  label,
  value,
  onCopy,
  copied,
}: {
  label: string;
  value: string;
  onCopy?: () => void;
  copied?: boolean;
}) {
  return (
    <div>
      <p className="text-xs text-slate-500">{label}</p>
      <div className="mt-1 flex items-center gap-2">
        <p className="min-w-0 truncate font-mono text-xs text-slate-700">{value}</p>
        {onCopy && (
          <button type="button" onClick={onCopy} className="text-slate-500 hover:text-blue-700">
            {copied ? <Check size={15} /> : <Copy size={15} />}
          </button>
        )}
      </div>
    </div>
  );
}
