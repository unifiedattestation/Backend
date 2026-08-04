import { useCallback, useEffect, useMemo, useState } from "react";
import { createPortal } from "react-dom";
import {
  AlertTriangle,
  AppWindow,
  ArrowRight,
  CheckCircle2,
  FileText,
  Info,
  Loader2,
  LockKeyhole,
  Network,
  RefreshCw,
  Search,
  Server,
  ShieldCheck,
  X,
} from "lucide-react";
import AppdevFooter from "../../components/appdev/Footer";
import { backendUrl } from "../../lib/config";

type FederationBackend = {
  id: string;
  backendId: string;
  name: string;
  url?: string | null;
  status: "active" | "disabled";
  publicKeys?: Array<{ kid?: string; alg?: string }>;
  createdAt?: string;
};

type DeveloperApp = {
  id: string;
  projectId: string;
  name: string;
};

type Profile = { id: string; email: string; displayName?: string | null };
const documentationUrl = "https://github.com/unifiedAttestation/Website/wiki";

export default function AppdevFederation({
  onProfileLoaded,
}: {
  onProfileLoaded?: (name: string) => void;
}) {
  const [backends, setBackends] = useState<FederationBackend[]>([]);
  const [apps, setApps] = useState<DeveloperApp[]>([]);
  const [profile, setProfile] = useState<Profile | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [status, setStatus] = useState("all");
  const [selectedBackend, setSelectedBackend] = useState<FederationBackend | null>(null);

  const load = useCallback(async () => {
    const token = localStorage.getItem("ua_access");
    if (!token) {
      window.location.href = "/login";
      return;
    }
    setLoading(true);
    try {
      const headers = { Authorization: `Bearer ${token}` };
      const [backendResponse, appsResponse, profileResponse] = await Promise.all([
        fetch(`${backendUrl}/api/v1/federation/backends`),
        fetch(`${backendUrl}/api/v1/apps`, { headers }),
        fetch(`${backendUrl}/api/v1/profile`, { headers }),
      ]);
      if (appsResponse.status === 401 || profileResponse.status === 401) {
        localStorage.removeItem("ua_access");
        localStorage.removeItem("ua_refresh");
        window.location.href = "/login";
        return;
      }
      if (!backendResponse.ok || !appsResponse.ok || !profileResponse.ok) {
        throw new Error("Unable to load federation data.");
      }
      const backendData: FederationBackend[] = await backendResponse.json();
      const appData: DeveloperApp[] = await appsResponse.json();
      const profileData: Profile = await profileResponse.json();
      setBackends(backendData);
      setApps(appData);
      setProfile(profileData);
      onProfileLoaded?.(
        profileData.displayName || profileData.email.split("@")[0] || "App Developer",
      );
      setError(null);
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Unable to load federation.");
    } finally {
      setLoading(false);
    }
  }, [onProfileLoaded]);

  useEffect(() => {
    load();
  }, [load]);

  const filteredBackends = useMemo(() => {
    const query = search.trim().toLowerCase();
    return backends.filter(
      (backend) =>
        (!query || `${backend.name} ${backend.backendId}`.toLowerCase().includes(query)) &&
        (status === "all" || backend.status === status),
    );
  }, [backends, search, status]);

  const active = backends.filter((backend) => backend.status === "active").length;

  return (
    <div className="flex min-h-[calc(100vh-3rem)] flex-col gap-4">
      <header className="flex flex-col gap-4 border-b border-slate-200 pb-4 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-[#071226]">Federation</h1>
          <p className="mt-1 text-sm text-slate-500">
            View federation servers available to your developer account.
          </p>
        </div>
        <div className="flex flex-col gap-2 sm:flex-row">
          <span className="flex h-10 items-center justify-center gap-2 rounded-lg border border-slate-300 bg-white px-4 text-sm text-slate-600">
            <LockKeyhole size={16} /> Read-only
          </span>
          <a
            href={documentationUrl}
            target="_blank"
            rel="noreferrer"
            className="flex h-10 items-center justify-center gap-2 rounded-lg border border-slate-300 bg-white px-4 text-sm text-slate-700 hover:bg-slate-50"
          >
            <FileText size={17} /> Federation Guide
          </a>
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
        <StatCard
          label="Federation Servers"
          value={backends.length.toString()}
          detail="Available servers"
          icon={<Server />}
          tone="blue"
        />
        <StatCard
          label="Active"
          value={active.toString()}
          detail={active === backends.length ? "All available" : "Limited availability"}
          icon={<CheckCircle2 />}
          tone="green"
        />
        <StatCard
          label="Applications"
          value={apps.length.toString()}
          detail={apps[0]?.name || "No applications"}
          icon={<AppWindow />}
          tone="blue"
        />
        <StatCard
          label="Management"
          value="Read-only"
          detail="Platform administrator"
          icon={<LockKeyhole />}
          tone="slate"
        />
      </section>

      <section className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
        <header className="border-b border-slate-200 p-4">
          <h2 className="text-lg font-semibold text-[#071226]">Federation Servers</h2>
          <p className="text-xs text-slate-500">
            Server configuration is managed by the platform administrator.
          </p>
          <div className="mt-4 grid gap-2 sm:grid-cols-[1fr_220px_auto]">
            <label className="relative">
              <Search
                size={17}
                className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400"
              />
              <input
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                placeholder="Search federation servers"
                className="h-10 w-full rounded-lg border border-slate-200 pl-10 pr-3 text-sm outline-none focus:border-blue-600"
              />
            </label>
            <select
              value={status}
              onChange={(event) => setStatus(event.target.value)}
              className="h-10 rounded-lg border border-slate-200 bg-white px-3 text-sm"
            >
              <option value="all">All statuses</option>
              <option value="active">Active</option>
              <option value="disabled">Disabled</option>
            </select>
            <button
              type="button"
              onClick={load}
              className="flex h-10 items-center justify-center rounded-lg border border-slate-200 px-3 text-slate-600 hover:bg-slate-50"
            >
              <RefreshCw size={17} className={loading ? "animate-spin" : ""} />
            </button>
          </div>
        </header>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[850px] text-left text-sm">
            <thead className="bg-slate-50 text-xs text-slate-500">
              <tr>
                <th className="px-4 py-3">Server</th>
                <th className="px-4 py-3">Server ID</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Availability</th>
                <th className="px-4 py-3">Management</th>
                <th className="px-4 py-3">Last Checked</th>
                <th className="px-4 py-3 text-right">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {filteredBackends.map((backend) => (
                <tr key={backend.id} className="hover:bg-blue-50/40">
                  <td className="px-4 py-3 font-medium text-blue-700">{backend.name}</td>
                  <td className="max-w-52 truncate px-4 py-3 font-mono text-xs text-slate-500">
                    {backend.backendId}
                  </td>
                  <td className="px-4 py-3">
                    <Availability
                      active={backend.status === "active"}
                      label={backend.status === "active" ? "Active" : "Disabled"}
                    />
                  </td>
                  <td className="px-4 py-3">
                    <Availability
                      active={backend.status === "active"}
                      label={backend.status === "active" ? "Available" : "Unavailable"}
                    />
                  </td>
                  <td className="px-4 py-3">
                    <span className="flex items-center gap-2 text-xs text-slate-600">
                      <LockKeyhole size={15} />
                      Platform managed
                    </span>
                  </td>
                  <td className="px-4 py-3 text-xs text-slate-500">Just now</td>
                  <td className="px-4 py-3 text-right">
                    <button
                      type="button"
                      onClick={() => setSelectedBackend(backend)}
                      className="rounded-lg p-2 text-slate-600 hover:bg-slate-100"
                    >
                      <ArrowRight size={17} />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {loading && (
            <div className="flex items-center justify-center gap-2 py-14 text-sm text-slate-500">
              <Loader2 size={18} className="animate-spin" />
              Loading federation servers...
            </div>
          )}
          {!loading && filteredBackends.length === 0 && (
            <div className="py-14 text-center text-sm text-slate-500">
              No federation servers found.
            </div>
          )}
        </div>
        <footer className="border-t border-slate-200 px-4 py-3 text-xs text-slate-500">
          {filteredBackends.length} servers
        </footer>
      </section>

      <section className="grid gap-4 xl:grid-cols-[0.8fr_1.15fr_0.85fr]">
        <FederationStatus backends={backends} />
        <ApplicationAccess apps={apps} available={active > 0} />
        <HowFederationWorks />
      </section>
      <Permissions />
      <AppdevFooter />

      {selectedBackend &&
        typeof document !== "undefined" &&
        createPortal(
          <>
            <button
              type="button"
              aria-label="Close server details"
              onClick={() => setSelectedBackend(null)}
              className="fixed inset-0 z-[9998] bg-[#071226]/55 backdrop-blur-sm"
            />
            <aside className="fixed inset-y-0 right-0 z-[9999] flex w-full max-w-md flex-col bg-white shadow-2xl">
              <header className="flex items-center justify-between border-b border-slate-200 px-6 py-5">
                <h2 className="text-lg font-semibold text-[#071226]">Server Details</h2>
                <button type="button" onClick={() => setSelectedBackend(null)}>
                  <X size={20} />
                </button>
              </header>
              <ServerDetails backend={selectedBackend} profile={profile} apps={apps} />
              <footer className="border-t border-slate-200 p-6">
                <button
                  type="button"
                  onClick={() => setSelectedBackend(null)}
                  className="h-11 w-full rounded-lg border border-blue-600 text-sm text-blue-700"
                >
                  Close Details
                </button>
              </footer>
            </aside>
          </>,
          document.body,
        )}
    </div>
  );
}

function StatCard({
  label,
  value,
  detail,
  icon,
  tone,
}: {
  label: string;
  value: string;
  detail: string;
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
      <div className="min-w-0">
        <p className="text-xs text-slate-500">{label}</p>
        <strong className="mt-1 block truncate text-xl text-[#071226]">{value}</strong>
        <p className="truncate text-xs text-slate-500">{detail}</p>
      </div>
    </article>
  );
}

function FederationStatus({ backends }: { backends: FederationBackend[] }) {
  const active = backends.filter((backend) => backend.status === "active").length;
  return (
    <article className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
      <h2 className="text-lg font-semibold text-[#071226]">Federation Status</h2>
      <div className="mt-3 space-y-3">
        <div className="flex items-center justify-between text-sm">
          <span className="text-slate-600">Overall Availability</span>
          <Availability active={active > 0} label={active > 0 ? "Healthy" : "Unavailable"} />
        </div>
        {backends.map((backend) => (
          <div key={backend.id} className="flex items-center justify-between text-sm">
            <span className="text-slate-600">{backend.name}</span>
            <Availability
              active={backend.status === "active"}
              label={backend.status === "active" ? "Active" : "Disabled"}
            />
          </div>
        ))}
      </div>
      <p className="mt-4 border-t border-slate-200 pt-4 text-xs leading-5 text-slate-500">
        {active === backends.length && active > 0
          ? "All federation servers are currently available to this account."
          : `${active} of ${backends.length} federation servers are available.`}
      </p>
    </article>
  );
}

function ApplicationAccess({ apps, available }: { apps: DeveloperApp[]; available: boolean }) {
  return (
    <article className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
      <header className="p-4">
        <h2 className="text-lg font-semibold text-[#071226]">Application Access</h2>
      </header>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[500px] text-left text-xs">
          <thead className="border-y border-slate-200 bg-slate-50 text-slate-500">
            <tr>
              <th className="px-4 py-3">Application</th>
              <th className="px-4 py-3">Project ID</th>
              <th className="px-4 py-3">Federation Access</th>
              <th className="px-4 py-3">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {apps.map((app) => (
              <tr key={app.id}>
                <td className="px-4 py-3 font-medium">{app.name}</td>
                <td className="px-4 py-3 text-slate-500">{app.projectId}</td>
                <td className="px-4 py-3">
                  <Availability
                    active={available}
                    label={available ? "Available" : "Unavailable"}
                  />
                </td>
                <td className="px-4 py-3">
                  <Availability active label="Active" />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {apps.length === 0 && (
          <p className="py-10 text-center text-sm text-slate-500">No applications registered.</p>
        )}
      </div>
      <a
        href="/appdev/applications"
        className="m-4 inline-flex h-9 items-center rounded-lg border border-blue-600 px-4 text-sm text-blue-700"
      >
        Open Applications
      </a>
    </article>
  );
}

function HowFederationWorks() {
  return (
    <article className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
      <h2 className="text-lg font-semibold text-[#071226]">How Federation Works</h2>
      <div className="mt-3 space-y-3">
        {[
          "Application submits attestation data",
          "Unified Attestation routes verification through available federation services",
          "Results appear in Device Reports",
        ].map((text, index) => (
          <div key={text} className="flex gap-3 text-sm">
            <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full border border-slate-400 text-xs">
              {index + 1}
            </span>
            <span className="text-slate-600">{text}</span>
          </div>
        ))}
      </div>
      <div className="mt-4 flex gap-2 rounded-lg border border-amber-200 bg-amber-50 p-3 text-xs text-amber-800">
        <AlertTriangle size={17} className="shrink-0" />
        Federation routing and server configuration are controlled by the platform administrator.
      </div>
      <a
        href={documentationUrl}
        target="_blank"
        rel="noreferrer"
        className="mt-4 block text-center text-sm text-blue-700"
      >
        Read Federation Guide
      </a>
    </article>
  );
}

function Permissions() {
  return (
    <article className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
      <h2 className="text-lg font-semibold text-[#071226]">Permissions</h2>
      <p className="text-xs text-slate-500">
        Your access is limited to viewing federation servers. Platform administrators manage
        configuration and operation.
      </p>
      <div className="mt-4 grid gap-5 md:grid-cols-2">
        <div>
          <h3 className="text-sm font-medium text-slate-700">You Can View</h3>
          <div className="mt-3 grid grid-cols-2 gap-3 text-sm text-slate-600">
            {["Server Name", "Status", "Masked Identifier", "Availability"].map((item) => (
              <span key={item} className="flex items-center gap-2">
                <CheckCircle2 size={16} className="text-emerald-600" />
                {item}
              </span>
            ))}
          </div>
        </div>
        <div className="border-slate-200 md:border-l md:pl-6">
          <h3 className="text-sm font-medium text-slate-700">Platform Administrator Manages</h3>
          <div className="mt-3 grid grid-cols-2 gap-3 text-sm text-slate-600">
            {["Server Configuration", "Routing", "Activation"].map((item) => (
              <span key={item} className="flex items-center gap-2">
                <LockKeyhole size={16} />
                {item}
              </span>
            ))}
          </div>
        </div>
      </div>
    </article>
  );
}

function ServerDetails({
  backend,
  profile,
  apps,
}: {
  backend: FederationBackend;
  profile: Profile | null;
  apps: DeveloperApp[];
}) {
  return (
    <div className="flex-1 overflow-y-auto p-6">
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-semibold text-[#071226]">{backend.name}</h3>
        <Availability
          active={backend.status === "active"}
          label={backend.status === "active" ? "Active" : "Disabled"}
        />
      </div>
      <dl className="mt-7 grid grid-cols-[120px_1fr] gap-y-4 text-sm">
        <dt className="text-slate-500">Server Name</dt>
        <dd>{backend.name}</dd>
        <dt className="text-slate-500">Server ID</dt>
        <dd className="break-all font-mono text-xs">{backend.backendId}</dd>
        <dt className="text-slate-500">Availability</dt>
        <dd>
          <Availability
            active={backend.status === "active"}
            label={backend.status === "active" ? "Available" : "Unavailable"}
          />
        </dd>
        <dt className="text-slate-500">Management</dt>
        <dd>Platform Administrator</dd>
        <dt className="text-slate-500">Access</dt>
        <dd>Read-only</dd>
        <dt className="text-slate-500">Public Keys</dt>
        <dd>{Array.isArray(backend.publicKeys) ? backend.publicKeys.length : 0}</dd>
        <dt className="text-slate-500">Last Checked</dt>
        <dd>Just Now</dd>
      </dl>
      <div className="my-6 border-t border-slate-200" />
      <h3 className="font-semibold text-[#071226]">Account Access</h3>
      <dl className="mt-4 grid grid-cols-[140px_1fr] gap-y-4 text-sm">
        <dt className="text-slate-500">Developer Account</dt>
        <dd>{profile?.displayName || profile?.email || "—"}</dd>
        <dt className="text-slate-500">Registered Apps</dt>
        <dd>{apps.length}</dd>
        <dt className="text-slate-500">Access Status</dt>
        <dd>
          <Availability active={backend.status === "active"} label="Available" />
        </dd>
      </dl>
      <div className="mt-7 flex gap-3 rounded-lg border border-blue-200 bg-blue-50 p-4 text-sm text-blue-700">
        <Info size={18} className="shrink-0" />
        Federation server settings cannot be changed from the Application Developer portal.
      </div>
    </div>
  );
}

function Availability({ active, label }: { active: boolean; label: string }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 text-xs ${active ? "text-emerald-600" : "text-red-600"}`}
    >
      {active ? <CheckCircle2 size={16} /> : <X size={16} />}
      {label}
    </span>
  );
}
