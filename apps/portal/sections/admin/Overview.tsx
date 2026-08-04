import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import {
  ArrowRight,
  Bell,
  Building2,
  CheckCircle2,
  Clock3,
  KeyRound,
  Network,
  Search,
  Server,
  ShieldCheck,
  UserRoundPlus,
  Users,
} from "lucide-react";
import Footer from "../../components/Footer";
import { backendUrl } from "../../lib/config";

type User = {
  id: string;
  email: string;
  role: "admin" | "app_dev" | "oem";
  displayName?: string | null;
  disabledAt?: string | null;
  createdAt?: string;
};

type BackendRoot = {
  id: string;
  name?: string | null;
  createdAt?: string;
  revokedAt?: string | null;
};

type Authority = {
  id: string;
  name: string;
  baseUrl: string;
  enabled: boolean;
  isLocal: boolean;
  createdAt?: string;
  statusCachedAt?: string | null;
  keyAvailability?: { rsa: boolean; ecdsa: boolean };
};

type FederationBackend = {
  id: string;
  name: string;
  backendId: string;
  url?: string | null;
  status: string;
  createdAt?: string;
};

type OverviewData = {
  users: User[];
  roots: BackendRoot[];
  authorities: Authority[];
  backends: FederationBackend[];
};

type AdminNotification = {
  id: string;
  title: string;
  date: string;
  read: boolean;
};

const emptyData: OverviewData = {
  users: [],
  roots: [],
  authorities: [],
  backends: [],
};

const roleLabels: Record<User["role"], string> = {
  admin: "Administrator",
  app_dev: "Application Developer",
  oem: "OEM",
};
const statStyles = {
  users: { icon: Users, color: "text-blue-600", background: "bg-blue-50" },
  roots: { icon: KeyRound, color: "text-violet-600", background: "bg-violet-50" },
  authorities: {
    icon: Building2,
    color: "text-emerald-600",
    background: "bg-emerald-50",
  },
  backends: { icon: Network, color: "text-sky-700", background: "bg-sky-50" },
};

function initials(user: User) {
  const source = user.displayName || user.email;
  return source.slice(0, 2).toUpperCase();
}

function relativeTime(date?: string) {
  if (!date) return "Recently";
  const elapsed = Date.now() - new Date(date).getTime();
  const minutes = Math.max(1, Math.floor(elapsed / 60_000));
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours} hr ago`;
  const days = Math.floor(hours / 24);
  return `${days} day${days === 1 ? "" : "s"} ago`;
}

function StatusPill({ healthy, children }: { healthy: boolean; children: ReactNode }) {
  return (
    <span
      className={[
        "inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium",
        healthy ? "bg-emerald-50 text-emerald-700" : "bg-red-50 text-red-700",
      ].join(" ")}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${healthy ? "bg-emerald-600" : "bg-red-600"}`} />
      {children}
    </span>
  );
}

function StatCard({
  title,
  value,
  description,
  href,
  linkLabel,
  style,
}: {
  title: string;
  value: number;
  description: string;
  href: string;
  linkLabel: string;
  style: (typeof statStyles)[keyof typeof statStyles];
}) {
  const Icon = style.icon;

  return (
    <article className="flex min-h-[158px] w-full flex-1 flex-col overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
      <div className="flex flex-1 items-start gap-4 p-5">
        <div
          className={`flex h-14 w-14 shrink-0 items-center justify-center rounded-xl ${style.background}`}
        >
          <Icon className={style.color} size={26} strokeWidth={2} />
        </div>
        <div>
          <p className="text-sm font-medium text-slate-700">{title}</p>
          <p className="mt-0.5 text-2xl font-semibold text-slate-950">{value}</p>
          <p className="mt-0.5 text-xs text-slate-500">{description}</p>
        </div>
      </div>
      <a
        href={href}
        className="flex items-center justify-center gap-2 border-t border-slate-200 px-4 py-2.5 text-xs font-medium text-blue-700 transition hover:bg-blue-50/60"
      >
        {linkLabel}
        <ArrowRight size={15} />
      </a>
    </article>
  );
}

function Panel({
  title,
  badge,
  children,
  footer,
}: {
  title: string;
  badge?: ReactNode;
  children: ReactNode;
  footer?: ReactNode;
}) {
  return (
    <section className="flex h-full flex-col overflow-hidden rounded-lg border border-slate-200 bg-white shadow-sm">
      <header className="flex min-h-12 items-center justify-between gap-3 border-b border-slate-200 px-4 py-2">
        <h2 className="text-base font-semibold text-slate-950">{title}</h2>
        {badge}
      </header>
      <div className="min-h-0 flex-1 overflow-y-auto">{children}</div>
      {footer && <footer className="border-t border-slate-200">{footer}</footer>}
    </section>
  );
}

export default function AdminOverview() {
  const [data, setData] = useState<OverviewData>(emptyData);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [notifications, setNotifications] = useState<AdminNotification[]>([]);
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  const previousData = useRef<OverviewData | null>(null);
  useEffect(() => {
    const accessToken = localStorage.getItem("ua_access");
    if (!accessToken) {
      window.location.href = "/login";
      return;
    }

    const authorizedHeaders = { Authorization: `Bearer ${accessToken}` };

    const loadOverview = () => {
      Promise.all([
        fetch(`${backendUrl}/api/v1/admin/users`, { headers: authorizedHeaders }),
        fetch(`${backendUrl}/api/v1/admin/backend-roots`, { headers: authorizedHeaders }),
        fetch(`${backendUrl}/api/v1/admin/attestation-authorities`, {
          headers: authorizedHeaders,
        }),
        fetch(`${backendUrl}/api/v1/federation/backends`),
      ])
        .then(async ([usersResponse, rootsResponse, authoritiesResponse, backendsResponse]) => {
          const responses = [usersResponse, rootsResponse, authoritiesResponse, backendsResponse];

          if (responses.some((response) => response.status === 401)) {
            localStorage.removeItem("ua_access");
            localStorage.removeItem("ua_refresh");
            window.location.href = "/login";
            return;
          }

          if (responses.some((response) => !response.ok)) {
            throw new Error("Some overview information could not be loaded.");
          }

          const [users, roots, authorities, backends] = await Promise.all(
            responses.map((response) => response.json()),
          );
          const nextData: OverviewData = { users, roots, authorities, backends };

          if (previousData.current) {
            const now = new Date().toISOString();
            const nextNotifications: AdminNotification[] = [];
            const oldData = previousData.current;

            const addNewItems = <T extends { id: string }>(
              currentItems: T[],
              oldItems: T[],
              prefix: string,
              getTitle: (item: T) => string,
            ) => {
              const oldIds = new Set(oldItems.map((item) => item.id));
              currentItems
                .filter((item) => !oldIds.has(item.id))
                .forEach((item) =>
                  nextNotifications.push({
                    id: `${prefix}-${item.id}`,
                    title: getTitle(item),
                    date: now,
                    read: false,
                  }),
                );
            };

            addNewItems(nextData.users, oldData.users, "user", (user) => {
              return `New user added: ${user.displayName || user.email}`;
            });
            addNewItems(nextData.roots, oldData.roots, "root", (root) => {
              return `New root anchor configured: ${root.name || "Root Anchor"}`;
            });
            addNewItems(
              nextData.authorities,
              oldData.authorities,
              "authority",
              (authority) => `New authority added: ${authority.name}`,
            );
            addNewItems(nextData.backends, oldData.backends, "backend", (backend) => {
              return `New federated backend added: ${backend.name}`;
            });

            nextData.backends.forEach((backend) => {
              const oldBackend = oldData.backends.find((item) => item.id === backend.id);
              if (oldBackend && oldBackend.status !== backend.status) {
                nextNotifications.push({
                  id: `backend-status-${backend.id}-${backend.status}`,
                  title: `${backend.name} status changed to ${backend.status}`,
                  date: now,
                  read: false,
                });
              }
            });

            if (nextNotifications.length > 0) {
              setNotifications((current) => {
                const existingIds = new Set(current.map((notification) => notification.id));
                const uniqueNewItems = nextNotifications.filter(
                  (notification) => !existingIds.has(notification.id),
                );
                return [...uniqueNewItems, ...current].slice(0, 20);
              });
            }
          }

          previousData.current = nextData;
          setData(nextData);
          setError(null);
        })
        .catch((requestError: Error) => setError(requestError.message))
        .finally(() => setLoading(false));
    };

    loadOverview();

    const refreshInterval = window.setInterval(loadOverview, 30_000);
    window.addEventListener("focus", loadOverview);

    return () => {
      window.clearInterval(refreshInterval);
      window.removeEventListener("focus", loadOverview);
    };
  }, []);

  const activeRoots = data.roots.filter((root) => !root.revokedAt);
  const activeAuthorities = data.authorities.filter((authority) => authority.enabled);
  const healthyBackends = data.backends.filter((backend) => backend.status === "active");

  const visibleUsers = useMemo(() => {
    const query = search.trim().toLowerCase();
    const users = query
      ? data.users.filter(
          (user) =>
            user.email.toLowerCase().includes(query) ||
            user.displayName?.toLowerCase().includes(query) ||
            roleLabels[user.role].toLowerCase().includes(query),
        )
      : data.users;

    return users.slice(0, 4);
  }, [data.users, search]);

  const recentActivity = useMemo(() => {
    const activities = [
      ...data.users.map((user) => ({
        id: `user-${user.id}`,
        title: `User ${user.displayName || user.email} added`,
        date: user.createdAt,
        icon: UserRoundPlus,
        iconClass: "bg-blue-50 text-blue-700",
      })),
      ...data.authorities.map((authority) => ({
        id: `authority-${authority.id}`,
        title: `${authority.name} health status checked`,
        date: authority.statusCachedAt || authority.createdAt,
        icon: ShieldCheck,
        iconClass: "bg-emerald-50 text-emerald-700",
      })),
      ...data.backends.map((backend) => ({
        id: `backend-${backend.id}`,
        title: `${backend.name} backend configured`,
        date: backend.createdAt,
        icon: Server,
        iconClass: "bg-sky-50 text-sky-700",
      })),
      ...data.roots.map((root) => ({
        id: `root-${root.id}`,
        title: `${root.name || "Root anchor"} configured`,
        date: root.createdAt,
        icon: KeyRound,
        iconClass: "bg-violet-50 text-violet-700",
      })),
    ];

    return activities
      .sort(
        (first, second) =>
          new Date(second.date || 0).getTime() - new Date(first.date || 0).getTime(),
      )
      .slice(0, 4);
  }, [data]);

  const allSecure =
    activeRoots.length > 0 &&
    activeAuthorities.length > 0 &&
    activeAuthorities.every(
      (authority) => authority.keyAvailability?.rsa && authority.keyAvailability?.ecdsa,
    );
  const federationHealthy =
    data.backends.length > 0 && healthyBackends.length === data.backends.length;
  const unreadNotifications = notifications.filter((notification) => !notification.read).length;

  return (
    <div className="flex min-h-[calc(100vh-3rem)] flex-col gap-3">
      {/* Overview، جست‌وجو و اعلان‌ها همیشه در یک ردیف هستند. */}
      <header className="flex items-center justify-between gap-4 border-b border-slate-200 pb-3">
        <h1 className="shrink-0 text-xl font-bold tracking-tight text-slate-950">Overview</h1>
        <div className="flex min-w-0 items-center gap-3">
          <label className="relative block w-40 sm:w-72">
            <Search
              size={18}
              className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-400"
            />
            <input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Search users"
              className="h-10 w-full rounded-lg border border-slate-200 bg-white pl-10 pr-3 text-sm outline-none transition placeholder:text-slate-400 focus:border-blue-600 focus:ring-2 focus:ring-blue-100"
            />
          </label>

          {/* اعلان تغییرات جدید backend */}
          <div className="relative">
            <button
              type="button"
              onClick={() => setNotificationsOpen((open) => !open)}
              aria-label="Open notifications"
              aria-expanded={notificationsOpen}
              className="relative flex h-10 w-10 items-center justify-center rounded-lg border border-slate-200 bg-white text-[#071226] transition hover:bg-slate-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-200"
            >
              <Bell size={20} />
              {unreadNotifications > 0 && (
                <span className="absolute -right-1.5 -top-1.5 flex h-5 min-w-5 items-center justify-center rounded-full bg-red-600 px-1 text-[10px] font-bold text-white">
                  {unreadNotifications > 9 ? "9+" : unreadNotifications}
                </span>
              )}
            </button>

            {notificationsOpen && (
              <div className="absolute right-0 top-12 z-40 w-[min(22rem,calc(100vw-2rem))] overflow-hidden rounded-xl border border-slate-200 bg-white shadow-xl">
                <div className="flex items-center justify-between border-b border-slate-200 px-4 py-3">
                  <div>
                    <p className="text-sm font-semibold text-slate-950">Notifications</p>
                    <p className="text-xs text-slate-500">{unreadNotifications} unread</p>
                  </div>
                  {unreadNotifications > 0 && (
                    <button
                      type="button"
                      onClick={() =>
                        setNotifications((current) =>
                          current.map((notification) => ({ ...notification, read: true })),
                        )
                      }
                      className="text-xs font-medium text-blue-700 hover:underline"
                    >
                      Mark all as read
                    </button>
                  )}
                </div>
                <div className="max-h-80 divide-y divide-slate-100 overflow-y-auto">
                  {notifications.map((notification) => (
                    <div
                      key={notification.id}
                      className={`flex gap-3 px-4 py-3 ${
                        notification.read ? "bg-white" : "bg-blue-50/60"
                      }`}
                    >
                      <span
                        className={`mt-1 h-2 w-2 shrink-0 rounded-full ${
                          notification.read ? "bg-slate-300" : "bg-blue-700"
                        }`}
                      />
                      <div className="min-w-0">
                        <p className="text-sm text-slate-800">{notification.title}</p>
                        <p className="mt-1 text-xs text-slate-500">
                          {relativeTime(notification.date)}
                        </p>
                      </div>
                    </div>
                  ))}
                  {notifications.length === 0 && (
                    <div className="px-4 py-10 text-center text-sm text-slate-500">
                      No new notifications.
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>
      </header>

      {error && (
        <div className="rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
          {error}
        </div>
      )}

      {/* کارت‌های آمار اصلی */}
      <section className="flex flex-col gap-4 md:flex-row">
        <StatCard
          title="Users"
          value={data.users.length}
          description="Total users"
          href="/admin/users"
          linkLabel="View all users"
          style={statStyles.users}
        />
        <StatCard
          title="Root Anchors"
          value={activeRoots.length}
          description="Configured"
          href="/admin/root-anchors"
          linkLabel="View root anchors"
          style={statStyles.roots}
        />
        <StatCard
          title="Authorities"
          value={activeAuthorities.length}
          description="Active"
          href="/admin/authorities"
          linkLabel="View authorities"
          style={statStyles.authorities}
        />
        <StatCard
          title="Federated Backends"
          value={data.backends.length}
          description={`${healthyBackends.length} healthy`}
          href="/admin/federation"
          linkLabel="View federation"
          style={statStyles.backends}
        />
      </section>

      {/* وضعیت امنیت و سلامت Federation */}
      <section className="grid items-stretch gap-4 md:grid-cols-2">
        <div id="security-status" className="lg:h-[190px]">
          <Panel
            title="Security Status"
            badge={
              <StatusPill healthy={allSecure}>
                {allSecure ? "All Systems Secure" : "Needs Attention"}
              </StatusPill>
            }
          >
            <div className="divide-y divide-slate-100 px-5">
              {activeAuthorities.map((authority) => {
                const healthy =
                  Boolean(authority.keyAvailability?.rsa) &&
                  Boolean(authority.keyAvailability?.ecdsa);
                return (
                  <div key={authority.id} className="flex items-center gap-3 py-2.5">
                    <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-emerald-50 text-emerald-600">
                      <Building2 size={18} />
                    </div>
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-sm font-medium text-slate-900">
                        {authority.name}
                      </p>
                      <p className="truncate text-xs text-slate-500">
                        {authority.isLocal ? "Local Authority" : authority.baseUrl}
                      </p>
                    </div>
                    <StatusPill healthy={healthy}>{healthy ? "Healthy" : "Check keys"}</StatusPill>
                  </div>
                );
              })}
              <div className="flex items-center gap-3 py-2.5">
                <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-emerald-50 text-emerald-600">
                  <ShieldCheck size={18} />
                </div>
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-medium text-slate-900">Root Anchors</p>
                  <p className="text-xs text-slate-500">
                    {activeRoots.length} active root anchor{activeRoots.length === 1 ? "" : "s"}
                  </p>
                </div>
                <StatusPill healthy={activeRoots.length > 0}>
                  {activeRoots.length > 0 ? "Healthy" : "Not configured"}
                </StatusPill>
              </div>
            </div>
          </Panel>
        </div>

        <div id="federation-health" className="lg:h-[190px]">
          <Panel
            title="Federation Health"
            badge={
              <StatusPill healthy={federationHealthy}>
                {federationHealthy ? "All Backends Healthy" : "Needs Attention"}
              </StatusPill>
            }
          >
            <div className="divide-y divide-slate-100 px-5">
              {data.backends.map((backend) => {
                const healthy = backend.status === "active";
                return (
                  <div key={backend.id} className="flex items-center gap-3 py-2.5">
                    <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-sky-50 text-sky-700">
                      <Server size={18} />
                    </div>
                    <div className="min-w-0 flex-1">
                      <p className="truncate text-sm font-medium text-slate-900">{backend.name}</p>
                      <p className="truncate text-xs text-slate-500">
                        {backend.url || backend.backendId}
                      </p>
                    </div>
                    <StatusPill healthy={healthy}>
                      {healthy ? "Healthy" : backend.status}
                    </StatusPill>
                  </div>
                );
              })}
              {!loading && data.backends.length === 0 && (
                <p className="py-8 text-center text-sm text-slate-500">
                  No federated backends configured.
                </p>
              )}
            </div>
          </Panel>
        </div>
      </section>

      {/* ردیف پایین مطابق تصویر: Activity در چپ و Users در راست */}
      <section className="flex flex-col gap-4 lg:flex-row">
        <div className="w-full lg:h-[230px] lg:w-1/2">
          <Panel
            title="Recent Activity"
            badge={<span className="text-xs font-medium text-blue-700">Latest updates</span>}
          >
            <div className="divide-y divide-slate-100">
              {recentActivity.map((activity) => {
                const ActivityIcon = activity.icon;
                return (
                  <div key={activity.id} className="flex items-center gap-3 px-4 py-2">
                    <span
                      className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-full ${activity.iconClass}`}
                    >
                      <ActivityIcon size={16} />
                    </span>
                    <p className="min-w-0 flex-1 truncate text-sm text-slate-800">
                      {activity.title}
                    </p>
                    <span className="shrink-0 text-xs text-slate-500">
                      {relativeTime(activity.date)}
                    </span>
                  </div>
                );
              })}
              {!loading && recentActivity.length === 0 && (
                <div className="flex flex-col items-center py-10 text-slate-500">
                  <Clock3 size={22} className="mb-2 text-slate-300" />
                  <p className="text-sm">No recent activity.</p>
                </div>
              )}
            </div>
          </Panel>
        </div>

        <div id="users" className="w-full min-w-0 lg:h-[230px] lg:w-1/2">
          <Panel
            title="Users"
            badge={
              <a
                href="/admin/users"
                className="flex items-center gap-1 text-xs font-medium text-blue-700"
              >
                View all users <ArrowRight size={14} />
              </a>
            }
          >
            <div className="overflow-x-auto lg:overflow-visible">
              <table className="w-full min-w-[680px] table-fixed text-left text-sm lg:min-w-0">
                <thead className="bg-slate-50 text-xs text-slate-600">
                  <tr>
                    <th className="w-[38%] px-3 py-2 font-semibold">Username</th>
                    <th className="w-[24%] px-3 py-2 font-semibold">Role</th>
                    <th className="w-[18%] px-3 py-2 font-semibold">Status</th>
                    <th className="w-[20%] px-3 py-2 font-semibold">Created</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {visibleUsers.map((user, index) => (
                    <tr key={user.id} className="transition hover:bg-slate-50/80">
                      <td className="px-3 py-2">
                        <div className="flex items-center gap-3">
                          <span
                            className={[
                              "flex h-8 w-8 items-center justify-center rounded-full text-xs font-semibold",
                              index % 2
                                ? "bg-violet-50 text-violet-700"
                                : "bg-blue-50 text-blue-700",
                            ].join(" ")}
                          >
                            {initials(user)}
                          </span>
                          <div className="min-w-0">
                            <p className="truncate font-medium text-slate-900">
                              {user.displayName || user.email}
                            </p>
                            {user.displayName && (
                              <p className="truncate text-xs text-slate-500">{user.email}</p>
                            )}
                          </div>
                        </div>
                      </td>
                      <td className="truncate px-3 py-2 text-slate-600">{roleLabels[user.role]}</td>
                      <td className="px-3 py-2">
                        <StatusPill healthy={!user.disabledAt}>
                          {user.disabledAt ? "Disabled" : "Active"}
                        </StatusPill>
                      </td>
                      <td className="truncate px-3 py-2 text-slate-500">
                        {user.createdAt ? new Date(user.createdAt).toLocaleDateString() : "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {!loading && visibleUsers.length === 0 && (
                <div className="flex flex-col items-center py-10 text-slate-500">
                  <CheckCircle2 size={24} className="mb-2 text-slate-300" />
                  <p className="text-sm">No users found.</p>
                </div>
              )}
              {loading && (
                <p className="py-10 text-center text-sm text-slate-500">Loading overview…</p>
              )}
            </div>
          </Panel>
        </div>
      </section>

      <Footer pushToBottom />
    </div>
  );
}
