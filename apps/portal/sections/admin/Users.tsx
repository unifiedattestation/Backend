import { useCallback, useEffect, useMemo, useState } from "react";
import { createPortal } from "react-dom";
import {
  ArrowLeft,
  ArrowRight,
  Building2,
  Check,
  Code2,
  Eye,
  EyeOff,
  KeyRound,
  Loader2,
  MoreVertical,
  Plus,
  RefreshCw,
  Search,
  ShieldCheck,
  UserRound,
  Users as UsersIcon,
  X,
} from "lucide-react";
import Footer from "../../components/Footer";
import { backendUrl } from "../../lib/config";

type UserRole = "admin" | "oem" | "app_dev";

type AdminUser = {
  id: string;
  email: string;
  role: UserRole;
  displayName?: string | null;
  disabledAt?: string | null;
  createdAt: string;
};

type DrawerMode = "create" | "password";

const roleLabels: Record<UserRole, string> = {
  admin: "Administrator",
  oem: "OEM",
  app_dev: "App Developer",
};

const pageSize = 8;

function initials(user: AdminUser) {
  return (user.displayName || user.email).slice(0, 2).toUpperCase();
}

function RoleIcon({ role, size = 17 }: { role: UserRole; size?: number }) {
  if (role === "admin") return <ShieldCheck size={size} />;
  if (role === "oem") return <Building2 size={size} />;
  return <Code2 size={size} />;
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

export default function AdminUsers() {
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [roleFilter, setRoleFilter] = useState<"all" | UserRole>("all");
  const [statusFilter, setStatusFilter] = useState<"all" | "active" | "disabled">("all");
  const [page, setPage] = useState(1);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [drawerMode, setDrawerMode] = useState<DrawerMode>("create");
  const [selectedUser, setSelectedUser] = useState<AdminUser | null>(null);
  const [actionMenu, setActionMenu] = useState<string | null>(null);
  const [actionMenuPosition, setActionMenuPosition] = useState({ top: 0, left: 0 });
  const [showPassword, setShowPassword] = useState(false);
  const [newUser, setNewUser] = useState({
    email: "",
    password: "",
    role: "app_dev" as "app_dev" | "oem",
  });
  const [replacementPassword, setReplacementPassword] = useState("");

  const getAccessToken = () => localStorage.getItem("ua_access");

  const loadUsers = useCallback(async () => {
    const accessToken = getAccessToken();
    if (!accessToken) {
      window.location.href = "/login";
      return;
    }

    setLoading(true);
    try {
      const response = await fetch(`${backendUrl}/api/v1/admin/users`, {
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      if (response.status === 401) {
        localStorage.removeItem("ua_access");
        localStorage.removeItem("ua_refresh");
        window.location.href = "/login";
        return;
      }
      if (!response.ok) throw new Error("Unable to load users.");
      setUsers(await response.json());
      setError(null);
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Unable to load users.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadUsers();
  }, [loadUsers]);

  const filteredUsers = useMemo(() => {
    const query = search.trim().toLowerCase();
    return users.filter((user) => {
      const matchesSearch =
        !query ||
        user.email.toLowerCase().includes(query) ||
        user.displayName?.toLowerCase().includes(query);
      const matchesRole = roleFilter === "all" || user.role === roleFilter;
      const matchesStatus =
        statusFilter === "all" ||
        (statusFilter === "active" && !user.disabledAt) ||
        (statusFilter === "disabled" && Boolean(user.disabledAt));
      return matchesSearch && matchesRole && matchesStatus;
    });
  }, [users, search, roleFilter, statusFilter]);

  const totalPages = Math.max(1, Math.ceil(filteredUsers.length / pageSize));
  const visibleUsers = filteredUsers.slice((page - 1) * pageSize, page * pageSize);

  useEffect(() => {
    setPage(1);
  }, [search, roleFilter, statusFilter]);

  useEffect(() => {
    if (page > totalPages) setPage(totalPages);
  }, [page, totalPages]);

  const openCreateDrawer = () => {
    setDrawerMode("create");
    setSelectedUser(null);
    setNewUser({ email: "", password: "", role: "app_dev" });
    setShowPassword(false);
    setError(null);
    setDrawerOpen(true);
  };

  const openPasswordDrawer = (user: AdminUser) => {
    setDrawerMode("password");
    setSelectedUser(user);
    setReplacementPassword("");
    setShowPassword(false);
    setError(null);
    setActionMenu(null);
    setDrawerOpen(true);
  };

  const createUser = async () => {
    const accessToken = getAccessToken();
    if (!accessToken) return;
    if (!newUser.email.trim()) {
      setError("Username is required.");
      return;
    }
    if (newUser.password.length < 5) {
      setError("Password must be at least 5 characters.");
      return;
    }

    setSubmitting(true);
    setError(null);
    try {
      const response = await fetch(`${backendUrl}/api/v1/admin/users`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${accessToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(newUser),
      });
      if (!response.ok) {
        const message = await response.text();
        throw new Error(message || "Unable to create user.");
      }
      setDrawerOpen(false);
      setNotice("User created successfully.");
      await loadUsers();
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Unable to create user.");
    } finally {
      setSubmitting(false);
    }
  };

  const changeUserStatus = async (user: AdminUser) => {
    const accessToken = getAccessToken();
    if (!accessToken) return;
    setActionMenu(null);
    setError(null);
    const action = user.disabledAt ? "enable" : "disable";

    try {
      const response = await fetch(`${backendUrl}/api/v1/admin/users/${user.id}/${action}`, {
        method: "POST",
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      if (!response.ok) throw new Error(`Unable to ${action} user.`);
      setNotice(`User ${action}d successfully.`);
      await loadUsers();
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : `Unable to ${action} user.`);
    }
  };

  const updatePassword = async () => {
    const accessToken = getAccessToken();
    if (!accessToken || !selectedUser) return;
    if (replacementPassword.length < 5) {
      setError("Password must be at least 5 characters.");
      return;
    }

    setSubmitting(true);
    setError(null);
    try {
      const response = await fetch(`${backendUrl}/api/v1/admin/users/${selectedUser.id}/password`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${accessToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ password: replacementPassword }),
      });
      if (!response.ok) {
        const message = await response.text();
        throw new Error(message || "Unable to update password.");
      }
      setDrawerOpen(false);
      setNotice("Password updated successfully.");
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Unable to update password.");
    } finally {
      setSubmitting(false);
    }
  };

  const deleteUser = async (user: AdminUser) => {
    if (!window.confirm(`Delete ${user.email}? This action cannot be undone.`)) return;
    const accessToken = getAccessToken();
    if (!accessToken) return;
    setActionMenu(null);

    try {
      const response = await fetch(`${backendUrl}/api/v1/admin/users/${user.id}`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      if (!response.ok) {
        const message = await response.text();
        throw new Error(message || "Unable to delete user.");
      }
      setNotice("User deleted successfully.");
      await loadUsers();
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Unable to delete user.");
    }
  };

  const roleCounts = {
    admin: users.filter((user) => user.role === "admin").length,
    oem: users.filter((user) => user.role === "oem").length,
    app_dev: users.filter((user) => user.role === "app_dev").length,
  };

  return (
    <div className="flex min-h-[calc(100vh-3rem)] flex-col gap-5">
      {/* هدر صفحه */}
      <header className="flex flex-col gap-4 border-b border-slate-200 pb-4 sm:flex-row sm:items-center sm:justify-between">
        <h1 className="text-2xl font-bold tracking-tight text-[#071226]">Users</h1>
        <label className="relative w-full sm:w-80">
          <Search
            size={18}
            className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-400"
          />
          <input
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Search users..."
            className="h-10 w-full rounded-lg border border-slate-200 bg-white pl-10 pr-3 text-sm outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-100"
          />
        </label>
      </header>

      <section className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <h2 className="text-xl font-semibold text-[#071226]">User Management</h2>
          <p className="mt-1 text-sm text-slate-500">
            Create and manage access across your attestation ecosystem.
          </p>
        </div>
        <button
          type="button"
          onClick={openCreateDrawer}
          className="flex h-10 items-center justify-center gap-2 rounded-lg bg-[#071226] px-4 text-sm font-medium text-white transition hover:bg-[#101f36]"
        >
          <Plus size={18} />
          Create User
        </button>
      </section>

      {/* کارت‌های آمار از داده واقعی backend */}
      <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard
          label="Total Users"
          value={users.length}
          icon={<UsersIcon size={23} />}
          color="bg-blue-50 text-blue-700"
        />
        <StatCard
          label="Administrators"
          value={roleCounts.admin}
          icon={<ShieldCheck size={23} />}
          color="bg-emerald-50 text-emerald-700"
        />
        <StatCard
          label="OEM Accounts"
          value={roleCounts.oem}
          icon={<Building2 size={23} />}
          color="bg-sky-50 text-sky-700"
        />
        <StatCard
          label="App Developers"
          value={roleCounts.app_dev}
          icon={<Code2 size={23} />}
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

      {/* فیلتر و جدول کاربران */}
      <section className="overflow-visible rounded-xl border border-slate-200 bg-white shadow-sm">
        <div className="grid gap-3 border-b border-slate-200 p-4 sm:grid-cols-2 xl:grid-cols-[1fr_210px_210px_44px]">
          <label className="relative">
            <Search
              size={17}
              className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-400"
            />
            <input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Search users..."
              className="h-10 w-full rounded-lg border border-slate-200 pl-9 pr-3 text-sm outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-100"
            />
          </label>
          <select
            value={roleFilter}
            onChange={(event) => setRoleFilter(event.target.value as "all" | UserRole)}
            className="h-10 rounded-lg border border-slate-200 bg-white px-3 text-sm text-slate-700 outline-none focus:border-blue-600"
          >
            <option value="all">All Roles</option>
            <option value="admin">Administrators</option>
            <option value="oem">OEM Accounts</option>
            <option value="app_dev">App Developers</option>
          </select>
          <select
            value={statusFilter}
            onChange={(event) =>
              setStatusFilter(event.target.value as "all" | "active" | "disabled")
            }
            className="h-10 rounded-lg border border-slate-200 bg-white px-3 text-sm text-slate-700 outline-none focus:border-blue-600"
          >
            <option value="all">All Statuses</option>
            <option value="active">Active</option>
            <option value="disabled">Disabled</option>
          </select>
          <button
            type="button"
            onClick={loadUsers}
            aria-label="Refresh users"
            className="flex h-10 items-center justify-center rounded-lg border border-slate-200 text-slate-600 transition hover:bg-slate-50"
          >
            <RefreshCw size={17} className={loading ? "animate-spin" : ""} />
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full min-w-[820px] text-left text-sm">
            <thead className="bg-slate-50 text-xs text-slate-500">
              <tr>
                <th className="px-5 py-3 font-semibold">User</th>
                <th className="px-5 py-3 font-semibold">Role</th>
                <th className="px-5 py-3 font-semibold">Status</th>
                <th className="px-5 py-3 font-semibold">Created</th>
                <th className="px-5 py-3 text-right font-semibold">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {visibleUsers.map((user, index) => (
                <tr key={user.id} className="transition hover:bg-slate-50/70">
                  <td className="px-5 py-3">
                    <div className="flex items-center gap-3">
                      <span
                        className={[
                          "flex h-9 w-9 items-center justify-center rounded-full text-xs font-semibold",
                          index % 2 ? "bg-violet-50 text-violet-700" : "bg-blue-50 text-blue-700",
                        ].join(" ")}
                      >
                        {initials(user)}
                      </span>
                      <div className="min-w-0">
                        <p className="font-medium text-slate-900">
                          {user.displayName || user.email}
                        </p>
                        {user.displayName && <p className="text-xs text-slate-500">{user.email}</p>}
                      </div>
                    </div>
                  </td>
                  <td className="px-5 py-3">
                    <span className="inline-flex items-center gap-2 text-slate-600">
                      <RoleIcon role={user.role} />
                      {roleLabels[user.role]}
                    </span>
                  </td>
                  <td className="px-5 py-3">
                    <StatusBadge active={!user.disabledAt} />
                  </td>
                  <td className="px-5 py-3 text-slate-500">
                    {new Date(user.createdAt).toLocaleString()}
                  </td>
                  <td className="relative px-5 py-3 text-right">
                    <button
                      type="button"
                      onClick={(event) => {
                        if (actionMenu === user.id) {
                          setActionMenu(null);
                          return;
                        }
                        const rect = event.currentTarget.getBoundingClientRect();
                        const menuHeight = user.role === "admin" ? 48 : 128;
                        setActionMenuPosition({
                          top:
                            rect.bottom + menuHeight + 8 <= window.innerHeight
                              ? rect.bottom + 6
                              : rect.top - menuHeight - 6,
                          left: Math.max(12, rect.right - 176),
                        });
                        setActionMenu(user.id);
                      }}
                      aria-label={`Actions for ${user.email}`}
                      className="rounded-lg p-2 text-slate-500 transition hover:bg-slate-100 hover:text-[#071226]"
                    >
                      <MoreVertical size={18} />
                    </button>
                    {actionMenu === user.id &&
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
                              onClick={() => openPasswordDrawer(user)}
                              className="flex w-full items-center gap-2 px-3 py-2 text-sm text-slate-700 hover:bg-slate-50"
                            >
                              <KeyRound size={16} />
                              Reset password
                            </button>
                            {user.role !== "admin" && (
                              <>
                                <button
                                  type="button"
                                  onClick={() => changeUserStatus(user)}
                                  className="flex w-full items-center gap-2 px-3 py-2 text-sm text-slate-700 hover:bg-slate-50"
                                >
                                  {user.disabledAt ? <Check size={16} /> : <X size={16} />}
                                  {user.disabledAt ? "Enable user" : "Disable user"}
                                </button>
                                <button
                                  type="button"
                                  onClick={() => deleteUser(user)}
                                  className="flex w-full items-center gap-2 px-3 py-2 text-sm text-red-600 hover:bg-red-50"
                                >
                                  <X size={16} />
                                  Delete user
                                </button>
                              </>
                            )}
                          </div>
                        </>,
                        document.body,
                      )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          {!loading && visibleUsers.length === 0 && (
            <div className="px-5 py-12 text-center text-sm text-slate-500">No users found.</div>
          )}
          {loading && (
            <div className="flex items-center justify-center gap-2 px-5 py-12 text-sm text-slate-500">
              <Loader2 size={18} className="animate-spin" />
              Loading users...
            </div>
          )}
        </div>

        <footer className="flex flex-col gap-3 border-t border-slate-200 px-5 py-4 text-xs text-slate-500 sm:flex-row sm:items-center sm:justify-between">
          <span>
            Showing {filteredUsers.length === 0 ? 0 : (page - 1) * pageSize + 1} to{" "}
            {Math.min(page * pageSize, filteredUsers.length)} of {filteredUsers.length} users
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

      {drawerOpen && (
        <>
          <button
            type="button"
            aria-label="Close drawer"
            onClick={() => setDrawerOpen(false)}
            className="fixed inset-0 z-40 bg-[#071226]/40 backdrop-blur-[1px]"
          />
          <aside className="fixed inset-y-0 right-0 z-50 flex w-full max-w-md flex-col bg-white shadow-2xl">
            <header className="flex items-center justify-between border-b border-slate-200 px-6 py-5">
              <div>
                <h2 className="text-lg font-semibold text-[#071226]">
                  {drawerMode === "create" ? "Create User" : "Reset Password"}
                </h2>
                {drawerMode === "password" && selectedUser && (
                  <p className="mt-1 text-xs text-slate-500">{selectedUser.email}</p>
                )}
              </div>
              <button
                type="button"
                onClick={() => setDrawerOpen(false)}
                className="rounded-lg p-2 text-slate-500 hover:bg-slate-100"
              >
                <X size={20} />
              </button>
            </header>

            <div className="flex-1 space-y-5 overflow-y-auto p-6">
              {drawerMode === "create" ? (
                <>
                  <div>
                    <label className="text-sm font-medium text-slate-700">Username</label>
                    <div className="relative mt-2">
                      <UserRound
                        size={18}
                        className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400"
                      />
                      <input
                        value={newUser.email}
                        onChange={(event) =>
                          setNewUser((current) => ({ ...current, email: event.target.value }))
                        }
                        placeholder="Enter username"
                        className="h-11 w-full rounded-lg border border-slate-200 pl-10 pr-3 text-sm outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-100"
                      />
                    </div>
                  </div>
                  <div>
                    <label className="text-sm font-medium text-slate-700">Temporary Password</label>
                    <div className="relative mt-2">
                      <KeyRound
                        size={18}
                        className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400"
                      />
                      <input
                        type={showPassword ? "text" : "password"}
                        value={newUser.password}
                        onChange={(event) =>
                          setNewUser((current) => ({ ...current, password: event.target.value }))
                        }
                        placeholder="At least 5 characters"
                        className="h-11 w-full rounded-lg border border-slate-200 pl-10 pr-11 text-sm outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-100"
                      />
                      <button
                        type="button"
                        onClick={() => setShowPassword((visible) => !visible)}
                        className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400"
                      >
                        {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                      </button>
                    </div>
                  </div>
                  <div>
                    <label className="text-sm font-medium text-slate-700">Role</label>
                    <select
                      value={newUser.role}
                      onChange={(event) =>
                        setNewUser((current) => ({
                          ...current,
                          role: event.target.value as "app_dev" | "oem",
                        }))
                      }
                      className="mt-2 h-11 w-full rounded-lg border border-slate-200 bg-white px-3 text-sm outline-none focus:border-blue-600"
                    >
                      <option value="app_dev">App Developer</option>
                      <option value="oem">OEM</option>
                    </select>
                  </div>
                  <div className="rounded-xl border border-blue-200 bg-blue-50 p-4">
                    <div className="flex gap-3">
                      <ShieldCheck className="shrink-0 text-blue-700" size={22} />
                      <div>
                        <p className="text-sm font-semibold text-slate-800">Security Note</p>
                        <p className="mt-1 text-xs leading-5 text-slate-600">
                          Share the temporary password securely. The administrator can reset it at
                          any time.
                        </p>
                      </div>
                    </div>
                  </div>
                </>
              ) : (
                <div>
                  <label className="text-sm font-medium text-slate-700">New Password</label>
                  <div className="relative mt-2">
                    <KeyRound
                      size={18}
                      className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400"
                    />
                    <input
                      type={showPassword ? "text" : "password"}
                      value={replacementPassword}
                      onChange={(event) => setReplacementPassword(event.target.value)}
                      placeholder="At least 5 characters"
                      className="h-11 w-full rounded-lg border border-slate-200 pl-10 pr-11 text-sm outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-100"
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword((visible) => !visible)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400"
                    >
                      {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                    </button>
                  </div>
                </div>
              )}

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
                onClick={drawerMode === "create" ? createUser : updatePassword}
                disabled={submitting}
                className="flex h-11 items-center justify-center gap-2 rounded-lg bg-[#071226] text-sm font-medium text-white hover:bg-[#101f36] disabled:opacity-60"
              >
                {submitting && <Loader2 size={17} className="animate-spin" />}
                {drawerMode === "create" ? "Create User" : "Update Password"}
              </button>
            </footer>
          </aside>
        </>
      )}
    </div>
  );
}
