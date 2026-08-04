import { useCallback, useEffect, useMemo, useState } from "react";
import { createPortal } from "react-dom";
import {
  Activity,
  AlertCircle,
  ArrowLeft,
  ArrowRight,
  BarChart3,
  Building2,
  Check,
  CheckCircle2,
  Code2,
  FileText,
  KeyRound,
  Loader2,
  MoreVertical,
  Search,
  ShieldCheck,
  Smartphone,
  Trash2,
  UserPlus,
  Users,
  X,
} from "lucide-react";
import OemFooter from "../../components/oem/Footer";
import { backendUrl } from "../../lib/config";

type Organization = {
  id: string;
  name: string;
  manufacturer?: string | null;
  brand?: string | null;
  createdAt: string;
};

type Member = {
  id: string;
  email: string;
  displayName?: string | null;
  organizationRole: string;
  status: "active" | "disabled";
  createdAt: string;
};

type Invite = {
  id: string;
  email: string;
  role: string;
  message: string;
  createdAt: string;
  expiresAt: string;
};

type ActivityItem = {
  id: string;
  action: string;
  details: Record<string, unknown>;
  createdAt: string;
  actorName: string;
};

type OrganizationResponse = {
  organization: Organization;
  members: Member[];
  pendingInvites: Invite[];
  activity: ActivityItem[];
};

const roleOptions = [
  ["administrator", "Administrator"],
  ["security_analyst", "Security Analyst"],
  ["developer", "Developer"],
  ["viewer", "Viewer"],
];

const tabs = ["General", "Members", "Roles & Permissions", "Security", "Billing"];

export default function OemOrganization({
  onOrganizationLoaded,
}: {
  onOrganizationLoaded?: (name: string) => void;
}) {
  const [organization, setOrganization] = useState<Organization | null>(null);
  const [members, setMembers] = useState<Member[]>([]);
  const [invites, setInvites] = useState<Invite[]>([]);
  const [activity, setActivity] = useState<ActivityItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState("Members");
  const [inviteOpen, setInviteOpen] = useState(false);
  const [email, setEmail] = useState("");
  const [role, setRole] = useState("viewer");
  const [message, setMessage] = useState("");
  const [sendEmail, setSendEmail] = useState(true);
  const [search, setSearch] = useState("");
  const [roleFilter, setRoleFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  const [page, setPage] = useState(1);
  const [menuId, setMenuId] = useState<string | null>(null);
  const [menuPosition, setMenuPosition] = useState({ top: 0, left: 0 });
  const [auditOpen, setAuditOpen] = useState(false);
  const [profileName, setProfileName] = useState("");
  const [manufacturer, setManufacturer] = useState("");
  const [brand, setBrand] = useState("");
  const pageSize = 6;

  const load = useCallback(async () => {
    const token = localStorage.getItem("ua_access");
    if (!token) {
      window.location.href = "/login";
      return;
    }
    setLoading(true);
    try {
      const response = await fetch(`${backendUrl}/api/v1/oem/organization`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (response.status === 401) {
        localStorage.removeItem("ua_access");
        localStorage.removeItem("ua_refresh");
        window.location.href = "/login";
        return;
      }
      let data: OrganizationResponse;
      if (response.ok) {
        data = await response.json();
      } else {
        const profileResponse = await fetch(`${backendUrl}/api/v1/oem/profile`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (!profileResponse.ok) throw new Error("Unable to connect to the backend.");
        const profile = await profileResponse.json();
        const currentUser = readCurrentUser(token);
        data = {
          organization: {
            id: profile.id,
            name: profile.name || "OEM Portal",
            manufacturer: profile.manufacturer,
            brand: profile.brand,
            createdAt: profile.createdAt,
          },
          members: currentUser
            ? [
                {
                  id: currentUser.id,
                  email: currentUser.email,
                  displayName: currentUser.name,
                  organizationRole: "owner",
                  status: "active",
                  createdAt: profile.createdAt,
                },
              ]
            : [],
          pendingInvites: [],
          activity: [],
        };
      }
      setOrganization(data.organization);
      setMembers(data.members || []);
      setInvites(data.pendingInvites || []);
      setActivity(data.activity || []);
      setProfileName(data.organization.name || "");
      setManufacturer(data.organization.manufacturer || "");
      setBrand(data.organization.brand || "");
      onOrganizationLoaded?.(data.organization.name || "OEM Portal");
      setError(null);
    } catch (requestError) {
      setError(
        requestError instanceof Error ? requestError.message : "Unable to load organization.",
      );
    } finally {
      setLoading(false);
    }
  }, [onOrganizationLoaded]);

  useEffect(() => {
    load();
  }, [load]);

  const rows = useMemo(() => {
    const memberRows = members.map((member) => ({ ...member, pending: false }));
    const inviteRows = invites.map((invite) => ({
      id: invite.id,
      email: invite.email,
      displayName: null,
      organizationRole: invite.role,
      status: "pending" as const,
      createdAt: invite.createdAt,
      pending: true,
    }));
    const query = search.trim().toLowerCase();
    return [...memberRows, ...inviteRows].filter((item) => {
      const matchesSearch =
        !query ||
        item.email.toLowerCase().includes(query) ||
        item.displayName?.toLowerCase().includes(query);
      const matchesRole = roleFilter === "all" || item.organizationRole === roleFilter;
      const matchesStatus = statusFilter === "all" || item.status === statusFilter;
      return matchesSearch && matchesRole && matchesStatus;
    });
  }, [members, invites, search, roleFilter, statusFilter]);

  useEffect(() => {
    setPage(1);
  }, [search, roleFilter, statusFilter]);

  const totalPages = Math.max(1, Math.ceil(rows.length / pageSize));
  const visibleRows = rows.slice((page - 1) * pageSize, page * pageSize);
  const administrators = members.filter((member) =>
    ["owner", "administrator"].includes(member.organizationRole),
  ).length;

  const inviteMember = async () => {
    const token = localStorage.getItem("ua_access");
    setSaving(true);
    try {
      const response = await fetch(`${backendUrl}/api/v1/oem/organization/invites`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify({ email, role, message, sendEmail }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data?.message || "Unable to send invitation.");
      setInviteOpen(false);
      setEmail("");
      setMessage("");
      setNotice("Invitation created successfully.");
      await load();
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Unable to invite member.");
    } finally {
      setSaving(false);
    }
  };

  const removeRow = async (row: (typeof rows)[number]) => {
    const token = localStorage.getItem("ua_access");
    const url = row.pending
      ? `${backendUrl}/api/v1/oem/organization/invites/${encodeURIComponent(row.email)}`
      : `${backendUrl}/api/v1/oem/organization/members/${row.id}`;
    setSaving(true);
    try {
      const response = await fetch(url, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data?.message || "Unable to remove member.");
      setMenuId(null);
      setNotice(row.pending ? "Invitation cancelled." : "Member removed.");
      await load();
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Unable to update member.");
    } finally {
      setSaving(false);
    }
  };

  const saveProfile = async () => {
    const token = localStorage.getItem("ua_access");
    setSaving(true);
    try {
      const response = await fetch(`${backendUrl}/api/v1/oem/profile`, {
        method: "PUT",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify({ name: profileName, manufacturer, brand }),
      });
      if (!response.ok) throw new Error("Unable to save organization profile.");
      setNotice("Organization profile saved.");
      await load();
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Unable to save profile.");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="flex min-h-[calc(100vh-3rem)] flex-col gap-5">
      <header className="flex flex-col gap-4 border-b border-slate-200 pb-0">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
          <div>
            <h1 className="text-2xl font-bold tracking-tight text-[#071226]">Organization</h1>
            <p className="mt-1 text-sm text-slate-500">
              Manage your organization profile, members, roles, and security settings.
            </p>
          </div>
          <div className="flex flex-col gap-2 sm:flex-row">
            <button
              type="button"
              onClick={() => setAuditOpen(true)}
              className="flex h-10 items-center justify-center gap-2 rounded-lg border border-slate-300 bg-white px-4 text-sm text-slate-700 hover:bg-slate-50"
            >
              <FileText size={17} />
              View Audit Log
            </button>
            <button
              type="button"
              onClick={() => setInviteOpen(true)}
              className="flex h-10 items-center justify-center gap-2 rounded-lg bg-[#071226] px-4 text-sm font-medium text-white hover:bg-[#101f36]"
            >
              <UserPlus size={17} />
              Invite Member
            </button>
          </div>
        </div>
        <nav className="flex gap-1 overflow-x-auto" aria-label="Organization sections">
          {tabs.map((tab) => (
            <button
              key={tab}
              type="button"
              onClick={() => setActiveTab(tab)}
              className={`whitespace-nowrap border-b-2 px-4 py-3 text-sm ${activeTab === tab ? "border-blue-700 text-blue-700" : "border-transparent text-slate-500 hover:text-slate-800"}`}
            >
              {tab}
            </button>
          ))}
        </nav>
      </header>

      {error && <Message tone="error" text={error} onClose={() => setError(null)} />}
      {notice && <Message tone="success" text={notice} onClose={() => setNotice(null)} />}

      {activeTab === "Members" && (
        <>
          <section className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            <StatCard label="Team Members" value={members.length} icon={<Users />} tone="blue" />
            <StatCard
              label="Administrators"
              value={administrators}
              icon={<ShieldCheck />}
              tone="green"
            />
            <StatCard
              label="Pending Invites"
              value={invites.length}
              icon={<UserPlus />}
              tone="amber"
            />
            <StatCard
              label="Active Sessions"
              value={members.filter((member) => member.status === "active").length}
              icon={<Smartphone />}
              tone="cyan"
            />
          </section>

          <section className="overflow-visible rounded-xl border border-slate-200 bg-white shadow-sm">
            <header className="border-b border-slate-200 p-4">
              <h2 className="text-lg font-semibold text-[#071226]">Members</h2>
              <p className="mt-1 text-xs text-slate-500">
                People who can access and manage {organization?.name || "this OEM organization"}.
              </p>
              <div className="mt-4 grid gap-3 md:grid-cols-[1fr_200px_200px]">
                <label className="relative">
                  <Search
                    size={17}
                    className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400"
                  />
                  <input
                    value={search}
                    onChange={(event) => setSearch(event.target.value)}
                    placeholder="Search members"
                    className="h-10 w-full rounded-lg border border-slate-200 pl-10 pr-3 text-sm outline-none focus:border-blue-600"
                  />
                </label>
                <select
                  value={roleFilter}
                  onChange={(event) => setRoleFilter(event.target.value)}
                  className="h-10 rounded-lg border border-slate-200 bg-white px-3 text-sm"
                >
                  <option value="all">All roles</option>
                  <option value="owner">Owner</option>
                  {roleOptions.map(([value, label]) => (
                    <option key={value} value={value}>
                      {label}
                    </option>
                  ))}
                </select>
                <select
                  value={statusFilter}
                  onChange={(event) => setStatusFilter(event.target.value)}
                  className="h-10 rounded-lg border border-slate-200 bg-white px-3 text-sm"
                >
                  <option value="all">All statuses</option>
                  <option value="active">Active</option>
                  <option value="disabled">Disabled</option>
                  <option value="pending">Pending</option>
                </select>
              </div>
            </header>
            <div className="overflow-x-auto">
              <table className="w-full min-w-[900px] text-left text-sm">
                <thead className="bg-slate-50 text-xs text-slate-500">
                  <tr>
                    <th className="px-4 py-3">Member</th>
                    <th className="px-4 py-3">Email</th>
                    <th className="px-4 py-3">Role</th>
                    <th className="px-4 py-3">Access</th>
                    <th className="px-4 py-3">Joined / Invited</th>
                    <th className="px-4 py-3">Status</th>
                    <th className="px-4 py-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {visibleRows.map((row) => (
                    <MemberRow
                      key={row.id}
                      row={row}
                      menuOpen={menuId === row.id}
                      setMenu={(event) => {
                        if (menuId === row.id) {
                          setMenuId(null);
                          return;
                        }
                        const rect = event.currentTarget.getBoundingClientRect();
                        setMenuPosition({
                          top: Math.min(rect.bottom + 6, window.innerHeight - 112),
                          left: Math.max(12, rect.right - 190),
                        });
                        setMenuId(row.id);
                      }}
                      onRemove={() => removeRow(row)}
                      menuPosition={menuPosition}
                      closeMenu={() => setMenuId(null)}
                    />
                  ))}
                </tbody>
              </table>
              {loading && (
                <div className="flex items-center justify-center gap-2 py-14 text-sm text-slate-500">
                  <Loader2 size={18} className="animate-spin" />
                  Loading members...
                </div>
              )}
              {!loading && visibleRows.length === 0 && (
                <div className="py-14 text-center text-sm text-slate-500">No members found.</div>
              )}
            </div>
            <footer className="flex items-center justify-between border-t border-slate-200 px-5 py-4 text-xs text-slate-500">
              <span>
                {rows.length ? (page - 1) * pageSize + 1 : 0}–
                {Math.min(page * pageSize, rows.length)} of {rows.length}
              </span>
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  disabled={page === 1}
                  onClick={() => setPage((value) => value - 1)}
                  className="rounded-lg border border-slate-200 p-2 disabled:opacity-40"
                >
                  <ArrowLeft size={15} />
                </button>
                <span className="flex h-8 min-w-8 items-center justify-center rounded-lg border border-blue-600 px-2 text-blue-700">
                  {page}
                </span>
                <button
                  type="button"
                  disabled={page === totalPages}
                  onClick={() => setPage((value) => value + 1)}
                  className="rounded-lg border border-slate-200 p-2 disabled:opacity-40"
                >
                  <ArrowRight size={15} />
                </button>
              </div>
            </footer>
          </section>

          <section className="grid gap-4 xl:grid-cols-2">
            <RoleDistribution members={members} invites={invites} />
            <RecentActivity items={activity.slice(0, 5)} />
          </section>
        </>
      )}

      {activeTab === "General" && (
        <GeneralSettings
          name={profileName}
          setName={setProfileName}
          manufacturer={manufacturer}
          setManufacturer={setManufacturer}
          brand={brand}
          setBrand={setBrand}
          saving={saving}
          onSave={saveProfile}
        />
      )}
      {activeTab === "Roles & Permissions" && <RolesPanel />}
      {activeTab === "Security" && <SecurityPanel members={members} />}
      {activeTab === "Billing" && <BillingPanel organization={organization} />}

      <OemFooter />

      {inviteOpen &&
        typeof document !== "undefined" &&
        createPortal(
          <>
            <button
              type="button"
              aria-label="Close invitation drawer"
              onClick={() => setInviteOpen(false)}
              className="fixed inset-0 z-[9998] bg-[#071226]/55 backdrop-blur-sm"
            />
            <aside className="fixed inset-y-0 right-0 z-[9999] flex w-full max-w-md flex-col bg-white shadow-2xl">
              <header className="flex items-center justify-between border-b border-slate-200 px-6 py-5">
                <h2 className="text-lg font-semibold text-[#071226]">Invite Member</h2>
                <button type="button" onClick={() => setInviteOpen(false)}>
                  <X size={20} />
                </button>
              </header>
              <div className="flex-1 space-y-5 overflow-y-auto p-6">
                <Field
                  label="Email Address"
                  value={email}
                  onChange={setEmail}
                  placeholder="name@company.com"
                  type="email"
                />
                <label className="block">
                  <span className="text-sm font-medium text-slate-700">Role</span>
                  <select
                    value={role}
                    onChange={(event) => setRole(event.target.value)}
                    className="mt-2 h-11 w-full rounded-lg border border-slate-200 bg-white px-3 text-sm"
                  >
                    {roleOptions.map(([value, label]) => (
                      <option key={value} value={value}>
                        {label}
                      </option>
                    ))}
                  </select>
                </label>
                <AccessSummary role={role} />
                <label className="block">
                  <span className="text-sm font-medium text-slate-700">Optional Message</span>
                  <textarea
                    value={message}
                    onChange={(event) => setMessage(event.target.value)}
                    rows={4}
                    placeholder="Add a personal message..."
                    className="mt-2 w-full resize-none rounded-lg border border-slate-200 p-3 text-sm outline-none focus:border-blue-600"
                  />
                </label>
                <label className="flex items-center gap-3 text-sm text-slate-700">
                  <input
                    type="checkbox"
                    checked={sendEmail}
                    onChange={(event) => setSendEmail(event.target.checked)}
                    className="h-4 w-4 accent-blue-700"
                  />
                  Send invitation email
                </label>
                <div className="flex gap-3 rounded-lg border border-blue-200 bg-blue-50 p-4 text-sm text-blue-700">
                  <AlertCircle size={19} className="shrink-0" />
                  The invitation expires after 7 days.
                </div>
              </div>
              <footer className="grid grid-cols-2 gap-3 border-t border-slate-200 p-6">
                <button
                  type="button"
                  onClick={() => setInviteOpen(false)}
                  className="h-11 rounded-lg border border-slate-300 text-sm"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  disabled={saving || !email.trim()}
                  onClick={inviteMember}
                  className="flex h-11 items-center justify-center gap-2 rounded-lg bg-[#071226] text-sm font-medium text-white disabled:opacity-50"
                >
                  {saving && <Loader2 size={17} className="animate-spin" />}Send Invitation
                </button>
              </footer>
            </aside>
          </>,
          document.body,
        )}

      {auditOpen &&
        typeof document !== "undefined" &&
        createPortal(
          <>
            <button
              type="button"
              aria-label="Close audit log"
              onClick={() => setAuditOpen(false)}
              className="fixed inset-0 z-[9998] bg-[#071226]/55 backdrop-blur-sm"
            />
            <aside className="fixed inset-y-0 right-0 z-[9999] flex w-full max-w-xl flex-col bg-white shadow-2xl">
              <header className="flex items-center justify-between border-b border-slate-200 px-6 py-5">
                <div>
                  <h2 className="text-lg font-semibold text-[#071226]">Organization Audit Log</h2>
                  <p className="mt-1 text-xs text-slate-500">
                    Recent security and management activity.
                  </p>
                </div>
                <button type="button" onClick={() => setAuditOpen(false)}>
                  <X size={20} />
                </button>
              </header>
              <div className="flex-1 overflow-y-auto p-6">
                <RecentActivity items={activity} plain />
              </div>
            </aside>
          </>,
          document.body,
        )}
    </div>
  );
}

type OrganizationRow =
  | (Member & { pending: boolean })
  | {
      id: string;
      email: string;
      displayName: null;
      organizationRole: string;
      status: "pending";
      createdAt: string;
      pending: boolean;
    };

function MemberRow({
  row,
  menuOpen,
  setMenu,
  onRemove,
  menuPosition,
  closeMenu,
}: {
  row: OrganizationRow;
  menuOpen: boolean;
  setMenu: (event: React.MouseEvent<HTMLButtonElement>) => void;
  onRemove: () => void;
  menuPosition: { top: number; left: number };
  closeMenu: () => void;
}) {
  const name = row.displayName || (row.pending ? row.email : row.email.split("@")[0]);
  return (
    <tr className="hover:bg-slate-50/70">
      <td className="px-4 py-3">
        <div className="flex items-center gap-3">
          <span className="flex h-8 w-8 items-center justify-center rounded-full bg-blue-100 text-xs font-semibold text-blue-700">
            {initials(name)}
          </span>
          <span className="font-medium text-slate-700">{name}</span>
        </div>
      </td>
      <td className="px-4 py-3 text-slate-500">{row.email}</td>
      <td className="px-4 py-3">
        <RoleBadge role={row.organizationRole} />
      </td>
      <td className="px-4 py-3 text-xs text-slate-500">{accessLabel(row.organizationRole)}</td>
      <td className="px-4 py-3 text-xs text-slate-500">
        {new Date(row.createdAt).toLocaleDateString()}
      </td>
      <td className="px-4 py-3">
        <StatusBadge status={row.status} />
      </td>
      <td className="px-4 py-3 text-right">
        <button
          type="button"
          onClick={setMenu}
          className="rounded-lg p-2 text-slate-500 hover:bg-slate-100"
        >
          <MoreVertical size={18} />
        </button>
        {menuOpen &&
          typeof document !== "undefined" &&
          createPortal(
            <>
              <button
                type="button"
                aria-label="Close member actions"
                onClick={closeMenu}
                className="fixed inset-0 z-[9990]"
              />
              <div
                className="fixed z-[9991] w-48 rounded-lg border border-slate-200 bg-white py-1 shadow-xl"
                style={menuPosition}
              >
                <button
                  type="button"
                  onClick={onRemove}
                  disabled={row.organizationRole === "owner"}
                  className="flex w-full items-center gap-2 px-4 py-2.5 text-sm text-red-600 hover:bg-red-50 disabled:cursor-not-allowed disabled:opacity-40"
                >
                  <Trash2 size={16} />
                  {row.pending ? "Cancel Invitation" : "Remove Member"}
                </button>
              </div>
            </>,
            document.body,
          )}
      </td>
    </tr>
  );
}

function StatCard({
  label,
  value,
  icon,
  tone,
}: {
  label: string;
  value: number;
  icon: React.ReactNode;
  tone: "blue" | "green" | "amber" | "cyan";
}) {
  const colors = {
    blue: "bg-blue-50 text-blue-700",
    green: "bg-emerald-50 text-emerald-700",
    amber: "bg-amber-50 text-amber-600",
    cyan: "bg-cyan-50 text-cyan-700",
  };
  return (
    <article className="flex min-h-28 items-center gap-4 rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
      <div className={`flex h-12 w-12 items-center justify-center rounded-full ${colors[tone]}`}>
        {icon}
      </div>
      <div>
        <p className="text-xs text-slate-500">{label}</p>
        <strong className="mt-1 block text-2xl text-[#071226]">{value}</strong>
      </div>
    </article>
  );
}

function RoleBadge({ role }: { role: string }) {
  const colors: Record<string, string> = {
    owner: "border-violet-200 bg-violet-50 text-violet-700",
    administrator: "border-emerald-200 bg-emerald-50 text-emerald-700",
    security_analyst: "border-blue-200 bg-blue-50 text-blue-700",
    developer: "border-purple-200 bg-purple-50 text-purple-700",
    viewer: "border-slate-200 bg-slate-50 text-slate-600",
  };
  return (
    <span className={`rounded border px-2 py-1 text-xs ${colors[role] || colors.viewer}`}>
      {roleLabel(role)}
    </span>
  );
}

function StatusBadge({ status }: { status: string }) {
  const colors =
    status === "active"
      ? "border-emerald-200 bg-emerald-50 text-emerald-700"
      : status === "pending"
        ? "border-amber-200 bg-amber-50 text-amber-700"
        : "border-red-200 bg-red-50 text-red-700";
  return (
    <span className={`rounded border px-2 py-1 text-xs ${colors}`}>
      {status[0].toUpperCase() + status.slice(1)}
    </span>
  );
}

function RoleDistribution({ members, invites }: { members: Member[]; invites: Invite[] }) {
  const counts = ["owner", "administrator", "security_analyst", "developer", "viewer"].map(
    (role) => ({
      role,
      count:
        members.filter((member) => member.organizationRole === role).length +
        invites.filter((invite) => invite.role === role).length,
    }),
  );
  const total = Math.max(
    1,
    counts.reduce((sum, item) => sum + item.count, 0),
  );
  let position = 0;
  const colors = ["#6d28d9", "#059669", "#3b82f6", "#c084fc", "#94a3b8"];
  const gradient = counts
    .map((item, index) => {
      const start = position;
      position += (item.count / total) * 100;
      return `${colors[index]} ${start}% ${position}%`;
    })
    .join(",");
  return (
    <article className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
      <h2 className="text-lg font-semibold text-[#071226]">Role Distribution</h2>
      <div className="mt-5 grid items-center gap-5 sm:grid-cols-[150px_1fr]">
        <div
          className="mx-auto flex h-32 w-32 items-center justify-center rounded-full"
          style={{ background: `conic-gradient(${gradient})` }}
        >
          <div className="h-20 w-20 rounded-full bg-white" />
        </div>
        <div className="space-y-2">
          {counts.map((item, index) => (
            <div key={item.role} className="flex items-center justify-between text-sm">
              <span className="flex items-center gap-2 text-slate-600">
                <i className="h-2.5 w-2.5 rounded-full" style={{ background: colors[index] }} />
                {roleLabel(item.role)}
              </span>
              <strong>{item.count}</strong>
            </div>
          ))}
        </div>
      </div>
    </article>
  );
}

function RecentActivity({ items, plain = false }: { items: ActivityItem[]; plain?: boolean }) {
  const content = (
    <div className="divide-y divide-slate-100">
      {items.map((item) => (
        <div key={item.id} className="flex items-center gap-3 py-3">
          <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-blue-50 text-blue-700">
            <Activity size={17} />
          </span>
          <div className="min-w-0 flex-1">
            <p className="truncate text-sm text-slate-700">{activityLabel(item)}</p>
            <p className="text-xs text-slate-500">{item.actorName}</p>
          </div>
          <time className="text-xs text-slate-400">
            {new Date(item.createdAt).toLocaleString()}
          </time>
        </div>
      ))}
      {items.length === 0 && (
        <p className="py-10 text-center text-sm text-slate-500">No recent activity.</p>
      )}
    </div>
  );
  return plain ? (
    content
  ) : (
    <article className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
      <h2 className="text-lg font-semibold text-[#071226]">Recent Activity</h2>
      {content}
    </article>
  );
}

function AccessSummary({ role }: { role: string }) {
  const items = [
    ["Devices", Smartphone],
    ["Build Policies", ShieldCheck],
    ["Trust Anchors", KeyRound],
    ["Reports", BarChart3],
    ["API Access", Code2],
    ["Organization", Users],
  ] as const;
  return (
    <div className="rounded-xl border border-slate-200 p-4">
      <h3 className="font-semibold text-[#071226]">Access Summary</h3>
      <div className="mt-3 space-y-3">
        {items.map(([label, Icon], index) => {
          const allowed =
            role === "administrator" ||
            (role === "security_analyst" && index < 4) ||
            (role === "developer" && [0, 1, 4].includes(index)) ||
            (role === "viewer" && index < 4);
          return (
            <div key={label} className="flex items-center gap-3 text-sm">
              <Icon size={17} className="text-slate-500" />
              <span className="flex-1 text-slate-600">{label}</span>
              <span className={allowed ? "text-emerald-600" : "text-slate-400"}>
                {allowed ? "View" : "No access"}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function GeneralSettings({
  name,
  setName,
  manufacturer,
  setManufacturer,
  brand,
  setBrand,
  saving,
  onSave,
}: {
  name: string;
  setName: (value: string) => void;
  manufacturer: string;
  setManufacturer: (value: string) => void;
  brand: string;
  setBrand: (value: string) => void;
  saving: boolean;
  onSave: () => void;
}) {
  return (
    <section className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
      <div className="max-w-2xl">
        <h2 className="text-lg font-semibold text-[#071226]">Organization Profile</h2>
        <p className="mt-1 text-sm text-slate-500">
          Update the public identity used across the OEM portal.
        </p>
        <div className="mt-6 space-y-5">
          <Field
            label="Organization Name"
            value={name}
            onChange={setName}
            placeholder="Organization name"
          />
          <Field
            label="Manufacturer"
            value={manufacturer}
            onChange={setManufacturer}
            placeholder="Manufacturer"
          />
          <Field label="Brand" value={brand} onChange={setBrand} placeholder="Brand" />
          <button
            type="button"
            onClick={onSave}
            disabled={saving || !name.trim()}
            className="flex h-11 items-center gap-2 rounded-lg bg-[#071226] px-5 text-sm font-medium text-white disabled:opacity-50"
          >
            {saving && <Loader2 size={17} className="animate-spin" />}Save Changes
          </button>
        </div>
      </div>
    </section>
  );
}

function RolesPanel() {
  return (
    <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
      {roleOptions.map(([value, label]) => (
        <article key={value} className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
          <RoleBadge role={value} />
          <h2 className="mt-4 font-semibold text-[#071226]">{label}</h2>
          <p className="mt-2 text-sm leading-6 text-slate-500">{accessLabel(value)}</p>
          <div className="mt-4">
            <AccessSummary role={value} />
          </div>
        </article>
      ))}
    </section>
  );
}

function SecurityPanel({ members }: { members: Member[] }) {
  return (
    <section className="grid gap-4 md:grid-cols-3">
      <StatCard
        label="Active Accounts"
        value={members.filter((member) => member.status === "active").length}
        icon={<CheckCircle2 />}
        tone="green"
      />
      <StatCard
        label="Disabled Accounts"
        value={members.filter((member) => member.status === "disabled").length}
        icon={<AlertCircle />}
        tone="amber"
      />
      <StatCard
        label="Administrators"
        value={
          members.filter((member) => ["owner", "administrator"].includes(member.organizationRole))
            .length
        }
        icon={<ShieldCheck />}
        tone="blue"
      />
    </section>
  );
}

function BillingPanel({ organization }: { organization: Organization | null }) {
  return (
    <section className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
      <Building2 size={28} className="text-blue-700" />
      <h2 className="mt-4 text-lg font-semibold text-[#071226]">Self-hosted Organization</h2>
      <p className="mt-2 text-sm text-slate-500">
        {organization?.name || "This organization"} is running on the self-hosted Unified
        Attestation plan.
      </p>
      <dl className="mt-6 grid max-w-xl grid-cols-2 gap-4 rounded-xl bg-slate-50 p-4 text-sm">
        <dt className="text-slate-500">Plan</dt>
        <dd className="text-right font-medium">Self-hosted</dd>
        <dt className="text-slate-500">Member limit</dt>
        <dd className="text-right font-medium">Unlimited</dd>
        <dt className="text-slate-500">Status</dt>
        <dd className="text-right text-emerald-600">Active</dd>
      </dl>
    </section>
  );
}

function Field({
  label,
  value,
  onChange,
  placeholder,
  type = "text",
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  placeholder: string;
  type?: string;
}) {
  return (
    <label className="block">
      <span className="text-sm font-medium text-slate-700">{label}</span>
      <input
        type={type}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        className="mt-2 h-11 w-full rounded-lg border border-slate-200 px-3 text-sm outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-100"
      />
    </label>
  );
}

function Message({
  tone,
  text,
  onClose,
}: {
  tone: "error" | "success";
  text: string;
  onClose: () => void;
}) {
  return (
    <div
      className={`flex items-center justify-between rounded-xl border px-4 py-3 text-sm ${tone === "error" ? "border-red-200 bg-red-50 text-red-700" : "border-emerald-200 bg-emerald-50 text-emerald-700"}`}
    >
      <span className="flex items-center gap-2">
        {tone === "success" && <Check size={17} />}
        {text}
      </span>
      <button type="button" onClick={onClose}>
        <X size={17} />
      </button>
    </div>
  );
}

function initials(value: string) {
  return (
    value
      .split(/[\s@._-]+/)
      .filter(Boolean)
      .slice(0, 2)
      .map((part) => part[0]?.toUpperCase())
      .join("") || "U"
  );
}

function roleLabel(role: string) {
  return roleOptions.find(([value]) => value === role)?.[1] || (role === "owner" ? "Owner" : role);
}

function accessLabel(role: string) {
  if (["owner", "administrator"].includes(role)) return "Full access";
  if (role === "security_analyst") return "Reports and trust anchors";
  if (role === "developer") return "Devices, builds, and API access";
  return "Read only";
}

function activityLabel(item: ActivityItem) {
  const labels: Record<string, string> = {
    OEM_MEMBER_INVITED: `invited ${String(item.details.email || "a member")}`,
    OEM_MEMBER_REMOVED: `removed ${String(item.details.email || "a member")}`,
    OEM_MEMBER_INVITE_CANCELLED: `cancelled the invitation for ${String(item.details.email || "a member")}`,
    OEM_API_CREDENTIAL_CREATED: "created an API credential",
    OEM_API_CREDENTIAL_REVOKED: "revoked an API credential",
    KEYBOX_GENERATED: "generated device keys",
  };
  return `${item.actorName} ${labels[item.action] || item.action.toLowerCase().replaceAll("_", " ")}`;
}

function readCurrentUser(token: string) {
  try {
    const payload = JSON.parse(atob(token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
    return {
      id: String(payload.sub || "current-user"),
      email: String(payload.email || "oem@local"),
      name: payload.displayName ? String(payload.displayName) : null,
    };
  } catch {
    return null;
  }
}
