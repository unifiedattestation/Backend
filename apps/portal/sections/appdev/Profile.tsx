import { useCallback, useEffect, useState } from "react";
import {
  AlertTriangle,
  AppWindow,
  BarChart3,
  Check,
  CheckCircle2,
  Eye,
  EyeOff,
  Info,
  KeyRound,
  Loader2,
  LockKeyhole,
  LogOut,
  Network,
  RotateCw,
  Save,
  ShieldCheck,
  UserRound,
  X,
} from "lucide-react";
import AppdevFooter from "../../components/appdev/Footer";
import { backendUrl } from "../../lib/config";

type Profile = {
  id: string;
  email: string;
  role: string;
  displayName?: string | null;
};

type DeveloperApp = { id: string; name: string; projectId: string };
type FederationBackend = { id: string; status: string };

export default function AppdevProfile({
  onProfileLoaded,
  onLogout,
}: {
  onProfileLoaded?: (name: string) => void;
  onLogout: () => void;
}) {
  const [profile, setProfile] = useState<Profile | null>(null);
  const [apps, setApps] = useState<DeveloperApp[]>([]);
  const [federation, setFederation] = useState<FederationBackend[]>([]);
  const [reportCount, setReportCount] = useState(0);
  const [displayName, setDisplayName] = useState("");
  const [originalName, setOriginalName] = useState("");
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [showCurrentPassword, setShowCurrentPassword] = useState(false);
  const [showNewPassword, setShowNewPassword] = useState(false);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const load = useCallback(async () => {
    const token = localStorage.getItem("ua_access");
    if (!token) {
      window.location.href = "/login";
      return;
    }
    setLoading(true);
    try {
      const headers = { Authorization: `Bearer ${token}` };
      const [profileResponse, appsResponse, federationResponse] = await Promise.all([
        fetch(`${backendUrl}/api/v1/profile`, { headers }),
        fetch(`${backendUrl}/api/v1/apps`, { headers }),
        fetch(`${backendUrl}/api/v1/federation/backends`),
      ]);
      if (profileResponse.status === 401 || appsResponse.status === 401) {
        onLogout();
        return;
      }
      if (!profileResponse.ok || !appsResponse.ok) throw new Error("Unable to load profile.");
      const profileData: Profile = await profileResponse.json();
      const appData: DeveloperApp[] = await appsResponse.json();
      const reportGroups = await Promise.all(
        appData.map(async (application) => {
          const response = await fetch(`${backendUrl}/api/v1/apps/${application.id}/reports`, {
            headers,
          });
          return response.ok ? ((await response.json()) as unknown[]) : [];
        }),
      );
      const name = profileData.displayName || profileData.email.split("@")[0];
      setProfile(profileData);
      setApps(appData);
      setFederation(federationResponse.ok ? await federationResponse.json() : []);
      setReportCount(reportGroups.reduce((sum, reports) => sum + reports.length, 0));
      setDisplayName(name);
      setOriginalName(name);
      onProfileLoaded?.(name);
      setError(null);
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Unable to load profile.");
    } finally {
      setLoading(false);
    }
  }, [onLogout, onProfileLoaded]);

  useEffect(() => {
    load();
  }, [load]);

  const saveProfile = async () => {
    if (!displayName.trim()) {
      setError("Display name is required.");
      return;
    }
    const token = localStorage.getItem("ua_access");
    setSaving(true);
    try {
      const response = await fetch(`${backendUrl}/api/v1/profile`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify({ displayName: displayName.trim() }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data?.message || "Unable to save profile.");
      setOriginalName(displayName.trim());
      onProfileLoaded?.(displayName.trim());
      setNotice("Profile information saved.");
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Unable to save profile.");
    } finally {
      setSaving(false);
    }
  };

  const changePassword = async () => {
    if (!currentPassword || newPassword.length < 5) {
      setError("Enter your current password and a new password with at least 5 characters.");
      return;
    }
    const token = localStorage.getItem("ua_access");
    setSaving(true);
    try {
      const response = await fetch(`${backendUrl}/api/v1/profile/password`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
        body: JSON.stringify({ currentPassword, newPassword }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data?.message || "Unable to change password.");
      setCurrentPassword("");
      setNewPassword("");
      setNotice("Password changed successfully.");
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Unable to change password.");
    } finally {
      setSaving(false);
    }
  };

  const activeFederation = federation.filter((backend) => backend.status === "active").length;

  return (
    <div className="flex min-h-[calc(100vh-3rem)] flex-col gap-4">
      <header className="flex flex-col gap-4 border-b border-slate-200 pb-4 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-[#071226]">Profile</h1>
          <p className="mt-1 text-sm text-slate-500">
            Manage your developer profile and account password.
          </p>
        </div>
        <button
          type="button"
          onClick={onLogout}
          className="flex h-10 items-center justify-center gap-2 rounded-lg border border-blue-600 bg-white px-5 text-sm text-blue-700 hover:bg-blue-50"
        >
          <LogOut size={17} />
          Log Out
        </button>
      </header>

      {error && <Message tone="error" text={error} onClose={() => setError(null)} />}
      {notice && <Message tone="success" text={notice} onClose={() => setNotice(null)} />}
      {loading && (
        <div className="flex items-center justify-center gap-2 rounded-xl border border-slate-200 bg-white py-14 text-sm text-slate-500">
          <Loader2 size={18} className="animate-spin" />
          Loading profile...
        </div>
      )}

      {!loading && (
        <>
          <section className="grid gap-5 rounded-xl border border-slate-200 bg-white p-5 shadow-sm lg:grid-cols-[300px_1fr] lg:items-center">
            <div className="flex items-center gap-4">
              <div className="flex h-16 w-16 shrink-0 items-center justify-center rounded-full bg-blue-700 text-2xl font-semibold text-white">
                {displayName.charAt(0).toUpperCase()}
              </div>
              <div className="min-w-0">
                <h2 className="truncate text-2xl font-semibold text-[#071226]">{displayName}</h2>
                <div className="mt-2 flex flex-wrap gap-2">
                  <span className="rounded border border-blue-200 bg-blue-50 px-2 py-1 text-xs text-blue-700">
                    Application Developer
                  </span>
                  <span className="inline-flex items-center gap-1 rounded border border-emerald-200 bg-emerald-50 px-2 py-1 text-xs text-emerald-700">
                    <CheckCircle2 size={13} />
                    Active
                  </span>
                </div>
              </div>
            </div>
            <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
              <Summary label="Registered Apps" value={apps.length.toString()} />
              <Summary
                label="Federation Servers"
                value={activeFederation.toString()}
                detail="available"
              />
              <Summary label="Device Reports" value={reportCount.toString()} />
              <Summary label="Access" value="Developer Portal" />
            </div>
          </section>

          <section className="grid gap-4 xl:grid-cols-2">
            <article className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
              <h2 className="text-lg font-semibold text-[#071226]">Profile Information</h2>
              <p className="text-xs text-slate-500">
                Choose the display name shown throughout the developer portal.
              </p>
              <div className="mt-5 space-y-4">
                <label className="block">
                  <span className="text-sm font-medium text-slate-700">Username</span>
                  <div className="relative mt-2">
                    <LockKeyhole
                      size={16}
                      className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500"
                    />
                    <input
                      value={profile?.email || ""}
                      disabled
                      className="h-11 w-full rounded-lg border border-slate-200 bg-slate-50 pl-10 pr-3 text-sm text-slate-500"
                    />
                  </div>
                  <span className="mt-1 block text-xs text-slate-400">
                    Your username cannot be changed.
                  </span>
                </label>
                <label className="block">
                  <span className="text-sm font-medium text-slate-700">Display Name</span>
                  <input
                    value={displayName}
                    maxLength={50}
                    onChange={(event) => setDisplayName(event.target.value)}
                    className="mt-2 h-11 w-full rounded-lg border border-slate-200 px-3 text-sm outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-100"
                  />
                  <span className="mt-1 block text-right text-xs text-slate-400">
                    {displayName.length} / 50
                  </span>
                </label>
                <div className="flex gap-3 rounded-lg border border-blue-200 bg-blue-50 p-3 text-xs text-blue-700">
                  <Info size={17} className="shrink-0" />
                  Updating your display name does not change your login username.
                </div>
                <div className="flex justify-end gap-2">
                  <button
                    type="button"
                    onClick={() => setDisplayName(originalName)}
                    className="h-10 rounded-lg border border-slate-300 px-5 text-sm"
                  >
                    Reset
                  </button>
                  <button
                    type="button"
                    disabled={saving || displayName.trim() === originalName}
                    onClick={saveProfile}
                    className="flex h-10 items-center gap-2 rounded-lg bg-[#071226] px-5 text-sm font-medium text-white disabled:opacity-40"
                  >
                    <Save size={16} />
                    Save Changes
                  </button>
                </div>
              </div>
            </article>

            <article className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
              <h2 className="text-lg font-semibold text-[#071226]">Change Password</h2>
              <p className="text-xs text-slate-500">
                Update the password used to sign in to your developer account.
              </p>
              <div className="mt-5 space-y-4">
                <PasswordField
                  label="Current Password"
                  value={currentPassword}
                  onChange={setCurrentPassword}
                  visible={showCurrentPassword}
                  setVisible={setShowCurrentPassword}
                />
                <PasswordField
                  label="New Password"
                  value={newPassword}
                  onChange={setNewPassword}
                  visible={showNewPassword}
                  setVisible={setShowNewPassword}
                />
                <div className="space-y-2 rounded-lg border border-blue-200 bg-blue-50 p-3 text-xs text-blue-700">
                  {[
                    "Use a strong, unique password",
                    "Do not reuse your app server secret",
                    "Keep credentials out of source code",
                  ].map((item) => (
                    <p key={item} className="flex items-center gap-2">
                      <CheckCircle2 size={15} />
                      {item}
                    </p>
                  ))}
                </div>
                <button
                  type="button"
                  disabled={saving || !currentPassword || newPassword.length < 5}
                  onClick={changePassword}
                  className="flex h-10 w-full items-center justify-center gap-2 rounded-lg bg-[#071226] text-sm font-medium text-white disabled:opacity-40"
                >
                  <KeyRound size={17} />
                  Change Password
                </button>
              </div>
            </article>
          </section>

          <section className="grid gap-4 xl:grid-cols-2">
            <AccountAccess />
            <AccountSecurity hasApps={apps.length > 0} />
          </section>

          <section className="flex flex-col gap-4 rounded-xl border border-slate-200 bg-white p-5 shadow-sm sm:flex-row sm:items-center sm:justify-between">
            <div>
              <h2 className="text-lg font-semibold text-[#071226]">Sign Out</h2>
              <p className="mt-1 text-sm text-slate-500">
                End your current portal session on this device.
              </p>
            </div>
            <button
              type="button"
              onClick={onLogout}
              className="flex h-10 items-center justify-center gap-2 rounded-lg border border-blue-600 px-5 text-sm text-blue-700 hover:bg-blue-50"
            >
              <LogOut size={17} />
              Log Out
            </button>
          </section>
        </>
      )}
      <AppdevFooter />
    </div>
  );
}

function Summary({ label, value, detail }: { label: string; value: string; detail?: string }) {
  return (
    <div className="border-slate-200 sm:border-l sm:pl-4">
      <p className="text-xs text-slate-500">{label}</p>
      <p className="mt-1 text-xl font-semibold text-[#071226]">{value}</p>
      {detail && <p className="text-xs text-emerald-600">{detail}</p>}
    </div>
  );
}

function PasswordField({
  label,
  value,
  onChange,
  visible,
  setVisible,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  visible: boolean;
  setVisible: (value: boolean) => void;
}) {
  return (
    <label className="block">
      <span className="text-sm font-medium text-slate-700">{label}</span>
      <div className="relative mt-2">
        <input
          type={visible ? "text" : "password"}
          value={value}
          onChange={(event) => onChange(event.target.value)}
          className="h-11 w-full rounded-lg border border-slate-200 px-3 pr-11 text-sm outline-none focus:border-blue-600"
        />
        <button
          type="button"
          onClick={() => setVisible(!visible)}
          className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500"
        >
          {visible ? <EyeOff size={18} /> : <Eye size={18} />}
        </button>
      </div>
    </label>
  );
}

function AccountAccess() {
  const rows = [
    ["Portal Role", "Application Developer", true],
    ["Applications", "Register, view, edit, delete", true],
    ["Server Secret", "Rotate", true],
    ["Device Reports", "View", true],
    ["Federation", "Read-only", false],
    ["Profile", "Edit", true],
  ] as const;
  return (
    <article className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
      <h2 className="text-lg font-semibold text-[#071226]">Account Access</h2>
      <div className="mt-3 divide-y divide-slate-100">
        {rows.map(([label, value, editable]) => (
          <div
            key={label}
            className="grid grid-cols-[140px_1fr_auto] items-center gap-3 py-2 text-sm"
          >
            <span className="text-slate-500">{label}</span>
            <span className="text-slate-700">{value}</span>
            {editable ? (
              <CheckCircle2 size={16} className="text-emerald-600" />
            ) : (
              <LockKeyhole size={16} className="text-slate-500" />
            )}
          </div>
        ))}
      </div>
    </article>
  );
}

function AccountSecurity({ hasApps }: { hasApps: boolean }) {
  return (
    <article className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
      <h2 className="text-lg font-semibold text-[#071226]">Account Security</h2>
      <div className="mt-3 divide-y divide-slate-100">
        <SecurityRow label="Password" value="Set" />
        <SecurityRow
          label="App Server Secret"
          value={hasApps ? "Configured" : "Not Configured"}
          ok={hasApps}
        />
        <SecurityRow label="Federation Access" value="Read-only" locked />
      </div>
      <div className="mt-4 flex gap-3 rounded-lg border border-amber-200 bg-amber-50 p-3 text-xs text-amber-800">
        <AlertTriangle size={17} className="shrink-0" />
        Your account password and app server secret are separate credentials.
      </div>
      <div className="mt-4 grid grid-cols-2 gap-2">
        <a
          href="/appdev/applications"
          className="flex h-10 items-center justify-center rounded-lg border border-blue-600 text-sm text-blue-700"
        >
          <AppWindow size={16} className="mr-2" />
          Open Applications
        </a>
        <a
          href="/appdev/applications"
          className="flex h-10 items-center justify-center rounded-lg border border-slate-300 text-sm text-slate-700"
        >
          <RotateCw size={16} className="mr-2" />
          Review Secret
        </a>
      </div>
    </article>
  );
}

function SecurityRow({
  label,
  value,
  ok = true,
  locked = false,
}: {
  label: string;
  value: string;
  ok?: boolean;
  locked?: boolean;
}) {
  return (
    <div className="flex items-center justify-between py-2 text-sm">
      <span className="text-slate-500">{label}</span>
      <span className="flex items-center gap-2 text-slate-700">
        {value}
        {locked ? (
          <LockKeyhole size={15} />
        ) : ok ? (
          <CheckCircle2 size={16} className="text-emerald-600" />
        ) : (
          <X size={16} className="text-red-600" />
        )}
      </span>
    </div>
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
