import { useEffect, useState } from "react";
import Layout from "../components/Layout";

const backendUrl = process.env.NEXT_PUBLIC_BACKEND_URL || "";

type Backend = {
  id: string;
  backendId: string;
  name: string;
  url?: string;
  status: string;
};

type User = {
  id: string;
  email: string;
  role: string;
  disabledAt?: string | null;
};

type Settings = {
  backendId: string;
  publicKey: string | null;
};

type BackendRootAnchor = {
  id: string;
  name?: string | null;
  rsaSerialHex: string;
  ecdsaSerialHex: string;
  rsaSubject: string;
  ecdsaSubject: string;
  createdAt: string;
  revokedAt?: string | null;
};

type AuthorityRoot = {
  id: string;
  name?: string | null;
  pem: string;
};

type Authority = {
  id: string;
  name: string;
  baseUrl: string;
  enabled: boolean;
  roots: AuthorityRoot[];
  statusCachedAt?: string | null;
  keyAvailability?: {
    rsa: boolean;
    ecdsa: boolean;
  };
};

export default function AdminPage() {
  const [backends, setBackends] = useState<Backend[]>([]);
  const [users, setUsers] = useState<User[]>([]);
  const [settings, setSettings] = useState<Settings | null>(null);
  const [backendRoots, setBackendRoots] = useState<BackendRootAnchor[]>([]);
  const [authorities, setAuthorities] = useState<Authority[]>([]);
  const [newUser, setNewUser] = useState({ email: "", password: "", role: "app_dev" });
  const [newBackendUrl, setNewBackendUrl] = useState("");
  const [newBackendName, setNewBackendName] = useState("");
  const [newAuthorityName, setNewAuthorityName] = useState("");
  const [newAuthorityUrl, setNewAuthorityUrl] = useState("");
  const [userError, setUserError] = useState<string | null>(null);
  const [passwordUpdates, setPasswordUpdates] = useState<Record<string, string>>({});
  const [passwordMessage, setPasswordMessage] = useState<string | null>(null);
  const [backendRootError, setBackendRootError] = useState<string | null>(null);
  const [authorityNotice, setAuthorityNotice] = useState<Record<string, string>>({});

  const access = typeof window !== "undefined" ? localStorage.getItem("ua_access") : null;

  const fetchAll = async () => {
    if (!access) return;
    const [backendRes, userRes, settingsRes, authorityRes, backendRootsRes] = await Promise.all([
      fetch(`${backendUrl}/api/v1/federation/backends`),
      fetch(`${backendUrl}/api/v1/admin/users`, {
        headers: { Authorization: `Bearer ${access}` }
      }),
      fetch(`${backendUrl}/api/v1/admin/settings`, {
        headers: { Authorization: `Bearer ${access}` }
      }),
      fetch(`${backendUrl}/api/v1/admin/attestation-authorities`, {
        headers: { Authorization: `Bearer ${access}` }
      }),
      fetch(`${backendUrl}/api/v1/admin/backend-roots`, {
        headers: { Authorization: `Bearer ${access}` }
      })
    ]);
    if (backendRes.ok) {
      setBackends(await backendRes.json());
    }
    if (userRes.ok) {
      setUsers(await userRes.json());
    }
    if (settingsRes.ok) {
      const data = await settingsRes.json();
      setSettings(data);
    }
    if (authorityRes.ok) {
      setAuthorities(await authorityRes.json());
    }
    if (backendRootsRes.ok) {
      setBackendRoots(await backendRootsRes.json());
    }
  };

  useEffect(() => {
    fetchAll();
  }, [access]);

  const createUser = async () => {
    if (!access) return;
    if (newUser.password.length < 5) {
      setUserError("Password must be at least 5 characters.");
      return;
    }
    setUserError(null);
    const res = await fetch(`${backendUrl}/api/v1/admin/users`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${access}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify(newUser)
    });
    if (res.ok) {
      setNewUser({ email: "", password: "", role: "app_dev" });
      fetchAll();
      return;
    }
    const raw = await res.text();
    setUserError(raw || "Failed to create user");
  };

  const disableUser = async (id: string) => {
    if (!access) return;
    await fetch(`${backendUrl}/api/v1/admin/users/${id}/disable`, {
      method: "POST",
      headers: { Authorization: `Bearer ${access}` }
    });
    fetchAll();
  };

  const deleteUser = async (id: string) => {
    if (!access) return;
    await fetch(`${backendUrl}/api/v1/admin/users/${id}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${access}` }
    });
    fetchAll();
  };

  const updatePassword = async (id: string) => {
    if (!access) return;
    setPasswordMessage(null);
    const nextPassword = passwordUpdates[id] || "";
    if (nextPassword.length < 5) {
      setPasswordMessage("Password must be at least 5 characters.");
      return;
    }
    const res = await fetch(`${backendUrl}/api/v1/admin/users/${id}/password`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${access}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ password: nextPassword })
    });
    if (res.ok) {
      setPasswordUpdates((prev) => ({ ...prev, [id]: "" }));
      setPasswordMessage("Password updated.");
      return;
    }
    const raw = await res.text();
    setPasswordMessage(raw || "Failed to update password");
  };

  const addBackend = async () => {
    if (!access || !newBackendUrl) return;
    const res = await fetch(`${backendUrl}/api/v1/federation/backends`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${access}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ url: newBackendUrl, name: newBackendName || undefined })
    });
    if (res.ok) {
      setNewBackendUrl("");
      setNewBackendName("");
      fetchAll();
    }
  };

  const rotateKey = async () => {
    if (!access) return;
    await fetch(`${backendUrl}/api/v1/admin/settings/rotate-key`, {
      method: "POST",
      headers: { Authorization: `Bearer ${access}` }
    });
    fetchAll();
  };

  const createAuthority = async () => {
    if (!access || !newAuthorityName || !newAuthorityUrl) return;
    const res = await fetch(`${backendUrl}/api/v1/admin/attestation-authorities`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${access}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ name: newAuthorityName, baseUrl: newAuthorityUrl })
    });
    if (res.ok) {
      setNewAuthorityName("");
      setNewAuthorityUrl("");
      fetchAll();
    }
  };

  const refreshAuthority = async (id: string) => {
    if (!access) return;
    setAuthorityNotice((prev) => ({ ...prev, [id]: "Refreshing..." }));
    const res = await fetch(`${backendUrl}/api/v1/admin/attestation-authorities/${id}/refresh`, {
      method: "POST",
      headers: { Authorization: `Bearer ${access}` }
    });
    if (res.ok) {
      setAuthorityNotice((prev) => ({ ...prev, [id]: "Refreshed successfully." }));
      fetchAll();
      return;
    }
    const raw = await res.text();
    setAuthorityNotice((prev) => ({ ...prev, [id]: raw || "Refresh failed." }));
  };

  const generateBackendRoot = async () => {
    if (!access) return;
    setBackendRootError(null);
    const res = await fetch(`${backendUrl}/api/v1/admin/backend-roots/generate`, {
      method: "POST",
      headers: { Authorization: `Bearer ${access}` }
    });
    if (res.ok) {
      const xml = await res.text();
      const blob = new Blob([xml], { type: "application/xml" });
      const link = document.createElement("a");
      link.href = window.URL.createObjectURL(blob);
      link.download = "backend_root_anchor.xml";
      link.click();
      window.URL.revokeObjectURL(link.href);
      fetchAll();
      return;
    }
    const raw = await res.text();
    setBackendRootError(raw || "Failed to generate backend root");
  };

  const revokeBackendRoot = async (id: string) => {
    if (!access) return;
    await fetch(`${backendUrl}/api/v1/admin/backend-roots/${id}/revoke`, {
      method: "POST",
      headers: { Authorization: `Bearer ${access}` }
    });
    fetchAll();
  };

  const removeBackendRoot = async (id: string) => {
    if (!access) return;
    await fetch(`${backendUrl}/api/v1/admin/backend-roots/${id}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${access}` }
    });
    fetchAll();
  };

  return (
    <Layout>
      <div className="grid lg:grid-cols-[1.2fr,1fr] gap-8">
        <section className="bg-white/70 rounded-2xl p-6 shadow-sm">
          <h2 className="text-xl font-semibold">Account Management</h2>
          <div className="mt-4 space-y-3">
            <div className="grid md:grid-cols-3 gap-2">
              <input
                className="rounded-lg border border-gray-300 px-3 py-2"
                placeholder="Username"
                value={newUser.email}
                onChange={(e) => setNewUser({ ...newUser, email: e.target.value })}
              />
              <input
                className="rounded-lg border border-gray-300 px-3 py-2"
                placeholder="Password"
                type="password"
                value={newUser.password}
                onChange={(e) => setNewUser({ ...newUser, password: e.target.value })}
              />
              <select
                className="rounded-lg border border-gray-300 px-3 py-2"
                value={newUser.role}
                onChange={(e) => setNewUser({ ...newUser, role: e.target.value })}
              >
                <option value="app_dev">App Dev</option>
                <option value="oem">OEM</option>
              </select>
            </div>
            <button className="rounded-lg bg-ink text-white px-4 py-2" onClick={createUser}>
              Create User
            </button>
            {userError && <div className="text-sm text-red-600">{userError}</div>}
          </div>
          <div className="mt-6 space-y-2">
            {users.map((user) => (
              <div key={user.id} className="rounded-lg border border-gray-200 px-4 py-2">
                <div className="text-sm">Username: {user.email}</div>
                <div className="text-xs text-gray-500">Role: {user.role}</div>
                <div className="mt-2 flex gap-2">
                  <button
                    className="rounded-md bg-sand px-3 py-1 text-xs"
                    onClick={() => disableUser(user.id)}
                  >
                    Disable
                  </button>
                  <button
                    className="rounded-md bg-rose-500 text-white px-3 py-1 text-xs"
                    onClick={() => deleteUser(user.id)}
                  >
                    Delete
                  </button>
                </div>
                <div className="mt-3 flex flex-col md:flex-row gap-2">
                  <input
                    className="flex-1 rounded-lg border border-gray-300 px-3 py-2"
                    placeholder="New password"
                    type="password"
                    value={passwordUpdates[user.id] || ""}
                    onChange={(e) =>
                      setPasswordUpdates((prev) => ({ ...prev, [user.id]: e.target.value }))
                    }
                  />
                  <button
                    className="rounded-lg bg-clay text-white px-4 py-2"
                    onClick={() => updatePassword(user.id)}
                  >
                    Change Password
                  </button>
                </div>
                {user.disabledAt && (
                  <div className="text-xs text-red-600">Disabled: {user.disabledAt}</div>
                )}
              </div>
            ))}
            {passwordMessage && <div className="text-sm text-red-600">{passwordMessage}</div>}
          </div>
        </section>
        <section className="bg-white/70 rounded-2xl p-6 shadow-sm space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-xl font-semibold">Backend Root Anchors</h2>
              <p className="text-sm text-gray-500">
                Generates the backend RSA + ECDSA roots used to chain OEM and device anchors.
              </p>
              {backendRootError && (
                <div className="mt-2 text-xs text-red-600">{backendRootError}</div>
              )}
            </div>
            <button
              className="rounded-lg bg-ink px-3 py-2 text-white text-sm"
              onClick={generateBackendRoot}
            >
              Generate Root
            </button>
          </div>
          <div className="space-y-3">
            {backendRoots.length === 0 && (
              <div className="text-sm text-gray-500">No backend roots yet.</div>
            )}
            {backendRoots.map((root) => (
              <div key={root.id} className="rounded-xl border border-gray-200 bg-white px-4 py-3">
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <div className="text-sm font-semibold">
                      {root.name || "Backend Root"}
                    </div>
                    <div className="mt-1 text-xs text-gray-600">RSA: {root.rsaSerialHex}</div>
                    <div className="text-xs text-gray-600">ECDSA: {root.ecdsaSerialHex}</div>
                    <div
                      className={`mt-2 text-xs ${
                        root.revokedAt ? "text-red-600" : "text-gray-500"
                      }`}
                    >
                      Created: {new Date(root.createdAt).toLocaleString()}
                      {root.revokedAt &&
                        ` · Revoked: ${new Date(root.revokedAt).toLocaleString()}`}
                    </div>
                  </div>
                  <div className="flex flex-col gap-2">
                    <button
                      className="rounded-lg border border-amber-500 px-3 py-1 text-xs text-amber-700"
                      onClick={() => revokeBackendRoot(root.id)}
                    >
                      Revoke
                    </button>
                    <button
                      className="rounded-lg border border-red-500 px-3 py-1 text-xs text-red-600"
                      onClick={() => removeBackendRoot(root.id)}
                    >
                      Remove
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </section>
        <section className="bg-white/70 rounded-2xl p-6 shadow-sm">
          <h2 className="text-xl font-semibold">Settings</h2>
          {settings && (
            <div className="mt-4 space-y-3">
              <div className="text-sm">Backend ID: {settings.backendId}</div>
              <div className="text-xs text-gray-500 break-all">
                Public key: {settings.publicKey || "Not ready"}
              </div>
              <div className="flex gap-2">
                <button className="rounded-lg bg-ink text-white px-4 py-2" onClick={rotateKey}>
                  Rotate Signing Key
                </button>
              </div>
            </div>
          )}
        </section>
      </div>

      <section className="mt-8 bg-white/70 rounded-2xl p-6 shadow-sm">
        <h2 className="text-xl font-semibold">Attestation Authorities</h2>
        <div className="mt-4 space-y-3">
          <div className="grid md:grid-cols-2 gap-2">
            <input
              className="rounded-lg border border-gray-300 px-3 py-2"
              placeholder="Authority name"
              value={newAuthorityName}
              onChange={(e) => setNewAuthorityName(e.target.value)}
            />
            <input
              className="rounded-lg border border-gray-300 px-3 py-2"
              placeholder="Base URL (https://...)"
              value={newAuthorityUrl}
              onChange={(e) => setNewAuthorityUrl(e.target.value)}
            />
          </div>
          <button className="rounded-lg bg-ink text-white px-4 py-2" onClick={createAuthority}>
            Add Authority
          </button>
        </div>
        <div className="mt-6 space-y-4">
          {authorities.map((authority) => (
            <div key={authority.id} className="rounded-xl border border-gray-200 p-4">
              <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-2">
                <div>
                  <div className="font-semibold">{authority.name}</div>
                  <div className="text-xs text-gray-500">{authority.baseUrl}</div>
                  <div className="mt-1 text-xs text-gray-500">
                    RSA: {authority.keyAvailability?.rsa ? "✅" : "❌"} · ECDSA:{" "}
                    {authority.keyAvailability?.ecdsa ? "✅" : "❌"}
                  </div>
                  <div className="text-xs text-gray-500">
                    Status cached: {authority.statusCachedAt ? new Date(authority.statusCachedAt).toLocaleString() : "never"}
                  </div>
                  {authorityNotice[authority.id] && (
                    <div className={`text-xs ${authorityNotice[authority.id].startsWith("Refreshed") ? "text-green-600" : "text-red-600"}`}>
                      {authorityNotice[authority.id]}
                    </div>
                  )}
                </div>
                <button
                  className="rounded-lg bg-moss text-white px-3 py-2 text-xs"
                  onClick={() => refreshAuthority(authority.id)}
                >
                  Refresh Roots/Status
                </button>
              </div>
            </div>
          ))}
        </div>
      </section>

      <section className="mt-8 bg-white/70 rounded-2xl p-6 shadow-sm">
        <h2 className="text-xl font-semibold">Federation Management</h2>
        <div className="mt-4 space-y-3">
          <div className="grid md:grid-cols-2 gap-2">
            <input
              className="rounded-lg border border-gray-300 px-3 py-2"
              placeholder="Backend URL"
              value={newBackendUrl}
              onChange={(e) => setNewBackendUrl(e.target.value)}
            />
            <input
              className="rounded-lg border border-gray-300 px-3 py-2"
              placeholder="Display name (optional)"
              value={newBackendName}
              onChange={(e) => setNewBackendName(e.target.value)}
            />
          </div>
          <button className="rounded-lg bg-moss text-white px-4 py-2" onClick={addBackend}>
            Add Backend
          </button>
        </div>
        <div className="mt-6 grid md:grid-cols-2 gap-4">
          {backends.map((backend) => (
            <div key={backend.id} className="rounded-xl border border-gray-200 p-4">
              <div className="font-semibold">{backend.name}</div>
              <div className="text-xs text-gray-500">{backend.backendId}</div>
              <div className="text-xs text-gray-500">URL: {backend.url || "manual"}</div>
              <div className="text-xs text-gray-500">Status: {backend.status}</div>
            </div>
          ))}
        </div>
      </section>
    </Layout>
  );
}
