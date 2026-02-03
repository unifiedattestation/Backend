import { useEffect, useState } from "react";
import Layout from "../components/Layout";

const backendUrl = "";

type App = {
  id: string;
  projectId: string;
  name: string;
  signerDigestSha256: string;
};

type DeviceReport = {
  id: string;
  scopedDeviceId: string;
  issuerBackendId: string;
  lastSeen: string;
  lastVerdict: { isTrusted: boolean; reasonCodes: string[] };
};

export default function Dashboard() {
  const [apps, setApps] = useState<App[]>([]);
  const [selectedApp, setSelectedApp] = useState<App | null>(null);
  const [appName, setAppName] = useState("");
  const [projectId, setProjectId] = useState("");
  const [signerDigest, setSignerDigest] = useState("");
  const [editName, setEditName] = useState("");
  const [editProjectId, setEditProjectId] = useState("");
  const [editSigner, setEditSigner] = useState("");
  const [reports, setReports] = useState<DeviceReport[]>([]);
  const [newSecret, setNewSecret] = useState<string | null>(null);
  const [appMessage, setAppMessage] = useState<string | null>(null);
  const [displayName, setDisplayName] = useState("");
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [passwordMessage, setPasswordMessage] = useState<string | null>(null);
  const [federationBackends, setFederationBackends] = useState<
    { id: string; backendId: string; name: string; status: string }[]
  >([]);

  const access = typeof window !== "undefined" ? localStorage.getItem("ua_access") : null;

  const fetchApps = async () => {
    if (!access) return;
    const res = await fetch(`${backendUrl}/api/v1/apps`, {
      headers: { Authorization: `Bearer ${access}` }
    });
    if (res.ok) {
      const data = await res.json();
      setApps(data);
    }
  };

  const fetchReports = async (appId: string) => {
    if (!access) return;
    const res = await fetch(`${backendUrl}/api/v1/apps/${appId}/reports`, {
      headers: { Authorization: `Bearer ${access}` }
    });
    if (res.ok) {
      const data = await res.json();
      setReports(data);
    }
  };

  const fetchProfile = async () => {
    if (!access) return;
    const res = await fetch(`${backendUrl}/api/v1/profile`, {
      headers: { Authorization: `Bearer ${access}` }
    });
    if (res.ok) {
      const data = await res.json();
      setDisplayName(data.displayName || "");
    }
  };

  const fetchFederation = async () => {
    const res = await fetch(`${backendUrl}/api/v1/federation/backends`);
    if (res.ok) {
      setFederationBackends(await res.json());
    }
  };

  useEffect(() => {
    fetchApps();
    fetchProfile();
    fetchFederation();
  }, [access]);

  const createApp = async () => {
    if (!access) return;
    const res = await fetch(`${backendUrl}/api/v1/apps`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${access}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ name: appName, projectId, signerDigestSha256: signerDigest })
    });
    if (res.ok) {
      const data = await res.json();
      setAppName("");
      setProjectId("");
      setSignerDigest("");
      setNewSecret(data.apiSecret);
      setAppMessage(null);
      fetchApps();
    }
  };

  const rotateSecret = async () => {
    if (!access || !selectedApp) return;
    const res = await fetch(`${backendUrl}/api/v1/apps/${selectedApp.id}/rotate-secret`, {
      method: "POST",
      headers: { Authorization: `Bearer ${access}` }
    });
    if (res.ok) {
      const data = await res.json();
      setNewSecret(data.apiSecret);
    }
  };

  const updateApp = async () => {
    if (!access || !selectedApp) return;
    const res = await fetch(`${backendUrl}/api/v1/apps/${selectedApp.id}`, {
      method: "PATCH",
      headers: {
        Authorization: `Bearer ${access}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        name: editName,
        projectId: editProjectId,
        signerDigestSha256: editSigner
      })
    });
    if (res.ok) {
      fetchApps();
      setNewSecret(null);
      setAppMessage("App updated.");
    } else {
      const raw = await res.text();
      setAppMessage(raw || "Update failed");
    }
  };

  const deleteApp = async () => {
    if (!access || !selectedApp) return;
    if (!confirm("Delete this app and all its reports?")) return;
    const res = await fetch(`${backendUrl}/api/v1/apps/${selectedApp.id}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${access}` }
    });
    if (res.ok) {
      setSelectedApp(null);
      setReports([]);
      fetchApps();
      setAppMessage("App deleted.");
    } else {
      const raw = await res.text();
      setAppMessage(raw || "Delete failed");
    }
  };

  const saveProfile = async () => {
    if (!access) return;
    await fetch(`${backendUrl}/api/v1/profile`, {
      method: "PATCH",
      headers: {
        Authorization: `Bearer ${access}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ displayName })
    });
  };

  const changePassword = async () => {
    if (!access) return;
    setPasswordMessage(null);
    const res = await fetch(`${backendUrl}/api/v1/profile/password`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${access}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ currentPassword, newPassword })
    });
    if (!res.ok) {
      const raw = await res.text();
      setPasswordMessage(raw || "Failed to update password");
      return;
    }
    setCurrentPassword("");
    setNewPassword("");
    setPasswordMessage("Password updated.");
  };

  return (
    <Layout>
      <div className="grid lg:grid-cols-[2fr,1fr] gap-8">
        <section className="bg-white/70 rounded-2xl p-6 shadow-sm">
          <h2 className="text-xl font-semibold">Registered Apps</h2>
          <div className="mt-4 space-y-3">
            {apps.map((app) => (
              <button
                key={app.id}
                className={`w-full text-left rounded-xl border px-4 py-3 transition ${
                  selectedApp?.id === app.id
                    ? "border-ink bg-ink text-white"
                    : "border-gray-200 bg-white"
                }`}
                onClick={() => {
                  setSelectedApp(app);
                  setEditName(app.name);
                  setEditProjectId(app.projectId);
                  setEditSigner(app.signerDigestSha256);
                  setAppMessage(null);
                  fetchReports(app.id);
                  setNewSecret(null);
                }}
              >
                <div className="font-medium">{app.name}</div>
                <div className="text-xs opacity-80">Project ID: {app.projectId}</div>
                <div className="text-xs opacity-80">
                  Signer digest: {app.signerDigestSha256.slice(0, 16)}...
                </div>
              </button>
            ))}
          </div>
        </section>
        <section className="bg-white/70 rounded-2xl p-6 shadow-sm">
          <h2 className="text-xl font-semibold">Register App</h2>
          <div className="mt-4 space-y-3">
            <input
              className="w-full rounded-lg border border-gray-300 px-3 py-2"
              placeholder="App name"
              value={appName}
              onChange={(e) => setAppName(e.target.value)}
            />
            <input
              className="w-full rounded-lg border border-gray-300 px-3 py-2"
              placeholder="Project ID (package name)"
              value={projectId}
              onChange={(e) => setProjectId(e.target.value)}
            />
            <input
              className="w-full rounded-lg border border-gray-300 px-3 py-2"
              placeholder="Signing cert SHA-256 (hex)"
              value={signerDigest}
              onChange={(e) => setSignerDigest(e.target.value)}
            />
            <button className="w-full rounded-lg bg-ink text-white py-2" onClick={createApp}>
              Register
            </button>
          </div>
        </section>
        <section className="bg-white/70 rounded-2xl p-6 shadow-sm">
          <h2 className="text-xl font-semibold">Edit App</h2>
          {!selectedApp ? (
            <div className="text-sm text-gray-600 mt-3">Select an app to edit.</div>
          ) : (
            <div className="mt-4 space-y-3">
              <input
                className="w-full rounded-lg border border-gray-300 px-3 py-2"
                placeholder="App name"
                value={editName}
                onChange={(e) => setEditName(e.target.value)}
              />
              <input
                className="w-full rounded-lg border border-gray-300 px-3 py-2"
                placeholder="Project ID (package name)"
                value={editProjectId}
                onChange={(e) => setEditProjectId(e.target.value)}
              />
              <input
                className="w-full rounded-lg border border-gray-300 px-3 py-2"
                placeholder="Signing cert SHA-256 (hex)"
                value={editSigner}
                onChange={(e) => setEditSigner(e.target.value)}
              />
              <div className="flex gap-3">
                <button className="flex-1 rounded-lg bg-ink text-white py-2" onClick={updateApp}>
                  Save
                </button>
                <button
                  className="flex-1 rounded-lg border border-red-500 text-red-600 py-2"
                  onClick={deleteApp}
                >
                  Delete
                </button>
              </div>
              {appMessage && <div className="text-sm text-gray-700">{appMessage}</div>}
            </div>
          )}
        </section>
      </div>

      {selectedApp && (
        <section className="mt-8 bg-white/70 rounded-2xl p-6 shadow-sm">
          <div className="flex items-center justify-between">
            <h2 className="text-xl font-semibold">App Server Secret</h2>
            <button className="rounded-lg bg-clay text-white px-4 py-2" onClick={rotateSecret}>
              Rotate Secret
            </button>
          </div>
          {newSecret && (
            <div className="mt-4 rounded-lg bg-ink text-white p-4 text-sm">
              <p className="font-semibold">Copy your API secret now:</p>
              <code className="block mt-2 break-all">{newSecret}</code>
            </div>
          )}
        </section>
      )}

      <section className="mt-8 bg-white/70 rounded-2xl p-6 shadow-sm">
        <h2 className="text-xl font-semibold">Profile</h2>
        <div className="mt-4 flex flex-col md:flex-row gap-3">
          <input
            className="flex-1 rounded-lg border border-gray-300 px-3 py-2"
            placeholder="Display name"
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
          />
          <button className="rounded-lg bg-ink text-white px-4 py-2" onClick={saveProfile}>
            Save
          </button>
        </div>
        <div className="mt-4 grid md:grid-cols-2 gap-3">
          <input
            className="rounded-lg border border-gray-300 px-3 py-2"
            placeholder="Current password"
            type="password"
            value={currentPassword}
            onChange={(e) => setCurrentPassword(e.target.value)}
          />
          <input
            className="rounded-lg border border-gray-300 px-3 py-2"
            placeholder="New password"
            type="password"
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
          />
          <button className="rounded-lg bg-moss text-white px-4 py-2" onClick={changePassword}>
            Change Password
          </button>
        </div>
        {passwordMessage && <div className="text-sm text-red-600 mt-2">{passwordMessage}</div>}
      </section>

      <section className="mt-8 bg-white/70 rounded-2xl p-6 shadow-sm">
        <h2 className="text-xl font-semibold">Federation (Read-only)</h2>
        <div className="mt-4 grid md:grid-cols-2 gap-4">
          {federationBackends.map((backend) => (
            <div key={backend.id} className="rounded-xl border border-gray-200 p-4">
              <div className="font-semibold">{backend.name}</div>
              <div className="text-xs text-gray-500">{backend.backendId}</div>
              <div className="text-xs text-gray-500">Status: {backend.status}</div>
            </div>
          ))}
        </div>
      </section>

      {selectedApp && (
        <section className="mt-8 bg-white/70 rounded-2xl p-6 shadow-sm">
          <h2 className="text-xl font-semibold">Device Reports</h2>
          <div className="mt-4 space-y-2">
            {reports.map((report) => (
              <div key={report.id} className="rounded-lg border border-gray-200 px-4 py-2">
                <div className="text-sm">Device: {report.scopedDeviceId.slice(0, 16)}...</div>
                <div className="text-xs text-gray-500">Issuer: {report.issuerBackendId}</div>
                <div className="text-xs text-gray-500">Last seen: {report.lastSeen}</div>
                <div className="text-xs text-gray-500">
                  Verdict: {report.lastVerdict?.isTrusted ? "trusted" : "rejected"}
                </div>
              </div>
            ))}
          </div>
        </section>
      )}
    </Layout>
  );
}
