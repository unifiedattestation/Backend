import { useEffect, useState } from "react";
import Layout from "../components/Layout";

const backendUrl = process.env.NEXT_PUBLIC_BACKEND_URL || "http://localhost:3001";

type DeviceFamily = {
  id: string;
  name: string;
  codename?: string | null;
  model?: string | null;
  enabled: boolean;
  createdAt: string;
};

type BuildPolicy = {
  id: string;
  buildFingerprint: string;
  verifiedBootKeyHex: string;
  verifiedBootHashHex?: string | null;
  osVersionRaw?: number | null;
  minOsPatchLevelRaw?: number | null;
  enabled: boolean;
  createdAt: string;
};

type DeviceReport = {
  id: string;
  scopedDeviceId: string;
  issuerBackendId: string;
  lastVerdict: { isTrusted: boolean; reasonCodes: string[] };
  lastSeen: string;
  buildFingerprint?: string | null;
};

type AttestationServer = {
  id: string;
  name: string;
  baseUrl: string;
  isLocal: boolean;
  statusCachedAt?: string | null;
  keyAvailability?: {
    rsa: boolean;
    ecdsa: boolean;
  };
};

type DeviceEntry = {
  id: string;
  rsaSerialHex: string;
  ecdsaSerialHex: string;
  rsaIntermediateSerialHex?: string | null;
  ecdsaIntermediateSerialHex?: string | null;
  revokedAt?: string | null;
  authorityName: string;
  rsaRoot?: { subject: string; serialHex: string; keyType: string } | null;
  ecdsaRoot?: { subject: string; serialHex: string; keyType: string } | null;
  deviceCodename?: string | null;
  createdAt: string;
};

export default function OemPage() {
  const [families, setFamilies] = useState<DeviceFamily[]>([]);
  const [selectedFamily, setSelectedFamily] = useState<DeviceFamily | null>(null);
  const [activeTab, setActiveTab] = useState<"device" | "builds" | "anchors" | "reports">("device");
  const [displayName, setDisplayName] = useState("");
  const [manufacturer, setManufacturer] = useState("");
  const [brand, setBrand] = useState("");
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [passwordMessage, setPasswordMessage] = useState<string | null>(null);
  const [oemAnchorReady, setOemAnchorReady] = useState(false);
  const [oemAnchorDetails, setOemAnchorDetails] = useState<{
    rsa?: { subject: string; serialHex: string };
    ecdsa?: { subject: string; serialHex: string };
  } | null>(null);
  const [activeDeviceAnchors, setActiveDeviceAnchors] = useState(0);
  const [linkedActiveAnchors, setLinkedActiveAnchors] = useState(0);
  const [trustAnchorHistory, setTrustAnchorHistory] = useState<
    Array<{
      id: string;
      rsaSerialHex: string;
      ecdsaSerialHex: string;
      rsaSubject: string;
      ecdsaSubject: string;
      createdAt: string;
      revokedAt?: string | null;
    }>
  >([]);
  const [oemAnchorNotice, setOemAnchorNotice] = useState<string | null>(null);
  const [oemAnchorError, setOemAnchorError] = useState<string | null>(null);
  const [federationBackends, setFederationBackends] = useState<
    { id: string; backendId: string; name: string; status: string }[]
  >([]);

  const [familyForm, setFamilyForm] = useState({
    codename: "",
    model: ""
  });

  const [familyEdit, setFamilyEdit] = useState({
    enabled: true,
    codename: "",
    model: ""
  });
  const [deviceCreateError, setDeviceCreateError] = useState<string | null>(null);


  const [builds, setBuilds] = useState<BuildPolicy[]>([]);
  const [buildForm, setBuildForm] = useState({
    id: "",
    buildFingerprint: "",
    verifiedBootKeyHex: "",
    verifiedBootHashHex: "",
    osVersionRaw: "",
    minOsPatchLevelRaw: "",
    enabled: true
  });

  const [reports, setReports] = useState<DeviceReport[]>([]);
  const [attestationServers, setAttestationServers] = useState<AttestationServer[]>([]);
  const [deviceEntries, setDeviceEntries] = useState<DeviceEntry[]>([]);
  const [deviceForm, setDeviceForm] = useState({
    authorityId: "",
    rsaSerialHex: "",
    ecdsaSerialHex: "",
    rsaIntermediateSerialHex: "",
    ecdsaIntermediateSerialHex: ""
  });
  const [deviceError, setDeviceError] = useState<string | null>(null);
  const [deviceNotice, setDeviceNotice] = useState<string | null>(null);

  const access = typeof window !== "undefined" ? localStorage.getItem("ua_access") : null;

  const loadFamilies = async () => {
    if (!access) return;
    const res = await fetch(`${backendUrl}/api/v1/oem/device-families`, {
      headers: { Authorization: `Bearer ${access}` }
    });
    if (res.ok) {
      setFamilies(await res.json());
    }
  };

  const loadBuilds = async (familyId: string) => {
    if (!access) return;
    const res = await fetch(`${backendUrl}/api/v1/oem/device-families/${familyId}/builds`, {
      headers: { Authorization: `Bearer ${access}` }
    });
    if (res.ok) {
      setBuilds(await res.json());
    }
  };

  const loadReports = async (familyId: string) => {
    if (!access) return;
    const res = await fetch(
      `${backendUrl}/api/v1/oem/reports/failing-devices?deviceFamilyId=${familyId}`,
      {
        headers: { Authorization: `Bearer ${access}` }
      }
    );
    if (res.ok) {
      setReports(await res.json());
    }
  };

  const loadProfile = async () => {
    if (!access) return;
    const res = await fetch(`${backendUrl}/api/v1/profile`, {
      headers: { Authorization: `Bearer ${access}` }
    });
    if (res.ok) {
      const data = await res.json();
      setDisplayName(data.displayName || "");
      setManufacturer(data.manufacturer || "");
      setBrand(data.brand || "");
      setOemAnchorReady(Boolean(data.oemTrustAnchorReady));
      setOemAnchorDetails(data.oemTrustAnchor || null);
      setActiveDeviceAnchors(Number(data.activeDeviceAnchors || 0));
      setLinkedActiveAnchors(Number(data.linkedActiveAnchors || 0));
      setTrustAnchorHistory(data.trustAnchorHistory || []);
    }
  };

  const loadFederation = async () => {
    const res = await fetch(`${backendUrl}/api/v1/federation/backends`);
    if (res.ok) {
      setFederationBackends(await res.json());
    }
  };

  const loadAttestationServers = async () => {
    if (!access) return;
    const res = await fetch(`${backendUrl}/api/v1/oem/attestation-servers`, {
      headers: { Authorization: `Bearer ${access}` }
    });
    if (res.ok) {
      setAttestationServers(await res.json());
    }
  };

  const loadAnchors = async (deviceFamilyId?: string) => {
    if (!access) return;
    const url = deviceFamilyId
      ? `${backendUrl}/api/v1/oem/anchors?deviceFamilyId=${deviceFamilyId}`
      : `${backendUrl}/api/v1/oem/anchors`;
    const res = await fetch(url, {
      headers: { Authorization: `Bearer ${access}` }
    });
    if (res.ok) {
      setDeviceEntries(await res.json());
    }
  };

  useEffect(() => {
    loadFamilies();
    loadProfile();
    loadFederation();
    loadAttestationServers();
  }, [access]);

  const createFamily = async () => {
    if (!access) return;
    setDeviceCreateError(null);
    const res = await fetch(`${backendUrl}/api/v1/oem/device-families`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${access}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        codename: familyForm.codename || undefined,
        model: familyForm.model || undefined
      })
    });
    if (!res.ok) {
      const raw = await res.text();
      setDeviceCreateError(raw || "Failed to register device");
      return;
    }
    setFamilyForm({ codename: "", model: "" });
    loadFamilies();
  };

  const updateFamily = async () => {
    if (!access || !selectedFamily) return;
    const res = await fetch(`${backendUrl}/api/v1/oem/device-families/${selectedFamily.id}`, {
      method: "PUT",
      headers: {
        Authorization: `Bearer ${access}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        enabled: familyEdit.enabled,
        codename: familyEdit.codename || undefined,
        model: familyEdit.model || undefined
      })
    });
    if (res.ok) {
      const updated = await res.json();
      setSelectedFamily(updated);
      loadFamilies();
    }
  };

  const saveBuild = async () => {
    if (!access || !selectedFamily) return;
    const payload = {
      buildFingerprint: buildForm.buildFingerprint,
      verifiedBootKeyHex: buildForm.verifiedBootKeyHex,
      verifiedBootHashHex: buildForm.verifiedBootHashHex || undefined,
      osVersionRaw: buildForm.osVersionRaw ? Number(buildForm.osVersionRaw) : undefined,
      minOsPatchLevelRaw: buildForm.minOsPatchLevelRaw
        ? Number(buildForm.minOsPatchLevelRaw)
        : undefined,
      enabled: buildForm.enabled
    };
    const isEdit = Boolean(buildForm.id);
    const url = isEdit
      ? `${backendUrl}/api/v1/oem/device-families/${selectedFamily.id}/builds/${buildForm.id}`
      : `${backendUrl}/api/v1/oem/device-families/${selectedFamily.id}/builds`;
    const method = isEdit ? "PUT" : "POST";
    const res = await fetch(url, {
      method,
      headers: {
        Authorization: `Bearer ${access}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify(payload)
    });
    if (res.ok) {
      setBuildForm({
        id: "",
        buildFingerprint: "",
        verifiedBootKeyHex: "",
        verifiedBootHashHex: "",
        osVersionRaw: "",
        minOsPatchLevelRaw: "",
        enabled: true
      });
      loadBuilds(selectedFamily.id);
    }
  };

  const editBuild = (build: BuildPolicy) => {
    setBuildForm({
      id: build.id,
      buildFingerprint: build.buildFingerprint,
      verifiedBootKeyHex: build.verifiedBootKeyHex,
      verifiedBootHashHex: build.verifiedBootHashHex || "",
      osVersionRaw: build.osVersionRaw?.toString() || "",
      minOsPatchLevelRaw: build.minOsPatchLevelRaw?.toString() || "",
      enabled: build.enabled
    });
  };

  const deleteBuild = async (buildId: string) => {
    if (!access || !selectedFamily) return;
    await fetch(
      `${backendUrl}/api/v1/oem/device-families/${selectedFamily.id}/builds/${buildId}`,
      {
        method: "DELETE",
        headers: { Authorization: `Bearer ${access}` }
      }
    );
    loadBuilds(selectedFamily.id);
  };

  const saveProfile = async () => {
    if (!access) return;
    await fetch(`${backendUrl}/api/v1/profile`, {
      method: "PATCH",
      headers: {
        Authorization: `Bearer ${access}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ displayName, manufacturer, brand })
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

  const generateOemTrustAnchor = async () => {
    if (!access) return;
    setOemAnchorNotice(null);
    setOemAnchorError(null);
    const res = await fetch(`${backendUrl}/api/v1/oem/profile/generate-trust-anchor`, {
      method: "POST",
      headers: { Authorization: `Bearer ${access}` }
    });
    if (!res.ok) {
      const raw = await res.text();
      setOemAnchorError(raw || "Failed to generate OEM trust anchor");
      return;
    }
    const blob = await res.blob();
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "oem_trust_anchor.xml";
    link.click();
    window.URL.revokeObjectURL(url);
    await loadProfile();
    setOemAnchorNotice("OEM trust anchor generated and downloaded.");
  };

  const revokeOemTrustAnchor = async () => {
    if (!access) return;
    setOemAnchorNotice(null);
    setOemAnchorError(null);
    const res = await fetch(`${backendUrl}/api/v1/oem/profile/revoke-trust-anchor`, {
      method: "POST",
      headers: { Authorization: `Bearer ${access}` }
    });
    if (!res.ok) {
      const raw = await res.text();
      setOemAnchorError(raw || "Failed to revoke OEM trust anchor");
      return;
    }
    const payload = await res.json();
    setOemAnchorReady(Boolean(payload.rsaReady && payload.ecdsaReady));
    await loadProfile();
    setOemAnchorNotice("OEM trust anchor revoked.");
  };


  const createAnchor = async () => {
    if (!access) {
      setDeviceError("Not authenticated.");
      return null;
    }
    if (!selectedFamily) {
      setDeviceError("Select a device first.");
      return null;
    }
    if (
      !deviceForm.authorityId ||
      !deviceForm.rsaSerialHex ||
      !deviceForm.ecdsaSerialHex ||
      !deviceForm.rsaIntermediateSerialHex ||
      !deviceForm.ecdsaIntermediateSerialHex
    ) {
      setDeviceError("Select an authority and enter leaf + intermediate serials.");
      return null;
    }
    setDeviceError(null);
    setDeviceNotice(null);
    const res = await fetch(`${backendUrl}/api/v1/oem/anchors`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${access}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        deviceFamilyId: selectedFamily.id,
        authorityId: deviceForm.authorityId,
        rsaSerialHex: deviceForm.rsaSerialHex,
        ecdsaSerialHex: deviceForm.ecdsaSerialHex,
        rsaIntermediateSerialHex: deviceForm.rsaIntermediateSerialHex,
        ecdsaIntermediateSerialHex: deviceForm.ecdsaIntermediateSerialHex
      })
    });
    if (!res.ok) {
      const raw = await res.text();
      setDeviceError(raw || "Failed to register device");
      return null;
    }
    const created = await res.json();
    setDeviceForm({
      authorityId: "",
      rsaSerialHex: "",
      ecdsaSerialHex: "",
      rsaIntermediateSerialHex: "",
      ecdsaIntermediateSerialHex: ""
    });
    loadAnchors(selectedFamily.id);
    return created as { id: string };
  };

  const revokeAnchor = async (id: string) => {
    if (!access) {
      setDeviceError("Not authenticated.");
      return;
    }
    if (!selectedFamily) return;
    setDeviceError(null);
    setDeviceNotice(null);
    await fetch(`${backendUrl}/api/v1/oem/anchors/${id}/revoke`, {
      method: "POST",
      headers: { Authorization: `Bearer ${access}` }
    });
    loadAnchors(selectedFamily.id);
  };

  const deleteAnchor = async (id: string) => {
    if (!access) {
      setDeviceError("Not authenticated.");
      return;
    }
    if (!selectedFamily) return;
    setDeviceError(null);
    setDeviceNotice(null);
    await fetch(`${backendUrl}/api/v1/oem/anchors/${id}`, {
      method: "DELETE",
      headers: { Authorization: `Bearer ${access}` }
    });
    loadAnchors(selectedFamily.id);
  };

  const downloadKeybox = async () => {
    if (!access) {
      setDeviceError("Not authenticated.");
      return;
    }
    if (!selectedFamily) {
      setDeviceError("Select a device first.");
      return;
    }
    setDeviceError(null);
    setDeviceNotice(null);
    const res = await fetch(`${backendUrl}/api/v1/oem/anchors/generate-keybox`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${access}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        deviceFamilyId: selectedFamily.id
      })
    });
    if (!res.ok) {
      const raw = await res.text();
      setDeviceError(raw || "Failed to generate keybox");
      return;
    }
    const blob = await res.blob();
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `keybox_${selectedFamily.codename || "device"}.xml`;
    link.click();
    window.URL.revokeObjectURL(url);
    setDeviceNotice("Keybox download started.");
    loadAnchors(selectedFamily.id);
  };

  const createAndGenerateKeybox = async () => {
    await downloadKeybox();
  };

  const selectFamily = (family: DeviceFamily) => {
    setSelectedFamily(family);
    setFamilyEdit({
      enabled: family.enabled,
      codename: family.codename || "",
      model: family.model || ""
    });
    setActiveTab("device");
    setDeviceForm({
      authorityId: "",
      rsaSerialHex: "",
      ecdsaSerialHex: "",
      rsaIntermediateSerialHex: "",
      ecdsaIntermediateSerialHex: ""
    });
    loadBuilds(family.id);
    loadReports(family.id);
  };

  useEffect(() => {
    if (selectedFamily) {
      loadReports(selectedFamily.id);
      loadAnchors(selectedFamily.id);
    }
  }, [selectedFamily]);

  return (
    <Layout>
      <div className="grid lg:grid-cols-[2fr,1fr] gap-8">
        <section className="bg-white/70 rounded-2xl p-6 shadow-sm">
          <h2 className="text-xl font-semibold">Devices</h2>
          <div className="mt-4 space-y-3">
            {families.map((family) => (
              <button
                key={family.id}
                className={`w-full text-left rounded-xl border px-4 py-3 transition ${
                  selectedFamily?.id === family.id
                    ? "border-ink bg-ink text-white"
                    : "border-gray-200 bg-white"
                }`}
                onClick={() => selectFamily(family)}
              >
                <div className="font-medium">{family.codename || family.name}</div>
                <div className="text-xs opacity-80">Model: {family.model || "-"}</div>
                {!family.enabled && <div className="text-xs opacity-80">Status: disabled</div>}
              </button>
            ))}
          </div>
        </section>

        <section className="bg-white/70 rounded-2xl p-6 shadow-sm">
          <h2 className="text-xl font-semibold">Register Device</h2>
          <div className="mt-4 space-y-3">
            <input
              className="w-full rounded-lg border border-gray-300 px-3 py-2"
              placeholder="Device codename"
              value={familyForm.codename}
              onChange={(e) => setFamilyForm({ ...familyForm, codename: e.target.value })}
            />
            <input
              className="w-full rounded-lg border border-gray-300 px-3 py-2"
              placeholder="Model (optional)"
              value={familyForm.model}
              onChange={(e) => setFamilyForm({ ...familyForm, model: e.target.value })}
            />
            <button className="w-full rounded-lg bg-moss text-white py-2" onClick={createFamily}>
              Save
            </button>
            {deviceCreateError && <div className="text-sm text-red-600">{deviceCreateError}</div>}
          </div>
        </section>
      </div>

      {selectedFamily && (
        <section className="mt-8 bg-white/70 rounded-2xl p-6 shadow-sm">
          <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3">
            <div>
              <h2 className="text-xl font-semibold">
                {selectedFamily.codename || selectedFamily.name}
              </h2>
              <p className="text-xs text-gray-500">ID: {selectedFamily.id}</p>
            </div>
            <div className="flex gap-2 text-sm">
              <button
                className={`rounded-full px-4 py-2 ${
                  activeTab === "device" ? "bg-ink text-white" : "bg-white border"
                }`}
                onClick={() => setActiveTab("device")}
              >
                Device
              </button>
              <button
                className={`rounded-full px-4 py-2 ${
                  activeTab === "builds" ? "bg-ink text-white" : "bg-white border"
                }`}
                onClick={() => setActiveTab("builds")}
              >
                Builds
              </button>
              <button
                className={`rounded-full px-4 py-2 ${
                  activeTab === "anchors" ? "bg-ink text-white" : "bg-white border"
                }`}
                onClick={() => setActiveTab("anchors")}
              >
                Trust Anchors
              </button>
              <button
                className={`rounded-full px-4 py-2 ${
                  activeTab === "reports" ? "bg-ink text-white" : "bg-white border"
                }`}
                onClick={() => setActiveTab("reports")}
              >
                Reports
              </button>
            </div>
          </div>

          <div className="mt-6">
            {activeTab === "device" && (
              <div className="max-w-xl">
                <h3 className="text-sm font-semibold text-gray-700">Device</h3>
                <div className="mt-3 space-y-2">
                  <input
                    className="w-full rounded-lg border border-gray-300 px-3 py-2"
                    placeholder="Device codename"
                    value={familyEdit.codename}
                    onChange={(e) => setFamilyEdit({ ...familyEdit, codename: e.target.value })}
                  />
                  <input
                    className="w-full rounded-lg border border-gray-300 px-3 py-2"
                    placeholder="Model (optional)"
                    value={familyEdit.model}
                    onChange={(e) => setFamilyEdit({ ...familyEdit, model: e.target.value })}
                  />
                  <label className="flex items-center gap-2 text-sm">
                    <input
                      type="checkbox"
                      checked={familyEdit.enabled}
                      onChange={(e) => setFamilyEdit({ enabled: e.target.checked })}
                    />
                    Enabled
                  </label>
                  <button className="rounded-lg bg-ink text-white px-4 py-2" onClick={updateFamily}>
                    Save Device Info
                  </button>
                </div>
              </div>
            )}

            {activeTab === "builds" && (
              <div>
                <h3 className="text-sm font-semibold text-gray-700">Build Policies</h3>
                <div className="mt-3 space-y-2">
                  <input
                    className="w-full rounded-lg border border-gray-300 px-3 py-2"
                    placeholder="Build fingerprint"
                    value={buildForm.buildFingerprint}
                    onChange={(e) =>
                      setBuildForm({ ...buildForm, buildFingerprint: e.target.value })
                    }
                  />
                  <input
                    className="w-full rounded-lg border border-gray-300 px-3 py-2"
                    placeholder="Verified boot key hex"
                    value={buildForm.verifiedBootKeyHex}
                    onChange={(e) =>
                      setBuildForm({ ...buildForm, verifiedBootKeyHex: e.target.value })
                    }
                  />
                  <input
                    className="w-full rounded-lg border border-gray-300 px-3 py-2"
                    placeholder="Verified boot hash hex"
                    value={buildForm.verifiedBootHashHex}
                    onChange={(e) =>
                      setBuildForm({ ...buildForm, verifiedBootHashHex: e.target.value })
                    }
                  />
                  <div className="grid grid-cols-2 gap-2">
                    <input
                      className="w-full rounded-lg border border-gray-300 px-3 py-2"
                      placeholder="OS version raw"
                      value={buildForm.osVersionRaw}
                      onChange={(e) => setBuildForm({ ...buildForm, osVersionRaw: e.target.value })}
                    />
                    <input
                      className="w-full rounded-lg border border-gray-300 px-3 py-2"
                      placeholder="OS patch level"
                      value={buildForm.minOsPatchLevelRaw}
                      onChange={(e) =>
                        setBuildForm({ ...buildForm, minOsPatchLevelRaw: e.target.value })
                      }
                    />
                  </div>
                  <label className="flex items-center gap-2 text-sm">
                    <input
                      type="checkbox"
                      checked={buildForm.enabled}
                      onChange={(e) => setBuildForm({ ...buildForm, enabled: e.target.checked })}
                    />
                    Enabled
                  </label>
                  <button className="rounded-lg bg-moss text-white px-4 py-2" onClick={saveBuild}>
                    {buildForm.id ? "Update Build" : "Add Build"}
                  </button>
                </div>

                <div className="mt-6 space-y-2">
                  {builds.map((build) => (
                    <div key={build.id} className="rounded-lg border border-gray-200 px-4 py-2">
                      <div className="font-medium">{build.buildFingerprint}</div>
                      <div className="text-xs text-gray-500">
                        Boot key: {build.verifiedBootKeyHex.slice(0, 16)}...
                      </div>
                      <div className="text-xs text-gray-500">
                        OS version: {build.osVersionRaw ?? "-"}
                      </div>
                      <div className="text-xs text-gray-500">
                        OS patch level: {build.minOsPatchLevelRaw ?? "-"}
                      </div>
                      <div className="text-xs text-gray-500">Enabled: {build.enabled ? "yes" : "no"}</div>
                      <div className="mt-2 flex gap-2 text-xs">
                        <button className="rounded-md bg-sand px-3 py-1" onClick={() => editBuild(build)}>
                          Edit
                        </button>
                        <button
                          className="rounded-md bg-rose-500 text-white px-3 py-1"
                          onClick={() => deleteBuild(build.id)}
                        >
                          Delete
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {activeTab === "anchors" && (
              <div>
                <h3 className="text-sm font-semibold text-gray-700">Trust Anchors</h3>
                <div className="mt-3">
                  <h3 className="text-sm font-semibold text-gray-700">Anchors</h3>
                  <div className="mt-3 grid lg:grid-cols-[1.2fr,1fr] gap-6">
                    <div className="space-y-3">
                      <select
                        className="w-full rounded-lg border border-gray-300 px-3 py-2"
                        value={deviceForm.authorityId}
                        onChange={(e) =>
                          setDeviceForm({ ...deviceForm, authorityId: e.target.value })
                        }
                      >
                        <option value="">Select attestation authority</option>
                        {attestationServers.map((server) => (
                          <option key={server.id} value={server.id}>
                            {server.isLocal ? `${server.name}` : server.name}
                          </option>
                        ))}
                      </select>
                      <input
                        className="w-full rounded-lg border border-gray-300 px-3 py-2"
                        placeholder="RSA leaf serial hex"
                        value={deviceForm.rsaSerialHex}
                        onChange={(e) =>
                          setDeviceForm({ ...deviceForm, rsaSerialHex: e.target.value })
                        }
                      />
                      <input
                        className="w-full rounded-lg border border-gray-300 px-3 py-2"
                        placeholder="RSA intermediate serial hex"
                        value={deviceForm.rsaIntermediateSerialHex}
                        onChange={(e) =>
                          setDeviceForm({ ...deviceForm, rsaIntermediateSerialHex: e.target.value })
                        }
                      />
                      <input
                        className="w-full rounded-lg border border-gray-300 px-3 py-2"
                        placeholder="ECDSA leaf serial hex"
                        value={deviceForm.ecdsaSerialHex}
                        onChange={(e) =>
                          setDeviceForm({ ...deviceForm, ecdsaSerialHex: e.target.value })
                        }
                      />
                      <input
                        className="w-full rounded-lg border border-gray-300 px-3 py-2"
                        placeholder="ECDSA intermediate serial hex"
                        value={deviceForm.ecdsaIntermediateSerialHex}
                        onChange={(e) =>
                          setDeviceForm({ ...deviceForm, ecdsaIntermediateSerialHex: e.target.value })
                        }
                      />
                      <div className="flex flex-wrap gap-2">
                        <button
                          className="rounded-lg bg-ink text-white px-4 py-2"
                          onClick={createAnchor}
                        >
                          Register Anchor
                        </button>
                        <button
                          className="rounded-lg bg-moss text-white px-4 py-2"
                          onClick={createAndGenerateKeybox}
                        >
                          Generate Keys
                        </button>
                      </div>
                      {deviceError && <div className="text-sm text-red-600">{deviceError}</div>}
                      {deviceNotice && <div className="text-sm text-green-700">{deviceNotice}</div>}
                    </div>
                    <div className="space-y-3">
                      {deviceEntries.map((device) => (
                        <div key={device.id} className="rounded-xl border border-gray-200 p-4">
                          <div className="text-sm font-semibold">
                            RSA: {device.rsaSerialHex}
                          </div>
                          {device.rsaIntermediateSerialHex && (
                            <div className="text-xs text-gray-500">
                              RSA intermediate: {device.rsaIntermediateSerialHex}
                            </div>
                          )}
                          <div className="text-sm font-semibold">
                            ECDSA: {device.ecdsaSerialHex}
                          </div>
                          {device.ecdsaIntermediateSerialHex && (
                            <div className="text-xs text-gray-500">
                              ECDSA intermediate: {device.ecdsaIntermediateSerialHex}
                            </div>
                          )}
                          <div className="text-xs text-gray-500">Authority: {device.authorityName}</div>
                          <div
                            className={`text-xs ${
                              device.revokedAt ? "text-red-600" : "text-gray-500"
                            }`}
                          >
                            Created: {new Date(device.createdAt).toLocaleString()}
                            {device.revokedAt && ` · Revoked: ${new Date(device.revokedAt).toLocaleString()}`}
                          </div>
                          <div className="mt-3 flex flex-wrap gap-2">
                            <button
                              className="rounded-md bg-rose-500 text-white px-3 py-1 text-xs"
                              onClick={() => revokeAnchor(device.id)}
                              disabled={Boolean(device.revokedAt)}
                            >
                              {device.revokedAt ? "Revoked" : "Revoke"}
                            </button>
                            <button
                              className="rounded-md bg-gray-200 text-gray-800 px-3 py-1 text-xs"
                              onClick={() => deleteAnchor(device.id)}
                            >
                              Remove
                            </button>
                          </div>
                        </div>
                      ))}
                      {deviceEntries.length === 0 && (
                        <div className="text-sm text-gray-500">No anchors registered yet.</div>
                      )}
                      {deviceError && <div className="text-sm text-red-600">{deviceError}</div>}
                      {deviceNotice && <div className="text-sm text-green-700">{deviceNotice}</div>}
                    </div>
                  </div>
                </div>
              </div>
            )}

            {activeTab === "reports" && (
              <div>
                <h3 className="text-sm font-semibold text-gray-700">Failing Devices</h3>
                <div className="mt-3 space-y-2">
                  {reports.map((report) => (
                    <div key={report.id} className="rounded-lg border border-gray-200 px-4 py-2">
                      <div className="text-sm">Device: {report.scopedDeviceId.slice(0, 16)}...</div>
                      <div className="text-xs text-gray-500">Last seen: {report.lastSeen}</div>
                      <div className="text-xs text-gray-500">
                        Build fingerprint: {report.buildFingerprint || "unmatched"}
                      </div>
                      <div className="text-xs text-gray-500">
                        Reasons: {report.lastVerdict?.reasonCodes?.join(", ") || "unknown"}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </section>
      )}

      <section className="mt-8 bg-white/70 rounded-2xl p-6 shadow-sm">
        <h2 className="text-xl font-semibold">Profile</h2>
        <div className="mt-4 grid md:grid-cols-3 gap-3">
          <input
            className="rounded-lg border border-gray-300 px-3 py-2"
            placeholder="Display name"
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
          />
          <input
            className="rounded-lg border border-gray-300 px-3 py-2"
            placeholder="Manufacturer"
            value={manufacturer}
            onChange={(e) => setManufacturer(e.target.value)}
          />
          <input
            className="rounded-lg border border-gray-300 px-3 py-2"
            placeholder="Brand"
            value={brand}
            onChange={(e) => setBrand(e.target.value)}
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
        <div className="mt-6 border-t border-gray-200 pt-4">
          <h3 className="text-sm font-semibold text-gray-700">OEM Trust Anchor</h3>
          <p className="text-xs text-gray-500 mt-1">
            Generate OEM RSA + ECDSA intermediate certs chained to the backend root.
          </p>
          <div className="mt-3 flex flex-wrap gap-2 items-center">
            <div className="text-xs text-gray-600">
              Status: {oemAnchorReady ? "active" : "not generated"}
            </div>
            <button
              className="rounded-lg bg-moss text-white px-4 py-2"
              onClick={generateOemTrustAnchor}
            >
              Generate OEM Trust Anchor
            </button>
          </div>
          {trustAnchorHistory.length > 0 ? (
            <div className="mt-4">
              <div className="space-y-3">
                {trustAnchorHistory.map((anchor) => {
                  const isActive = !anchor.revokedAt;
                  return (
                    <div key={anchor.id} className="rounded-xl border border-gray-200 bg-white px-4 py-3">
                      <div className="flex items-center justify-between" />
                      <div className="mt-2 space-y-2">
                        <div>
                          <div className="text-xs text-gray-500">RSA Intermediate</div>
                          <div className="text-sm font-semibold">{anchor.rsaSubject}</div>
                          <div className="text-xs text-gray-600">Serial: {anchor.rsaSerialHex}</div>
                        </div>
                        <div>
                          <div className="text-xs text-gray-500">ECDSA Intermediate</div>
                          <div className="text-sm font-semibold">{anchor.ecdsaSubject}</div>
                          <div className="text-xs text-gray-600">
                            Serial: {anchor.ecdsaSerialHex}
                          </div>
                        </div>
                      </div>
                      <div className={`mt-2 text-xs ${anchor.revokedAt ? "text-red-600" : "text-gray-500"}`}>
                        Created: {new Date(anchor.createdAt).toLocaleString()}
                        {anchor.revokedAt && ` · Revoked: ${new Date(anchor.revokedAt).toLocaleString()}`}
                      </div>
                      <div className="mt-3 flex flex-wrap gap-2">
                        <button
                          className="rounded-md bg-rose-500 text-white px-3 py-1 text-xs"
                          onClick={revokeOemTrustAnchor}
                          disabled={!isActive}
                        >
                          Revoke
                        </button>
                        <button
                          className="rounded-md bg-gray-200 text-gray-800 px-3 py-1 text-xs"
                          onClick={revokeOemTrustAnchor}
                          disabled={!isActive}
                        >
                          Remove
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          ) : (
            <div className="mt-3 text-xs text-gray-500">No OEM trust anchors yet.</div>
          )}
          {oemAnchorError && <div className="text-sm text-red-600 mt-2">{oemAnchorError}</div>}
          {oemAnchorNotice && <div className="text-sm text-green-700 mt-2">{oemAnchorNotice}</div>}
        </div>
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
    </Layout>
  );
}
