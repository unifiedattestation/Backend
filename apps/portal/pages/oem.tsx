import { useEffect, useState } from "react";
import Layout from "../components/Layout";

const backendUrl = process.env.NEXT_PUBLIC_BACKEND_URL || "http://localhost:3001";

type TrustRoot = {
  id: string;
  name: string;
  backendId: string;
  publicKeyPem?: string;
  jwksUrl?: string;
  createdAt: string;
};

export default function OemPage() {
  const [trustRoots, setTrustRoots] = useState<TrustRoot[]>([]);
  const [name, setName] = useState("");
  const [publicKeyPem, setPublicKeyPem] = useState("");
  const [jwksUrl, setJwksUrl] = useState("");

  const access = typeof window !== "undefined" ? localStorage.getItem("ua_access") : null;

  const loadRoots = async () => {
    if (!access) return;
    const res = await fetch(`${backendUrl}/v1/oem/trust-roots`, {
      headers: { Authorization: `Bearer ${access}` }
    });
    if (res.ok) {
      const data = await res.json();
      setTrustRoots(data);
    }
  };

  useEffect(() => {
    loadRoots();
  }, [access]);

  const createRoot = async () => {
    if (!access) return;
    const res = await fetch(`${backendUrl}/v1/oem/trust-roots`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${access}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ name, publicKeyPem, jwksUrl })
    });
    if (res.ok) {
      setName("");
      setPublicKeyPem("");
      setJwksUrl("");
      loadRoots();
    }
  };

  return (
    <Layout>
      <div className="grid lg:grid-cols-[2fr,1fr] gap-8">
        <section className="bg-white/70 rounded-2xl p-6 shadow-sm">
          <h2 className="text-xl font-semibold">Device Trust Roots</h2>
          <div className="mt-4 space-y-2">
            {trustRoots.map((root) => (
              <div key={root.id} className="rounded-lg border border-gray-200 px-4 py-2">
                <div className="font-medium">{root.name}</div>
                <div className="text-xs text-gray-500">Backend: {root.backendId}</div>
              </div>
            ))}
          </div>
        </section>
        <section className="bg-white/70 rounded-2xl p-6 shadow-sm">
          <h2 className="text-xl font-semibold">Register Trust Root</h2>
          <div className="mt-4 space-y-3">
            <input
              className="w-full rounded-lg border border-gray-300 px-3 py-2"
              placeholder="Name"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
            <textarea
              className="w-full rounded-lg border border-gray-300 px-3 py-2"
              placeholder="Public key PEM (optional)"
              value={publicKeyPem}
              onChange={(e) => setPublicKeyPem(e.target.value)}
            />
            <input
              className="w-full rounded-lg border border-gray-300 px-3 py-2"
              placeholder="JWKS URL (optional)"
              value={jwksUrl}
              onChange={(e) => setJwksUrl(e.target.value)}
            />
            <button className="w-full rounded-lg bg-moss text-white py-2" onClick={createRoot}>
              Register
            </button>
          </div>
        </section>
      </div>
    </Layout>
  );
}
