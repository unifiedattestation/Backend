import { useEffect, useState } from "react";
import Layout from "../components/Layout";

const backendUrl = process.env.NEXT_PUBLIC_BACKEND_URL || "http://localhost:3001";

type Backend = {
  backendId: string;
  name: string;
  region: string;
  trustLevel: number;
  status: string;
};

export default function AdminPage() {
  const [backends, setBackends] = useState<Backend[]>([]);

  useEffect(() => {
    fetch(`${backendUrl}/v1/federation/backends`)
      .then((res) => res.json())
      .then((data) => setBackends(data));
  }, []);

  return (
    <Layout>
      <section className="bg-white/70 rounded-2xl p-6 shadow-sm">
        <h2 className="text-xl font-semibold">Federation Backends</h2>
        <div className="mt-4 grid md:grid-cols-2 gap-4">
          {backends.map((backend) => (
            <div key={backend.backendId} className="rounded-xl border border-gray-200 p-4">
              <div className="font-semibold">{backend.name}</div>
              <div className="text-xs text-gray-500">{backend.backendId}</div>
              <div className="text-xs text-gray-500">Region: {backend.region}</div>
              <div className="text-xs text-gray-500">Trust: {backend.trustLevel}</div>
              <div className="text-xs text-gray-500">Status: {backend.status}</div>
            </div>
          ))}
        </div>
      </section>
    </Layout>
  );
}
