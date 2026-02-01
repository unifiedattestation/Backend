import { useState } from "react";
import { useRouter } from "next/router";

const backendUrl = process.env.NEXT_PUBLIC_BACKEND_URL || "";

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setError(null);
    const endpoint = "/api/v1/auth/login";
    const body = { email, password };

    const res = await fetch(`${backendUrl}${endpoint}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
    if (!res.ok) {
      setError("Authentication failed");
      return;
    }
    const data = await res.json();
    localStorage.setItem("ua_access", data.accessToken);
    localStorage.setItem("ua_refresh", data.refreshToken);
    try {
      const payload = JSON.parse(atob(data.accessToken.split(".")[1]));
      if (payload.role === "admin") {
        router.push("/admin");
        return;
      }
      if (payload.role === "oem") {
        router.push("/oem");
        return;
      }
    } catch {
      // fall back to app dev dashboard
    }
    router.push("/dashboard");
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-sand via-white to-sand">
      <div className="bg-white/80 shadow-xl rounded-2xl p-8 w-full max-w-md border border-sand">
        <h1 className="text-2xl font-semibold">Unified Attestation</h1>
        <p className="text-sm text-gray-600 mt-1">Sign in to manage apps, OEM policy, and trust.</p>
        <form onSubmit={submit} className="mt-6 space-y-4">
          <div>
            <label className="text-sm">Username</label>
            <input
              className="mt-1 w-full rounded-lg border border-gray-300 px-3 py-2"
              type="text"
              placeholder="admin"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
            />
          </div>
          <div>
            <label className="text-sm">Password</label>
            <input
              className="mt-1 w-full rounded-lg border border-gray-300 px-3 py-2"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </div>
          {error && <p className="text-sm text-red-600">{error}</p>}
          <button
            type="submit"
            className="w-full rounded-lg bg-ink text-white py-2 font-medium"
          >
            Sign in
          </button>
        </form>
        <p className="mt-4 text-xs text-gray-500">
          Default admin: <span className="font-semibold">admin / admin</span>
        </p>
      </div>
    </div>
  );
}
