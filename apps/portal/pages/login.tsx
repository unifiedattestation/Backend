import { useState } from "react";
import { useRouter } from "next/router";

const backendUrl = process.env.NEXT_PUBLIC_BACKEND_URL || "http://localhost:3001";

export default function LoginPage() {
  const router = useRouter();
  const [isRegister, setIsRegister] = useState(false);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("developer");
  const [error, setError] = useState<string | null>(null);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setError(null);
    const endpoint = isRegister ? "/v1/auth/register" : "/v1/auth/login";
    const body: any = { email, password };
    if (isRegister) body.role = role;

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
    router.push("/dashboard");
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-sand via-white to-sand">
      <div className="bg-white/80 shadow-xl rounded-2xl p-8 w-full max-w-md border border-sand">
        <h1 className="text-2xl font-semibold">Unified Attestation</h1>
        <p className="text-sm text-gray-600 mt-1">
          {isRegister ? "Create a new portal account" : "Sign in to manage your apps"}
        </p>
        <form onSubmit={submit} className="mt-6 space-y-4">
          <div>
            <label className="text-sm">Email</label>
            <input
              className="mt-1 w-full rounded-lg border border-gray-300 px-3 py-2"
              type="email"
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
          {isRegister && (
            <div>
              <label className="text-sm">Role</label>
              <select
                className="mt-1 w-full rounded-lg border border-gray-300 px-3 py-2"
                value={role}
                onChange={(e) => setRole(e.target.value)}
              >
                <option value="developer">Developer</option>
                <option value="oem">OEM</option>
              </select>
            </div>
          )}
          {error && <p className="text-sm text-red-600">{error}</p>}
          <button
            type="submit"
            className="w-full rounded-lg bg-ink text-white py-2 font-medium"
          >
            {isRegister ? "Create account" : "Sign in"}
          </button>
        </form>
        <button
          className="mt-4 text-sm text-clay"
          onClick={() => setIsRegister(!isRegister)}
        >
          {isRegister ? "Already have an account? Sign in" : "Need an account? Register"}
        </button>
      </div>
    </div>
  );
}
