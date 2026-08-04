import { useState } from "react";
import { useRouter } from "next/router";
import { ArrowRight, KeyRound, Loader2, ShieldCheck, UserRound } from "lucide-react";
import { backendUrl } from "../lib/config";

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setError(null);
    setLoading(true);

    try {
      const response = await fetch(`${backendUrl}/api/v1/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });

      if (!response.ok) {
        setError("The username or password is incorrect.");
        return;
      }

      const data = await response.json();
      localStorage.setItem("ua_access", data.accessToken);
      localStorage.setItem("ua_refresh", data.refreshToken);

      const payload = JSON.parse(atob(data.accessToken.split(".")[1]));
      if (payload.role === "admin") {
        await router.push("/admin");
        return;
      }
      if (payload.role === "oem") {
        await router.push("/oem");
        return;
      }
      await router.push("/appdev");
    } catch {
      setError("Unable to connect. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="flex min-h-screen items-center justify-center bg-slate-100 p-5">
      <section className="w-full max-w-md rounded-2xl border border-slate-200 bg-white p-6 shadow-xl shadow-slate-300/30 sm:p-8">
        <div className="flex items-center gap-3">
          <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-[#071226] text-white">
            <ShieldCheck size={24} />
          </div>
          <div>
            <h1 className="font-semibold text-[#071226]">Unified Attestation</h1>
            <p className="text-xs text-slate-500">Administration Portal</p>
          </div>
        </div>

        <div className="mt-7">
          <h2 className="text-2xl font-bold tracking-tight text-[#071226]">Sign in</h2>
          <p className="mt-1 text-sm text-slate-500">Enter your credentials to continue.</p>
        </div>

        <form onSubmit={submit} className="mt-6 space-y-4">
          <div>
            <label htmlFor="username" className="text-sm font-medium text-slate-700">
              Username
            </label>
            <div className="relative mt-1.5">
              <UserRound
                size={18}
                className="pointer-events-none absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400"
              />
              <input
                id="username"
                className="h-11 w-full rounded-xl border border-slate-200 pl-11 pr-4 text-sm outline-none transition placeholder:text-slate-400 focus:border-blue-600 focus:ring-4 focus:ring-blue-100"
                type="text"
                placeholder="Enter your username"
                autoComplete="username"
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                required
              />
            </div>
          </div>

          <div>
            <label htmlFor="password" className="text-sm font-medium text-slate-700">
              Password
            </label>
            <div className="relative mt-1.5">
              <KeyRound
                size={18}
                className="pointer-events-none absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400"
              />
              <input
                id="password"
                className="h-11 w-full rounded-xl border border-slate-200 pl-11 pr-4 text-sm outline-none transition placeholder:text-slate-400 focus:border-blue-600 focus:ring-4 focus:ring-blue-100"
                type="password"
                placeholder="Enter your password"
                autoComplete="current-password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                required
              />
            </div>
          </div>

          {error && (
            <div
              role="alert"
              className="rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700"
            >
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="flex h-11 w-full items-center justify-center gap-2 rounded-xl bg-[#071226] text-sm font-semibold text-white transition hover:bg-[#101f36] focus:outline-none focus-visible:ring-4 focus-visible:ring-blue-200 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {loading ? (
              <>
                <Loader2 size={18} className="animate-spin" />
                Signing in...
              </>
            ) : (
              <>
                Sign in
                <ArrowRight size={18} />
              </>
            )}
          </button>
        </form>

        <p className="mt-5 text-center text-xs text-slate-400">
          Default administrator:{" "}
          <span className="font-mono font-medium text-slate-600">admin / admin</span>
        </p>
      </section>
    </main>
  );
}
