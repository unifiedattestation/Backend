import Link from "next/link";

export default function Layout({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen bg-gradient-to-br from-sand via-white to-sand">
      <header className="px-8 py-6 flex items-center justify-between">
        <h1 className="text-2xl font-semibold tracking-tight">Unified Attestation Portal</h1>
        <nav className="flex gap-4 text-sm">
          <Link href="/dashboard" className="hover:text-clay">
            Dashboard
          </Link>
          <Link href="/oem" className="hover:text-clay">
            OEM
          </Link>
          <Link href="/admin" className="hover:text-clay">
            Federation
          </Link>
        </nav>
      </header>
      <main className="px-8 pb-16">{children}</main>
    </div>
  );
}
