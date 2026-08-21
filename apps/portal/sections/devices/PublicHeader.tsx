import Link from "next/link";
import { ArrowRight } from "lucide-react";

export default function PublicHeader() {
  return (
    <header className="sticky top-0 z-20 bg-[#071226] text-white">
      <div className="mx-auto flex h-16 w-full max-w-[1600px] items-center justify-between px-4 sm:px-5 lg:px-6">
        <div className="flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-white text-slate-950">
            <img src="/unified-attestation-logo.svg" alt="" className="h-7 w-7" />
          </div>
          <div>
            <p className="text-sm font-semibold text-white">Unified Attestation</p>
            <p className="text-xs text-slate-400">Device Registry</p>
          </div>
        </div>
        <Link
          href="/login"
          className="flex h-9 items-center gap-2 rounded-lg border border-white/15 px-3 text-sm font-medium text-slate-200 transition hover:bg-white/10 hover:text-white"
        >
          Sign in
          <ArrowRight size={15} />
        </Link>
      </div>
    </header>
  );
}
