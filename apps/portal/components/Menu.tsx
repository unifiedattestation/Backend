import { useEffect, useState, type ReactNode } from "react";
import {
  LayoutDashboard,
  Users,
  ShieldCheck,
  KeyRound,
  Network,
  Settings,
  Menu,
  X,
  LogOut,
} from "lucide-react";

export type MenuItem = {
  id: string;
  label: string;
  href: string;
  icon?: ReactNode;
  badge?: string | number;
};

type ResponsiveMenuProps = {
  activeItem: string;
  userName?: string;
  userRole?: string;
  logo?: ReactNode;
  items?: MenuItem[];
  children: ReactNode;
  onNavigate?: (item: MenuItem) => void;
  onLogout?: () => void;
};

const defaultItems: MenuItem[] = [
  {
    id: "overview",
    label: "Overview",
    href: "/admin",
    icon: <LayoutDashboard size={20} />,
  },
  {
    id: "users",
    label: "Users",
    href: "/admin/users",
    icon: <Users size={20} />,
  },
  {
    id: "root-anchors",
    label: "Root Anchors",
    href: "/admin/root-anchors",
    icon: <KeyRound size={20} />,
  },
  {
    id: "authorities",
    label: "Attestation Authorities",
    href: "/admin/authorities",
    icon: <ShieldCheck size={20} />,
  },
  {
    id: "federation",
    label: "Federation",
    href: "/admin/federation",
    icon: <Network size={20} />,
  },
  {
    id: "settings",
    label: "Settings",
    href: "/admin/settings",
    icon: <Settings size={20} />,
  },
];

export default function ResponsiveMenu({
  activeItem,
  userName = "Administrator",
  userRole = "Platform Admin",
  logo,
  items = defaultItems,
  children,
  onNavigate,
  onLogout,
}: ResponsiveMenuProps) {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  useEffect(() => {
    document.body.style.overflow = mobileMenuOpen ? "hidden" : "";

    return () => {
      document.body.style.overflow = "";
    };
  }, [mobileMenuOpen]);
  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setMobileMenuOpen(false);
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);

  const handleNavigate = (item: MenuItem) => {
    setMobileMenuOpen(false);

    if (onNavigate) {
      onNavigate(item);
      return;
    }

    window.location.href = item.href;
  };

  const sidebarContent = (
    <div className="flex h-full flex-col bg-[#071226] text-slate-200">
      {/* Logo */}
      <div className="flex h-16 items-center border-b border-white/10 px-5">
        {logo ?? (
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-white text-slate-950">
              <img src="/unified-attestation-logo.svg" alt="" className="h-7 w-7" />
            </div>

            <div>
              <p className="text-sm font-semibold text-white">Unified Attestation</p>
              <p className="text-xs text-slate-400">Admin Console</p>
            </div>
          </div>
        )}
      </div>
      <nav className="flex-1 space-y-1 overflow-y-auto px-3 py-5" aria-label="Main navigation">
        <p className="mb-3 px-3 text-[11px] font-semibold uppercase tracking-widest text-slate-500">
          Management
        </p>

        {items.map((item) => {
          const isActive = activeItem === item.id;

          return (
            <button
              key={item.id}
              type="button"
              onClick={() => handleNavigate(item)}
              aria-current={isActive ? "page" : undefined}
              className={[
                "group flex w-full items-center gap-3 rounded-xl px-3 py-2.5",
                "text-left text-sm font-medium transition-colors",
                "focus:outline-none focus-visible:ring-2 focus-visible:ring-[#6f88b5]",
                isActive
                  ? "bg-[#1b2d4d] text-white shadow-lg shadow-black/20"
                  : "text-slate-300 hover:bg-[#101f36] hover:text-white",
              ].join(" ")}
            >
              <span className={isActive ? "text-white" : "text-slate-400 group-hover:text-white"}>
                {item.icon}
              </span>

              <span className="min-w-0 flex-1 truncate">{item.label}</span>

              {item.badge !== undefined && (
                <span
                  className={[
                    "rounded-full px-2 py-0.5 text-xs",
                    isActive ? "bg-white/10 text-white" : "bg-white/10 text-slate-300",
                  ].join(" ")}
                >
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* User */}
      <div className="border-t border-white/10 p-3">
        <div className="mb-2 flex items-center gap-3 rounded-xl px-3 py-2">
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-slate-700 text-sm font-semibold text-white">
            {userName.charAt(0).toUpperCase()}
          </div>

          <div className="min-w-0 flex-1">
            <p className="truncate text-sm font-medium text-white">{userName}</p>
            <p className="truncate text-xs text-slate-400">{userRole}</p>
          </div>
        </div>

        <button
          type="button"
          onClick={onLogout}
          className="flex w-full items-center gap-3 rounded-xl px-3 py-2.5 text-sm text-slate-400 transition hover:bg-red-500/10 hover:text-red-300 focus:outline-none focus-visible:ring-2 focus-visible:ring-red-400"
        >
          <LogOut size={19} />
          Sign out
        </button>
      </div>
    </div>
  );

  return (
    <div className="min-h-screen bg-slate-50">
      <aside className="fixed inset-y-0 left-0 z-30 hidden w-72 lg:block">{sidebarContent}</aside>
      <header className="sticky top-0 z-20 flex h-16 items-center justify-between border-b border-slate-200 bg-white/95 px-4 backdrop-blur lg:hidden">
        <div className="flex items-center gap-2">
          <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-[#071226] text-white">
            <img
              src="/unified-attestation-logo.svg"
              alt=""
              className="h-6 w-6 brightness-0 invert"
            />
          </div>

          <div>
            <p className="text-sm font-semibold text-slate-900">Unified Attestation</p>
            <p className="text-xs text-slate-500">Admin Console</p>
          </div>
        </div>

        <button
          type="button"
          onClick={() => setMobileMenuOpen(true)}
          aria-label="Open navigation menu"
          aria-expanded={mobileMenuOpen}
          className="rounded-xl border border-slate-200 p-2.5 text-slate-700 transition hover:bg-slate-100 focus:outline-none focus-visible:ring-2 focus-visible:ring-[#48658f]"
        >
          <Menu size={22} />
        </button>
      </header>
      <div
        aria-hidden={!mobileMenuOpen}
        onClick={() => setMobileMenuOpen(false)}
        className={[
          "fixed inset-0 z-40 bg-[#071226]/70 backdrop-blur-sm transition-opacity lg:hidden",
          mobileMenuOpen ? "pointer-events-auto opacity-100" : "pointer-events-none opacity-0",
        ].join(" ")}
      />
      <aside
        role="dialog"
        aria-modal="true"
        aria-label="Navigation menu"
        className={[
          "fixed inset-y-0 left-0 z-50 w-[min(88vw,320px)] transition-transform duration-300 ease-out lg:hidden",
          mobileMenuOpen ? "translate-x-0" : "-translate-x-full",
        ].join(" ")}
      >
        <button
          type="button"
          onClick={() => setMobileMenuOpen(false)}
          aria-label="Close navigation menu"
          className="absolute right-3 top-3 z-10 rounded-lg p-2 text-slate-400 transition hover:bg-white/10 hover:text-white"
        >
          <X size={21} />
        </button>

        {sidebarContent}
      </aside>
      <main className="min-w-0 lg:pl-72">
        <div className="mx-auto w-full max-w-[1600px] p-4 sm:p-5 lg:p-6">{children}</div>
      </main>
    </div>
  );
}
