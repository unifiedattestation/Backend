import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/router";
import { ArrowLeft, ArrowRight, ChevronRight, Loader2, Search, Smartphone } from "lucide-react";
import { backendUrl } from "../../lib/config";
import PublicHeader from "./PublicHeader";

type DeviceListItem = {
  slug: string;
  manufacturer: string | null;
  brand: string | null;
  model: string | null;
  codename: string | null;
  name: string;
  enabled: boolean;
  createdAt: string;
  oemOrgName: string;
};

type DeviceListResponse = {
  items: DeviceListItem[];
  page: number;
  pageSize: number;
  total: number;
  totalPages: number;
};

export default function DevicesList() {
  const router = useRouter();
  const [search, setSearch] = useState("");
  const [debouncedSearch, setDebouncedSearch] = useState("");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [data, setData] = useState<DeviceListResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [rateLimited, setRateLimited] = useState(false);

  useEffect(() => {
    if (!router.isReady) return;
    const query = router.query;
    if (typeof query.search === "string") {
      setSearch(query.search);
      setDebouncedSearch(query.search);
    }
    if (typeof query.page === "string") setPage(Math.max(1, Number(query.page) || 1));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [router.isReady]);

  // Only the free-text search box is debounced — page/pageSize changes load immediately.
  useEffect(() => {
    const timeout = setTimeout(() => setDebouncedSearch(search), 300);
    return () => clearTimeout(timeout);
  }, [search]);

  useEffect(() => {
    setPage(1);
  }, [debouncedSearch]);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    setRateLimited(false);
    try {
      const params = new URLSearchParams({
        page: String(page),
        pageSize: String(pageSize),
      });
      if (debouncedSearch.trim()) params.set("search", debouncedSearch.trim());
      const response = await fetch(`${backendUrl}/api/v1/devices?${params.toString()}`);
      if (response.status === 429) {
        setRateLimited(true);
        return;
      }
      if (!response.ok) throw new Error("Unable to load the device registry.");
      const body: DeviceListResponse = await response.json();
      setData(body);
    } catch (requestError) {
      setError(
        requestError instanceof Error ? requestError.message : "Unable to load the device registry.",
      );
    } finally {
      setLoading(false);
    }
  }, [page, pageSize, debouncedSearch]);

  useEffect(() => {
    if (!router.isReady) return;
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [load, router.isReady]);

  useEffect(() => {
    if (!router.isReady) return;
    const query: Record<string, string> = {};
    if (debouncedSearch.trim()) query.search = debouncedSearch.trim();
    if (page > 1) query.page = String(page);
    router.replace({ pathname: "/devices", query }, undefined, { shallow: true });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [debouncedSearch, page]);

  const items = data?.items ?? [];
  const total = data?.total ?? 0;
  const totalPages = data?.totalPages ?? 1;

  return (
    <div className="min-h-screen bg-slate-50">
      <PublicHeader />
      <div className="mx-auto w-full max-w-[1600px] p-4 sm:p-5 lg:p-6">
        <div className="mb-5">
          <h1 className="text-2xl font-semibold text-[#071226]">Device Registry</h1>
          <p className="mt-1 text-sm text-slate-500">
            Browse every device model registered with this backend.
          </p>
        </div>

        {error && (
          <div className="mb-4 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
            {error}
          </div>
        )}
        {rateLimited && (
          <div className="mb-4 rounded-xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-700">
            Too many requests — please slow down and try again shortly.
          </div>
        )}

        <section className="overflow-visible rounded-xl border border-slate-200 bg-white shadow-sm">
          <header className="flex flex-col gap-3 border-b border-slate-200 p-4 sm:flex-row">
            <label className="relative flex-1">
              <Search
                size={18}
                className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-400"
              />
              <input
                value={search}
                onChange={(event) => setSearch(event.target.value)}
                placeholder="Search manufacturer, model, codename, OEM..."
                className="h-10 w-full rounded-lg border border-slate-200 pl-10 pr-3 text-sm outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-100"
              />
            </label>
          </header>

          <div className="overflow-x-auto">
            <table className="w-full min-w-[860px] text-left text-sm">
              <thead className="bg-slate-50 text-xs text-slate-500">
                <tr>
                  <th className="px-5 py-3 font-semibold">Manufacturer</th>
                  <th className="px-5 py-3 font-semibold">Brand</th>
                  <th className="px-5 py-3 font-semibold">Model</th>
                  <th className="px-5 py-3 font-semibold">Codename</th>
                  <th className="px-5 py-3 font-semibold">OEM</th>
                  <th className="px-5 py-3 font-semibold" />
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {items.map((item) => (
                  <tr key={item.slug} className="hover:bg-slate-50/70">
                    <td className="px-5 py-3">
                      <div className="flex items-center gap-3">
                        <span className="flex h-9 w-9 items-center justify-center rounded-lg bg-blue-50 text-blue-700">
                          <Smartphone size={18} />
                        </span>
                        <span className="font-medium text-slate-900">
                          {item.manufacturer || "—"}
                        </span>
                      </div>
                    </td>
                    <td className="px-5 py-3 text-slate-500">{item.brand || "—"}</td>
                    <td className="px-5 py-3 text-slate-500">{item.model || "—"}</td>
                    <td className="px-5 py-3 text-slate-500">{item.codename || "—"}</td>
                    <td className="px-5 py-3 text-slate-500">{item.oemOrgName}</td>
                    <td className="px-5 py-3 text-right">
                      <Link
                        href={`/devices/${item.slug}`}
                        className="inline-flex items-center gap-1 font-medium text-blue-700 hover:underline"
                      >
                        View
                        <ChevronRight size={15} />
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {loading && (
              <div className="flex items-center justify-center gap-2 px-5 py-14 text-sm text-slate-500">
                <Loader2 size={18} className="animate-spin" />
                Loading devices...
              </div>
            )}
            {!loading && items.length === 0 && (
              <div className="px-5 py-14 text-center text-sm text-slate-500">
                {search.trim() ? "No devices match your search." : "No devices registered yet."}
              </div>
            )}
          </div>

          <footer className="flex flex-col gap-3 border-t border-slate-200 px-5 py-4 text-xs text-slate-500 sm:flex-row sm:items-center sm:justify-between">
            <span>
              Showing {total ? (page - 1) * pageSize + 1 : 0} to {Math.min(page * pageSize, total)}{" "}
              of {total} results
            </span>
            <div className="flex items-center gap-2">
              <button
                type="button"
                disabled={page === 1}
                onClick={() => setPage((current) => Math.max(1, current - 1))}
                className="rounded-lg border border-slate-200 p-2 disabled:opacity-40"
              >
                <ArrowLeft size={15} />
              </button>
              <span className="flex h-8 min-w-8 items-center justify-center rounded-lg border border-blue-600 px-2 font-medium text-blue-700">
                {page}
              </span>
              <button
                type="button"
                disabled={page >= totalPages}
                onClick={() => setPage((current) => current + 1)}
                className="rounded-lg border border-slate-200 p-2 disabled:opacity-40"
              >
                <ArrowRight size={15} />
              </button>
              <select
                value={pageSize}
                onChange={(event) => {
                  setPageSize(Number(event.target.value));
                  setPage(1);
                }}
                className="h-8 rounded-lg border border-slate-200 bg-white px-2"
              >
                <option value={10}>10 per page</option>
                <option value={20}>20 per page</option>
                <option value={50}>50 per page</option>
              </select>
            </div>
          </footer>
        </section>
      </div>
    </div>
  );
}
