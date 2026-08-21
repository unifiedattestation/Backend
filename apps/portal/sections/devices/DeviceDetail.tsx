import { useEffect, useState } from "react";
import Head from "next/head";
import Link from "next/link";
import { ArrowLeft, Check, Copy, ExternalLink, Loader2 } from "lucide-react";
import { backendUrl } from "../../lib/config";
import PublicHeader from "./PublicHeader";

type DeviceCertificate = {
  rsaLeafSerialHex: string;
  rsaIntermediateSerialHex: string | null;
  ecdsaLeafSerialHex: string;
  ecdsaIntermediateSerialHex: string | null;
  authority: { name: string; rootCertificatesUrl: string };
};

type DeviceBuild = {
  buildFingerprint: string;
  verifiedBootKeyHex: string;
  verifiedBootHashHex: string | null;
  osVersionRaw: number | null;
  minOsPatchLevelRaw: number | null;
  createdAt: string;
};

type DeviceDetail = {
  slug: string;
  manufacturer: string | null;
  brand: string | null;
  model: string | null;
  codename: string | null;
  name: string;
  enabled: boolean;
  createdAt: string;
  oemOrgName: string;
  certificate: DeviceCertificate | null;
  builds: DeviceBuild[];
};

function androidVersion(value?: number | null) {
  if (!value) return "—";
  return value >= 10000 ? String(Math.floor(value / 10000)) : String(value);
}

function masked(value?: string | null) {
  if (!value) return "—";
  if (value.length < 16) return value;
  return `${value.slice(0, 4)}••••••••••••${value.slice(-4)}`;
}

function Detail({
  label,
  value,
  onCopy,
  copied,
}: {
  label: string;
  value: string;
  onCopy?: () => void;
  copied?: boolean;
}) {
  return (
    <div>
      <p className="text-xs text-slate-500">{label}</p>
      <div className="mt-1 flex items-center gap-2">
        <p className="min-w-0 truncate font-mono text-xs text-slate-700">{value}</p>
        {onCopy && (
          <button type="button" onClick={onCopy} className="text-slate-500 hover:text-blue-700">
            {copied ? <Check size={15} /> : <Copy size={15} />}
          </button>
        )}
      </div>
    </div>
  );
}

export default function DeviceDetail({ slug }: { slug: string }) {
  const [device, setDevice] = useState<DeviceDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [notFound, setNotFound] = useState(false);
  const [rateLimited, setRateLimited] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      setLoading(true);
      setError(null);
      setNotFound(false);
      setRateLimited(false);
      try {
        const response = await fetch(`${backendUrl}/api/v1/devices/${encodeURIComponent(slug)}`);
        if (cancelled) return;
        if (response.status === 429) {
          setRateLimited(true);
          return;
        }
        if (response.status === 404) {
          setNotFound(true);
          return;
        }
        if (!response.ok) throw new Error("Unable to load this device.");
        const body: DeviceDetail = await response.json();
        setDevice(body);
      } catch (requestError) {
        if (!cancelled) {
          setError(requestError instanceof Error ? requestError.message : "Unable to load this device.");
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    load();
    return () => {
      cancelled = true;
    };
  }, [slug]);

  const copyValue = async (id: string, value: string) => {
    await navigator.clipboard.writeText(value);
    setCopied(id);
    window.setTimeout(() => setCopied(null), 1400);
  };

  return (
    <div className="min-h-screen bg-slate-50">
      {device && (
        <Head>
          <title>{`${device.name} | Unified Attestation`}</title>
        </Head>
      )}
      <PublicHeader />
      <div className="mx-auto w-full max-w-[1600px] p-4 sm:p-5 lg:p-6">
        <Link
          href="/devices"
          className="mb-4 inline-flex items-center gap-2 text-sm font-medium text-slate-600 hover:text-slate-900"
        >
          <ArrowLeft size={15} />
          Back to Device Registry
        </Link>

        {loading && (
          <div className="flex items-center justify-center gap-2 rounded-xl border border-slate-200 bg-white px-5 py-14 text-sm text-slate-500 shadow-sm">
            <Loader2 size={18} className="animate-spin" />
            Loading device...
          </div>
        )}

        {!loading && rateLimited && (
          <div className="rounded-xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-700">
            Too many requests — please slow down and try again shortly.
          </div>
        )}

        {!loading && !rateLimited && notFound && (
          <div className="rounded-xl border border-slate-200 bg-white px-5 py-14 text-center text-sm text-slate-500 shadow-sm">
            Device not found.{" "}
            <Link href="/devices" className="font-medium text-blue-700 hover:underline">
              Back to Device Registry
            </Link>
          </div>
        )}

        {!loading && !rateLimited && error && (
          <div className="rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
            {error}
          </div>
        )}

        {!loading && !rateLimited && !notFound && !error && device && (
          <div className="flex flex-col gap-5">
            <section className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
              <div className="flex flex-wrap items-center gap-3">
                <h2 className="text-xl font-semibold text-[#071226]">
                  {device.model || device.name}
                  {device.codename ? ` (${device.codename})` : ""}
                </h2>
                <span
                  className={`inline-flex items-center rounded-full px-2.5 py-1 text-xs font-medium ${
                    device.enabled ? "bg-emerald-50 text-emerald-700" : "bg-red-50 text-red-700"
                  }`}
                >
                  {device.enabled ? "Enabled" : "Disabled"}
                </span>
              </div>
              <p className="mt-2 text-sm text-slate-500">
                {[device.manufacturer, device.brand, device.codename].filter(Boolean).join(" · ") ||
                  "—"}
              </p>
              <p className="mt-1 text-sm text-slate-500">Registered by {device.oemOrgName}</p>
            </section>

            <section className="rounded-xl border border-slate-200 bg-white shadow-sm">
              <header className="border-b border-slate-200 px-5 py-3">
                <h3 className="text-sm font-semibold text-slate-700">Certificate</h3>
              </header>
              {device.certificate ? (
                <div className="grid gap-5 p-5 lg:grid-cols-[1fr_1fr]">
                  <div className="space-y-4">
                    <Detail
                      label="RSA Leaf Serial Hex"
                      value={device.certificate.rsaLeafSerialHex}
                      onCopy={() => copyValue("rsa-leaf", device.certificate!.rsaLeafSerialHex)}
                      copied={copied === "rsa-leaf"}
                    />
                    <Detail
                      label="RSA Intermediate Serial Hex"
                      value={device.certificate.rsaIntermediateSerialHex || "—"}
                      onCopy={
                        device.certificate.rsaIntermediateSerialHex
                          ? () => copyValue("rsa-intermediate", device.certificate!.rsaIntermediateSerialHex || "")
                          : undefined
                      }
                      copied={copied === "rsa-intermediate"}
                    />
                    <Detail
                      label="ECDSA Leaf Serial Hex"
                      value={device.certificate.ecdsaLeafSerialHex}
                      onCopy={() => copyValue("ecdsa-leaf", device.certificate!.ecdsaLeafSerialHex)}
                      copied={copied === "ecdsa-leaf"}
                    />
                    <Detail
                      label="ECDSA Intermediate Serial Hex"
                      value={device.certificate.ecdsaIntermediateSerialHex || "—"}
                      onCopy={
                        device.certificate.ecdsaIntermediateSerialHex
                          ? () =>
                              copyValue(
                                "ecdsa-intermediate",
                                device.certificate!.ecdsaIntermediateSerialHex || "",
                              )
                          : undefined
                      }
                      copied={copied === "ecdsa-intermediate"}
                    />
                  </div>
                  <dl className="grid h-fit grid-cols-2 gap-x-5 gap-y-3 text-sm">
                    <dt className="text-slate-500">Authority</dt>
                    <dd className="text-slate-700">{device.certificate.authority.name}</dd>
                    <dt className="text-slate-500">Root Certificates</dt>
                    <dd>
                      <a
                        href={device.certificate.authority.rootCertificatesUrl}
                        target="_blank"
                        rel="noreferrer"
                        className="inline-flex items-center gap-1 font-medium text-blue-700 hover:underline"
                      >
                        View
                        <ExternalLink size={13} />
                      </a>
                    </dd>
                  </dl>
                </div>
              ) : (
                <div className="px-5 py-8 text-center text-sm text-slate-500">
                  No active certificate registered for this device.
                </div>
              )}
            </section>

            <section className="rounded-xl border border-slate-200 bg-white shadow-sm">
              <header className="border-b border-slate-200 px-5 py-3">
                <h3 className="text-sm font-semibold text-slate-700">Builds ({device.builds.length})</h3>
              </header>
              {device.builds.length > 0 ? (
                <div className="overflow-x-auto">
                  <table className="w-full min-w-[760px] text-left text-sm">
                    <thead className="bg-slate-50 text-xs text-slate-500">
                      <tr>
                        <th className="px-5 py-3 font-semibold">Fingerprint</th>
                        <th className="px-5 py-3 font-semibold">AVB Key</th>
                        <th className="px-5 py-3 font-semibold">OS</th>
                        <th className="px-5 py-3 font-semibold">Patch</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100">
                      {device.builds.map((build) => (
                        <tr key={build.buildFingerprint} className="hover:bg-slate-50/70">
                          <td className="max-w-64 truncate px-5 py-3 font-mono text-xs text-slate-600">
                            {build.buildFingerprint}
                          </td>
                          <td className="px-5 py-3 font-mono text-xs text-slate-600">
                            {masked(build.verifiedBootKeyHex)}
                          </td>
                          <td className="px-5 py-3 text-slate-600">
                            Android {androidVersion(build.osVersionRaw)}
                          </td>
                          <td className="px-5 py-3 text-slate-600">{build.minOsPatchLevelRaw || "—"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="px-5 py-8 text-center text-sm text-slate-500">
                  No active builds registered for this device.
                </div>
              )}
            </section>
          </div>
        )}
      </div>
    </div>
  );
}
