import "../styles/globals.css";
import type { AppProps } from "next/app";
import Head from "next/head";
import { useRouter } from "next/router";

const pageTitles: Record<string, string> = {
  "/": "Unified Attestation",
  "/login": "Sign In",
  "/admin": "Admin Overview",
  "/admin/users": "User Management",
  "/admin/root-anchors": "Root Anchors",
  "/admin/authorities": "Attestation Authorities",
  "/admin/federation": "Federation Management",
  "/admin/settings": "Platform Settings",
  "/oem": "OEM Overview",
  "/oem/devices": "Device Families",
  "/oem/build-policies": "Build Policies",
  "/oem/trust-anchors": "Trust Anchors",
  "/oem/reports": "Attestation Reports",
  "/oem/api-access": "API Access",
  "/oem/organization": "Organization",
  "/appdev": "Developer Dashboard",
  "/appdev/applications": "Applications",
  "/appdev/reports": "Device Reports",
  "/appdev/federation": "Federation",
  "/appdev/profile": "Developer Profile",
};

export default function App({ Component, pageProps }: AppProps) {
  const router = useRouter();
  const pageTitle = pageTitles[router.pathname] || "Unified Attestation";
  const title =
    pageTitle === "Unified Attestation" ? pageTitle : `${pageTitle} | Unified Attestation`;
  const description =
    "Unified Attestation provides secure device attestation, trust management, federation, and application integration.";
  const siteUrl = (process.env.NEXT_PUBLIC_SITE_URL || "https://uattest.net").replace(/\/$/, "");
  const canonicalUrl = `${siteUrl}${router.asPath.split("?")[0]}`;
  const socialImage = `${siteUrl}/social-preview.png`;

  return (
    <>
      <Head>
        <title>{title}</title>
        <meta name="description" content={description} />
        <meta name="application-name" content="Unified Attestation" />
        <meta name="theme-color" content="#071226" />
        <link rel="icon" href="/favicon.ico" sizes="any" />
        <link rel="icon" href="/unified-attestation-logo.svg" type="image/svg+xml" />
        <link rel="canonical" href={canonicalUrl} />

        <meta property="og:type" content="website" />
        <meta property="og:site_name" content="Unified Attestation" />
        <meta property="og:title" content={title} />
        <meta property="og:description" content={description} />
        <meta property="og:url" content={canonicalUrl} />
        <meta property="og:image" content={socialImage} />
        <meta property="og:image:type" content="image/png" />
        <meta property="og:image:width" content="1200" />
        <meta property="og:image:height" content="630" />
        <meta property="og:image:alt" content="Unified Attestation platform" />

        <meta name="twitter:card" content="summary_large_image" />
        <meta name="twitter:title" content={title} />
        <meta name="twitter:description" content={description} />
        <meta name="twitter:image" content={socialImage} />
        <meta name="twitter:image:alt" content="Unified Attestation platform" />
      </Head>
      <Component {...pageProps} />
    </>
  );
}
