import { useRouter } from "next/router";
import DeviceDetail from "../../sections/devices/DeviceDetail";

export default function DeviceDetailPage() {
  const router = useRouter();
  const slug = typeof router.query.slug === "string" ? router.query.slug : undefined;
  if (!slug) return null;
  return <DeviceDetail slug={slug} />;
}
