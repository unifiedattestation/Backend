import { useCallback, useState } from "react";
import OemMenu from "../../components/oem/Menu";
import OemTrustAnchors from "../../sections/oem/TrustAnchors";

export default function OemTrustAnchorsPage() {
  const [organizationName, setOrganizationName] = useState("OEM Portal");
  const handleOrganizationLoaded = useCallback((name: string) => {
    setOrganizationName(name || "OEM Portal");
  }, []);

  const logout = () => {
    localStorage.removeItem("ua_access");
    localStorage.removeItem("ua_refresh");
    window.location.href = "/login";
  };

  return (
    <OemMenu activeItem="anchors" organizationName={organizationName} onLogout={logout}>
      <OemTrustAnchors onOrganizationLoaded={handleOrganizationLoaded} />
    </OemMenu>
  );
}
