import { useCallback, useState } from "react";
import OemMenu from "../../components/oem/Menu";
import OemApiAccess from "../../sections/oem/ApiAccess";

export default function OemApiAccessPage() {
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
    <OemMenu activeItem="api" organizationName={organizationName} onLogout={logout}>
      <OemApiAccess onOrganizationLoaded={handleOrganizationLoaded} />
    </OemMenu>
  );
}
