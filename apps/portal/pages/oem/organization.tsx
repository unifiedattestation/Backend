import { useCallback, useState } from "react";
import OemMenu from "../../components/oem/Menu";
import OemOrganization from "../../sections/oem/Organization";

export default function OemOrganizationPage() {
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
    <OemMenu activeItem="organization" organizationName={organizationName} onLogout={logout}>
      <OemOrganization onOrganizationLoaded={handleOrganizationLoaded} />
    </OemMenu>
  );
}
