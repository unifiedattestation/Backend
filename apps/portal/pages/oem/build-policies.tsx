import { useCallback, useState } from "react";
import OemMenu from "../../components/oem/Menu";
import OemBuildPolicies from "../../sections/oem/BuildPolicies";

export default function OemBuildPoliciesPage() {
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
    <OemMenu activeItem="builds" organizationName={organizationName} onLogout={logout}>
      <OemBuildPolicies onOrganizationLoaded={handleOrganizationLoaded} />
    </OemMenu>
  );
}
