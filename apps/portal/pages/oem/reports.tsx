import { useCallback, useState } from "react";
import OemMenu from "../../components/oem/Menu";
import OemReports from "../../sections/oem/Reports";

export default function OemReportsPage() {
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
    <OemMenu activeItem="reports" organizationName={organizationName} onLogout={logout}>
      <OemReports onOrganizationLoaded={handleOrganizationLoaded} />
    </OemMenu>
  );
}
