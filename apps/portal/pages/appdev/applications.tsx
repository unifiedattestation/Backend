import { useCallback, useState } from "react";
import AppdevMenu from "../../components/appdev/Menu";
import AppdevApplications from "../../sections/appdev/Applications";

export default function AppdevApplicationsPage() {
  const [displayName, setDisplayName] = useState("App Developer");
  const handleProfileLoaded = useCallback((name: string) => {
    setDisplayName(name || "App Developer");
  }, []);

  const logout = () => {
    localStorage.removeItem("ua_access");
    localStorage.removeItem("ua_refresh");
    window.location.href = "/login";
  };

  return (
    <AppdevMenu activeItem="applications" userName={displayName} onLogout={logout}>
      <AppdevApplications onProfileLoaded={handleProfileLoaded} />
    </AppdevMenu>
  );
}
