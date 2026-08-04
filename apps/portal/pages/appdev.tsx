import { useCallback, useState } from "react";
import AppdevMenu from "../components/appdev/Menu";
import AppdevDashboard from "../sections/appdev/Dashboard";

export default function AppdevPage() {
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
    <AppdevMenu activeItem="dashboard" userName={displayName} onLogout={logout}>
      <AppdevDashboard onProfileLoaded={handleProfileLoaded} />
    </AppdevMenu>
  );
}
