import { useCallback, useState } from "react";
import AppdevMenu from "../../components/appdev/Menu";
import AppdevReports from "../../sections/appdev/Reports";

export default function AppdevReportsPage() {
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
    <AppdevMenu activeItem="reports" userName={displayName} onLogout={logout}>
      <AppdevReports onProfileLoaded={handleProfileLoaded} />
    </AppdevMenu>
  );
}
