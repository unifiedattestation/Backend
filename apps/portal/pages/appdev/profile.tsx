import { useCallback, useState } from "react";
import AppdevMenu from "../../components/appdev/Menu";
import AppdevProfile from "../../sections/appdev/Profile";

export default function AppdevProfilePage() {
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
    <AppdevMenu activeItem="profile" userName={displayName} onLogout={logout}>
      <AppdevProfile onProfileLoaded={handleProfileLoaded} onLogout={logout} />
    </AppdevMenu>
  );
}
