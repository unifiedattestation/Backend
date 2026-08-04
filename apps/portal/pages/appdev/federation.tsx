import { useCallback, useState } from "react";
import AppdevMenu from "../../components/appdev/Menu";
import AppdevFederation from "../../sections/appdev/Federation";

export default function AppdevFederationPage() {
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
    <AppdevMenu activeItem="federation" userName={displayName} onLogout={logout}>
      <AppdevFederation onProfileLoaded={handleProfileLoaded} />
    </AppdevMenu>
  );
}
