import ResponsiveMenu from "../../components/Menu";
import AdminSettings from "../../sections/admin/Settings";

export default function SettingsPage() {
  const logout = () => {
    localStorage.removeItem("ua_access");
    localStorage.removeItem("ua_refresh");
    window.location.href = "/login";
  };

  return (
    <ResponsiveMenu activeItem="settings" onLogout={logout}>
      <AdminSettings />
    </ResponsiveMenu>
  );
}
