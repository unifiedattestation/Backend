import ResponsiveMenu from "../components/Menu";
import AdminOverview from "../sections/admin/Overview";

export default function AdminPage() {
  const handleLogout = () => {
    localStorage.removeItem("ua_access");
    localStorage.removeItem("ua_refresh");
    window.location.href = "/login";
  };

  return (
    <ResponsiveMenu activeItem="overview" onLogout={handleLogout}>
      <AdminOverview />
    </ResponsiveMenu>
  );
}
