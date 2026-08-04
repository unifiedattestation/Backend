import ResponsiveMenu from "../../components/Menu";
import AdminFederation from "../../sections/admin/Federation";

export default function AdminFederationPage() {
  const handleLogout = () => {
    localStorage.removeItem("ua_access");
    localStorage.removeItem("ua_refresh");
    window.location.href = "/login";
  };

  return (
    <ResponsiveMenu activeItem="federation" onLogout={handleLogout}>
      <AdminFederation />
    </ResponsiveMenu>
  );
}
