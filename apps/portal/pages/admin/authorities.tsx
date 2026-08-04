import ResponsiveMenu from "../../components/Menu";
import AdminAuthorities from "../../sections/admin/Authorities";

export default function AdminAuthoritiesPage() {
  const handleLogout = () => {
    localStorage.removeItem("ua_access");
    localStorage.removeItem("ua_refresh");
    window.location.href = "/login";
  };

  return (
    <ResponsiveMenu activeItem="authorities" onLogout={handleLogout}>
      <AdminAuthorities />
    </ResponsiveMenu>
  );
}
