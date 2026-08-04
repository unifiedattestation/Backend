import ResponsiveMenu from "../../components/Menu";
import AdminUsers from "../../sections/admin/Users";

export default function AdminUsersPage() {
  const handleLogout = () => {
    localStorage.removeItem("ua_access");
    localStorage.removeItem("ua_refresh");
    window.location.href = "/login";
  };

  return (
    <ResponsiveMenu activeItem="users" onLogout={handleLogout}>
      <AdminUsers />
    </ResponsiveMenu>
  );
}
