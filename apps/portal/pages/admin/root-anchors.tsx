import ResponsiveMenu from "../../components/Menu";
import AdminRootAnchors from "../../sections/admin/RootAnchors";

export default function AdminRootAnchorsPage() {
  const handleLogout = () => {
    localStorage.removeItem("ua_access");
    localStorage.removeItem("ua_refresh");
    window.location.href = "/login";
  };

  return (
    <ResponsiveMenu activeItem="root-anchors" onLogout={handleLogout}>
      <AdminRootAnchors />
    </ResponsiveMenu>
  );
}
