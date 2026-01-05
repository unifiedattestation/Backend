import { useEffect, useState } from "react";
import Layout from "../components/Layout";

const backendUrl = process.env.NEXT_PUBLIC_BACKEND_URL || "http://localhost:3001";

type Project = {
  id: string;
  orgId: string;
  name: string;
  packageName: string;
  createdAt: string;
};

type ApiKey = {
  id: string;
  keyPrefix: string;
  createdAt: string;
  revokedAt?: string | null;
};

export default function Dashboard() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedProject, setSelectedProject] = useState<Project | null>(null);
  const [projectName, setProjectName] = useState("");
  const [packageName, setPackageName] = useState("");
  const [apiKeys, setApiKeys] = useState<ApiKey[]>([]);
  const [newKey, setNewKey] = useState<string | null>(null);

  const access = typeof window !== "undefined" ? localStorage.getItem("ua_access") : null;

  const fetchProjects = async () => {
    if (!access) return;
    const res = await fetch(`${backendUrl}/v1/projects`, {
      headers: { Authorization: `Bearer ${access}` }
    });
    if (res.ok) {
      const data = await res.json();
      setProjects(data);
    }
  };

  const fetchApiKeys = async (projectId: string) => {
    if (!access) return;
    const res = await fetch(`${backendUrl}/v1/projects/${projectId}/api-keys`, {
      headers: { Authorization: `Bearer ${access}` }
    });
    if (res.ok) {
      const data = await res.json();
      setApiKeys(data);
    }
  };

  useEffect(() => {
    fetchProjects();
  }, [access]);

  const createProject = async () => {
    if (!access) return;
    const res = await fetch(`${backendUrl}/v1/projects`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${access}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ name: projectName, packageName })
    });
    if (res.ok) {
      setProjectName("");
      setPackageName("");
      fetchProjects();
    }
  };

  const createApiKey = async () => {
    if (!access || !selectedProject) return;
    const res = await fetch(`${backendUrl}/v1/projects/${selectedProject.id}/api-keys`, {
      method: "POST",
      headers: { Authorization: `Bearer ${access}` }
    });
    if (res.ok) {
      const data = await res.json();
      setNewKey(data.apiKey);
      fetchApiKeys(selectedProject.id);
    }
  };

  return (
    <Layout>
      <div className="grid lg:grid-cols-[2fr,1fr] gap-8">
        <section className="bg-white/70 rounded-2xl p-6 shadow-sm">
          <h2 className="text-xl font-semibold">Projects</h2>
          <div className="mt-4 space-y-3">
            {projects.map((project) => (
              <button
                key={project.id}
                className={`w-full text-left rounded-xl border px-4 py-3 transition ${
                  selectedProject?.id === project.id
                    ? "border-ink bg-ink text-white"
                    : "border-gray-200 bg-white"
                }`}
                onClick={() => {
                  setSelectedProject(project);
                  fetchApiKeys(project.id);
                  setNewKey(null);
                }}
              >
                <div className="font-medium">{project.name}</div>
                <div className="text-xs opacity-80">{project.packageName}</div>
                <div className="text-xs opacity-80">Project ID: {project.id}</div>
                <div className="text-xs opacity-80">Developer Client ID: {project.orgId}</div>
              </button>
            ))}
          </div>
        </section>
        <section className="bg-white/70 rounded-2xl p-6 shadow-sm">
          <h2 className="text-xl font-semibold">Create Project</h2>
          <div className="mt-4 space-y-3">
            <input
              className="w-full rounded-lg border border-gray-300 px-3 py-2"
              placeholder="Project name"
              value={projectName}
              onChange={(e) => setProjectName(e.target.value)}
            />
            <input
              className="w-full rounded-lg border border-gray-300 px-3 py-2"
              placeholder="Package name"
              value={packageName}
              onChange={(e) => setPackageName(e.target.value)}
            />
            <button className="w-full rounded-lg bg-ink text-white py-2" onClick={createProject}>
              Create
            </button>
          </div>
        </section>
      </div>

      {selectedProject && (
        <section className="mt-8 bg-white/70 rounded-2xl p-6 shadow-sm">
          <div className="flex items-center justify-between">
            <h2 className="text-xl font-semibold">API Keys</h2>
            <button className="rounded-lg bg-clay text-white px-4 py-2" onClick={createApiKey}>
              Generate API Key
            </button>
          </div>
          {newKey && (
            <div className="mt-4 rounded-lg bg-ink text-white p-4 text-sm">
              <p className="font-semibold">Copy your new API key now:</p>
              <code className="block mt-2 break-all">{newKey}</code>
            </div>
          )}
          <div className="mt-4 space-y-2">
            {apiKeys.map((key) => (
              <div key={key.id} className="rounded-lg border border-gray-200 px-4 py-2">
                <div className="text-sm">Key Prefix: {key.keyPrefix}</div>
                <div className="text-xs text-gray-500">Created: {key.createdAt}</div>
                {key.revokedAt && (
                  <div className="text-xs text-red-600">Revoked: {key.revokedAt}</div>
                )}
              </div>
            ))}
          </div>
        </section>
      )}
    </Layout>
  );
}
