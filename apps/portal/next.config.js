module.exports = {
  reactStrictMode: true,
  async rewrites() {
    const backendUrl = process.env.UA_BACKEND_URL || "http://localhost:3001";
    return [
      {
        source: "/api/:path*",
        destination: `${backendUrl}/api/:path*`
      }
    ];
  }
};
