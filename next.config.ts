import type { NextConfig } from "next";

// Where the FastAPI backend listens. The browser only ever talks to this
// Next.js origin under /api/witness/*; Next forwards to the backend.
const backend = (process.env.WITNESS_BACKEND_URL || "http://localhost:8000").replace(/\/$/, "");

const nextConfig: NextConfig = {
  output: "standalone",
  reactStrictMode: false,
  async rewrites() {
    return [{ source: "/api/witness/:path*", destination: `${backend}/:path*` }];
  },
};

export default nextConfig;
