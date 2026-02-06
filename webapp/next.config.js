/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  
  // Standalone output for Docker deployment
  output: 'standalone',
  
  // Transpile Ant Design for optimal performance
  transpilePackages: ['antd', '@ant-design/icons', '@ant-design/cssinjs'],
  
  // Environment variables exposed to the client
  env: {
    NEXT_PUBLIC_API_URL: process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8080',
    NEXT_PUBLIC_WS_URL: process.env.NEXT_PUBLIC_WS_URL || 'ws://localhost:8080',
  },
  
  // Security headers
  async headers() {
    return [
      {
        source: '/:path*',
        headers: [
          {
            key: 'X-Frame-Options',
            value: 'DENY',
          },
          {
            key: 'X-Content-Type-Options',
            value: 'nosniff',
          },
          {
            key: 'Referrer-Policy',
            value: 'strict-origin-when-cross-origin',
          },
        ],
      },
    ];
  },

  // Next.js 16: Turbopack is default; empty config acknowledges migration.
  // react-force-graph-2d uses dynamic import and runs in browser; no fs fallback needed with Turbopack.
  turbopack: {},
};

module.exports = nextConfig;
