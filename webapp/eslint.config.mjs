/**
 * ESLint 9 flat config for Arc Mission Control
 * Next.js 16 + TypeScript
 */
import nextConfig from "eslint-config-next";

const config = [
  {
    files: ["**/*.{js,mjs,cjs,ts,tsx}"],
  },
  ...(Array.isArray(nextConfig) ? nextConfig : [nextConfig]),
];

export default config;
