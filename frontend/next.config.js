/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',

  // Disable x-powered-by header
  poweredByHeader: false,

  // Strict mode for React
  reactStrictMode: true,

  // Environment variables exposed to the browser (non-secret only)
  env: {
    NEXT_PUBLIC_APP_VERSION: process.env.APP_VERSION || 'dev',
  },

  // Server-side environment variables (not exposed to browser)
  // BACKEND_INTERNAL_URL is used for SSR requests to avoid public Nginx loop
  serverRuntimeConfig: {
    backendInternalUrl: process.env.BACKEND_INTERNAL_URL || 'http://backend:8080',
  },

  // Public runtime config (available on both server and client)
  publicRuntimeConfig: {
    appVersion: process.env.APP_VERSION || 'dev',
  },

  // Security headers are set by Next.js middleware (middleware.ts) per-request
  // with a nonce. Do not set static CSP here.
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'Referrer-Policy', value: 'no-referrer' },
          { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
          { key: 'Cross-Origin-Opener-Policy', value: 'same-origin' },
          { key: 'Cross-Origin-Resource-Policy', value: 'same-origin' },
        ],
      },
    ]
  },
}

module.exports = nextConfig
