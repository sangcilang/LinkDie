import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'
import crypto from 'crypto'

export function middleware(request: NextRequest) {
  const nonce = crypto.randomBytes(16).toString('base64')
  const cspHeader = [
    `default-src 'self'`,
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'`,
    `style-src 'self' 'unsafe-inline'`, // Next.js requires unsafe-inline for styles
    `img-src 'self' data:`,
    `font-src 'self'`,
    `object-src 'none'`,
    `frame-ancestors 'none'`,
    `base-uri 'none'`,
    `form-action 'self'`,
  ].join('; ')

  const response = NextResponse.next({
    request: {
      headers: new Headers(request.headers),
    },
  })

  response.headers.set('Content-Security-Policy', cspHeader)
  response.headers.set('x-nonce', nonce) // passed to layout for <script nonce={nonce}>

  return response
}

export const config = {
  matcher: [
    // Apply to all routes except static files and _next internals
    '/((?!_next/static|_next/image|favicon.ico).*)',
  ],
}
