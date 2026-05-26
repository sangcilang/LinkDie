import type { Metadata } from 'next'
import { headers } from 'next/headers'

export const metadata: Metadata = {
  title: 'EphemeralShare',
  description: 'Secure one-time file sharing',
  robots: {
    index: false,
    follow: false,
  },
}

interface RootLayoutProps {
  children: React.ReactNode
}

export default function RootLayout({ children }: RootLayoutProps) {
  // Retrieve the nonce injected by middleware.ts for CSP nonce-based script allowlisting.
  const nonce = headers().get('x-nonce') ?? ''

  return (
    <html lang="en">
      <head>
        {/* Inline styles are allowed without nonce; scripts require nonce */}
        <meta charSet="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
      </head>
      <body>
        {/* Pass nonce down via a data attribute so client components can read it if needed */}
        <div id="app-root" data-nonce={nonce}>
          {children}
        </div>
      </body>
    </html>
  )
}
