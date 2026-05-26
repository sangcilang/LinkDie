import { redirect } from 'next/navigation'
import getConfig from 'next/config'
import DownloadCard from './DownloadCard'

interface PageProps {
  params: { token: string }
}

export default async function DownloadPage({ params }: PageProps) {
  const { serverRuntimeConfig } = getConfig()
  const backendURL = serverRuntimeConfig?.backendInternalUrl || 'http://backend:8080'

  // Fetch token metadata from backend (SSR — uses internal URL)
  let metadata: {
    filename?: string
    size_bytes: number
    content_type: string
    expires_at: string
    token_hash: string
  } | null = null

  try {
    const res = await fetch(`${backendURL}/d/${encodeURIComponent(params.token)}`, {
      cache: 'no-store',
      headers: { 'Cache-Control': 'no-store' },
    })

    if (res.status === 302 || res.status === 301) {
      // Backend redirected to /expired
      redirect('/expired')
    }

    if (!res.ok) {
      redirect('/expired')
    }

    metadata = await res.json()
  } catch {
    redirect('/expired')
  }

  if (!metadata) {
    redirect('/expired')
  }

  return (
    <main style={{ maxWidth: 500, margin: '80px auto', padding: '0 16px' }}>
      <DownloadCard
        token={params.token}
        filename={metadata.filename}
        sizeBytes={metadata.size_bytes}
        contentType={metadata.content_type}
        expiresAt={metadata.expires_at}
      />
    </main>
  )
}
