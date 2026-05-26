'use client'

import { useState } from 'react'
import { ApiClient, ApiError } from '@/lib/api'

const apiClient = new ApiClient('')

interface DownloadCardProps {
  token: string
  filename?: string
  sizeBytes: number
  contentType: string
  expiresAt: string
}

export default function DownloadCard({ token, filename, sizeBytes, contentType, expiresAt }: DownloadCardProps) {
  const [downloading, setDownloading] = useState(false)
  const [consumed, setConsumed] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function handleDownload() {
    setError(null)
    setDownloading(true)
    try {
      const redirectURL = await apiClient.downloadToken(token)
      setConsumed(true)
      // Navigate to the presigned URL to trigger browser download
      window.location.href = redirectURL
    } catch (err) {
      if (err instanceof ApiError) {
        if (err.status === 423) {
          setError('Download already in progress. Please wait 30 seconds and try again.')
        } else if (err.status === 302 || err.message === 'EXPIRED') {
          setError('This link has expired or already been used.')
        } else {
          setError('Download failed. The link may have expired.')
        }
      } else {
        setError('Download failed. Please try again.')
      }
    } finally {
      setDownloading(false)
    }
  }

  const expiryDate = new Date(expiresAt)
  const fileSizeMB = (sizeBytes / 1024 / 1024).toFixed(2)

  return (
    <div>
      <h1>Secure File Download</h1>

      {/* File info */}
      <dl>
        {filename && (
          <>
            <dt>File name</dt>
            <dd>{filename}</dd>
          </>
        )}
        <dt>File size</dt>
        <dd>{fileSizeMB} MB</dd>
        <dt>File type</dt>
        <dd>{contentType}</dd>
        <dt>Link expires</dt>
        <dd>{expiryDate.toLocaleString()}</dd>
      </dl>

      {/* One-time warning */}
      <div role="alert" style={{ background: '#fff3cd', border: '1px solid #ffc107', borderRadius: 4, padding: 12, marginBottom: 16 }}>
        <strong>⚠ One-time link</strong>
        <p style={{ margin: '4px 0 0' }}>
          This link can only be used once. After you click Download, the file will be permanently deleted.
        </p>
      </div>

      {consumed ? (
        <p style={{ color: 'green' }}>
          ✓ Download started. This link has been consumed and is no longer valid.
        </p>
      ) : (
        <button
          onClick={handleDownload}
          disabled={downloading}
          style={{ padding: '12px 24px', fontSize: 16, cursor: downloading ? 'not-allowed' : 'pointer' }}
        >
          {downloading ? 'Preparing download…' : 'Download file'}
        </button>
      )}

      {error && <p role="alert" style={{ color: 'red', marginTop: 8 }}>{error}</p>}
    </div>
  )
}
