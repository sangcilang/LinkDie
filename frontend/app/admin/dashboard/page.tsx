'use client'

import { useState, useEffect, useRef, useCallback, DragEvent, ChangeEvent } from 'react'
import { useRouter } from 'next/navigation'
import { useAuth } from '@/lib/auth-context'
import { ApiClient, ApiError, UnauthorizedError, TokenListItem, ConfirmUploadResponse } from '@/lib/api'

const apiClient = new ApiClient('')

const ALLOWED_MIME_TYPES = [
  'application/pdf', 'application/zip', 'application/x-zip-compressed',
  'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  'application/vnd.ms-powerpoint', 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  'image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/svg+xml',
  'text/plain', 'text/csv', 'video/mp4', 'video/webm', 'audio/mpeg', 'audio/ogg', 'audio/wav',
]
const MAX_FILE_SIZE = 500 * 1024 * 1024 // 500 MB

export default function AdminDashboardPage() {
  const router = useRouter()
  const { accessToken, setAuth, clearAuth } = useAuth()
  const [tokens, setTokens] = useState<TokenListItem[]>([])
  const [shareResult, setShareResult] = useState<ConfirmUploadResponse | null>(null)
  const [uploadProgress, setUploadProgress] = useState<number>(0)
  const [uploading, setUploading] = useState(false)
  const [uploadError, setUploadError] = useState<string | null>(null)
  const [ttlHours, setTtlHours] = useState(24)
  const [adminNote, setAdminNote] = useState('')
  const [isDragging, setIsDragging] = useState(false)
  const fileInputRef = useRef<HTMLInputElement>(null)

  // Redirect to login if not authenticated
  useEffect(() => {
    if (!accessToken) {
      // Try to refresh first
      apiClient.refresh()
        .then(resp => setAuth(resp.access_token, resp.session_id))
        .catch(() => router.push('/admin'))
    }
  }, [accessToken, router, setAuth])

  // Load token list
  const loadTokens = useCallback(async () => {
    if (!accessToken) return
    try {
      const list = await apiClient.listTokens()
      setTokens(list)
    } catch (err) {
      if (err instanceof UnauthorizedError) {
        try {
          const resp = await apiClient.refresh()
          setAuth(resp.access_token, resp.session_id)
        } catch {
          clearAuth()
          router.push('/admin')
        }
      }
    }
  }, [accessToken, router, setAuth, clearAuth])

  useEffect(() => {
    loadTokens()
  }, [loadTokens])

  async function handleFile(file: File) {
    setUploadError(null)
    setShareResult(null)
    setUploadProgress(0)

    // Client-side validation
    if (file.size > MAX_FILE_SIZE) {
      setUploadError('File exceeds 500 MB limit.')
      return
    }
    if (!ALLOWED_MIME_TYPES.includes(file.type)) {
      setUploadError(`File type "${file.type}" is not allowed.`)
      return
    }

    setUploading(true)
    try {
      // Step 1: Request presigned upload URL
      const uploadResp = await apiClient.requestUpload(
        file.name, file.type, file.size, ttlHours, adminNote || undefined
      )

      // Step 2: PUT file directly to S3 presigned URL with progress tracking
      const etag = await uploadToS3(uploadResp.presigned_upload_url, file, (pct) => {
        setUploadProgress(pct)
      })

      // Step 3: Confirm upload
      const confirmResp = await apiClient.confirmUpload(
        uploadResp.object_key, etag, file.name, file.type, file.size,
        uploadResp.upload_id, ttlHours, adminNote || undefined
      )

      setShareResult(confirmResp)
      setAdminNote('')
      await loadTokens()
    } catch (err) {
      if (err instanceof UnauthorizedError) {
        try {
          const resp = await apiClient.refresh()
          setAuth(resp.access_token, resp.session_id)
          setUploadError('Session refreshed. Please try again.')
        } catch {
          clearAuth()
          router.push('/admin')
        }
      } else if (err instanceof ApiError) {
        if (err.message === 'MALWARE_DETECTED') {
          setUploadError('File rejected: malware detected.')
        } else if (err.message === 'FILE_TOO_LARGE') {
          setUploadError('File exceeds the server size limit.')
        } else if (err.message === 'INVALID_CONTENT_TYPE') {
          setUploadError('File type is not allowed.')
        } else {
          setUploadError(`Upload failed: ${err.message}`)
        }
      } else {
        setUploadError('Upload failed. Please try again.')
      }
    } finally {
      setUploading(false)
    }
  }

  async function handleRevoke(tokenHash: string) {
    try {
      await apiClient.revokeToken(tokenHash)
      await loadTokens()
    } catch (err) {
      if (err instanceof UnauthorizedError) {
        try {
          const resp = await apiClient.refresh()
          setAuth(resp.access_token, resp.session_id)
        } catch {
          clearAuth()
          router.push('/admin')
        }
      }
    }
  }

  function handleDrop(e: DragEvent<HTMLDivElement>) {
    e.preventDefault()
    setIsDragging(false)
    const file = e.dataTransfer.files[0]
    if (file) handleFile(file)
  }

  function handleFileInput(e: ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (file) handleFile(file)
    e.target.value = '' // reset so same file can be re-selected
  }

  if (!accessToken) return null

  return (
    <main style={{ maxWidth: 800, margin: '40px auto', padding: '0 16px' }}>
      <h1>EphemeralShare Dashboard</h1>

      {/* Upload Zone */}
      <section aria-label="Upload file">
        <div
          role="button"
          tabIndex={0}
          aria-label="Drop file here or click to select"
          onDragOver={e => { e.preventDefault(); setIsDragging(true) }}
          onDragLeave={() => setIsDragging(false)}
          onDrop={handleDrop}
          onClick={() => fileInputRef.current?.click()}
          onKeyDown={e => e.key === 'Enter' && fileInputRef.current?.click()}
          style={{
            border: `2px dashed ${isDragging ? '#0070f3' : '#ccc'}`,
            borderRadius: 8,
            padding: 40,
            textAlign: 'center',
            cursor: uploading ? 'not-allowed' : 'pointer',
            background: isDragging ? '#f0f7ff' : 'transparent',
          }}
        >
          {uploading ? (
            <div>
              <p>Uploading… {uploadProgress}%</p>
              <progress value={uploadProgress} max={100} style={{ width: '100%' }} />
            </div>
          ) : (
            <p>Drop a file here or click to select</p>
          )}
        </div>
        <input
          ref={fileInputRef}
          type="file"
          style={{ display: 'none' }}
          onChange={handleFileInput}
          disabled={uploading}
          aria-hidden="true"
        />

        <div style={{ marginTop: 12, display: 'flex', gap: 12, flexWrap: 'wrap' }}>
          <label>
            TTL:
            <select
              value={ttlHours}
              onChange={e => setTtlHours(Number(e.target.value))}
              disabled={uploading}
              style={{ marginLeft: 8 }}
            >
              <option value={1}>1 hour</option>
              <option value={6}>6 hours</option>
              <option value={24}>24 hours</option>
              <option value={48}>48 hours</option>
              <option value={72}>3 days</option>
              <option value={168}>7 days</option>
            </select>
          </label>
          <label style={{ flex: 1 }}>
            Note:
            <input
              type="text"
              value={adminNote}
              onChange={e => setAdminNote(e.target.value)}
              placeholder="Optional admin note"
              disabled={uploading}
              style={{ marginLeft: 8, width: '100%' }}
            />
          </label>
        </div>

        {uploadError && <p role="alert" style={{ color: 'red', marginTop: 8 }}>{uploadError}</p>}
      </section>

      {/* Share Link Card */}
      {shareResult && (
        <section aria-label="Share link" style={{ marginTop: 24, padding: 16, border: '1px solid #0070f3', borderRadius: 8 }}>
          <h2>Share Link</h2>
          <p>Expires: {new Date(shareResult.expires_at).toLocaleString()}</p>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <input
              type="text"
              readOnly
              value={shareResult.share_url}
              style={{ flex: 1, fontFamily: 'monospace' }}
              aria-label="Share URL"
            />
            <button
              onClick={() => navigator.clipboard.writeText(shareResult.share_url)}
              aria-label="Copy share URL"
            >
              Copy
            </button>
          </div>
        </section>
      )}

      {/* Token List */}
      <section aria-label="Active tokens" style={{ marginTop: 32 }}>
        <h2>Active Tokens</h2>
        {tokens.length === 0 ? (
          <p>No active tokens.</p>
        ) : (
          <ul style={{ listStyle: 'none', padding: 0 }}>
            {tokens.map(t => (
              <li key={t.token_hash} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 0', borderBottom: '1px solid #eee' }}>
                <div>
                  <strong>{t.filename || '(unnamed)'}</strong>
                  <span style={{ marginLeft: 8, color: '#666', fontSize: 12 }}>
                    {(t.size_bytes / 1024 / 1024).toFixed(2)} MB · expires {new Date(t.expires_at).toLocaleString()}
                  </span>
                </div>
                <button
                  onClick={() => handleRevoke(t.token_hash)}
                  aria-label={`Revoke token for ${t.filename}`}
                  style={{ color: 'red' }}
                >
                  Revoke
                </button>
              </li>
            ))}
          </ul>
        )}
        <button onClick={loadTokens} style={{ marginTop: 8 }}>Refresh</button>
      </section>
    </main>
  )
}

// Upload file to S3 presigned URL using XHR for progress tracking.
// Returns the ETag from the response headers.
function uploadToS3(url: string, file: File, onProgress: (pct: number) => void): Promise<string> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest()
    xhr.open('PUT', url)
    xhr.setRequestHeader('Content-Type', file.type)
    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable) {
        onProgress(Math.round((e.loaded / e.total) * 100))
      }
    }
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        const etag = xhr.getResponseHeader('ETag') ?? ''
        resolve(etag)
      } else {
        reject(new Error(`S3 upload failed with status ${xhr.status}`))
      }
    }
    xhr.onerror = () => reject(new Error('S3 upload network error'))
    xhr.send(file)
  })
}
