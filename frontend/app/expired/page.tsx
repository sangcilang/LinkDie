/**
 * Expired page — shown when a share link has expired or already been used.
 * Requirement 11.4: Must NOT reveal whether the link expired due to TTL or
 * because the file was already downloaded.
 */
export default function ExpiredPage() {
  return (
    <main style={{ maxWidth: 500, margin: '80px auto', padding: '0 16px', textAlign: 'center' }}>
      <h1>Link Unavailable</h1>
      <p>
        This file is no longer available. The link may have expired or the file
        has already been downloaded.
      </p>
      <p style={{ marginTop: 24, color: '#666' }}>
        If you need access to this file, please contact the sender to request a
        new link.
      </p>
      <div style={{ marginTop: 32, padding: 16, border: '1px solid #eee', borderRadius: 8 }}>
        <h2 style={{ fontSize: 16, marginBottom: 8 }}>Contact options</h2>
        <p style={{ color: '#666', fontSize: 14 }}>
          Reach out to the person who shared this link with you.
        </p>
      </div>
    </main>
  )
}
