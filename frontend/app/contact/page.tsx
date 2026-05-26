/**
 * Contact page — provides contact information for recipients who need a new link.
 */
export default function ContactPage() {
  return (
    <main style={{ maxWidth: 500, margin: '80px auto', padding: '0 16px' }}>
      <h1>Contact</h1>
      <p>
        If you need to request a new file link, please contact the sender
        directly using the information they provided.
      </p>
      <p style={{ marginTop: 16, color: '#666' }}>
        For security reasons, we do not store sender contact information.
        Please reach out through the channel where you originally received
        the share link.
      </p>
    </main>
  )
}
