'use client'

import { useState, FormEvent } from 'react'
import { useRouter } from 'next/navigation'
import { useAuth } from '@/lib/auth-context'
import { ApiClient, ApiError } from '@/lib/api'

const apiClient = new ApiClient('') // relative URLs — goes through Nginx

export default function AdminLoginPage() {
  const router = useRouter()
  const { setAuth } = useAuth()
  const [password, setPassword] = useState('')
  const [totpCode, setTotpCode] = useState('')
  const [showTotp, setShowTotp] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setError(null)
    setLoading(true)
    try {
      const resp = await apiClient.login(password, showTotp ? totpCode : undefined)
      setAuth(resp.access_token, resp.session_id)
      router.push('/admin/dashboard')
    } catch (err) {
      if (err instanceof ApiError) {
        if (err.message === 'TOTP_REQUIRED') {
          setShowTotp(true)
          setError('Please enter your TOTP code.')
        } else if (err.message === 'TOTP_INVALID') {
          setError('Invalid TOTP code.')
        } else if (err.message === 'LOCKED_OUT') {
          setError('Too many failed attempts. Try again in 15 minutes.')
        } else if (err.status === 429) {
          setError('Too many requests. Please wait.')
        } else {
          setError('Invalid password.')
        }
      } else {
        setError('Login failed. Please try again.')
      }
    } finally {
      setLoading(false)
    }
  }

  return (
    <main style={{ maxWidth: 400, margin: '80px auto', padding: '0 16px' }}>
      <h1>EphemeralShare Admin</h1>
      <form onSubmit={handleSubmit}>
        <div>
          <label htmlFor="password">Password</label>
          <input
            id="password"
            type="password"
            value={password}
            onChange={e => setPassword(e.target.value)}
            required
            autoComplete="current-password"
            disabled={loading}
          />
        </div>
        {showTotp && (
          <div>
            <label htmlFor="totp">TOTP Code</label>
            <input
              id="totp"
              type="text"
              inputMode="numeric"
              pattern="[0-9]{6}"
              maxLength={6}
              value={totpCode}
              onChange={e => setTotpCode(e.target.value)}
              required
              autoComplete="one-time-code"
              disabled={loading}
            />
          </div>
        )}
        {error && (
          <p role="alert" style={{ color: 'red' }}>
            {error}
          </p>
        )}
        <button type="submit" disabled={loading}>
          {loading ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
    </main>
  )
}
