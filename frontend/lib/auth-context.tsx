'use client'

import { createContext, useContext, useState, useCallback } from 'react'
import type { ReactNode } from 'react'

interface AuthContextValue {
  accessToken: string | null
  sessionId: string | null
  setAuth: (token: string, sessionId: string) => void
  clearAuth: () => void
  isAuthenticated: boolean
}

const AuthContext = createContext<AuthContextValue>({
  accessToken: null,
  sessionId: null,
  setAuth: () => {},
  clearAuth: () => {},
  isAuthenticated: false,
})

export function AuthProvider({ children }: { children: ReactNode }) {
  // Access token is stored in React state only — NOT in localStorage or cookies.
  // It is intentionally ephemeral: lost on page refresh, re-issued via the
  // HttpOnly refresh token cookie through POST /api/admin/refresh.
  const [accessToken, setAccessToken] = useState<string | null>(null)
  const [sessionId, setSessionId] = useState<string | null>(null)

  const setAuth = useCallback((token: string, sid: string) => {
    setAccessToken(token)
    setSessionId(sid)
  }, [])

  const clearAuth = useCallback(() => {
    setAccessToken(null)
    setSessionId(null)
  }, [])

  return (
    <AuthContext.Provider
      value={{
        accessToken,
        sessionId,
        setAuth,
        clearAuth,
        isAuthenticated: accessToken !== null,
      }}
    >
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth(): AuthContextValue {
  return useContext(AuthContext)
}

export { AuthContext }
