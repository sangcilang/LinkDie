// Types matching backend responses

export interface TokenMetadata {
  filename?: string
  size_bytes: number
  content_type: string
  expires_at: string
  token_hash: string
}

export interface LoginResponse {
  access_token: string
  session_id: string
  expires_in: number
}

export interface RequestUploadResponse {
  presigned_upload_url: string
  object_key: string
  upload_id: string
  expires_in: number
}

export interface ConfirmUploadResponse {
  share_url: string
  token_hash: string
  expires_at: string
}

export interface TokenListItem {
  token_hash: string
  filename: string
  expires_at: string
  size_bytes: number
  content_type: string
}

export interface HealthResponse {
  status: string
  redis: string
  storage: string
  version: string
}

export class UnauthorizedError extends Error {
  constructor(message = 'Unauthorized') {
    super(message)
    this.name = 'UnauthorizedError'
  }
}

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message)
    this.name = 'ApiError'
  }
}

export class ApiClient {
  private baseURL: string
  private getAccessToken: () => string | null

  constructor(baseURL: string, getAccessToken: () => string | null = () => null) {
    this.baseURL = baseURL.replace(/\/$/, '') // strip trailing slash
    this.getAccessToken = getAccessToken
  }

  private async fetch<T>(path: string, options: RequestInit = {}): Promise<T> {
    const token = this.getAccessToken()

    const headers = new Headers(options.headers)
    if (!headers.has('Content-Type') && options.body) {
      headers.set('Content-Type', 'application/json')
    }
    if (token) {
      headers.set('Authorization', `Bearer ${token}`)
    }

    const response = await globalThis.fetch(`${this.baseURL}${path}`, {
      ...options,
      headers,
    })

    if (response.status === 401) {
      throw new UnauthorizedError()
    }

    if (!response.ok) {
      let message = response.statusText
      try {
        const body = await response.json()
        if (body?.error) message = body.error
        else if (body?.message) message = body.message
      } catch {
        // ignore JSON parse errors — use statusText
      }
      throw new ApiError(response.status, message)
    }

    // Handle empty responses (e.g. 204 No Content)
    const contentType = response.headers.get('Content-Type') ?? ''
    if (response.status === 204 || !contentType.includes('application/json')) {
      return undefined as unknown as T
    }

    return response.json() as Promise<T>
  }

  // Auth endpoints

  async login(password: string, totpCode?: string): Promise<LoginResponse> {
    return this.fetch<LoginResponse>('/api/admin/login', {
      method: 'POST',
      body: JSON.stringify({ password, totp_code: totpCode }),
    })
  }

  async refresh(): Promise<LoginResponse> {
    return this.fetch<LoginResponse>('/api/admin/refresh', {
      method: 'POST',
      credentials: 'include', // send HttpOnly refresh token cookie
    })
  }

  async logout(): Promise<void> {
    return this.fetch<void>('/api/admin/logout', {
      method: 'POST',
      credentials: 'include',
    })
  }

  // Upload endpoints

  async requestUpload(
    filename: string,
    contentType: string,
    sizeBytes: number,
    ttlHours?: number,
    adminNote?: string,
  ): Promise<RequestUploadResponse> {
    return this.fetch<RequestUploadResponse>('/api/admin/request-upload', {
      method: 'POST',
      body: JSON.stringify({
        filename,
        content_type: contentType,
        size_bytes: sizeBytes,
        ttl_hours: ttlHours,
        admin_note: adminNote,
      }),
    })
  }

  async confirmUpload(
    objectKey: string,
    etag: string,
    filename: string,
    contentType: string,
    sizeBytes: number,
    uploadId?: string,
    ttlHours?: number,
    adminNote?: string,
  ): Promise<ConfirmUploadResponse> {
    return this.fetch<ConfirmUploadResponse>('/api/admin/confirm-upload', {
      method: 'POST',
      body: JSON.stringify({
        object_key: objectKey,
        etag,
        filename,
        content_type: contentType,
        size_bytes: sizeBytes,
        upload_id: uploadId,
        ttl_hours: ttlHours,
        admin_note: adminNote,
      }),
    })
  }

  // Token management endpoints

  async listTokens(): Promise<TokenListItem[]> {
    return this.fetch<TokenListItem[]>('/api/admin/tokens')
  }

  async revokeToken(tokenHash: string): Promise<void> {
    return this.fetch<void>(`/api/admin/tokens/${encodeURIComponent(tokenHash)}`, {
      method: 'DELETE',
    })
  }

  // Download endpoints

  /** Fetch token metadata — calls GET /d/{token} (SSR metadata endpoint) */
  async getTokenMetadata(token: string): Promise<TokenMetadata> {
    return this.fetch<TokenMetadata>(`/d/${encodeURIComponent(token)}`)
  }

  /**
   * Initiate download — calls POST /api/download/{token}.
   * The backend responds with a 302 redirect to the presigned S3 URL.
   * Returns the redirect URL from the Location header.
   */
  async downloadToken(token: string): Promise<string> {
    const response = await globalThis.fetch(
      `${this.baseURL}/api/download/${encodeURIComponent(token)}`,
      {
        method: 'POST',
        redirect: 'manual', // capture the 302 instead of following it
      },
    )

    if (response.status === 401) {
      throw new UnauthorizedError()
    }

    // 302 redirect — return the Location header as the presigned download URL
    if (response.status === 302 || response.status === 301) {
      const location = response.headers.get('Location')
      if (!location) {
        throw new ApiError(response.status, 'Missing Location header in redirect response')
      }
      return location
    }

    if (!response.ok) {
      let message = response.statusText
      try {
        const body = await response.json()
        if (body?.error) message = body.error
        else if (body?.message) message = body.message
      } catch {
        // ignore JSON parse errors
      }
      throw new ApiError(response.status, message)
    }

    throw new ApiError(response.status, 'Unexpected response from download endpoint')
  }
}
