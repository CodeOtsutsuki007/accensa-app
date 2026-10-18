import { describe, expect, it } from 'vitest'
import { extractMerchantId, verifyAuth, verifyToken } from './verify-auth'

function b64url(str: string): string {
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

async function mintToken(payload: Record<string, unknown>, secret: string): Promise<string> {
  const header = { alg: 'HS256', typ: 'JWT' }
  const headerB64 = b64url(JSON.stringify(header))
  const payloadB64 = b64url(JSON.stringify(payload))
  const encoder = new TextEncoder()
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  )
  const data = encoder.encode(`${headerB64}.${payloadB64}`)
  const sigBuf = await crypto.subtle.sign('HMAC', key, data)
  const sigBytes = new Uint8Array(sigBuf)
  let binary = ''
  for (let i = 0; i < sigBytes.byteLength; i++) {
    binary += String.fromCharCode(sigBytes[i])
  }
  const sigB64 = btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
  return `${headerB64}.${payloadB64}.${sigB64}`
}

describe('verifyAuth and verifyToken', () => {
  const secret = 'test-secret-key-1234567890'

  it('rejects missing authorization header', async () => {
    const req = new Request('https://example.com/api', { headers: {} })
    const res = await verifyAuth(req, { secret })
    expect(res).toEqual({ valid: false, error: 'No authorization header' })
  })

  it('rejects non-Bearer authorization format', async () => {
    const req = new Request('https://example.com/api', {
      headers: { authorization: 'Basic dXNlcjpwYXNz' },
    })
    const res = await verifyAuth(req, { secret })
    expect(res).toEqual({ valid: false, error: 'Invalid authorization format' })
  })

  it('rejects malformed Bearer header with incorrect parts count', async () => {
    const req = new Request('https://example.com/api', {
      headers: { authorization: 'Bearer' },
    })
    const res = await verifyAuth(req, { secret })
    expect(res).toEqual({ valid: false, error: 'Invalid authorization format' })
  })

  it('rejects tokens that are not three dot-separated parts', async () => {
    const res1 = await verifyToken('one.two', { secret })
    expect(res1).toEqual({ valid: false, error: 'Invalid token format' })

    const res2 = await verifyToken('one.two.three.four', { secret })
    expect(res2).toEqual({ valid: false, error: 'Invalid token format' })
  })

  it('rejects expired tokens beyond clockTolerance', async () => {
    const expiredExp = Math.floor(Date.now() / 1000) - 100
    const token = await mintToken({ exp: expiredExp }, secret)
    const res = await verifyToken(token, { secret, clockTolerance: 30 })
    expect(res.valid).toBe(false)
    expect(res.error).toBe('Token expired')
    expect(res.expiresAt).toBe(expiredExp)
  })

  it('rejects issuer mismatch', async () => {
    const token = await mintToken({ iss: 'wrong-issuer' }, secret)
    const res = await verifyToken(token, { secret, issuer: 'expected-issuer' })
    expect(res).toEqual({ valid: false, error: 'Invalid issuer' })
  })

  it('rejects token signed with a different secret', async () => {
    const token = await mintToken({ sub: 'user_1' }, 'other-secret')
    const res = await verifyToken(token, { secret })
    expect(res).toEqual({ valid: false, error: 'Invalid signature' })
  })

  it('catches base64/JSON corruption and returns valid:false', async () => {
    const res = await verifyToken('header.invalid-base64-json!!!.signature', { secret })
    expect(res.valid).toBe(false)
    expect(res.error).toBeDefined()
  })

  it('successfully verifies a valid signed token', async () => {
    const exp = Math.floor(Date.now() / 1000) + 3600
    const token = await mintToken({ sub: 'merchant_abc', iss: 'expected-issuer', exp }, secret)
    const res = await verifyToken(token, { secret, issuer: 'expected-issuer' })
    expect(res.valid).toBe(true)
    expect(res.payload).toMatchObject({ sub: 'merchant_abc' })
    expect(res.expiresAt).toBe(exp)
  })

  it('extractMerchantId prioritizes merchantId, then sub, then null', () => {
    expect(extractMerchantId({ merchantId: 'm_123', sub: 'sub_456' })).toBe('m_123')
    expect(extractMerchantId({ sub: 'sub_456' })).toBe('sub_456')
    expect(extractMerchantId({ other: 'val' })).toBeNull()
  })
})

