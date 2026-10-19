import { describe, it, expect } from 'vitest';
import { verifyAuth, extractMerchantId } from './verify-auth';

async function createToken(payload: object, secret: string): Promise<string> {
  const enc = new TextEncoder();
  const keyData = enc.encode(secret);
  const key = await crypto.subtle.importKey(
    'raw',
    keyData,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  const body = btoa(JSON.stringify(payload)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  const data = enc.encode(`${header}.${body}`);
  const sigBuf = await crypto.subtle.sign('HMAC', key, data);
  const sig = btoa(String.fromCharCode(...new Uint8Array(sigBuf)))
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
  return `${header}.${body}.${sig}`;
}

describe('verify-auth', () => {
  const secret = 'test-secret';

  it('rejects missing authorization header', async () => {
    const res = await verifyAuth(undefined, secret);
    expect(res.valid).toBe(false);
    if (!res.valid) {
      expect(res.error).toBeDefined();
    }
  });

  it('rejects non-Bearer authorization header', async () => {
    const res = await verifyAuth('Basic 12345', secret);
    expect(res.valid).toBe(false);
  });

  it('rejects token with invalid part count', async () => {
    const res = await verifyAuth('Bearer one.two', secret);
    expect(res.valid).toBe(false);
  });

  it('rejects expired token', async () => {
    const expiredPayload = {
      exp: Math.floor(Date.now() / 1000) - 60,
      iss: 'accensa',
      sub: 'merchant-123',
    };
    const token = await createToken(expiredPayload, secret);
    const res = await verifyAuth(`Bearer ${token}`, secret);
    expect(res.valid).toBe(false);
    if (!res.valid) {
      expect(res.error).toContain('expired');
    }
  });

  it('rejects issuer mismatch', async () => {
    const payload = {
      exp: Math.floor(Date.now() / 1000) + 3600,
      iss: 'wrong-issuer',
      sub: 'merchant-123',
    };
    const token = await createToken(payload, secret);
    const res = await verifyAuth(`Bearer ${token}`, secret);
    expect(res.valid).toBe(false);
    if (!res.valid) {
      expect(res.error).toContain('issuer');
    }
  });

  it('rejects invalid signature', async () => {
    const payload = {
      exp: Math.floor(Date.now() / 1000) + 3600,
      iss: 'accensa',
      sub: 'merchant-123',
    };
    const token = await createToken(payload, 'wrong-secret');
    const res = await verifyAuth(`Bearer ${token}`, secret);
    expect(res.valid).toBe(false);
    if (!res.valid) {
      expect(res.error).toContain('signature');
    }
  });

  it('successfully verifies a valid signed token', async () => {
    const payload = {
      exp: Math.floor(Date.now() / 1000) + 3600,
      iss: 'accensa',
      merchantId: 'merch-999',
      sub: 'sub-111',
    };
    const token = await createToken(payload, secret);
    const res = await verifyAuth(`Bearer ${token}`, secret);
    expect(res.valid).toBe(true);
    if (res.valid) {
      expect(res.merchantId).toBe('merch-999');
    }
  });

  it('extractMerchantId prioritizes merchantId then sub then null', () => {
    expect(extractMerchantId({ merchantId: 'm1', sub: 's1' })).toBe('m1');
    expect(extractMerchantId({ sub: 's1' })).toBe('s1');
    expect(extractMerchantId({})).toBeNull();
  });
});
