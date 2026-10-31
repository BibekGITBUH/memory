import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import type { Request, Response } from 'express';
import type { AppConfig } from '../config/env.js';
import type { BrowserSession } from './auth.types.js';
import type { Stores } from '../storage/stores.js';
import type { User } from '../storage/schemas.js';

const SESSION_COOKIE = 'mcp_memory_session';
const LOGIN_CSRF_COOKIE = 'mcp_memory_login_csrf';

function sign(value: string, secret: string): string {
  return createHmac('sha256', secret).update(value).digest('base64url');
}

function constantCompare(a: string, b: string): boolean {
  const aa = Buffer.from(a);
  const bb = Buffer.from(b);
  return aa.length === bb.length && timingSafeEqual(aa, bb);
}

function cookieValue(req: Request, name: string): string | undefined {
  const raw = req.headers.cookie;
  if (!raw) return undefined;
  for (const item of raw.split(';')) {
    const [key, ...rest] = item.trim().split('=');
    if (key === name) { try { return decodeURIComponent(rest.join('=')); } catch { return undefined; } }
  }
  return undefined;
}

function cookieFlags(config: AppConfig, maxAge: number): string {
  const secure = new URL(config.publicBaseUrl).protocol === 'https:' ? '; Secure' : '';
  return `Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secure}`;
}

function encodeSigned(payload: object, secret: string): string {
  const encoded = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return `${encoded}.${sign(encoded, secret)}`;
}

function decodeSigned<T>(value: string | undefined, secret: string): T | undefined {
  if (!value) return undefined;
  const [encoded, signature] = value.split('.');
  if (!encoded || !signature || !constantCompare(signature, sign(encoded, secret))) return undefined;
  try { return JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8')) as T; } catch { return undefined; }
}

export function issueLoginCsrf(req: Request, res: Response, config: AppConfig): string {
  const csrf = randomBytes(32).toString('base64url');
  res.setHeader('Set-Cookie', `${LOGIN_CSRF_COOKIE}=${encodeURIComponent(encodeSigned({ csrf, exp: Date.now() + 10 * 60_000 }, config.sessionSecret))}; ${cookieFlags(config, 600)}`);
  return csrf;
}

export function verifyLoginCsrf(req: Request, submitted: unknown, config: AppConfig): boolean {
  const data = decodeSigned<{ csrf: string; exp: number }>(cookieValue(req, LOGIN_CSRF_COOKIE), config.sessionSecret);
  return Boolean(data && data.exp > Date.now() && typeof submitted === 'string' && constantCompare(data.csrf, submitted));
}

export function createBrowserSession(res: Response, user: User, config: AppConfig): string {
  const csrf = randomBytes(32).toString('base64url');
  const expiresAt = Date.now() + 8 * 60 * 60_000;
  const value = encodeSigned({ uid: user.id, csrf, exp: expiresAt }, config.sessionSecret);
  res.setHeader('Set-Cookie', `${SESSION_COOKIE}=${encodeURIComponent(value)}; ${cookieFlags(config, 8 * 60 * 60)}`);
  return csrf;
}

export async function getBrowserSession(req: Request, stores: Stores, config: AppConfig): Promise<BrowserSession | undefined> {
  const data = decodeSigned<{ uid: string; csrf: string; exp: number }>(cookieValue(req, SESSION_COOKIE), config.sessionSecret);
  if (!data || data.exp <= Date.now()) return undefined;
  const user = (await stores.users.read()).find(item => item.id === data.uid && item.disabledAt === null);
  if (!user) return undefined;
  return { user, csrf: data.csrf, expiresAt: data.exp };
}

export function clearBrowserSession(res: Response, config: AppConfig): void {
  const secure = new URL(config.publicBaseUrl).protocol === 'https:' ? '; Secure' : '';
  res.setHeader('Set-Cookie', `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${secure}`);
}
