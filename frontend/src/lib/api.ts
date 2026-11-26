// Thin fetch wrapper: JSON in/out, session cookie + CSRF header, normalised errors.

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
    public fields: Record<string, string> = {},
    public retryAfter?: number
  ) {
    super(message);
  }
}

let base: string = import.meta.env.VITE_API_URL ?? '';
let csrf = '';

export function setCsrf(token: string) {
  csrf = token;
}

/**
 * The API address can also be supplied at run time by /config.json ({"apiUrl": "https://api.example.com"}),
 * so one frontend build works for staging and production (needed when the SPA is hosted on a CDN).
 */
export async function loadRuntimeConfig() {
  try {
    const res = await fetch('/config.json', { cache: 'no-store' });
    if (!res.ok || !(res.headers.get('content-type') ?? '').includes('json')) return;
    const cfg = await res.json();
    if (typeof cfg?.apiUrl === 'string') base = cfg.apiUrl.replace(/\/$/, '');
  } catch {
    /* no runtime config: keep the build-time value */
  }
}

export async function api<T = unknown>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json' };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (method !== 'GET' && csrf) headers['X-CSRF-Token'] = csrf;

  let res: Response;
  try {
    res = await fetch(base + path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials: 'include'
    });
  } catch {
    throw new ApiError(0, 'network', 'Cannot reach the server. Check your connection and try again.');
  }
  if (res.status === 204) return undefined as T;

  const data = await res.json().catch(() => null);
  if (!res.ok) {
    const e = data?.error;
    throw new ApiError(
      res.status,
      e?.code ?? 'error',
      e?.message ?? 'Something went wrong. Please try again.',
      e?.fields ?? {},
      Number(res.headers.get('Retry-After')) || undefined
    );
  }
  return data as T;
}

export function errorMessage(e: unknown): string {
  if (e instanceof ApiError) {
    if (e.retryAfter && (e.status === 429 || e.code === 'account_locked')) {
      const m = Math.ceil(e.retryAfter / 60);
      return `${e.message} (try again in ${m > 1 ? m + ' minutes' : 'a minute'})`;
    }
    return e.message;
  }
  return 'Something went wrong. Please try again.';
}
