import { api, ApiError, setCsrf } from './api';

export type User = {
  id: string;
  email: string;
  username: string;
  name: string;
  emailVerified: boolean;
  twoFactorEnabled: boolean;
  createdAt: string;
};

export const auth = $state<{ user: User | null; ready: boolean }>({ user: null, ready: false });

/** Ask the server who we are (the session lives in an HttpOnly cookie the page cannot read). */
export async function refreshSession() {
  try {
    const r = await api<{ user: User; csrfToken: string }>('GET', '/api/auth/me');
    auth.user = r.user;
    setCsrf(r.csrfToken);
  } catch (e) {
    if (e instanceof ApiError && e.status === 401) {
      auth.user = null;
      setCsrf('');
    } else if (!(e instanceof ApiError)) {
      throw e;
    }
  } finally {
    auth.ready = true;
  }
}

export function startSession(user: User, csrfToken: string) {
  auth.user = user;
  setCsrf(csrfToken);
}

export async function signOut() {
  try {
    await api('POST', '/api/auth/logout', {});
  } finally {
    auth.user = null;
    setCsrf('');
  }
}
