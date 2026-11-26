import { api } from './api';

export type CaptchaProvider = 'none' | 'pow' | 'turnstile' | 'hcaptcha' | 'recaptcha';

export const captchaCfg = $state<{ loaded: boolean; provider: CaptchaProvider; siteKey: string; mode: 'off' | 'adaptive' | 'always' }>({
  loaded: false,
  provider: 'none',
  siteKey: '',
  mode: 'adaptive'
});

export async function loadCaptchaConfig() {
  try {
    const c = await api<{ provider: CaptchaProvider; siteKey?: string; mode: 'off' | 'adaptive' | 'always' }>('GET', '/api/captcha/config');
    captchaCfg.provider = c.provider;
    captchaCfg.siteKey = c.siteKey ?? '';
    captchaCfg.mode = c.mode;
  } finally {
    captchaCfg.loaded = true;
  }
}

/** Registration, password reset and verification resend always ask (unless captcha is off). */
export function captchaAlways() {
  return captchaCfg.provider !== 'none' && captchaCfg.mode !== 'off';
}

/** Login asks always, or (adaptive) once the server demanded it after failed attempts. */
export function captchaForLogin(serverDemanded: boolean) {
  if (captchaCfg.provider === 'none' || captchaCfg.mode === 'off') return false;
  return captchaCfg.mode === 'always' || serverDemanded;
}
