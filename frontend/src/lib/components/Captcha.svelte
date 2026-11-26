<script lang="ts">
  // One component for every provider. `token` is what the API expects in the "captcha" field.
  // Tokens are single use: call reset() after every submit (success or failure).
  import { onMount, onDestroy } from 'svelte';
  import { api } from '$lib/api';
  import { captchaCfg } from '$lib/captcha.svelte';
  import PowWorker from '$lib/captcha/pow.worker?worker';

  let { token = $bindable('') }: { token: string } = $props();

  let host: HTMLDivElement | undefined = $state();
  let status = $state<'idle' | 'working' | 'done' | 'error'>('idle');
  let attempts = $state(0);
  let widgetId: string | number | undefined;
  let worker: Worker | undefined;
  let run = 0; // invalidates a stale proof-of-work run after reset()

  const SCRIPTS: Record<string, string> = {
    turnstile: 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit',
    hcaptcha: 'https://js.hcaptcha.com/1/api.js?render=explicit',
    recaptcha: 'https://www.google.com/recaptcha/api.js?render=explicit'
  };

  function loadScript(src: string): Promise<void> {
    return new Promise((resolve, reject) => {
      if (document.querySelector(`script[src="${src}"]`)) return resolve();
      const s = document.createElement('script');
      s.src = src;
      s.async = true;
      s.onload = () => resolve();
      s.onerror = () => reject(new Error('captcha script failed to load'));
      document.head.appendChild(s);
    });
  }

  async function startPow() {
    const my = ++run;
    token = '';
    status = 'working';
    attempts = 0;
    try {
      const ch = await api<{ payload: string; signature: string; difficulty: number }>('GET', '/api/captcha/challenge');
      worker?.terminate();
      worker = new PowWorker();
      worker.onmessage = (e: MessageEvent<{ progress?: number; nonce?: number }>) => {
        if (my !== run) return;
        if (e.data.progress !== undefined) attempts = e.data.progress;
        if (e.data.nonce !== undefined) {
          token = `${ch.payload}~${ch.signature}~${e.data.nonce}`;
          status = 'done';
          worker?.terminate();
        }
      };
      worker.onerror = () => {
        if (my === run) status = 'error';
      };
      worker.postMessage({ payload: ch.payload, difficulty: ch.difficulty });
    } catch {
      if (my === run) status = 'error';
    }
  }

  async function startWidget() {
    const p = captchaCfg.provider;
    try {
      await loadScript(SCRIPTS[p]);
      const g = (window as any)[p === 'recaptcha' ? 'grecaptcha' : p];
      await new Promise<void>((r) => (g.ready ? g.ready(() => r()) : r()));
      widgetId = g.render(host, {
        sitekey: captchaCfg.siteKey,
        callback: (t: string) => (token = t),
        'expired-callback': () => (token = ''),
        'error-callback': () => (token = '')
      });
    } catch {
      status = 'error';
    }
  }

  export function reset() {
    token = '';
    if (captchaCfg.provider === 'pow') {
      startPow();
    } else if (widgetId !== undefined) {
      const g = (window as any)[captchaCfg.provider === 'recaptcha' ? 'grecaptcha' : captchaCfg.provider];
      g?.reset(widgetId);
    }
  }

  onMount(() => {
    if (captchaCfg.provider === 'pow') startPow();
    else if (captchaCfg.provider !== 'none') startWidget();
  });

  onDestroy(() => {
    run++;
    worker?.terminate();
    if (widgetId !== undefined) {
      const g = (window as any)[captchaCfg.provider === 'recaptcha' ? 'grecaptcha' : captchaCfg.provider];
      try {
        g?.remove?.(widgetId);
      } catch {
        /* ignore */
      }
    }
  });
</script>

{#if captchaCfg.provider === 'pow'}
  <div class="flex items-center gap-2 rounded-md border bg-muted/40 px-3 py-2 text-sm" role="status" aria-live="polite">
    {#if status === 'working'}
      <span class="size-3 animate-spin rounded-full border-2 border-muted-foreground border-t-transparent"></span>
      <span class="text-muted-foreground">Verifying you are human… {attempts.toLocaleString()}</span>
    {:else if status === 'done'}
      <span class="text-emerald-600 dark:text-emerald-400">✓ Verified</span>
    {:else if status === 'error'}
      <span class="text-destructive">Verification failed.</span>
      <button type="button" class="underline" onclick={startPow}>Retry</button>
    {/if}
  </div>
{:else if captchaCfg.provider !== 'none'}
  <div bind:this={host}></div>
  {#if status === 'error'}
    <p class="text-sm text-destructive">The captcha could not be loaded. Disable content blockers and reload.</p>
  {/if}
{/if}
