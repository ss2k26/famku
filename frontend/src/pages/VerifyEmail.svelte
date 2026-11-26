<script lang="ts">
  import { onMount } from 'svelte';
  import { api, errorMessage } from '$lib/api';
  import { captchaAlways } from '$lib/captcha.svelte';
  import { takeFragmentToken, link } from '$lib/router.svelte';
  import AuthShell from '$lib/components/AuthShell.svelte';
  import Field from '$lib/components/Field.svelte';
  import Captcha from '$lib/components/Captcha.svelte';
  import { Button } from '$lib/components/ui/button';
  import { Input } from '$lib/components/ui/input';
  import * as Alert from '$lib/components/ui/alert';

  const token = takeFragmentToken();
  let state_ = $state<'checking' | 'ok' | 'failed' | 'resend'>(token ? 'checking' : 'resend');
  let error = $state('');
  let email = $state('');
  let captchaToken = $state('');
  let captcha: Captcha | undefined = $state();
  let sent = $state(false);
  let busy = $state(false);
  const needCaptcha = captchaAlways();

  onMount(async () => {
    if (!token) return;
    try {
      await api('POST', '/api/auth/verify-email', { token });
      state_ = 'ok';
    } catch (err) {
      error = errorMessage(err);
      state_ = 'failed';
    }
  });

  async function resend(e: SubmitEvent) {
    e.preventDefault();
    error = '';
    busy = true;
    try {
      await api('POST', '/api/auth/resend-verification', { email, captcha: captchaToken });
      sent = true;
    } catch (err) {
      error = errorMessage(err);
    } finally {
      busy = false;
      captcha?.reset();
    }
  }
</script>

<AuthShell title="Verify your email">
  {#if state_ === 'checking'}
    <p class="text-sm text-muted-foreground">Checking your link…</p>
  {:else if state_ === 'ok'}
    <Alert.Root variant="success"><Alert.Description>Your email is verified.</Alert.Description></Alert.Root>
    <a href="/login" use:link class="text-center text-sm underline">Sign in</a>
  {:else}
    {#if state_ === 'failed'}
      <Alert.Root variant="destructive"><Alert.Description>{error || 'This link is invalid or has expired.'}</Alert.Description></Alert.Root>
    {/if}
    {#if sent}
      <Alert.Root variant="success"><Alert.Description>If the address is registered and unverified, a new link is on its way.</Alert.Description></Alert.Root>
    {:else}
      <form class="grid gap-4" onsubmit={resend}>
        {#if error && state_ !== 'failed'}<Alert.Root variant="destructive"><Alert.Description>{error}</Alert.Description></Alert.Root>{/if}
        <Field id="email" label="Email" hint="Request a new verification link.">
          <Input id="email" type="email" autocomplete="email" required bind:value={email} />
        </Field>
        {#if needCaptcha}<Captcha bind:this={captcha} bind:token={captchaToken} />{/if}
        <Button type="submit" disabled={busy || (needCaptcha && !captchaToken)}>{busy ? 'Sending…' : 'Send verification link'}</Button>
      </form>
    {/if}
  {/if}
</AuthShell>
