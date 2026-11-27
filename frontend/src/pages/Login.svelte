<script lang="ts">
  import { api, ApiError, errorMessage } from '$lib/api';
  import { startSession, type User } from '$lib/auth.svelte';
  import { captchaForLogin } from '$lib/captcha.svelte';
  import { navigate, link } from '$lib/router.svelte';
  import AuthShell from '$lib/components/AuthShell.svelte';
  import Field from '$lib/components/Field.svelte';
  import Captcha from '$lib/components/Captcha.svelte';
  import { Button } from '$lib/components/ui/button';
  import { Input } from '$lib/components/ui/input';
  import * as Alert from '$lib/components/ui/alert';

  let identifier = $state('');
  let password = $state('');
  let totp = $state('');
  let recovery = $state('');
  let useRecovery = $state(false);
  let needTwoFactor = $state(false);
  let captchaDemanded = $state(false); // the server asked after failed attempts (adaptive mode)
  let captchaToken = $state('');
  let captcha: Captcha | undefined = $state();
  let error = $state('');
  let unverified = $state(false);
  let busy = $state(false);

  const showCaptcha = $derived(captchaForLogin(captchaDemanded));

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    error = '';
    unverified = false;
    busy = true;
    try {
      const r = await api<{ user: User; csrfToken: string }>('POST', '/api/auth/login', {
        identifier: identifier.trim(),
        password,
        captcha: captchaToken,
        totpCode: needTwoFactor && !useRecovery ? totp.trim() : '',
        recoveryCode: needTwoFactor && useRecovery ? recovery.trim() : ''
      });
      startSession(r.user, r.csrfToken);
      password = '';
      navigate('/account', true);
    } catch (err) {
      if (err instanceof ApiError) {
        if (err.code === 'captcha_required') captchaDemanded = true;
        if (err.code === 'two_factor_required') {
          needTwoFactor = true;
          error = '';
          return;
        }
        if (err.code === 'email_not_verified') unverified = true;
      }
      error = errorMessage(err);
    } finally {
      busy = false;
      captcha?.reset(); // a captcha token can be used once
    }
  }
</script>

<AuthShell title="Sign in" description="Welcome back.">
  <form class="grid gap-4" onsubmit={submit}>
    {#if error}
      <Alert.Root variant="destructive"><Alert.Description>{error}</Alert.Description></Alert.Root>
    {/if}
    {#if unverified}
      <p class="text-sm"><a href="/verify-email" use:link class="underline">Resend the verification email</a></p>
    {/if}

    {#if !needTwoFactor}
      <Field id="identifier" label="Username or email">
        <Input id="identifier" autocomplete="username" autocapitalize="none" spellcheck="false" required maxlength={254} bind:value={identifier} />
      </Field>
      <Field id="password" label="Password">
        <Input id="password" type="password" autocomplete="current-password" required bind:value={password} />
      </Field>
      <div class="text-right text-sm"><a href="/forgot-password" use:link class="underline">Forgot password?</a></div>
    {:else if !useRecovery}
      <Field id="totp" label="Authentication code" hint="Enter the 6-digit code from your authenticator app.">
        <Input id="totp" inputmode="numeric" autocomplete="one-time-code" maxlength={8} required bind:value={totp} />
      </Field>
      <button type="button" class="text-left text-sm underline" onclick={() => (useRecovery = true)}>Use a recovery code instead</button>
    {:else}
      <Field id="recovery" label="Recovery code" hint="Each recovery code works once.">
        <Input id="recovery" autocomplete="off" required bind:value={recovery} />
      </Field>
      <button type="button" class="text-left text-sm underline" onclick={() => (useRecovery = false)}>Use an authenticator code instead</button>
    {/if}

    {#if showCaptcha}
      <Captcha bind:this={captcha} bind:token={captchaToken} />
    {/if}

    <Button type="submit" disabled={busy || (showCaptcha && !captchaToken)}>{busy ? 'Signing in…' : 'Sign in'}</Button>
  </form>
  {#snippet footer()}
    <span>No account? <a href="/register" use:link class="underline">Create one</a></span>
  {/snippet}
</AuthShell>
