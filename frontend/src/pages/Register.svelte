<script lang="ts">
  import { api, ApiError, errorMessage } from '$lib/api';
  import { captchaAlways } from '$lib/captcha.svelte';
  import { link } from '$lib/router.svelte';
  import AuthShell from '$lib/components/AuthShell.svelte';
  import Field from '$lib/components/Field.svelte';
  import Captcha from '$lib/components/Captcha.svelte';
  import { Button } from '$lib/components/ui/button';
  import { Input } from '$lib/components/ui/input';
  import * as Alert from '$lib/components/ui/alert';

  let name = $state('');
  let username = $state('');
  let email = $state('');
  let password = $state('');
  let captchaToken = $state('');
  let captcha: Captcha | undefined = $state();
  let error = $state('');
  let fields = $state<Record<string, string>>({});
  let busy = $state(false);
  let done = $state<null | { verificationRequired: boolean }>(null);

  const needCaptcha = captchaAlways();

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    error = '';
    fields = {};
    busy = true;
    try {
      const r = await api<{ verificationRequired: boolean }>('POST', '/api/auth/register', { name, username, email, password, captcha: captchaToken });
      done = { verificationRequired: r.verificationRequired };
      password = '';
    } catch (err) {
      if (err instanceof ApiError && err.fields) fields = err.fields;
      error = errorMessage(err);
    } finally {
      busy = false;
      captcha?.reset();
    }
  }
</script>

<AuthShell title="Create your account" description="Use a long, unique password (12+ characters).">
  {#if done}
    <Alert.Root variant="success">
      <Alert.Description>
        {#if done.verificationRequired}
          If the address can be registered, we sent a verification link to <strong>{email}</strong>. Open it to activate your account.
        {:else}
          Your account is ready. You can sign in now.
        {/if}
      </Alert.Description>
    </Alert.Root>
    <a href="/login" use:link class="text-center text-sm underline">Go to sign in</a>
  {:else}
    <form class="grid gap-4" onsubmit={submit}>
      {#if error}<Alert.Root variant="destructive"><Alert.Description>{error}</Alert.Description></Alert.Root>{/if}
      <Field id="name" label="Name" error={fields.name}>
        <Input id="name" autocomplete="name" required maxlength={80} bind:value={name} />
      </Field>
      <Field id="username" label="Username" error={fields.username} hint="3-30 characters: letters, numbers, . _ -  You can sign in with it.">
        <Input id="username" autocomplete="username" autocapitalize="none" spellcheck="false" required minlength={3} maxlength={30} pattern="[A-Za-z0-9][A-Za-z0-9._\-]*[A-Za-z0-9]" bind:value={username} />
      </Field>
      <Field id="email" label="Email" error={fields.email}>
        <Input id="email" type="email" autocomplete="email" required bind:value={email} />
      </Field>
      <Field id="password" label="Password" error={fields.password} hint="At least 12 characters. Passphrases work well.">
        <Input id="password" type="password" autocomplete="new-password" required minlength={12} maxlength={128} bind:value={password} />
      </Field>
      {#if needCaptcha}<Captcha bind:this={captcha} bind:token={captchaToken} />{/if}
      <Button type="submit" disabled={busy || (needCaptcha && !captchaToken)}>{busy ? 'Creating…' : 'Create account'}</Button>
    </form>
  {/if}
  {#snippet footer()}
    <span>Already registered? <a href="/login" use:link class="underline">Sign in</a></span>
  {/snippet}
</AuthShell>
