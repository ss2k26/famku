<script lang="ts">
  import { api, errorMessage } from '$lib/api';
  import { captchaAlways } from '$lib/captcha.svelte';
  import { link } from '$lib/router.svelte';
  import AuthShell from '$lib/components/AuthShell.svelte';
  import Field from '$lib/components/Field.svelte';
  import Captcha from '$lib/components/Captcha.svelte';
  import { Button } from '$lib/components/ui/button';
  import { Input } from '$lib/components/ui/input';
  import * as Alert from '$lib/components/ui/alert';

  let email = $state('');
  let captchaToken = $state('');
  let captcha: Captcha | undefined = $state();
  let error = $state('');
  let busy = $state(false);
  let sent = $state(false);
  const needCaptcha = captchaAlways();

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    error = '';
    busy = true;
    try {
      await api('POST', '/api/auth/forgot-password', { email, captcha: captchaToken });
      sent = true;
    } catch (err) {
      error = errorMessage(err);
    } finally {
      busy = false;
      captcha?.reset();
    }
  }
</script>

<AuthShell title="Reset your password" description="We will email you a link if the address is registered.">
  {#if sent}
    <Alert.Root variant="success"><Alert.Description>If an account exists for that address, a reset link is on its way. It expires in 30 minutes.</Alert.Description></Alert.Root>
  {:else}
    <form class="grid gap-4" onsubmit={submit}>
      {#if error}<Alert.Root variant="destructive"><Alert.Description>{error}</Alert.Description></Alert.Root>{/if}
      <Field id="email" label="Email">
        <Input id="email" type="email" autocomplete="email" required bind:value={email} />
      </Field>
      {#if needCaptcha}<Captcha bind:this={captcha} bind:token={captchaToken} />{/if}
      <Button type="submit" disabled={busy || (needCaptcha && !captchaToken)}>{busy ? 'Sending…' : 'Send reset link'}</Button>
    </form>
  {/if}
  {#snippet footer()}
    <a href="/login" use:link class="underline">Back to sign in</a>
  {/snippet}
</AuthShell>
