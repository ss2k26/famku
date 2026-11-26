<script lang="ts">
  import { api, ApiError, errorMessage } from '$lib/api';
  import { takeFragmentToken, link } from '$lib/router.svelte';
  import AuthShell from '$lib/components/AuthShell.svelte';
  import Field from '$lib/components/Field.svelte';
  import { Button } from '$lib/components/ui/button';
  import { Input } from '$lib/components/ui/input';
  import * as Alert from '$lib/components/ui/alert';

  // The token travels in the URL fragment, so it is never sent to a server or written to access logs.
  const token = takeFragmentToken();
  let password = $state('');
  let confirm = $state('');
  let error = $state('');
  let fields = $state<Record<string, string>>({});
  let busy = $state(false);
  let done = $state(false);

  async function submit(e: SubmitEvent) {
    e.preventDefault();
    error = '';
    fields = {};
    if (password !== confirm) {
      error = 'The passwords do not match.';
      return;
    }
    busy = true;
    try {
      await api('POST', '/api/auth/reset-password', { token, password });
      done = true;
    } catch (err) {
      if (err instanceof ApiError && err.fields) fields = err.fields;
      error = errorMessage(err);
    } finally {
      busy = false;
    }
  }
</script>

<AuthShell title="Choose a new password">
  {#if !token && !done}
    <Alert.Root variant="destructive"><Alert.Description>This link is missing its token. Request a new reset link.</Alert.Description></Alert.Root>
    <a href="/forgot-password" use:link class="text-center text-sm underline">Request a new link</a>
  {:else if done}
    <Alert.Root variant="success"><Alert.Description>Password updated. Other devices were signed out.</Alert.Description></Alert.Root>
    <a href="/login" use:link class="text-center text-sm underline">Sign in</a>
  {:else}
    <form class="grid gap-4" onsubmit={submit}>
      {#if error}<Alert.Root variant="destructive"><Alert.Description>{error}</Alert.Description></Alert.Root>{/if}
      <Field id="password" label="New password" error={fields.password} hint="At least 12 characters.">
        <Input id="password" type="password" autocomplete="new-password" required minlength={12} maxlength={128} bind:value={password} />
      </Field>
      <Field id="confirm" label="Confirm password">
        <Input id="confirm" type="password" autocomplete="new-password" required bind:value={confirm} />
      </Field>
      <Button type="submit" disabled={busy}>{busy ? 'Saving…' : 'Update password'}</Button>
    </form>
  {/if}
</AuthShell>
