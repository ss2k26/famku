<script lang="ts">
  import { api, ApiError, errorMessage } from '$lib/api';
  import * as Card from '$lib/components/ui/card';
  import Field from '$lib/components/Field.svelte';
  import { Input } from '$lib/components/ui/input';
  import { Button } from '$lib/components/ui/button';
  import * as Alert from '$lib/components/ui/alert';

  let current = $state('');
  let next = $state('');
  let error = $state('');
  let ok = $state(false);
  let fields = $state<Record<string, string>>({});
  let busy = $state(false);

  async function save(e: SubmitEvent) {
    e.preventDefault();
    error = '';
    ok = false;
    fields = {};
    busy = true;
    try {
      await api('POST', '/api/account/password', { currentPassword: current, newPassword: next });
      ok = true;
      current = next = '';
    } catch (err) {
      if (err instanceof ApiError && err.fields) fields = err.fields;
      error = errorMessage(err);
    } finally {
      busy = false;
    }
  }
</script>

<Card.Root>
  <Card.Header>
    <Card.Title>Password</Card.Title>
    <Card.Description>Changing it signs out all your other devices.</Card.Description>
  </Card.Header>
  <Card.Content>
    <form class="grid gap-4" onsubmit={save}>
      {#if error}<Alert.Root variant="destructive"><Alert.Description>{error}</Alert.Description></Alert.Root>{/if}
      {#if ok}<Alert.Root variant="success"><Alert.Description>Password changed.</Alert.Description></Alert.Root>{/if}
      <Field id="cur" label="Current password" error={fields.currentPassword}>
        <Input id="cur" type="password" autocomplete="current-password" required bind:value={current} />
      </Field>
      <Field id="new" label="New password" error={fields.newPassword} hint="At least 12 characters.">
        <Input id="new" type="password" autocomplete="new-password" required minlength={12} maxlength={128} bind:value={next} />
      </Field>
      <div><Button type="submit" disabled={busy}>Change password</Button></div>
    </form>
  </Card.Content>
</Card.Root>
