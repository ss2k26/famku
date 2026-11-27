<script lang="ts">
  import { api, ApiError, errorMessage } from '$lib/api';
  import { auth, type User } from '$lib/auth.svelte';
  import * as Card from '$lib/components/ui/card';
  import Field from '$lib/components/Field.svelte';
  import { Input } from '$lib/components/ui/input';
  import { Button } from '$lib/components/ui/button';
  import * as Alert from '$lib/components/ui/alert';

  let name = $state(auth.user?.name ?? '');
  let username = $state(auth.user?.username ?? '');
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
      const r = await api<{ user: User }>('PATCH', '/api/account/profile', { name, username });
      username = r.user.username;
      auth.user = r.user;
      ok = true;
    } catch (err) {
      if (err instanceof ApiError && err.fields) fields = err.fields;
      error = errorMessage(err);
    } finally {
      busy = false;
    }
  }
</script>

<Card.Root>
  <Card.Header><Card.Title>Profile</Card.Title></Card.Header>
  <Card.Content>
    <form class="grid gap-4" onsubmit={save}>
      {#if error}<Alert.Root variant="destructive"><Alert.Description>{error}</Alert.Description></Alert.Root>{/if}
      {#if ok}<Alert.Root variant="success"><Alert.Description>Saved.</Alert.Description></Alert.Root>{/if}
      <Field id="pname" label="Name" error={fields.name}>
        <Input id="pname" required maxlength={80} bind:value={name} />
      </Field>
      <Field id="puser" label="Username" error={fields.username} hint="Used to sign in, together with your email.">
        <Input id="puser" autocapitalize="none" spellcheck="false" required minlength={3} maxlength={30} bind:value={username} />
      </Field>
      <div><Button type="submit" disabled={busy}>Save</Button></div>
    </form>
  </Card.Content>
</Card.Root>
