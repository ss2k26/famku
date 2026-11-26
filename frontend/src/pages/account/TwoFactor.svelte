<script lang="ts">
  import { api, errorMessage } from '$lib/api';
  import { auth } from '$lib/auth.svelte';
  import * as Card from '$lib/components/ui/card';
  import Field from '$lib/components/Field.svelte';
  import { Input } from '$lib/components/ui/input';
  import { Button } from '$lib/components/ui/button';
  import * as Alert from '$lib/components/ui/alert';

  let setup = $state<{ secret: string; uri: string } | null>(null);
  let codes = $state<string[]>([]);
  let code = $state('');
  let password = $state('');
  let mode = $state<'idle' | 'disable' | 'regen'>('idle');
  let error = $state('');
  let busy = $state(false);

  function setEnabled(v: boolean) {
    if (auth.user) auth.user = { ...auth.user, twoFactorEnabled: v };
  }

  async function run(fn: () => Promise<void>) {
    error = '';
    busy = true;
    try {
      await fn();
    } catch (err) {
      error = errorMessage(err);
    } finally {
      busy = false;
    }
  }

  const begin = () =>
    run(async () => {
      codes = [];
      setup = await api('POST', '/api/account/2fa/setup', {});
    });

  const enable = (e: SubmitEvent) => {
    e.preventDefault();
    return run(async () => {
      const r = await api<{ recoveryCodes: string[] }>('POST', '/api/account/2fa/enable', { code: code.trim() });
      codes = r.recoveryCodes;
      setup = null;
      code = '';
      setEnabled(true);
    });
  };

  const disable = (e: SubmitEvent) => {
    e.preventDefault();
    return run(async () => {
      await api('POST', '/api/account/2fa/disable', { password, code: code.trim() });
      setEnabled(false);
      mode = 'idle';
      password = code = '';
    });
  };

  const regen = (e: SubmitEvent) => {
    e.preventDefault();
    return run(async () => {
      const r = await api<{ recoveryCodes: string[] }>('POST', '/api/account/2fa/recovery-codes', { password });
      codes = r.recoveryCodes;
      mode = 'idle';
      password = '';
    });
  };

  function cancel() {
    setup = null;
    mode = 'idle';
    error = '';
    password = code = '';
  }
</script>

<Card.Root>
  <Card.Header>
    <Card.Title>Two-factor authentication</Card.Title>
    <Card.Description>
      {auth.user?.twoFactorEnabled ? 'Enabled. A code from your authenticator app is required at sign-in.' : 'Add a second step to sign-in with an authenticator app.'}
    </Card.Description>
  </Card.Header>
  <Card.Content class="grid gap-4">
    {#if error}<Alert.Root variant="destructive"><Alert.Description>{error}</Alert.Description></Alert.Root>{/if}

    {#if codes.length}
      <Alert.Root variant="success">
        <Alert.Title>Save your recovery codes</Alert.Title>
        <Alert.Description>
          <p class="mb-2">Each works once if you lose your device. They are shown only now.</p>
          <ul class="grid grid-cols-2 gap-1 font-mono text-sm">{#each codes as c (c)}<li>{c}</li>{/each}</ul>
          <Button variant="outline" size="sm" class="mt-3" onclick={() => (codes = [])}>I saved them</Button>
        </Alert.Description>
      </Alert.Root>
    {/if}

    {#if setup}
      <div class="grid gap-3 text-sm">
        <p>1. In your authenticator app, add an account with this key (or open the link on your phone):</p>
        <code class="block rounded-md bg-muted px-3 py-2 font-mono text-base tracking-wider break-all select-all">{setup.secret}</code>
        <a href={setup.uri} class="underline">Open in authenticator app</a>
        <form class="grid gap-3" onsubmit={enable}>
          <Field id="tcode" label="2. Enter the 6-digit code">
            <Input id="tcode" inputmode="numeric" autocomplete="one-time-code" maxlength={8} required bind:value={code} />
          </Field>
          <div class="flex gap-2">
            <Button type="submit" disabled={busy}>Enable</Button>
            <Button variant="ghost" onclick={cancel}>Cancel</Button>
          </div>
        </form>
      </div>
    {:else if mode === 'disable'}
      <form class="grid gap-3" onsubmit={disable}>
        <Field id="dpw" label="Password"><Input id="dpw" type="password" autocomplete="current-password" required bind:value={password} /></Field>
        <Field id="dcode" label="Authentication code"><Input id="dcode" inputmode="numeric" autocomplete="one-time-code" required bind:value={code} /></Field>
        <div class="flex gap-2">
          <Button type="submit" variant="destructive" disabled={busy}>Disable</Button>
          <Button variant="ghost" onclick={cancel}>Cancel</Button>
        </div>
      </form>
    {:else if mode === 'regen'}
      <form class="grid gap-3" onsubmit={regen}>
        <Field id="rpw" label="Password" hint="Generating new codes invalidates the old ones.">
          <Input id="rpw" type="password" autocomplete="current-password" required bind:value={password} />
        </Field>
        <div class="flex gap-2">
          <Button type="submit" disabled={busy}>Generate</Button>
          <Button variant="ghost" onclick={cancel}>Cancel</Button>
        </div>
      </form>
    {:else if auth.user?.twoFactorEnabled}
      <div class="flex flex-wrap gap-2">
        <Button variant="outline" onclick={() => (mode = 'regen')}>New recovery codes</Button>
        <Button variant="destructive" onclick={() => (mode = 'disable')}>Disable</Button>
      </div>
    {:else}
      <div><Button onclick={begin} disabled={busy}>Set up</Button></div>
    {/if}
  </Card.Content>
</Card.Root>
