<script lang="ts">
  import { onMount } from 'svelte';
  import { api, errorMessage } from '$lib/api';
  import * as Card from '$lib/components/ui/card';
  import { Button } from '$lib/components/ui/button';
  import * as Alert from '$lib/components/ui/alert';

  type S = { id: string; userAgent: string; ip: string; createdAt: string; lastSeenAt: string; current: boolean };
  let sessions = $state<S[]>([]);
  let error = $state('');
  let loading = $state(true);

  const fmt = (s: string) => new Date(s).toLocaleString();

  async function load() {
    try {
      sessions = (await api<{ sessions: S[] }>('GET', '/api/account/sessions')).sessions;
    } catch (e) {
      error = errorMessage(e);
    } finally {
      loading = false;
    }
  }
  onMount(load);

  async function revoke(id: string) {
    error = '';
    try {
      await api('DELETE', `/api/account/sessions/${encodeURIComponent(id)}`);
      await load();
    } catch (e) {
      error = errorMessage(e);
    }
  }

  async function revokeOthers() {
    error = '';
    try {
      await api('POST', '/api/account/sessions/revoke-others', {});
      await load();
    } catch (e) {
      error = errorMessage(e);
    }
  }
</script>

<Card.Root>
  <Card.Header>
    <Card.Title>Active sessions</Card.Title>
    <Card.Description>Devices currently signed in to your account.</Card.Description>
  </Card.Header>
  <Card.Content class="grid gap-3">
    {#if error}<Alert.Root variant="destructive"><Alert.Description>{error}</Alert.Description></Alert.Root>{/if}
    {#if loading}
      <p class="text-sm text-muted-foreground">Loading…</p>
    {/if}
    {#each sessions as s (s.id)}
      <div class="flex items-start justify-between gap-3 rounded-md border p-3 text-sm">
        <div class="min-w-0">
          <p class="truncate font-medium">{s.userAgent || 'Unknown device'}{#if s.current}<span class="ml-2 rounded bg-primary px-1.5 py-0.5 text-xs text-primary-foreground">this device</span>{/if}</p>
          <p class="text-muted-foreground">{s.ip} · last active {fmt(s.lastSeenAt)}</p>
        </div>
        {#if !s.current}<Button variant="outline" size="sm" onclick={() => revoke(s.id)}>Revoke</Button>{/if}
      </div>
    {/each}
    {#if sessions.length > 1}
      <div><Button variant="destructive" size="sm" onclick={revokeOthers}>Sign out all other devices</Button></div>
    {/if}
  </Card.Content>
</Card.Root>
