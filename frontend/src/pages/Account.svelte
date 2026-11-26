<script lang="ts">
  import { auth, signOut } from '$lib/auth.svelte';
  import { navigate } from '$lib/router.svelte';
  import { Button } from '$lib/components/ui/button';
  import ThemeToggle from '$lib/components/ThemeToggle.svelte';
  import Profile from './account/Profile.svelte';
  import Password from './account/Password.svelte';
  import TwoFactor from './account/TwoFactor.svelte';
  import Sessions from './account/Sessions.svelte';

  async function out() {
    try {
      await signOut();
    } finally {
      navigate('/login', true);
    }
  }
</script>

<div class="mx-auto min-h-svh max-w-2xl p-4 pb-16">
  <header class="flex items-center justify-between py-4">
    <div>
      <p class="text-lg font-semibold tracking-tight">famku</p>
      <p class="text-sm text-muted-foreground">{auth.user?.email}</p>
    </div>
    <div class="flex items-center gap-2">
      <ThemeToggle />
      <Button variant="outline" size="sm" onclick={out}>Sign out</Button>
    </div>
  </header>

  <main class="grid gap-6">
    {#if auth.user && !auth.user.emailVerified}
      <p class="rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-sm">Your email address is not verified yet.</p>
    {/if}
    <Profile />
    <Password />
    <TwoFactor />
    <Sessions />
  </main>
</div>
