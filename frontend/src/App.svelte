<script lang="ts">
  import { route, navigate } from '$lib/router.svelte';
  import { auth } from '$lib/auth.svelte';
  import Login from './pages/Login.svelte';
  import Register from './pages/Register.svelte';
  import Forgot from './pages/Forgot.svelte';
  import Reset from './pages/Reset.svelte';
  import VerifyEmail from './pages/VerifyEmail.svelte';
  import Account from './pages/Account.svelte';
  import NotFound from './pages/NotFound.svelte';

  const guestOnly = ['/login', '/register', '/forgot-password'];
  const needsAuth = ['/', '/account'];

  // Route guard: runs whenever the path or the session changes.
  $effect(() => {
    if (!auth.ready) return;
    if (!auth.user && needsAuth.includes(route.path)) navigate('/login', true);
    else if (auth.user && guestOnly.includes(route.path)) navigate('/account', true);
  });
</script>

{#if route.path === '/login'}
  <Login />
{:else if route.path === '/register'}
  <Register />
{:else if route.path === '/forgot-password'}
  <Forgot />
{:else if route.path === '/reset-password'}
  <Reset />
{:else if route.path === '/verify-email'}
  <VerifyEmail />
{:else if (route.path === '/' || route.path === '/account') && auth.user}
  <Account />
{:else if route.path === '/' || route.path === '/account'}
  <div class="p-8 text-center text-muted-foreground">Loading…</div>
{:else}
  <NotFound />
{/if}
