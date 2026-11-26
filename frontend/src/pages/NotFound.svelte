<script lang="ts">
  import { link } from '$lib/router.svelte';
  import { buttonVariants } from '$lib/components/ui/button';
</script>

<div class="flex min-h-svh flex-col items-center justify-center gap-4 p-4 text-center">
  <h1 class="text-4xl font-semibold">404</h1>
  <p class="text-muted-foreground">This page does not exist.</p>
  <a href="/" use:link class={buttonVariants({ variant: 'outline' })}>Go home</a>
</div>
