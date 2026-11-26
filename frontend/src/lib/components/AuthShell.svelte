<script lang="ts">
  import type { Snippet } from 'svelte';
  import * as Card from '$lib/components/ui/card';
  import ThemeToggle from './ThemeToggle.svelte';

  let { title, description, children, footer }: { title: string; description?: string; children: Snippet; footer?: Snippet } = $props();
</script>

<div class="relative flex min-h-svh items-center justify-center p-4">
  <div class="absolute top-4 right-4"><ThemeToggle /></div>
  <div class="w-full max-w-sm">
    <p class="mb-6 text-center text-2xl font-semibold tracking-tight">famku</p>
    <Card.Root>
      <Card.Header>
        <Card.Title>{title}</Card.Title>
        {#if description}<Card.Description>{description}</Card.Description>{/if}
      </Card.Header>
      <Card.Content class="grid gap-4">{@render children()}</Card.Content>
      {#if footer}<Card.Footer class="justify-center text-sm text-muted-foreground">{@render footer()}</Card.Footer>{/if}
    </Card.Root>
  </div>
</div>
