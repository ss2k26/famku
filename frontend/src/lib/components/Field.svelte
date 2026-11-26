<script lang="ts">
  import type { Snippet } from 'svelte';
  import { Label } from '$lib/components/ui/label';

  let { id, label, error, hint, children }: { id: string; label: string; error?: string; hint?: string; children: Snippet } = $props();
</script>

<div class="grid gap-2">
  <Label for={id}>{label}</Label>
  {@render children()}
  {#if error}
    <p class="text-sm text-destructive" id="{id}-error">{error}</p>
  {:else if hint}
    <p class="text-sm text-muted-foreground">{hint}</p>
  {/if}
</div>
