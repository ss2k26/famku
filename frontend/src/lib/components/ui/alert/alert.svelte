<script lang="ts" module>
  export type AlertVariant = 'default' | 'destructive' | 'success';
</script>

<script lang="ts">
  import type { HTMLAttributes } from 'svelte/elements';
  import { cn } from '$lib/utils';

  let {
    class: className,
    variant = 'default',
    children,
    ...rest
  }: HTMLAttributes<HTMLDivElement> & { variant?: AlertVariant } = $props();

  const variants: Record<AlertVariant, string> = {
    default: 'bg-card text-card-foreground',
    destructive: 'border-destructive/50 text-destructive bg-card',
    success: 'border-emerald-500/50 text-emerald-700 dark:text-emerald-400 bg-card'
  };
</script>

<div role={variant === 'destructive' ? 'alert' : 'status'} class={cn('relative w-full rounded-lg border px-4 py-3 text-sm', variants[variant], className)} {...rest}>
  {@render children?.()}
</div>
