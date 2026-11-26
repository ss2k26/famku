<script lang="ts" module>
  import { cn } from '$lib/utils';

  export type ButtonVariant = 'default' | 'destructive' | 'outline' | 'secondary' | 'ghost' | 'link';
  export type ButtonSize = 'default' | 'sm' | 'lg' | 'icon';

  const base =
    "inline-flex shrink-0 items-center justify-center gap-2 rounded-md text-sm font-medium whitespace-nowrap transition-all outline-none focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/50 disabled:pointer-events-none disabled:opacity-50 [&_svg]:pointer-events-none [&_svg]:shrink-0";
  const variants: Record<ButtonVariant, string> = {
    default: 'bg-primary text-primary-foreground shadow-xs hover:bg-primary/90',
    destructive: 'bg-destructive text-white shadow-xs hover:bg-destructive/90 focus-visible:ring-destructive/20',
    outline: 'border bg-background shadow-xs hover:bg-accent hover:text-accent-foreground',
    secondary: 'bg-secondary text-secondary-foreground shadow-xs hover:bg-secondary/80',
    ghost: 'hover:bg-accent hover:text-accent-foreground',
    link: 'text-primary underline-offset-4 hover:underline'
  };
  const sizes: Record<ButtonSize, string> = {
    default: 'h-9 px-4 py-2',
    sm: 'h-8 gap-1.5 rounded-md px-3',
    lg: 'h-10 rounded-md px-6',
    icon: 'size-9'
  };

  export function buttonVariants({ variant = 'default', size = 'default' }: { variant?: ButtonVariant; size?: ButtonSize } = {}) {
    return cn(base, variants[variant], sizes[size]);
  }
</script>

<script lang="ts">
  import type { HTMLButtonAttributes } from 'svelte/elements';

  let {
    class: className,
    variant = 'default',
    size = 'default',
    type = 'button',
    children,
    ...rest
  }: HTMLButtonAttributes & { variant?: ButtonVariant; size?: ButtonSize } = $props();
</script>

<button {type} class={cn(buttonVariants({ variant, size }), className)} {...rest}>
  {@render children?.()}
</button>
