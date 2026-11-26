<script lang="ts">
  import { Button } from '$lib/components/ui/button';
  import { toggleTheme, isDark } from '$lib/theme';

  let dark = $state(isDark());
</script>

<Button variant="ghost" size="sm" aria-label="Toggle dark mode" onclick={() => (dark = toggleTheme())}>
  {dark ? 'Light' : 'Dark'}
</Button>
