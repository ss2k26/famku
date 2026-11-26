// A very small history-API router (no dependency): enough for a handful of pages.

export const route = $state({ path: location.pathname, search: location.search });

export function navigate(to: string, replace = false) {
  const url = new URL(to, location.origin);
  if (replace) history.replaceState({}, '', url);
  else history.pushState({}, '', url);
  route.path = url.pathname;
  route.search = url.search;
  window.scrollTo(0, 0);
}

window.addEventListener('popstate', () => {
  route.path = location.pathname;
  route.search = location.search;
});

/** Svelte action: turn same-origin links into client-side navigation. Usage: <a href="/login" use:link> */
export function link(node: HTMLAnchorElement) {
  const onClick = (e: MouseEvent) => {
    if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    const href = node.getAttribute('href');
    if (!href || !href.startsWith('/') || href.startsWith('//')) return;
    e.preventDefault();
    navigate(href);
  };
  node.addEventListener('click', onClick);
  return { destroy: () => node.removeEventListener('click', onClick) };
}

/** Read (and remove from the address bar) a one-time token passed in the URL fragment: /reset-password#token=... */
export function takeFragmentToken(): string {
  const m = /(?:^#|&)token=([^&]+)/.exec(location.hash);
  if (m) history.replaceState({}, '', location.pathname + location.search);
  return m ? decodeURIComponent(m[1]) : '';
}
