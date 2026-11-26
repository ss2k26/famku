// Light/dark mode: follows the system until the user picks one.
const KEY = 'famku-theme';

function read(): 'light' | 'dark' | null {
  try {
    const v = localStorage.getItem(KEY);
    return v === 'light' || v === 'dark' ? v : null;
  } catch {
    return null; // storage can be blocked
  }
}

export function isDark(): boolean {
  return document.documentElement.classList.contains('dark');
}

export function applyTheme() {
  const t = read() ?? (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
  document.documentElement.classList.toggle('dark', t === 'dark');
}

export function toggleTheme(): boolean {
  const next = isDark() ? 'light' : 'dark';
  document.documentElement.classList.toggle('dark', next === 'dark');
  try {
    localStorage.setItem(KEY, next);
  } catch {
    /* ignore */
  }
  return next === 'dark';
}
