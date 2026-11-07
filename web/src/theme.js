import { useEffect, useState } from 'react';

// "system" follows the OS. index.html applies the stored choice before first
// paint so there is no flash; this hook keeps it in sync afterwards.
const KEY = 'oc_theme';
const media = window.matchMedia('(prefers-color-scheme: dark)');

function apply(theme) {
  const dark = theme === 'dark' || (theme === 'system' && media.matches);
  document.documentElement.classList.toggle('dark', dark);
}

export function useTheme() {
  const [theme, setTheme] = useState(() => localStorage.getItem(KEY) || 'system');

  useEffect(() => {
    localStorage.setItem(KEY, theme);
    apply(theme);
    if (theme !== 'system') return;
    const onChange = () => apply('system');
    media.addEventListener('change', onChange);
    return () => media.removeEventListener('change', onChange);
  }, [theme]);

  return [theme, setTheme];
}
