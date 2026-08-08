import { useSyncExternalStore } from "react";

/**
 * Light and dark, resolved once and remembered.
 *
 * The console is read in two places that want opposite things: a darkened
 * operations floor, and a laptop in daylight. Everything colour means here is
 * defined twice in `index.css` — the four severity hues are re-picked for a
 * light ground rather than reused, because the dark-theme values fail contrast
 * as small text on white.
 *
 * `index.html` applies the stored choice in a blocking inline script before the
 * first paint. Doing it here instead would render one frame of dark before
 * React mounted, which is exactly the flash the attribute exists to avoid.
 */

export type Theme = "dark" | "light";

const KEY = "sentry.theme";

function systemTheme(): Theme {
  // Both hops are optional. jsdom does not implement `matchMedia` at all, so
  // `window.matchMedia?.(…).matches` throws on the property access rather than
  // short-circuiting — which took out every test that mounts the nav.
  return window.matchMedia?.("(prefers-color-scheme: light)")?.matches ? "light" : "dark";
}

function stored(): Theme | null {
  try {
    const v = localStorage.getItem(KEY);
    return v === "dark" || v === "light" ? v : null;
  } catch {
    // Safari in private mode throws on access rather than returning null.
    return null;
  }
}

export function currentTheme(): Theme {
  const attr = document.documentElement.dataset.theme;
  if (attr === "dark" || attr === "light") return attr;
  return stored() ?? systemTheme();
}

function apply(theme: Theme) {
  document.documentElement.dataset.theme = theme;
  // Keeps form controls, scrollbars and the browser's own chrome in step with
  // the palette; without it a light page keeps dark scrollbars.
  document
    .querySelector('meta[name="color-scheme"]')
    ?.setAttribute("content", theme);
}

const listeners = new Set<() => void>();

export function setTheme(theme: Theme) {
  apply(theme);
  try {
    localStorage.setItem(KEY, theme);
  } catch {
    // A console that cannot persist the choice still has to honour it now.
  }
  listeners.forEach((fn) => fn());
}

export function toggleTheme() {
  setTheme(currentTheme() === "dark" ? "light" : "dark");
}

function subscribe(fn: () => void) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

export function useTheme(): Theme {
  return useSyncExternalStore(subscribe, currentTheme, () => "dark" as Theme);
}
