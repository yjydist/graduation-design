export type ThemeMode = "light" | "dark";

const STORAGE_KEY = "theme";

export function readCurrentTheme(): ThemeMode {
  if (typeof document === "undefined") {
    return "light";
  }
  return document.documentElement.classList.contains("dark") ? "dark" : "light";
}

export function applyTheme(theme: ThemeMode): void {
  const dark = theme === "dark";
  document.documentElement.classList.toggle("dark", dark);
  document.documentElement.style.colorScheme = dark ? "dark" : "light";
  try {
    localStorage.setItem(STORAGE_KEY, theme);
  } catch {
    // Ignore storage write errors in private contexts.
  }
}

export function toggleTheme(): ThemeMode {
  const next: ThemeMode = readCurrentTheme() === "dark" ? "light" : "dark";
  applyTheme(next);
  return next;
}
