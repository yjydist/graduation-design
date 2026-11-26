import fs from "node:fs";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { applyTheme, readCurrentTheme, toggleTheme } from "./theme";

interface MockEnvOptions {
  savedTheme?: string | null;
  prefersDark?: boolean;
  throwOnStorage?: boolean;
}

function setupMockDom(options: MockEnvOptions = {}) {
  const classes = new Set<string>();
  const store = new Map<string, string>();
  if (options.savedTheme !== undefined && options.savedTheme !== null) {
    store.set("theme", options.savedTheme);
  }

  const documentElement = {
    classList: {
      toggle(name: string, force?: boolean) {
        if (force === undefined) {
          if (classes.has(name)) {
            classes.delete(name);
            return false;
          }
          classes.add(name);
          return true;
        }
        if (force) classes.add(name);
        else classes.delete(name);
        return force;
      },
      contains(name: string) {
        return classes.has(name);
      },
    },
    style: { colorScheme: "" },
  };

  const localStorageStub = {
    getItem(key: string) {
      if (options.throwOnStorage) throw new Error("storage blocked");
      return store.get(key) ?? null;
    },
    setItem(key: string, value: string) {
      if (options.throwOnStorage) throw new Error("storage blocked");
      store.set(key, value);
    },
  };

  const windowStub = {
    matchMedia: (query: string) => ({
      matches:
        query === "(prefers-color-scheme: dark)"
          ? Boolean(options.prefersDark)
          : false,
    }),
  };

  vi.stubGlobal("document", { documentElement });
  vi.stubGlobal("localStorage", localStorageStub);
  vi.stubGlobal("window", windowStub);

  return { documentElement, store };
}

const themeInitSource = fs.readFileSync(
  path.resolve(__dirname, "../../public/theme-init.js"),
  "utf-8",
);

function runThemeInitScript() {
  const fn = new Function(themeInitSource);
  fn();
}

describe("theme-init.js (CSP-safe pre-render script) and theme helpers", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("follows prefers-color-scheme on first visit when no saved theme exists", () => {
    const darkDom = setupMockDom({ prefersDark: true });
    runThemeInitScript();
    expect(darkDom.documentElement.classList.contains("dark")).toBe(true);
    expect(darkDom.documentElement.style.colorScheme).toBe("dark");

    const lightDom = setupMockDom({ prefersDark: false });
    runThemeInitScript();
    expect(lightDom.documentElement.classList.contains("dark")).toBe(false);
    expect(lightDom.documentElement.style.colorScheme).toBe("light");
  });

  it("honors persisted localStorage theme over system preference on reload", () => {
    const forceDark = setupMockDom({ savedTheme: "dark", prefersDark: false });
    runThemeInitScript();
    expect(forceDark.documentElement.classList.contains("dark")).toBe(true);
    expect(forceDark.documentElement.style.colorScheme).toBe("dark");

    const forceLight = setupMockDom({ savedTheme: "light", prefersDark: true });
    runThemeInitScript();
    expect(forceLight.documentElement.classList.contains("dark")).toBe(false);
    expect(forceLight.documentElement.style.colorScheme).toBe("light");
  });

  it("handles restricted storage gracefully without throwing", () => {
    setupMockDom({ throwOnStorage: true, prefersDark: true });
    expect(() => runThemeInitScript()).not.toThrow();
    expect(() => applyTheme("dark")).not.toThrow();
  });

  it("toggles and persists light/dark mode consistently", () => {
    const { documentElement, store } = setupMockDom({ prefersDark: false });
    expect(readCurrentTheme()).toBe("light");

    const first = toggleTheme();
    expect(first).toBe("dark");
    expect(documentElement.classList.contains("dark")).toBe(true);
    expect(documentElement.style.colorScheme).toBe("dark");
    expect(store.get("theme")).toBe("dark");

    const second = toggleTheme();
    expect(second).toBe("light");
    expect(documentElement.classList.contains("dark")).toBe(false);
    expect(documentElement.style.colorScheme).toBe("light");
    expect(store.get("theme")).toBe("light");
  });
});
