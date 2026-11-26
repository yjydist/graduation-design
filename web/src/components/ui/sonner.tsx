import { useEffect, useState } from "react";
import { Toaster as Sonner, type ToasterProps } from "sonner";
import {
  CircleCheckIcon,
  InfoIcon,
  Loader2Icon,
  OctagonXIcon,
  TriangleAlertIcon,
} from "lucide-react";
import { readCurrentTheme, type ThemeMode } from "@/lib/theme";

function useDomTheme(): ThemeMode {
  const [theme, setTheme] = useState<ThemeMode>(() => readCurrentTheme());

  useEffect(() => {
    const observer = new MutationObserver(() => {
      setTheme(readCurrentTheme());
    });
    observer.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ["class"],
    });
    return () => observer.disconnect();
  }, []);

  return theme;
}

function useIsMobileViewport(): boolean {
  const [isMobile, setIsMobile] = useState<boolean>(() => {
    if (typeof window === "undefined" || typeof window.matchMedia !== "function") {
      return false;
    }
    return window.matchMedia("(max-width: 767px)").matches;
  });

  useEffect(() => {
    if (typeof window === "undefined" || typeof window.matchMedia !== "function") {
      return;
    }
    const media = window.matchMedia("(max-width: 767px)");
    const onChange = (event: MediaQueryListEvent) => setIsMobile(event.matches);
    setIsMobile(media.matches);
    media.addEventListener("change", onChange);
    return () => media.removeEventListener("change", onChange);
  }, []);

  return isMobile;
}

const Toaster = ({ position, ...props }: ToasterProps) => {
  const theme = useDomTheme();
  const isMobile = useIsMobileViewport();
  const resolvedPosition = position ?? (isMobile ? "top-center" : "bottom-right");

  return (
    <Sonner
      theme={theme}
      position={resolvedPosition}
      visibleToasts={3}
      closeButton
      className="toaster group z-toast"
      icons={{
        success: <CircleCheckIcon className="size-4 text-success" />,
        info: <InfoIcon className="size-4 text-brand" />,
        warning: <TriangleAlertIcon className="size-4 text-warning-text" />,
        error: <OctagonXIcon className="size-4 text-destructive" />,
        loading: <Loader2Icon className="size-4 animate-spin" />,
      }}
      toastOptions={{
        classNames: {
          toast:
            "rounded-xl border border-border bg-popover text-popover-foreground shadow-e2 text-sm",
          description: "text-xs text-muted-foreground",
          actionButton:
            "rounded-md bg-primary text-primary-foreground text-xs font-medium",
          cancelButton:
            "rounded-md bg-secondary text-secondary-foreground text-xs font-medium",
        },
      }}
      {...props}
    />
  );
};

export { Toaster };
