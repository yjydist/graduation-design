import { useState } from "react";
import { Moon, Sun } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { readCurrentTheme, toggleTheme, type ThemeMode } from "@/lib/theme";

export function ThemeToggle() {
  const [theme, setTheme] = useState<ThemeMode>(() => readCurrentTheme());

  const handleToggle = () => {
    const next = toggleTheme();
    setTheme(next);
  };

  const label = theme === "dark" ? "切换至浅色模式" : "切换至暗色模式";

  return (
    <Tooltip>
      <TooltipTrigger
        render={
          <Button
            type="button"
            variant="ghost"
            size="icon"
            onClick={handleToggle}
            aria-label={label}
            className="size-9 rounded-lg focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background"
          />
        }
      >
        {theme === "dark" ? (
          <Sun className="size-4" strokeWidth={2} aria-hidden="true" />
        ) : (
          <Moon className="size-4" strokeWidth={2} aria-hidden="true" />
        )}
      </TooltipTrigger>
      <TooltipContent>{label}</TooltipContent>
    </Tooltip>
  );
}
