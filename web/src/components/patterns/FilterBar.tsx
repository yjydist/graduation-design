import type { ReactNode } from "react";
import { Search, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";

export interface FilterBarProps {
  searchValue?: string;
  onSearchChange?: (value: string) => void;
  searchPlaceholder?: string;
  searchAriaLabel?: string;
  children?: ReactNode;
  hasActiveFilters?: boolean;
  onReset?: () => void;
  className?: string;
}

export function FilterBar({
  searchValue,
  onSearchChange,
  searchPlaceholder = "按编号或关键词筛选",
  searchAriaLabel = "搜索筛选",
  children,
  hasActiveFilters = false,
  onReset,
  className,
}: FilterBarProps) {
  return (
    <div
      className={cn(
        "mb-4 flex flex-col gap-3 sm:flex-row sm:flex-wrap sm:items-center",
        className,
      )}
    >
      {onSearchChange !== undefined && (
        <div className="relative w-full sm:max-w-xs">
          <Search
            className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground"
            strokeWidth={2}
            aria-hidden="true"
          />
          <Input
            type="search"
            value={searchValue ?? ""}
            onChange={(event) => onSearchChange(event.target.value)}
            placeholder={searchPlaceholder}
            aria-label={searchAriaLabel}
            className="h-9 rounded-lg pl-9"
          />
        </div>
      )}

      {children && (
        <div className="flex flex-wrap items-center gap-2">{children}</div>
      )}

      {hasActiveFilters && onReset && (
        <Button
          type="button"
          variant="ghost"
          size="sm"
          onClick={onReset}
          className="h-9 gap-1.5 rounded-lg text-muted-foreground hover:text-foreground"
        >
          <X className="size-4" strokeWidth={2} aria-hidden="true" />
          <span>清除筛选</span>
        </Button>
      )}
    </div>
  );
}
