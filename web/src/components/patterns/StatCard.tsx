import type { ReactNode } from "react";
import { cn } from "@/lib/utils";
import { EMPTY_PLACEHOLDER } from "@/lib/format";

export interface StatCardProps {
  label: string;
  value: string | number | null | undefined;
  hint?: string;
  hintTone?: "neutral" | "success" | "destructive" | "warning";
  icon?: ReactNode;
  mono?: boolean;
  className?: string;
}

export function StatCard({
  label,
  value,
  hint,
  hintTone = "neutral",
  icon,
  mono = false,
  className,
}: StatCardProps) {
  const displayValue =
    value === null || value === undefined || value === ""
      ? EMPTY_PLACEHOLDER
      : String(value);

  const toneClass = {
    neutral: "text-muted-foreground",
    success: "text-success",
    destructive: "text-destructive",
    warning: "text-warning-text",
  }[hintTone];

  return (
    <section
      className={cn(
        "flex flex-col justify-between gap-2 rounded-xl border border-border bg-card p-5 text-card-foreground",
        className,
      )}
    >
      <div className="flex items-center justify-between gap-2">
        <p className="text-xs font-medium text-muted-foreground">{label}</p>
        {icon && (
          <span className="text-muted-foreground" aria-hidden="true">
            {icon}
          </span>
        )}
      </div>
      <p
        className={cn(
          "truncate font-semibold tabular-nums text-card-foreground",
          mono ? "font-mono text-base" : "text-2xl",
        )}
        title={displayValue}
      >
        {displayValue}
      </p>
      {hint && <p className={cn("text-xs leading-5", toneClass)}>{hint}</p>}
    </section>
  );
}
