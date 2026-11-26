import {
  AlertTriangle,
  CheckCircle2,
  Clock,
  HelpCircle,
  PauseCircle,
  XCircle,
} from "lucide-react";
import { cn } from "@/lib/utils";
import {
  resolveStatusLabel,
  resolveStatusTone,
  type StatusTone,
} from "@/lib/domain-labels";

export interface StatusBadgeProps {
  status: string | null | undefined;
  label?: string;
  tone?: StatusTone;
  className?: string;
}

export function StatusBadge({
  status,
  label,
  tone,
  className,
}: StatusBadgeProps) {
  const resolvedTone = tone ?? resolveStatusTone(status);
  const resolvedLabel = label ?? resolveStatusLabel(status);
  const normalizedKey = String(status ?? "")
    .trim()
    .toLowerCase()
    .replaceAll("-", "_");

  const toneClasses: Record<StatusTone, string> = {
    success: "bg-success text-success-foreground border-transparent",
    destructive: "bg-destructive text-destructive-foreground border-transparent",
    warning: "bg-warning text-warning-foreground border-transparent",
    brand: "bg-brand-muted text-brand border-transparent",
    neutral: "bg-muted text-muted-foreground border-border",
  };

  const renderIcon = () => {
    if (normalizedKey === "paused" || normalizedKey === "suspended") {
      return <PauseCircle className="size-3.5 shrink-0" strokeWidth={2} aria-hidden="true" />;
    }
    if (normalizedKey === "unknown" || normalizedKey === "outcome_unknown") {
      return <HelpCircle className="size-3.5 shrink-0" strokeWidth={2} aria-hidden="true" />;
    }
    if (resolvedTone === "success") {
      return <CheckCircle2 className="size-3.5 shrink-0" strokeWidth={2} aria-hidden="true" />;
    }
    if (resolvedTone === "destructive") {
      return <XCircle className="size-3.5 shrink-0" strokeWidth={2} aria-hidden="true" />;
    }
    if (resolvedTone === "warning") {
      return <Clock className="size-3.5 shrink-0" strokeWidth={2} aria-hidden="true" />;
    }
    return <AlertTriangle className="size-3.5 shrink-0" strokeWidth={2} aria-hidden="true" />;
  };

  return (
    <span
      title={status ?? undefined}
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-medium whitespace-nowrap",
        toneClasses[resolvedTone],
        className,
      )}
    >
      {renderIcon()}
      <span>{resolvedLabel}</span>
    </span>
  );
}
