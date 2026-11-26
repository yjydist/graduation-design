import { CheckCircle2, AlertTriangle, Loader2 } from "lucide-react";
import { cn } from "@/lib/utils";

export interface DomainBadgeProps {
  domainId: "A" | "B" | "C" | null;
  ready: boolean | null;
  className?: string;
}

const DOMAIN_NAMES: Record<"A" | "B" | "C", string> = {
  A: "A 域（买方）",
  B: "B 域（代理）",
  C: "C 域（卖方/网关）",
};

export function DomainBadge({ domainId, ready, className }: DomainBadgeProps) {
  const domainText = domainId ? DOMAIN_NAMES[domainId] : "本域";

  if (ready === null) {
    return (
      <span
        className={cn(
          "inline-flex items-center gap-1.5 rounded-full border border-border bg-muted px-2.5 py-1 text-xs font-medium text-muted-foreground",
          className,
        )}
        role="status"
      >
        <Loader2 className="size-3.5 animate-spin" aria-hidden="true" />
        <span>正在检查域状态</span>
      </span>
    );
  }

  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-medium",
        ready
          ? "border-border bg-card text-foreground"
          : "border-destructive bg-destructive text-destructive-foreground",
        className,
      )}
      role="status"
    >
      {ready ? (
        <CheckCircle2 className="size-3.5 text-success" aria-hidden="true" />
      ) : (
        <AlertTriangle className="size-3.5" aria-hidden="true" />
      )}
      <span>{domainText}</span>
      <span className={cn(ready ? "text-muted-foreground" : "text-destructive-foreground")}>
        {ready ? "已就绪" : "服务未就绪"}
      </span>
    </span>
  );
}
