import { AlertCircle, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

export interface ErrorStateProps {
  title?: string;
  message: string;
  code?: string;
  requestId?: string;
  onRetry?: () => void;
  retrying?: boolean;
  className?: string;
}

export function ErrorState({
  title = "数据加载失败",
  message,
  code,
  requestId,
  onRetry,
  retrying = false,
  className,
}: ErrorStateProps) {
  return (
    <div
      role="alert"
      className={cn(
        "flex flex-col items-start gap-4 rounded-xl border border-destructive bg-card p-5 text-card-foreground",
        className,
      )}
    >
      <div className="flex items-start gap-3">
        <span
          className="mt-0.5 flex size-8 shrink-0 items-center justify-center rounded-full bg-destructive text-destructive-foreground"
          aria-hidden="true"
        >
          <AlertCircle className="size-4" strokeWidth={2} />
        </span>
        <div className="min-w-0 space-y-1">
          <h2 className="text-base font-semibold text-foreground">{title}</h2>
          <p className="text-sm leading-6 text-muted-foreground">{message}</p>
          {(code || requestId) && (
            <p className="break-all font-mono text-xs text-muted-foreground">
              {[code ? `错误码: ${code}` : null, requestId ? `请求 ID: ${requestId}` : null]
                .filter(Boolean)
                .join(" · ")}
            </p>
          )}
        </div>
      </div>

      {onRetry && (
        <Button
          type="button"
          variant="outline"
          size="sm"
          disabled={retrying}
          onClick={onRetry}
          className="gap-1.5 rounded-lg"
        >
          <RefreshCw
            className={cn("size-4", retrying && "animate-spin")}
            strokeWidth={2}
            aria-hidden="true"
          />
          <span>{retrying ? "正在重试…" : "重新加载"}</span>
        </Button>
      )}
    </div>
  );
}
