import { useState, type ReactNode } from "react";
import { Check, Copy } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { EMPTY_PLACEHOLDER } from "@/lib/format";
import { cn } from "@/lib/utils";

export interface KeyValueItem {
  label: string;
  value: ReactNode;
  mono?: boolean;
  copyText?: string;
}

export interface KeyValueListProps {
  items: KeyValueItem[];
  columns?: 1 | 2 | 3;
  className?: string;
}

function CopyButton({ text, label }: { text: string; label: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      toast.success(`已复制${label}。`, { duration: 3000 });
      window.setTimeout(() => setCopied(false), 1800);
    } catch {
      toast.error("复制失败：浏览器未授予剪贴板权限。请手动选中复制。", {
        duration: 6000,
      });
    }
  };

  return (
    <Button
      type="button"
      variant="ghost"
      size="icon"
      onClick={() => void handleCopy()}
      aria-label={`复制${label}`}
      className="size-9 shrink-0 rounded-md text-muted-foreground hover:text-foreground"
    >
      {copied ? (
        <Check className="size-3.5 text-success" strokeWidth={2} aria-hidden="true" />
      ) : (
        <Copy className="size-3.5" strokeWidth={2} aria-hidden="true" />
      )}
    </Button>
  );
}

export function KeyValueList({
  items,
  columns = 2,
  className,
}: KeyValueListProps) {
  const gridClass = {
    1: "grid-cols-1",
    2: "grid-cols-1 sm:grid-cols-2",
    3: "grid-cols-1 sm:grid-cols-2 lg:grid-cols-3",
  }[columns];

  return (
    <dl className={cn("grid gap-4", gridClass, className)}>
      {items.map((item) => {
        const isEmpty =
          item.value === null ||
          item.value === undefined ||
          item.value === "";
        return (
          <div key={item.label} className="min-w-0 space-y-1">
            <dt className="text-xs font-medium text-muted-foreground">
              {item.label}
            </dt>
            <dd className="flex items-start justify-between gap-2 text-sm leading-6 text-foreground">
              <span
                className={cn(
                  "min-w-0 flex-1 break-all",
                  item.mono && "font-mono text-xs leading-5",
                  isEmpty && "text-muted-foreground",
                )}
              >
                {isEmpty ? EMPTY_PLACEHOLDER : item.value}
              </span>
              {!isEmpty && item.copyText && (
                <CopyButton text={item.copyText} label={item.label} />
              )}
            </dd>
          </div>
        );
      })}
    </dl>
  );
}
