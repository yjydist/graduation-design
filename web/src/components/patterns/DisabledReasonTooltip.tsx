import type { ReactNode } from "react";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";

export interface DisabledReasonTooltipProps {
  /** Explanation shown when the wrapped control is disabled; null renders children directly. */
  reason: string | null;
  children: ReactNode;
  className?: string;
}

/**
 * Wraps a disabled interactive control in a keyboard-focusable tooltip trigger so
 * both pointer and keyboard users receive an explanation of why the action is unavailable.
 */
export function DisabledReasonTooltip({
  reason,
  children,
  className,
}: DisabledReasonTooltipProps) {
  if (!reason) {
    return <>{children}</>;
  }
  return (
    <Tooltip>
      <TooltipTrigger
        render={
          <span
            tabIndex={0}
            className={cn(
              "inline-flex rounded-lg outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background",
              className,
            )}
          />
        }
      >
        {children}
      </TooltipTrigger>
      <TooltipContent>{reason}</TooltipContent>
    </Tooltip>
  );
}
