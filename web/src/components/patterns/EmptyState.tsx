import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

export interface EmptyStateProps {
  icon: ReactNode;
  title: string;
  description: string;
  headingAs?: "h1" | "h2";
  action?: ReactNode;
  secondaryAction?: ReactNode;
  className?: string;
}

export function EmptyState({
  icon,
  title,
  description,
  headingAs = "h2",
  action,
  secondaryAction,
  className,
}: EmptyStateProps) {
  const Heading = headingAs;
  return (
    <div
      className={cn(
        "mx-auto flex max-w-sm flex-col items-center justify-center px-4 py-12 text-center",
        className,
      )}
    >
      <div
        className="mb-4 flex size-10 items-center justify-center rounded-full bg-muted text-muted-foreground"
        aria-hidden="true"
      >
        {icon}
      </div>
      <Heading className="text-base font-semibold text-foreground">
        {title}
      </Heading>
      <p className="mt-1.5 text-sm leading-6 text-muted-foreground">
        {description}
      </p>
      {(action || secondaryAction) && (
        <div className="mt-5 flex flex-wrap items-center justify-center gap-3">
          {action}
          {secondaryAction}
        </div>
      )}
    </div>
  );
}
