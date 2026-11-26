// Customized from shadcn base-vega: use solid bg-card surface, token focus ring,
// and border-destructive without shadow-xs or opacity-synthesized dark surfaces
// per web/AGENTS.md sections 1, 3.1, and 8.1.
import * as React from "react"
import { cn } from "@/lib/utils"

function Textarea({ className, ...props }: React.ComponentProps<"textarea">) {
  return (
    <textarea
      data-slot="textarea"
      className={cn(
        "flex field-sizing-content min-h-16 w-full rounded-lg border border-input bg-card px-3 py-2 text-base text-foreground transition-colors duration-150 outline-none placeholder:text-muted-foreground hover:border-ring focus-visible:border-ring focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background disabled:cursor-not-allowed disabled:opacity-50 aria-invalid:border-destructive md:text-sm",
        className
      )}
      {...props}
    />
  )
}

export { Textarea }
