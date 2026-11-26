import { LogOut, Menu, Loader2, User } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { DomainBadge } from "@/components/app/DomainBadge";
import { ThemeToggle } from "@/components/app/ThemeToggle";

export interface TopbarProps {
  domainId: "A" | "B" | "C" | null;
  ready: boolean | null;
  roleLabel: string;
  subjectId: string;
  loggingOut: boolean;
  onLogout: () => void;
  onOpenMobileMenu: () => void;
}

export function Topbar({
  domainId,
  ready,
  roleLabel,
  subjectId,
  loggingOut,
  onLogout,
  onOpenMobileMenu,
}: TopbarProps) {
  return (
    <header className="sticky top-0 z-30 flex h-14 shrink-0 items-center justify-between gap-3 border-b border-border bg-background px-4 md:px-6 lg:px-8">
      <div className="flex min-w-0 items-center gap-2.5">
        <Button
          type="button"
          variant="ghost"
          size="icon"
          onClick={onOpenMobileMenu}
          aria-label="打开导航菜单"
          className="size-9 rounded-lg md:hidden focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background"
        >
          <Menu className="size-5" strokeWidth={2} aria-hidden="true" />
        </Button>
        <DomainBadge domainId={domainId} ready={ready} />
      </div>

      <div className="flex shrink-0 items-center gap-2">
        <ThemeToggle />
        <DropdownMenu>
          <DropdownMenuTrigger
            render={
              <Button
                type="button"
                variant="outline"
                size="sm"
                className="h-9 max-w-44 gap-2 rounded-lg px-3 focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background"
              />
            }
          >
            <User className="size-4 shrink-0 text-muted-foreground" strokeWidth={2} aria-hidden="true" />
            <span className="truncate text-sm font-medium">{roleLabel}</span>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-72 rounded-xl border border-border bg-popover shadow-e2">
            <DropdownMenuLabel className="space-y-1 py-2">
              <p className="text-sm font-semibold text-popover-foreground">
                {roleLabel}
              </p>
              <p className="break-all font-mono text-xs font-normal text-muted-foreground">
                {subjectId}
              </p>
            </DropdownMenuLabel>
            <DropdownMenuSeparator />
            <DropdownMenuItem
              disabled={loggingOut}
              onClick={onLogout}
              className="gap-2 text-destructive focus:text-destructive"
            >
              {loggingOut ? (
                <Loader2 className="size-4 animate-spin" aria-hidden="true" />
              ) : (
                <LogOut className="size-4" strokeWidth={2} aria-hidden="true" />
              )}
              <span>{loggingOut ? "正在退出…" : "退出登录"}</span>
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </header>
  );
}
