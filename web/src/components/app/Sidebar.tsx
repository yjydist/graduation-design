import type { ComponentType } from "react";
import { NavLink } from "react-router-dom";
import { ShieldCheck } from "lucide-react";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";

export interface NavItemConfig {
  to: string;
  label: string;
  icon: ComponentType<{ className?: string; strokeWidth?: number }>;
  group: string;
}

export interface SidebarProps {
  items: NavItemConfig[];
  domainId: "A" | "B" | "C" | null;
  collapsed?: boolean;
  onNavigate?: () => void;
  className?: string;
}

export function Sidebar({
  items,
  domainId,
  collapsed = false,
  onNavigate,
  className,
}: SidebarProps) {
  const groups = Array.from(new Set(items.map((item) => item.group)));

  return (
    <aside
      aria-label="主导航"
      className={cn(
        "flex h-full flex-col border-r border-sidebar-border bg-sidebar text-sidebar-foreground transition-colors duration-150",
        collapsed ? "w-16" : "w-64",
        className,
      )}
    >
      <div
        className={cn(
          "flex h-14 shrink-0 items-center border-b border-sidebar-border",
          collapsed ? "justify-center px-2" : "gap-2.5 px-4",
        )}
      >
        <span className="flex size-8 shrink-0 items-center justify-center rounded-lg bg-primary text-primary-foreground">
          <ShieldCheck className="size-4" strokeWidth={2} aria-hidden="true" />
        </span>
        {!collapsed && (
          <div className="min-w-0 flex-1">
            <p className="truncate text-sm font-semibold leading-5 text-sidebar-foreground">
              跨域采购工作台
            </p>
            <p className="truncate text-xs text-muted-foreground">
              {domainId ? `${domainId} 域独立实例` : "三域同构控制台"}
            </p>
          </div>
        )}
      </div>

      <nav className="flex-1 space-y-5 overflow-y-auto px-2 py-4 pb-[env(safe-area-inset-bottom)]">
        {groups.map((group) => {
          const groupItems = items.filter((item) => item.group === group);
          return (
            <div key={group} className="space-y-1">
              {!collapsed && (
                <p className="px-3 pb-1 text-xs font-medium text-muted-foreground">
                  {group}
                </p>
              )}
              <ul className="space-y-1">
                {groupItems.map((item) => {
                  const Icon = item.icon;
                  const link = (
                    <NavLink
                      to={item.to}
                      onClick={onNavigate}
                      className={({ isActive }) =>
                        cn(
                          "relative flex h-9 items-center rounded-lg text-sm font-medium transition-colors duration-150 outline-none focus-visible:ring-2 focus-visible:ring-sidebar-ring focus-visible:ring-offset-2 focus-visible:ring-offset-sidebar",
                          collapsed ? "justify-center px-2" : "gap-2.5 px-3",
                          isActive
                            ? "bg-brand-muted text-brand"
                            : "text-sidebar-foreground hover:bg-accent hover:text-accent-foreground",
                        )
                      }
                    >
                      {({ isActive }) => (
                        <>
                          {isActive && (
                            <span
                              aria-hidden="true"
                              className="absolute inset-y-1.5 left-0 w-0.5 rounded-full bg-brand"
                            />
                          )}
                          <Icon
                            className="size-5 shrink-0"
                            strokeWidth={2}
                            aria-hidden="true"
                          />
                          {!collapsed && (
                            <span className="truncate">{item.label}</span>
                          )}
                        </>
                      )}
                    </NavLink>
                  );

                  if (collapsed) {
                    return (
                      <li key={item.to}>
                        <Tooltip>
                          <TooltipTrigger render={link} />
                          <TooltipContent side="right">
                            {item.label}
                          </TooltipContent>
                        </Tooltip>
                      </li>
                    );
                  }

                  return <li key={item.to}>{link}</li>;
                })}
              </ul>
            </div>
          );
        })}
      </nav>
    </aside>
  );
}
