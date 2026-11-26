import { useState, type ReactNode } from "react";
import { Sheet, SheetContent, SheetTitle } from "@/components/ui/sheet";
import { Sidebar, type NavItemConfig } from "@/components/app/Sidebar";
import { Topbar } from "@/components/app/Topbar";

export interface AppShellProps {
  navItems: NavItemConfig[];
  domainId: "A" | "B" | "C" | null;
  ready: boolean | null;
  roleLabel: string;
  subjectId: string;
  loggingOut: boolean;
  onLogout: () => void;
  children: ReactNode;
}

export function AppShell({
  navItems,
  domainId,
  ready,
  roleLabel,
  subjectId,
  loggingOut,
  onLogout,
  children,
}: AppShellProps) {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  return (
    <div className="flex h-dvh w-full overflow-hidden bg-background text-foreground">
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:fixed focus:top-3 focus:left-3 focus:z-tooltip focus:rounded-lg focus:bg-primary focus:px-4 focus:py-2 focus:text-sm focus:font-medium focus:text-primary-foreground focus:outline-none focus:ring-2 focus:ring-ring"
      >
        跳至主内容
      </a>

      {/* Tablet collapsed rail (md..lg) */}
      <div className="hidden md:flex lg:hidden">
        <Sidebar items={navItems} domainId={domainId} collapsed />
      </div>

      {/* Desktop full sidebar (lg+) */}
      <div className="hidden lg:flex">
        <Sidebar items={navItems} domainId={domainId} />
      </div>

      {/* Mobile drawer (<768px) */}
      <Sheet open={mobileMenuOpen} onOpenChange={setMobileMenuOpen}>
        <SheetContent
          side="left"
          showCloseButton={false}
          className="w-64 p-0 pb-[env(safe-area-inset-bottom)]"
        >
          <SheetTitle className="sr-only">工作台导航菜单</SheetTitle>
          <Sidebar
            items={navItems}
            domainId={domainId}
            onNavigate={() => setMobileMenuOpen(false)}
            className="w-full border-r-0"
          />
        </SheetContent>
      </Sheet>

      <div className="flex min-w-0 flex-1 flex-col overflow-hidden">
        <Topbar
          domainId={domainId}
          ready={ready}
          roleLabel={roleLabel}
          subjectId={subjectId}
          loggingOut={loggingOut}
          onLogout={onLogout}
          onOpenMobileMenu={() => setMobileMenuOpen(true)}
        />
        <main
          id="main-content"
          tabIndex={-1}
          className="flex-1 overflow-y-auto overflow-x-hidden outline-none"
        >
          <div className="mx-auto w-full max-w-7xl px-4 py-6 md:px-6 lg:px-8 lg:py-8">
            {children}
          </div>
        </main>
      </div>
    </div>
  );
}
