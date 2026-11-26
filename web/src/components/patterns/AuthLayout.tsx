import type { ReactNode } from "react";
import { ShieldCheck } from "lucide-react";
import { DomainBadge } from "@/components/app/DomainBadge";
import { ThemeToggle } from "@/components/app/ThemeToggle";

export interface AuthLayoutProps {
  domainId: "A" | "B" | "C" | null;
  ready: boolean | null;
  title: string;
  description?: string;
  children: ReactNode;
}

export function AuthLayout({
  domainId,
  ready,
  title,
  description,
  children,
}: AuthLayoutProps) {
  return (
    <div className="flex min-h-dvh flex-col bg-background text-foreground">
      <a
        href="#auth-main"
        className="sr-only focus:not-sr-only focus:fixed focus:top-3 focus:left-3 focus:z-tooltip focus:rounded-lg focus:bg-primary focus:px-4 focus:py-2 focus:text-sm focus:font-medium focus:text-primary-foreground"
      >
        跳至登录表单
      </a>
      <header className="flex h-14 items-center justify-between border-b border-border px-4 md:px-6">
        <DomainBadge domainId={domainId} ready={ready} />
        <ThemeToggle />
      </header>

      <main
        id="auth-main"
        tabIndex={-1}
        className="flex flex-1 items-center justify-center px-4 py-8 outline-none"
      >
        <section className="w-full max-w-sm rounded-xl border border-border bg-card p-6 text-card-foreground">
          <div className="mb-6 space-y-2">
            <div className="flex items-center gap-2.5">
              <span className="flex size-9 shrink-0 items-center justify-center rounded-lg bg-primary text-primary-foreground">
                <ShieldCheck className="size-5" strokeWidth={2} aria-hidden="true" />
              </span>
              <div className="min-w-0">
                <p className="text-xs font-medium text-muted-foreground">
                  跨域多智能体采购工作台
                </p>
                <h1 className="text-2xl font-semibold text-foreground">
                  {title}
                </h1>
              </div>
            </div>
            {description && (
              <p className="text-sm leading-6 text-muted-foreground">
                {description}
              </p>
            )}
          </div>
          {children}
        </section>
      </main>
    </div>
  );
}
