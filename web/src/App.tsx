import { useMemo } from "react";
import { CSPProvider } from "@base-ui/react/csp-provider";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { Building2, ListChecks, MessageSquare, Scale } from "lucide-react";
import { AppShell } from "@/components/app/AppShell";
import type { NavItemConfig } from "@/components/app/Sidebar";
import { Skeleton } from "@/components/ui/skeleton";
import { Toaster } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { AuthProvider, useAuth } from "@/features/auth/AuthContext";
import { ChatPage } from "@/pages/ChatPage";
import { DecisionsAuditPage } from "@/pages/DecisionsAuditPage";
import { ForbiddenPage } from "@/pages/ForbiddenPage";
import { LoginPage } from "@/pages/LoginPage";
import { ManagementPage } from "@/pages/ManagementPage";
import { RunDetailPage } from "@/pages/RunDetailPage";
import { RunsListPage } from "@/pages/RunsListPage";
import { resolveRoleLabel } from "@/lib/domain-labels";

function WorkbenchRouter() {
  const {
    domainId,
    ready,
    session,
    initializing,
    loggingOut,
    logout,
    hasAction,
  } = useAuth();

  const navItems = useMemo<NavItemConfig[]>(() => {
    const items: NavItemConfig[] = [];
    if (hasAction("managePurchasingAuthority")) {
      items.push({
        to: "/management",
        label: "本域管理",
        icon: Building2,
        group: "域治理",
      });
    }
    if (hasAction("procure")) {
      items.push(
        {
          to: "/chat",
          label: "采购对话",
          icon: MessageSquare,
          group: "跨域采购",
        },
        {
          to: "/runs",
          label: "采购运行",
          icon: ListChecks,
          group: "跨域采购",
        },
      );
    }
    if (hasAction("auditDecisions")) {
      items.push({
        to: "/decisions",
        label: "决策审计",
        icon: Scale,
        group: "合规审计",
      });
    }
    return items;
  }, [hasAction]);

  const homePath = useMemo(() => {
    if (hasAction("procure")) return "/runs";
    if (hasAction("managePurchasingAuthority")) return "/management";
    if (hasAction("auditDecisions")) return "/decisions";
    return "/management";
  }, [hasAction]);

  if (initializing) {
    return (
      <div className="flex min-h-dvh flex-col items-center justify-center gap-4 bg-background p-6">
        <Skeleton className="h-8 w-48" />
        <Skeleton className="h-4 w-64" />
      </div>
    );
  }

  if (!session) {
    return (
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="*" element={<Navigate to="/login" replace />} />
      </Routes>
    );
  }

  return (
    <AppShell
      navItems={navItems}
      domainId={domainId}
      ready={ready}
      roleLabel={resolveRoleLabel(session.role)}
      subjectId={session.subjectId}
      loggingOut={loggingOut}
      onLogout={() => void logout()}
    >
      <Routes>
        <Route path="/" element={<Navigate to={homePath} replace />} />
        <Route path="/login" element={<Navigate to={homePath} replace />} />

        {hasAction("managePurchasingAuthority") && (
          <>
            <Route path="/management" element={<ManagementPage />} />
            <Route
              path="/management/:operationId"
              element={<ManagementPage />}
            />
          </>
        )}

        {hasAction("procure") && (
          <>
            <Route path="/chat" element={<ChatPage />} />
            <Route path="/chat/:draftId" element={<ChatPage />} />
            <Route path="/runs" element={<RunsListPage />} />
            <Route path="/runs/:runId" element={<RunDetailPage />} />
          </>
        )}

        {hasAction("auditDecisions") && (
          <>
            <Route path="/decisions" element={<DecisionsAuditPage />} />
            <Route
              path="/decisions/:decisionId"
              element={<DecisionsAuditPage />}
            />
          </>
        )}

        <Route path="*" element={<ForbiddenPage homePath={homePath} />} />
      </Routes>
    </AppShell>
  );
}

export function App() {
  return (
    <CSPProvider disableStyleElements>
      <BrowserRouter>
        <TooltipProvider>
          <AuthProvider>
            <WorkbenchRouter />
            <Toaster />
          </AuthProvider>
        </TooltipProvider>
      </BrowserRouter>
    </CSPProvider>
  );
}
