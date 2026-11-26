import { useMemo } from "react";
import {
  BrowserRouter,
  Navigate,
  Route,
  Routes,
  useNavigate,
} from "react-router-dom";
import {
  Building2,
  ListChecks,
  MessageSquare,
  Scale,
  ShieldAlert,
} from "lucide-react";
import { AppShell } from "@/components/app/AppShell";
import type { NavItemConfig } from "@/components/app/Sidebar";
import { EmptyState } from "@/components/patterns/EmptyState";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Toaster } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { AuthProvider, useAuth } from "@/features/auth/AuthContext";
import { LoginPage } from "@/features/auth/LoginPage";
import { DecisionsAuditPage } from "@/features/evidence/DecisionsAuditPage";
import { RunEvidencePanel } from "@/features/evidence/RunEvidencePanel";
import { ManagementPage } from "@/features/management/ManagementPage";
import { ChatPage } from "@/features/procurement/ChatPage";
import { RunDetailPage } from "@/features/procurement/RunDetailPage";
import { RunsListPage } from "@/features/procurement/RunsListPage";
import { resolveRoleLabel } from "@/lib/domain-labels";

function ForbiddenPage({ homePath }: { homePath: string }) {
  const navigate = useNavigate();
  return (
    <EmptyState
      icon={<ShieldAlert className="size-5" strokeWidth={2} />}
      title="当前账号无权访问此页面"
      description="操作权限由本域会话角色与链上登记决定。请返回当前账号获准使用的工作区。"
      action={
        <Button
          type="button"
          size="sm"
          onClick={() => navigate(homePath, { replace: true })}
          className="rounded-lg"
        >
          返回可用页面
        </Button>
      }
    />
  );
}

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
            <Route
              path="/runs/:runId"
              element={
                <RunDetailPage
                  renderEvidence={({ run, evidence, loading, error, onRetry }) => (
                    <RunEvidencePanel
                      evidence={evidence}
                      loading={loading}
                      error={error}
                      onRetry={onRetry}
                      taskMaxAmountMinor={
                        evidence?.delegations.find((d) => d.parentId && d.parentId !== d.rootId)
                          ?.maxAmountMinor ??
                        evidence?.delegations[0]?.maxAmountMinor ??
                        run.task.maxAmountMinor
                      }
                    />
                  )}
                />
              }
            />
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
    <BrowserRouter>
      <TooltipProvider>
        <AuthProvider>
          <WorkbenchRouter />
          <Toaster position="bottom-right" />
        </AuthProvider>
      </TooltipProvider>
    </BrowserRouter>
  );
}
