import { useCallback, useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import {
  AlertTriangle,
  Bot,
  Cpu,
  PauseCircle,
  PlayCircle,
  RefreshCw,
  Terminal,
} from "lucide-react";
import { toast } from "sonner";
import { classifyToolTrace } from "@/api/agent";
import { backendApi } from "@/api/backend";
import {
  formatApiError,
  getOrCreateIdempotencyKey,
  type FormattedApiError,
} from "@/api/http";
import type { Run, RunEvidence, RunStep, ToolTrace } from "@/api/types";
import { ConfirmDialog } from "@/components/patterns/ConfirmDialog";
import { EmptyState } from "@/components/patterns/EmptyState";
import { ErrorState } from "@/components/patterns/ErrorState";
import { KeyValueList } from "@/components/patterns/KeyValueList";
import { PageHeader } from "@/components/patterns/PageHeader";
import { StatusBadge } from "@/components/patterns/StatusBadge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useAuth } from "@/features/auth/AuthContext";
import { RunEvidencePanel } from "@/features/evidence/RunEvidencePanel";
import { resolveModeLabel, resolveStageLabel } from "@/lib/domain-labels";
import {
  EMPTY_PLACEHOLDER,
  formatInteger,
  formatMinorAmount,
  formatUnixSeconds,
  truncateMiddle,
} from "@/lib/format";

const ACTIVE_STEP_STATUSES = new Set([
  "pending",
  "accepted",
  "submitted",
  "running",
  "waiting",
]);

/**
 * Determines whether the run detail view should keep background polling active.
 * Polls only when the run is non-terminal (PENDING / OUTCOME_UNKNOWN) or has an
 * in-flight ledger step (e.g. a newly submitted G1 suspend/resume operation),
 * stopping automatically once finalized or when the backend returns an error.
 */
// eslint-disable-next-line react-refresh/only-export-components
export function shouldPollRun(run: Run | null, hasError: boolean): boolean {
  if (!run || hasError) {
    return false;
  }
  if (run.status === "PENDING" || run.status === "OUTCOME_UNKNOWN") {
    return true;
  }
  return run.steps.some((step) =>
    ACTIVE_STEP_STATUSES.has(step.status.trim().toLowerCase()),
  );
}

function RunStepsList({ steps }: { steps: RunStep[] }) {
  if (!steps.length) {
    return (
      <p className="py-4 text-sm text-muted-foreground">
        尚未产生链上登记或交付步骤，请稍候自动刷新。
      </p>
    );
  }

  return (
    <ol className="space-y-3">
      {steps.map((step, index) => (
        <li
          key={`${step.stage}-${step.at}-${index}`}
          className="space-y-3 rounded-lg border border-border bg-background p-4"
        >
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <span className="text-sm font-semibold text-foreground">
                {resolveStageLabel(step.stage)}
              </span>
              <span className="text-xs tabular-nums text-muted-foreground">
                {formatUnixSeconds(step.at)}
              </span>
            </div>
            <StatusBadge status={step.status} />
          </div>

          <KeyValueList
            columns={2}
            items={[
              ...(step.operationId
                ? [
                    {
                      label: "操作 ID",
                      value: step.operationId,
                      mono: true,
                      copyText: step.operationId,
                    },
                  ]
                : []),
              ...(step.txId
                ? [
                    {
                      label: "原交易 txId",
                      value: step.txId,
                      mono: true,
                      copyText: step.txId,
                    },
                  ]
                : []),
              ...(step.grantId
                ? [
                    {
                      label: "委托 ID",
                      value: step.grantId,
                      mono: true,
                      copyText: step.grantId,
                    },
                  ]
                : []),
              ...(step.validationCode
                ? [
                    {
                      label: "入块校验码",
                      value: step.validationCode,
                      mono: true,
                    },
                  ]
                : []),
              ...(step.code
                ? [{ label: "结果码", value: step.code, mono: true }]
                : []),
            ]}
          />
        </li>
      ))}
    </ol>
  );
}

function ToolTracesList({ traces }: { traces: ToolTrace[] | null }) {
  if (!traces || traces.length === 0) {
    return (
      <EmptyState
        icon={<Terminal className="size-5" strokeWidth={2} />}
        title="暂无工具调用轨迹"
        description="当 A1 转委托与 B1 发起询价、下单或后台自动核账后，已脱敏轨迹将实时呈现在此处。"
      />
    );
  }

  return (
    <ol className="space-y-3">
      {traces.map((trace, index) => {
        const info = classifyToolTrace(trace);
        const facts = [
          {
            label: "调用来源",
            value:
              info.originKind === "service"
                ? "服务调用（step: 0，域间 HTTP / 探针 / 自动核账）"
                : `模型轮次（step: ${trace.step}）`,
          },
          {
            label: "耗时",
            value: `${formatInteger(trace.durationMs)} ms`,
          },
          ...(info.grantId
            ? [
                {
                  label: "原委托 ID（grantId）",
                  value: info.grantId,
                  mono: true,
                  copyText: info.grantId,
                },
              ]
            : []),
          ...(info.actionId
            ? [
                {
                  label: "原意图 ID（actionId）",
                  value: info.actionId,
                  mono: true,
                  copyText: info.actionId,
                },
              ]
            : []),
          ...(info.decisionId
            ? [
                {
                  label: "原决定 ID（decisionId）",
                  value: info.decisionId,
                  mono: true,
                  copyText: info.decisionId,
                },
              ]
            : []),
          ...(info.operationId
            ? [
                {
                  label: "操作 ID",
                  value: info.operationId,
                  mono: true,
                  copyText: info.operationId,
                },
              ]
            : []),
          ...(info.txId
            ? [
                {
                  label: "原交易 txId",
                  value: info.txId,
                  mono: true,
                  copyText: info.txId,
                },
              ]
            : []),
          ...(info.quoteId
            ? [
                {
                  label: "报价 ID",
                  value: info.quoteId,
                  mono: true,
                  copyText: info.quoteId,
                },
              ]
            : []),
          ...(info.orderId
            ? [
                {
                  label: "订单 ID",
                  value: info.orderId,
                  mono: true,
                  copyText: info.orderId,
                },
              ]
            : []),
          ...(info.totalAmountMinor !== undefined
            ? [
                {
                  label: "涉及金额",
                  value: formatMinorAmount(info.totalAmountMinor),
                },
              ]
            : []),
          ...(info.errorCode
            ? [{ label: "错误码", value: info.errorCode, mono: true }]
            : []),
          ...(info.code
            ? [{ label: "结果码", value: info.code, mono: true }]
            : []),
          ...(info.provider
            ? [{ label: "模型协议", value: info.provider }]
            : []),
          ...(info.requestedModel
            ? [
                {
                  label: "请求模型",
                  value: info.requestedModel,
                  mono: true,
                },
              ]
            : []),
          ...(info.responseModel
            ? [
                {
                  label: "返回模型",
                  value: info.responseModel,
                  mono: true,
                },
              ]
            : []),
        ];

        return (
          <li
            key={`${trace.step}-${trace.toolName}-${index}`}
            className="space-y-3 rounded-lg border border-border bg-background p-4"
          >
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex flex-wrap items-center gap-2">
                <Badge
                  variant={
                    info.originKind === "service" ? "secondary" : "outline"
                  }
                  className="gap-1 text-xs"
                >
                  {info.originKind === "service" ? (
                    <Cpu className="size-3.5" aria-hidden="true" />
                  ) : (
                    <Bot className="size-3.5 text-brand" aria-hidden="true" />
                  )}
                  <span>{info.originLabel}</span>
                </Badge>
                <span className="font-mono text-sm font-semibold text-foreground">
                  {info.displayName}
                </span>
              </div>
              <StatusBadge status={info.displayStatus} />
            </div>

            {info.isOutcomeUnknown && (
              <div
                role="status"
                className="flex items-start gap-2 rounded-lg border border-warning bg-muted px-3 py-2 text-xs leading-5 text-warning-text"
              >
                <AlertTriangle
                  className="mt-0.5 size-4 shrink-0"
                  aria-hidden="true"
                />
                <span>
                  业务结果未知（OUTCOME_UNKNOWN / UNKNOWN）：请依据下方原委托 ID、意图 ID 与决定 ID 核对后台自动核账与 C 网关最终状态。
                </span>
              </div>
            )}

            <KeyValueList columns={2} items={facts} />
          </li>
        );
      })}
    </ol>
  );
}

export function RunDetailPage() {
  const { runId } = useParams<{ runId: string }>();
  const { session } = useAuth();

  const [run, setRun] = useState<Run | null>(null);
  const [runLoading, setRunLoading] = useState(true);
  const [runError, setRunError] = useState<FormattedApiError | null>(null);

  const [evidence, setEvidence] = useState<RunEvidence | null>(null);
  const [evidenceLoading, setEvidenceLoading] = useState(true);
  const [evidenceError, setEvidenceError] = useState<FormattedApiError | null>(
    null,
  );

  const [pendingAction, setPendingAction] = useState<
    "suspend" | "resume" | null
  >(null);
  const [actionLoading, setActionLoading] = useState(false);

  const loadAll = useCallback(
    async (silent = false) => {
      if (!runId) return;
      if (!silent) {
        setRunLoading(true);
        setEvidenceLoading(true);
      }
      const [runRes, evRes] = await Promise.allSettled([
        backendApi.getRun(runId),
        backendApi.getRunEvidence(runId),
      ]);

      if (runRes.status === "fulfilled") {
        setRun(runRes.value);
        setRunError(null);
      } else {
        setRunError(formatApiError(runRes.reason));
      }
      setRunLoading(false);

      if (evRes.status === "fulfilled") {
        setEvidence(evRes.value);
        setEvidenceError(null);
      } else {
        setEvidenceError(formatApiError(evRes.reason));
      }
      setEvidenceLoading(false);
    },
    [runId],
  );

  useEffect(() => {
    void loadAll(false);
  }, [loadAll]);

  const pollingEnabled = shouldPollRun(run, Boolean(runError));

  useEffect(() => {
    if (!runId || !pollingEnabled) return;
    const timer = window.setInterval(() => {
      void loadAll(true);
    }, 2500);
    return () => window.clearInterval(timer);
  }, [runId, pollingEnabled, loadAll]);

  const handleGrantAction = async () => {
    if (!run || !session || !pendingAction) return;
    setActionLoading(true);
    try {
      const idempotencyKey = getOrCreateIdempotencyKey(
        session.domainId,
        session.subjectId,
        pendingAction,
        run.runId,
        run.grantRevision ?? 1,
      );
      const updated =
        pendingAction === "suspend"
          ? await backendApi.suspendRunGrant(run.runId, idempotencyKey)
          : await backendApi.resumeRunGrant(run.runId, idempotencyKey);
      setRun(updated);
      setPendingAction(null);
      toast.success(
        pendingAction === "suspend"
          ? "已提交暂停 G1 委托操作，正在等待链上确认。"
          : "已提交恢复 G1 委托操作，正在等待链上确认。",
        { duration: 3000 },
      );
      void loadAll(true);
    } catch (err) {
      const formatted = formatApiError(err);
      toast.error(
        pendingAction === "suspend" ? "暂停 G1 失败" : "恢复 G1 失败",
        {
          description: formatted.message,
          duration: 6000,
        },
      );
    } finally {
      setActionLoading(false);
    }
  };

  const allowedActions = run?.allowedActions ?? [];
  const canSuspend = allowedActions.includes("suspend");
  const canResume = allowedActions.includes("resume");

  return (
    <div className="space-y-6">
      <PageHeader
        title="采购运行详情"
        description={
          run
            ? `任务 ${truncateMiddle(run.taskId, 12, 8)} · ${run.task.productId} × ${run.task.quantity}`
            : "核对运行状态、链上步骤、已脱敏工具轨迹与五类业务证据。"
        }
        breadcrumbs={[
          { label: "采购运行", to: "/runs" },
          { label: runId ? truncateMiddle(runId, 10, 8) : "运行详情" },
        ]}
        actions={
          <>
            <Button
              type="button"
              variant="outline"
              size="sm"
              disabled={runLoading}
              onClick={() => void loadAll(false)}
              className="h-9 gap-1.5 rounded-lg"
            >
              <RefreshCw
                className={`size-4 ${runLoading ? "animate-spin" : ""}`}
                strokeWidth={2}
                aria-hidden="true"
              />
              <span>立即刷新</span>
            </Button>
            {canSuspend && (
              <Button
                type="button"
                variant="destructive"
                size="sm"
                onClick={() => setPendingAction("suspend")}
                className="h-9 gap-1.5 rounded-lg"
              >
                <PauseCircle
                  className="size-4"
                  strokeWidth={2}
                  aria-hidden="true"
                />
                <span>暂停 G1</span>
              </Button>
            )}
            {canResume && (
              <Button
                type="button"
                size="sm"
                onClick={() => setPendingAction("resume")}
                className="h-9 gap-1.5 rounded-lg"
              >
                <PlayCircle
                  className="size-4"
                  strokeWidth={2}
                  aria-hidden="true"
                />
                <span>恢复 G1</span>
              </Button>
            )}
          </>
        }
      />

      {runLoading ? (
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
          <div className="space-y-4 lg:col-span-8">
            <Skeleton className="h-10 w-64" />
            <Skeleton className="h-64 w-full rounded-xl" />
          </div>
          <div className="space-y-4 lg:col-span-4">
            <Skeleton className="h-56 w-full rounded-xl" />
            <Skeleton className="h-56 w-full rounded-xl" />
          </div>
        </div>
      ) : runError || !run ? (
        <ErrorState
          title="无法加载采购运行详情"
          message={runError?.message ?? "未找到对应采购运行记录。"}
          code={runError?.code}
          requestId={runError?.requestId}
          onRetry={() => void loadAll(false)}
        />
      ) : (
        <>
          {run.status === "OUTCOME_UNKNOWN" && (
            <div
              role="alert"
              className="flex items-start gap-3 rounded-xl border border-warning bg-card p-4 text-sm"
            >
              <AlertTriangle
                className="mt-0.5 size-5 shrink-0 text-warning-text"
                strokeWidth={2}
                aria-hidden="true"
              />
              <div className="space-y-1">
                <p className="font-semibold text-foreground">
                  当前业务结果未知（OUTCOME_UNKNOWN）
                </p>
                <p className="text-xs leading-5 text-muted-foreground">
                  跨域请求在超时窗口内未取得终态响应。请结合下方工具轨迹中的原业务 ID（grantId、actionId、decisionId）与五类业务证据核对 C 网关实际定案。
                </p>
              </div>
            </div>
          )}

          <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
            {/* Primary 2/3 area */}
            <div className="space-y-6 lg:col-span-8">
              <Tabs defaultValue="evidence" className="space-y-4">
                <TabsList className="flex h-auto w-full flex-wrap justify-start gap-1 sm:w-fit">
                  <TabsTrigger value="evidence">五类业务证据</TabsTrigger>
                  <TabsTrigger value="traces">
                    工具轨迹（{run.traces?.length ?? 0}）
                  </TabsTrigger>
                  <TabsTrigger value="steps">
                    链上步骤（{run.steps.length}）
                  </TabsTrigger>
                </TabsList>

                <TabsContent value="evidence">
                  <RunEvidencePanel
                    evidence={evidence}
                    loading={evidenceLoading}
                    error={evidenceError}
                    onRetry={() => void loadAll(false)}
                    taskMaxAmountMinor={run.task.maxAmountMinor}
                  />
                </TabsContent>

                <TabsContent value="traces">
                  <Card>
                    <CardHeader>
                      <CardTitle className="text-base font-semibold">
                        已脱敏工具与服务调用轨迹
                      </CardTitle>
                      <CardDescription className="text-sm text-muted-foreground">
                        清晰区分 step 0（域间 HTTP、探针与后台核账服务调用）与 step ≥ 1（智能体模型推理轮次）。
                      </CardDescription>
                    </CardHeader>
                    <CardContent>
                      <ToolTracesList traces={run.traces} />
                    </CardContent>
                  </Card>
                </TabsContent>

                <TabsContent value="steps">
                  <Card>
                    <CardHeader>
                      <CardTitle className="text-base font-semibold">
                        链上登记与委托交付步骤
                      </CardTitle>
                      <CardDescription className="text-sm text-muted-foreground">
                        追踪任务登记、G0 / G1 签发交付及暂停/恢复委托的 Fabric 交易确认记录。
                      </CardDescription>
                    </CardHeader>
                    <CardContent>
                      <RunStepsList steps={run.steps} />
                    </CardContent>
                  </Card>
                </TabsContent>
              </Tabs>
            </div>

            {/* Secondary 1/3 metadata rail */}
            <aside className="space-y-6 lg:col-span-4">
              <Card>
                <CardHeader className="flex flex-row items-center justify-between gap-2">
                  <CardTitle className="text-base font-semibold">
                    运行状态
                  </CardTitle>
                  <StatusBadge status={run.status} />
                </CardHeader>
                <CardContent>
                  <KeyValueList
                    columns={1}
                    items={[
                      {
                        label: "运行 ID",
                        value: run.runId,
                        mono: true,
                        copyText: run.runId,
                      },
                      {
                        label: "任务 ID",
                        value: run.taskId,
                        mono: true,
                        copyText: run.taskId,
                      },
                      {
                        label: "当前阶段",
                        value: resolveStageLabel(run.stage),
                      },
                      {
                        label: "G1 委托状态",
                        value: run.grantStatus ? (
                          <StatusBadge status={run.grantStatus} />
                        ) : (
                          EMPTY_PLACEHOLDER
                        ),
                      },
                      {
                        label: "G1 登记版本",
                        value:
                          run.grantRevision !== undefined
                            ? formatInteger(run.grantRevision)
                            : EMPTY_PLACEHOLDER,
                      },
                      {
                        label: "确认时间",
                        value: formatUnixSeconds(run.confirmedAt),
                      },
                    ]}
                  />
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle className="text-base font-semibold">
                    已确认任务参数
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <KeyValueList
                    columns={1}
                    items={[
                      {
                        label: "商品编号",
                        value: run.task.productId,
                        mono: true,
                      },
                      {
                        label: "数量",
                        value: formatInteger(run.task.quantity),
                      },
                      {
                        label: "授权模式",
                        value: resolveModeLabel(run.task.mode),
                      },
                      {
                        label: "单笔上限",
                        value: formatMinorAmount(run.task.maxAmountMinor),
                      },
                      {
                        label: "截止时间",
                        value: formatUnixSeconds(run.task.expiresAt),
                      },
                      {
                        label: "受托者 DID",
                        value: run.task.delegateDid,
                        mono: true,
                        copyText: run.task.delegateDid,
                      },
                      {
                        label: "任务说明",
                        value: run.task.description,
                      },
                    ]}
                  />
                </CardContent>
              </Card>
            </aside>
          </div>
        </>
      )}

      <ConfirmDialog
        open={pendingAction !== null}
        onOpenChange={(open) => {
          if (!open) setPendingAction(null);
        }}
        variant={pendingAction === "suspend" ? "destructive" : "default"}
        title={
          pendingAction === "suspend"
            ? "暂停本次运行的 G1 委托？"
            : "恢复本次运行的 G1 委托？"
        }
        description={
          pendingAction === "suspend"
            ? `将提交 Fabric 暂停操作以挂起运行「${run?.runId ?? ""}」的 G1 委托（当前版本 ${run?.grantRevision ?? 1}）。C 网关采用该区块后，所有基于该 G1 及其子委托 G2 的新请求均会被拒绝。`
            : `将恢复运行「${run?.runId ?? ""}」的 G1 委托（当前版本 ${run?.grantRevision ?? 1}）。恢复后原委托截止期限保持不变，子委托 G2 随祖先恢复生效。`
        }
        confirmLabel={pendingAction === "suspend" ? "暂停 G1 委托" : "恢复 G1 委托"}
        cancelLabel="暂不变更"
        loading={actionLoading}
        onConfirm={handleGrantAction}
      />
    </div>
  );
}
