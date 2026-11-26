import { useCallback, useEffect, useState, type FormEvent } from "react";
import { useNavigate, useParams } from "react-router-dom";
import {
  FileCheck2,
  GitBranch,
  RefreshCw,
  Scale,
  Search,
  ShieldCheck,
} from "lucide-react";
import { backendApi } from "@/api/backend";
import { formatApiError, type FormattedApiError } from "@/api/http";
import type { Decision } from "@/api/types";
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
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import {
  EMPTY_PLACEHOLDER,
  formatInteger,
  formatIsoTimestamp,
  formatUnixSeconds,
} from "@/lib/format";
import { cn } from "@/lib/utils";

export function DecisionsAuditPage() {
  const { decisionId: routeDecisionId } = useParams<{ decisionId?: string }>();
  const navigate = useNavigate();

  const [queryInput, setQueryInput] = useState(routeDecisionId ?? "");
  const [queryError, setQueryError] = useState<string | null>(null);
  const [decision, setDecision] = useState<Decision | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<FormattedApiError | null>(null);

  useEffect(() => {
    setQueryInput(routeDecisionId ?? "");
    setQueryError(null);
  }, [routeDecisionId]);

  const loadDecision = useCallback(async (id: string) => {
    setLoading(true);
    setError(null);
    try {
      const record = await backendApi.getDecision(id);
      setDecision(record);
    } catch (err) {
      setDecision(null);
      setError(formatApiError(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!routeDecisionId) {
      setDecision(null);
      setError(null);
      setLoading(false);
      return;
    }
    void loadDecision(routeDecisionId);
  }, [routeDecisionId, loadDecision]);

  const handleSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const trimmed = queryInput.trim();
    if (!trimmed) {
      setQueryError("请输入有效的决定 ID 后查询。");
      return;
    }
    setQueryError(null);
    navigate(`/decisions/${encodeURIComponent(trimmed)}`);
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="决策审计"
        description="输入可核对的网关决定 ID，读取当前身份获准查看的完整 C 网关决策、采用块高与策略环境快照。"
        actions={
          routeDecisionId && (
            <Button
              type="button"
              variant="outline"
              size="sm"
              disabled={loading}
              onClick={() => void loadDecision(routeDecisionId)}
              className="h-9 gap-1.5 rounded-lg"
            >
              <RefreshCw
                className={cn("size-4", loading && "animate-spin")}
                strokeWidth={2}
                aria-hidden="true"
              />
              <span>重新读取</span>
            </Button>
          )
        }
      />

      <Card>
        <CardHeader>
          <CardTitle className="text-base font-semibold">
            查询网关决定
          </CardTitle>
          <CardDescription className="text-sm text-muted-foreground">
            C 域审计员可按决定 ID 复核全部已归档的网关决策记录；其他主体仅限查询与其权限匹配的记录。
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form
            onSubmit={handleSubmit}
            noValidate
            className="max-w-2xl space-y-1.5"
          >
            <div className="flex flex-col gap-3 sm:flex-row sm:items-end">
              <div className="min-w-0 flex-1 space-y-1.5">
                <Label htmlFor="decision-id-input" className="text-sm font-medium">
                  决定 ID（decisionId）{" "}
                  <span className="text-destructive" aria-hidden="true">
                    *
                  </span>
                </Label>
                <Input
                  id="decision-id-input"
                  name="decisionId"
                  required
                  aria-required="true"
                  aria-invalid={Boolean(queryError)}
                  aria-describedby={queryError ? "decision-id-error" : undefined}
                  value={queryInput}
                  onChange={(e) => {
                    setQueryInput(e.target.value);
                    if (queryError) setQueryError(null);
                  }}
                  placeholder="输入完整的决定 ID"
                  autoComplete="off"
                  autoCapitalize="none"
                  spellCheck={false}
                  className={cn(
                    "h-9 rounded-lg font-mono text-xs",
                    queryError && "border-destructive",
                  )}
                />
              </div>
              <Button type="submit" className="h-9 shrink-0 gap-1.5 rounded-lg">
                <Search className="size-4" strokeWidth={2} aria-hidden="true" />
                <span>读取完整决定</span>
              </Button>
            </div>
            {queryError && (
              <p
                id="decision-id-error"
                role="alert"
                className="text-xs text-destructive"
              >
                {queryError}
              </p>
            )}
          </form>
        </CardContent>
      </Card>

      {loading ? (
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          {Array.from({ length: 4 }).map((_, idx) => (
            <Card key={idx}>
              <CardHeader>
                <Skeleton className="h-5 w-36" />
              </CardHeader>
              <CardContent className="space-y-3">
                <Skeleton className="h-4 w-full" />
                <Skeleton className="h-4 w-4/5" />
                <Skeleton className="h-4 w-2/3" />
              </CardContent>
            </Card>
          ))}
        </div>
      ) : error ? (
        <ErrorState
          title="决策记录读取失败"
          message={error.message}
          code={error.code}
          requestId={error.requestId}
          onRetry={
            routeDecisionId
              ? () => void loadDecision(routeDecisionId)
              : undefined
          }
        />
      ) : decision ? (
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <Scale
                  className="size-4 text-muted-foreground"
                  strokeWidth={2}
                  aria-hidden="true"
                />
                <CardTitle className="text-base font-semibold">
                  定案摘要与原因
                </CardTitle>
              </div>
              <StatusBadge status={decision.outcome} />
            </CardHeader>
            <CardContent>
              <KeyValueList
                columns={2}
                items={[
                  {
                    label: "决定 ID",
                    value: decision.decisionId,
                    mono: true,
                    copyText: decision.decisionId,
                  },
                  {
                    label: "请求 ID",
                    value: decision.requestId,
                    mono: true,
                    copyText: decision.requestId,
                  },
                  {
                    label: "业务动作",
                    value: decision.action,
                    mono: true,
                  },
                  {
                    label: "决定原因码",
                    value: decision.code,
                    mono: true,
                  },
                  {
                    label: "拒绝/说明理由",
                    value: decision.reason ?? EMPTY_PLACEHOLDER,
                  },
                  {
                    label: "失效对象 ID",
                    value: decision.failedObjectId ?? EMPTY_PLACEHOLDER,
                    mono: Boolean(decision.failedObjectId),
                    copyText: decision.failedObjectId,
                  },
                  {
                    label: "执行主体（actor）",
                    value: decision.actor,
                    mono: true,
                    copyText: decision.actor,
                  },
                  {
                    label: "任务 ID",
                    value: decision.taskId,
                    mono: true,
                    copyText: decision.taskId,
                  },
                  {
                    label: "定案时间",
                    value: formatUnixSeconds(decision.decisionAt),
                  },
                  {
                    label: "幂等键",
                    value: decision.idempotencyKey,
                    mono: true,
                  },
                  ...(decision.quoteId
                    ? [
                        {
                          label: "报价 ID",
                          value: decision.quoteId,
                          mono: true,
                          copyText: decision.quoteId,
                        },
                      ]
                    : []),
                  ...(decision.orderId
                    ? [
                        {
                          label: "订单 ID",
                          value: decision.orderId,
                          mono: true,
                          copyText: decision.orderId,
                        },
                      ]
                    : []),
                ]}
              />
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center gap-2">
              <FileCheck2
                className="size-4 text-muted-foreground"
                strokeWidth={2}
                aria-hidden="true"
              />
              <CardTitle className="text-base font-semibold">
                账本视图与探针期限
              </CardTitle>
            </CardHeader>
            <CardContent>
              <KeyValueList
                columns={2}
                items={[
                  { label: "状态来源", value: decision.stateSource, mono: true },
                  {
                    label: "状态版本 / 重查次数",
                    value: `${formatInteger(decision.revision)} / ${formatInteger(decision.stateRechecks)} 次`,
                  },
                  {
                    label: "状态读取时间",
                    value: formatIsoTimestamp(decision.stateReadAt),
                  },
                  {
                    label: "撤销纪元（revocationEpoch）",
                    value: formatInteger(decision.revocationEpoch),
                  },
                  {
                    label: "采用块高",
                    value: formatInteger(decision.blockNumber),
                  },
                  {
                    label: "采用区块哈希",
                    value: decision.blockHash ?? EMPTY_PLACEHOLDER,
                    mono: Boolean(decision.blockHash),
                    copyText: decision.blockHash ?? undefined,
                  },
                  {
                    label: "原探针交易 txId",
                    value: decision.probeTxId ?? EMPTY_PLACEHOLDER,
                    mono: Boolean(decision.probeTxId),
                    copyText: decision.probeTxId ?? undefined,
                  },
                  {
                    label: "探针确认块高",
                    value: formatInteger(decision.probeBlock),
                  },
                  {
                    label: "探针发出时间",
                    value: formatUnixSeconds(decision.probeSentAt),
                  },
                  {
                    label: "原探针期限（probeDeadline）",
                    value: formatUnixSeconds(decision.probeDeadline),
                  },
                  {
                    label: "实际有效截止（effectiveDeadline）",
                    value: formatUnixSeconds(decision.effectiveDeadline),
                  },
                  {
                    label: "挑战 ID",
                    value: decision.challengeId,
                    mono: true,
                  },
                ]}
              />
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center gap-2">
              <ShieldCheck
                className="size-4 text-muted-foreground"
                strokeWidth={2}
                aria-hidden="true"
              />
              <CardTitle className="text-base font-semibold">
                身份信任根与域认证
              </CardTitle>
            </CardHeader>
            <CardContent>
              <KeyValueList
                columns={2}
                items={[
                  {
                    label: "部署标识",
                    value: decision.deploymentId,
                    mono: true,
                  },
                  {
                    label: "信任根 DID / 密钥版本",
                    value: `${decision.rootDid} (v${decision.rootKeyVersion})`,
                    mono: true,
                  },
                  {
                    label: "所属域 / 域登记版本",
                    value: `${decision.domainId ?? EMPTY_PLACEHOLDER} · v${decision.domainRevision}`,
                  },
                  {
                    label: "身份签发者 DID",
                    value: decision.identityIssuer ?? EMPTY_PLACEHOLDER,
                    mono: Boolean(decision.identityIssuer),
                  },
                  {
                    label: "域认证 ID",
                    value: decision.certificationId ?? EMPTY_PLACEHOLDER,
                    mono: Boolean(decision.certificationId),
                  },
                  {
                    label: "域认证摘要",
                    value: decision.certificationDigest ?? EMPTY_PLACEHOLDER,
                    mono: Boolean(decision.certificationDigest),
                    copyText: decision.certificationDigest,
                  },
                ]}
              />
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center gap-2">
              <GitBranch
                className="size-4 text-muted-foreground"
                strokeWidth={2}
                aria-hidden="true"
              />
              <CardTitle className="text-base font-semibold">
                策略、环境版本与授权路径
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <KeyValueList
                columns={2}
                items={[
                  {
                    label: "策略摘要（policyDigest）",
                    value: decision.policyDigest,
                    mono: true,
                    copyText: decision.policyDigest,
                  },
                  {
                    label: "环境版本 / 风险级别",
                    value: `v${formatInteger(decision.contextVersion)} · ${decision.contextRiskLevel || EMPTY_PLACEHOLDER}`,
                  },
                  {
                    label: "环境观测时间",
                    value: formatUnixSeconds(decision.contextObservedAt),
                  },
                  {
                    label: "环境访问截止",
                    value: formatUnixSeconds(decision.contextAccessDeadline),
                  },
                ]}
              />

              <div className="space-y-2 border-t border-border pt-4">
                <p className="text-xs font-medium text-muted-foreground">
                  授权委托路径（grantPath）
                </p>
                {decision.grantPath && decision.grantPath.length > 0 ? (
                  <ol className="space-y-1.5">
                    {decision.grantPath.map((grantId, index) => (
                      <li
                        key={`${grantId}-${index}`}
                        className="flex items-center gap-2 rounded-lg border border-border bg-muted px-3 py-1.5 text-xs"
                      >
                        <Badge variant="secondary" className="font-mono text-xs">
                          G{index}
                        </Badge>
                        <span className="break-all font-mono text-foreground">
                          {grantId}
                        </span>
                      </li>
                    ))}
                  </ol>
                ) : (
                  <p className="text-xs text-muted-foreground">
                    本次决策无关联委托路径记录。
                  </p>
                )}
              </div>
            </CardContent>
          </Card>
        </div>
      ) : (
        <Card>
          <CardContent className="p-0">
            <EmptyState
              icon={<Scale className="size-5" strokeWidth={2} />}
              title="尚未选择待审计的决定记录"
              description="在上方输入来自采购运行证据时间线或日志中的 decisionId，即可核验完整的区块、策略与委托链证据。"
            />
          </CardContent>
        </Card>
      )}
    </div>
  );
}
