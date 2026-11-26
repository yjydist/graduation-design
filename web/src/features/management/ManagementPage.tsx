import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import { useNavigate, useParams } from "react-router-dom";
import {
  Blocks,
  Building2,
  FileSearch,
  Hash,
  Loader2,
  RefreshCw,
  Search,
  Server,
  Shield,
} from "lucide-react";
import { toast } from "sonner";
import { backendApi } from "@/api/backend";
import { formatApiError, getOrCreateIdempotencyKey } from "@/api/http";
import type { Operation, PurchasingAuthority } from "@/api/types";
import { ConfirmDialog } from "@/components/patterns/ConfirmDialog";
import { EmptyState } from "@/components/patterns/EmptyState";
import { ErrorState } from "@/components/patterns/ErrorState";
import { KeyValueList } from "@/components/patterns/KeyValueList";
import { PageHeader } from "@/components/patterns/PageHeader";
import { StatCard } from "@/components/patterns/StatCard";
import { StatusBadge } from "@/components/patterns/StatusBadge";
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { useAuth } from "@/features/auth/AuthContext";
import { DOMAIN_LABELS } from "@/lib/domain-labels";
import { EMPTY_PLACEHOLDER, formatInteger } from "@/lib/format";

const CLEAR_SENTINEL = "__CLEAR_PA__";

export function ManagementPage() {
  const { operationId: routeOpId } = useParams<{ operationId?: string }>();
  const navigate = useNavigate();
  const { session, ready } = useAuth();

  const [authority, setAuthority] = useState<PurchasingAuthority | null>(null);
  const [authorityLoading, setAuthorityLoading] = useState(true);
  const [authorityError, setAuthorityError] = useState<{
    message: string;
    code?: string;
    requestId?: string;
  } | null>(null);

  const [selectedService, setSelectedService] = useState<string>("");
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  const [lookupInput, setLookupInput] = useState(routeOpId ?? "");
  const [operation, setOperation] = useState<Operation | null>(null);
  const [operationLoading, setOperationLoading] = useState(false);
  const [operationError, setOperationError] = useState<{
    message: string;
    code?: string;
    requestId?: string;
  } | null>(null);

  const prevOpStatusRef = useRef<string | null>(null);

  useEffect(() => {
    setLookupInput(routeOpId ?? "");
  }, [routeOpId]);

  const loadAuthority = useCallback(async (silent = false) => {
    if (!silent) {
      setAuthorityLoading(true);
    }
    setAuthorityError(null);
    try {
      const data = await backendApi.getPurchasingAuthority();
      setAuthority(data);
      setSelectedService((prev) => {
        if (
          data.purchasingAuthority &&
          data.eligibleServiceIds.includes(data.purchasingAuthority)
        ) {
          return data.purchasingAuthority;
        }
        if (prev && data.eligibleServiceIds.includes(prev)) {
          return prev;
        }
        return data.eligibleServiceIds[0] ?? (data.purchasingAuthority ? CLEAR_SENTINEL : "");
      });
    } catch (err) {
      setAuthorityError(formatApiError(err));
    } finally {
      setAuthorityLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadAuthority();
  }, [loadAuthority]);

  const loadOperation = useCallback(
    async (opId: string, silent = false) => {
      if (!silent) {
        setOperationLoading(true);
      }
      setOperationError(null);
      try {
        const op = await backendApi.getOperation(opId);
        setOperation(op);
        if (prevOpStatusRef.current === "PENDING" && op.status === "CONFIRMED") {
          toast.success("链上交易已确认，本域采购权威登记已更新。", {
            duration: 3000,
          });
          void loadAuthority(true);
        } else if (
          prevOpStatusRef.current === "PENDING" &&
          op.status === "FAILED"
        ) {
          toast.error("链上交易确认失败", {
            description: op.failureCode || op.validationCode || "请检查失败码与登记版本。",
            duration: 6000,
          });
        }
        prevOpStatusRef.current = op.status;
      } catch (err) {
        setOperation(null);
        setOperationError(formatApiError(err));
      } finally {
        setOperationLoading(false);
      }
    },
    [loadAuthority],
  );

  useEffect(() => {
    prevOpStatusRef.current = null;
    if (!routeOpId) {
      setOperation(null);
      setOperationError(null);
      setOperationLoading(false);
      return;
    }
    void loadOperation(routeOpId);
  }, [routeOpId, loadOperation]);

  useEffect(() => {
    if (!routeOpId || operation?.status !== "PENDING") {
      return;
    }
    const timer = window.setInterval(() => {
      void loadOperation(routeOpId, true);
    }, 2500);
    return () => window.clearInterval(timer);
  }, [routeOpId, operation?.status, loadOperation]);

  const handleOpenConfirm = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!authority || !selectedService) {
      toast.error("请先选择一个合资格的本域服务或清除操作。", {
        duration: 6000,
      });
      return;
    }
    setConfirmOpen(true);
  };

  const handleConfirmAuthority = async () => {
    if (!authority || !session || !selectedService) return;
    setSubmitting(true);
    try {
      const targetAuthority =
        selectedService === CLEAR_SENTINEL ? null : selectedService;
      const body = {
        expectedRevision: authority.expectedRevision,
        purchasingAuthority: targetAuthority,
      };
      const idempotencyKey = getOrCreateIdempotencyKey(
        session.domainId,
        session.subjectId,
        "authority",
        authority.domainId,
        body,
      );
      const result = await backendApi.setPurchasingAuthority(
        body,
        idempotencyKey,
      );
      setConfirmOpen(false);
      toast.success("已受理资格变更操作，正在跟踪链上入块状态。", {
        duration: 3000,
      });
      navigate(`/management/${encodeURIComponent(result.operationId)}`);
    } catch (err) {
      const formatted = formatApiError(err);
      toast.error("提交资格变更失败", {
        description: formatted.message,
        duration: 6000,
      });
    } finally {
      setSubmitting(false);
    }
  };

  const handleLookupSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const trimmed = lookupInput.trim();
    if (!trimmed) {
      toast.error("请输入有效的操作 ID 后查询。", { duration: 6000 });
      return;
    }
    navigate(`/management/${encodeURIComponent(trimmed)}`);
  };

  const isClearing = selectedService === CLEAR_SENTINEL;
  const hasAnyChoice =
    Boolean(authority?.eligibleServiceIds.length) ||
    Boolean(authority?.purchasingAuthority);

  return (
    <div className="space-y-6">
      <PageHeader
        title="本域管理"
        description="配置本域采购权威（PA）资格，并核对链上原操作 ID、交易 txId 与入块确认结果。"
        actions={
          <Button
            type="button"
            variant="outline"
            size="sm"
            disabled={authorityLoading}
            onClick={() => {
              void loadAuthority();
              if (routeOpId) void loadOperation(routeOpId);
            }}
            className="h-9 gap-1.5 rounded-lg"
          >
            <RefreshCw
              className={`size-4 ${authorityLoading ? "animate-spin" : ""}`}
              strokeWidth={2}
              aria-hidden="true"
            />
            <span>刷新状态</span>
          </Button>
        }
      />

      {authorityLoading ? (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {Array.from({ length: 4 }).map((_, idx) => (
            <div
              key={idx}
              className="space-y-3 rounded-xl border border-border bg-card p-5"
            >
              <Skeleton className="h-3.5 w-24" />
              <Skeleton className="h-7 w-32" />
              <Skeleton className="h-3.5 w-20" />
            </div>
          ))}
        </div>
      ) : authorityError ? (
        <ErrorState
          title="无法读取本域采购权威状态"
          message={authorityError.message}
          code={authorityError.code}
          requestId={authorityError.requestId}
          onRetry={() => void loadAuthority()}
        />
      ) : authority ? (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <StatCard
            label="当前所属域"
            value={DOMAIN_LABELS[authority.domainId]}
            hint={ready ? "本域后端与账本通道已就绪" : "请检查本域服务就绪状态"}
            hintTone={ready ? "success" : "destructive"}
            icon={<Building2 className="size-4" strokeWidth={2} />}
          />
          <StatCard
            label="当前采购权威（PA）"
            value={authority.purchasingAuthority ?? EMPTY_PLACEHOLDER}
            hint={
              authority.purchasingAuthority
                ? "已绑定本域合资格服务"
                : "当前尚未指定采购权威"
            }
            hintTone={authority.purchasingAuthority ? "success" : "warning"}
            mono
            icon={<Shield className="size-4" strokeWidth={2} />}
          />
          <StatCard
            label="当前登记版本"
            value={formatInteger(authority.expectedRevision)}
            hint="写操作提交时执行乐观锁校验"
            icon={<Hash className="size-4" strokeWidth={2} />}
          />
          <StatCard
            label="合资格本域服务"
            value={formatInteger(authority.eligibleServiceIds.length)}
            hint="依据当前 Fabric 账本判据筛选"
            icon={<Server className="size-4" strokeWidth={2} />}
          />
        </div>
      ) : null}

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        <div className="lg:col-span-6">
          <Card className="rounded-xl border border-border bg-card shadow-none">
            <CardHeader>
              <CardTitle className="text-base font-semibold">
                PA 资格配置
              </CardTitle>
              <CardDescription className="text-sm text-muted-foreground">
                仅可指定本域处于有效登记状态的服务作为采购权威，或清除当前指定。
              </CardDescription>
            </CardHeader>
            <CardContent>
              {authorityLoading ? (
                <div className="space-y-4">
                  <Skeleton className="h-9 w-full" />
                  <Skeleton className="h-9 w-36" />
                </div>
              ) : !authority ? (
                <EmptyState
                  icon={<Shield className="size-5" strokeWidth={2} />}
                  title="尚未获取到本域登记信息"
                  description="请点击页面右上角刷新状态，或检查本域账本连接。"
                />
              ) : !hasAnyChoice ? (
                <EmptyState
                  icon={<Server className="size-5" strokeWidth={2} />}
                  title="暂无可指定的本域服务"
                  description="当前链上登记中没有合资格的本域服务，请先完成服务身份登记后再配置 PA。"
                />
              ) : (
                <form
                  onSubmit={handleOpenConfirm}
                  className="max-w-xl space-y-5"
                >
                  <KeyValueList
                    columns={1}
                    items={[
                      {
                        label: "当前采购权威 DID",
                        value: authority.purchasingAuthority ?? "未指定",
                        mono: Boolean(authority.purchasingAuthority),
                        copyText: authority.purchasingAuthority ?? undefined,
                      },
                      {
                        label: "期望登记版本（expectedRevision）",
                        value: formatInteger(authority.expectedRevision),
                      },
                    ]}
                  />

                  <div className="space-y-1.5">
                    <Label
                      htmlFor="pa-service-select"
                      className="text-sm font-medium"
                    >
                      目标采购权威服务{" "}
                      <span className="text-destructive" aria-hidden="true">
                        *
                      </span>
                    </Label>
                    <Select
                      value={selectedService}
                      onValueChange={(value) => setSelectedService(value ?? "")}
                      disabled={submitting}
                    >
                      <SelectTrigger
                        id="pa-service-select"
                        aria-label="选择目标采购权威服务"
                        className="h-9 w-full rounded-lg"
                      >
                        <SelectValue placeholder="请选择本域合资格服务或清除操作" />
                      </SelectTrigger>
                      <SelectContent>
                        {authority.eligibleServiceIds.map((serviceId) => (
                          <SelectItem key={serviceId} value={serviceId}>
                            <span className="font-mono text-xs">
                              {serviceId}
                            </span>
                          </SelectItem>
                        ))}
                        {authority.purchasingAuthority && (
                          <SelectItem value={CLEAR_SENTINEL}>
                            清除当前采购权威（置空）
                          </SelectItem>
                        )}
                      </SelectContent>
                    </Select>
                    <p className="text-xs text-muted-foreground">
                      变更提交后生成幂等原操作 ID，经 Hyperledger Fabric 通道背书并入块后生效。
                    </p>
                  </div>

                  <Button
                    type="submit"
                    disabled={submitting || !selectedService}
                    className="h-9 gap-1.5 rounded-lg"
                  >
                    {submitting && (
                      <Loader2 className="size-4 animate-spin" aria-hidden="true" />
                    )}
                    <span>{isClearing ? "申请清除采购权威" : "提交资格变更"}</span>
                  </Button>
                </form>
              )}
            </CardContent>
          </Card>
        </div>

        <div className="space-y-6 lg:col-span-6">
          <Card className="rounded-xl border border-border bg-card shadow-none">
            <CardHeader>
              <CardTitle className="text-base font-semibold">
                原交易与入块状态核对
              </CardTitle>
              <CardDescription className="text-sm text-muted-foreground">
                输入操作 ID 查询提交阶段、Fabric 交易 txId、入块校验码与区块哈希。
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-5">
              <form
                onSubmit={handleLookupSubmit}
                className="flex flex-col gap-3 sm:flex-row sm:items-end"
              >
                <div className="min-w-0 flex-1 space-y-1.5">
                  <Label htmlFor="operation-id-input" className="text-sm font-medium">
                    操作 ID
                  </Label>
                  <Input
                    id="operation-id-input"
                    name="operationId"
                    value={lookupInput}
                    onChange={(e) => setLookupInput(e.target.value)}
                    placeholder="输入原操作 ID（operationId）"
                    autoCapitalize="none"
                    spellCheck={false}
                    className="h-9 rounded-lg font-mono text-xs"
                  />
                </div>
                <Button
                  type="submit"
                  variant="secondary"
                  className="h-9 shrink-0 gap-1.5 rounded-lg"
                >
                  <Search className="size-4" strokeWidth={2} aria-hidden="true" />
                  <span>查询原交易</span>
                </Button>
              </form>

              {operationLoading ? (
                <div className="space-y-3 rounded-lg border border-border p-4">
                  <Skeleton className="h-5 w-28" />
                  <Skeleton className="h-4 w-full" />
                  <Skeleton className="h-4 w-5/6" />
                  <Skeleton className="h-4 w-2/3" />
                </div>
              ) : operationError ? (
                <ErrorState
                  title="操作记录查询失败"
                  message={operationError.message}
                  code={operationError.code}
                  requestId={operationError.requestId}
                  onRetry={
                    routeOpId ? () => void loadOperation(routeOpId) : undefined
                  }
                />
              ) : operation ? (
                <div className="space-y-4 rounded-xl border border-border bg-muted p-4">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <Blocks
                        className="size-4 text-muted-foreground"
                        strokeWidth={2}
                        aria-hidden="true"
                      />
                      <span className="text-sm font-semibold text-foreground">
                        {operation.method || "链上登记操作"}
                      </span>
                    </div>
                    <StatusBadge status={operation.status} />
                  </div>

                  {operation.status === "PENDING" && (
                    <p className="text-xs text-muted-foreground">
                      正在每 2.5 秒自动轮询 Fabric 入块确认结果…
                    </p>
                  )}

                  <KeyValueList
                    columns={2}
                    items={[
                      {
                        label: "操作 ID",
                        value: operation.operationId,
                        mono: true,
                        copyText: operation.operationId,
                      },
                      {
                        label: "原交易 txId",
                        value: operation.txId ?? "等待账本分配",
                        mono: Boolean(operation.txId),
                        copyText: operation.txId ?? undefined,
                      },
                      {
                        label: "交易阶段",
                        value: operation.stage,
                      },
                      {
                        label: "入块校验码",
                        value: operation.validationCode ?? EMPTY_PLACEHOLDER,
                        mono: Boolean(operation.validationCode),
                      },
                      {
                        label: "确认块高",
                        value:
                          operation.blockNumber !== null
                            ? formatInteger(operation.blockNumber)
                            : EMPTY_PLACEHOLDER,
                      },
                      {
                        label: "交易序号",
                        value:
                          operation.transactionIndex !== null
                            ? formatInteger(operation.transactionIndex)
                            : EMPTY_PLACEHOLDER,
                      },
                      {
                        label: "区块哈希",
                        value: operation.blockHash ?? EMPTY_PLACEHOLDER,
                        mono: Boolean(operation.blockHash),
                        copyText: operation.blockHash,
                      },
                      {
                        label: "观测节点",
                        value: operation.observedPeer ?? EMPTY_PLACEHOLDER,
                        mono: Boolean(operation.observedPeer),
                      },
                      {
                        label: "已交付状态",
                        value: operation.delivered ? "是" : "否",
                      },
                      {
                        label: "提交失败码",
                        value: operation.failureCode ?? EMPTY_PLACEHOLDER,
                        mono: Boolean(operation.failureCode),
                      },
                    ]}
                  />
                </div>
              ) : (
                <EmptyState
                  icon={<FileSearch className="size-5" strokeWidth={2} />}
                  title="尚未查询操作记录"
                  description="在左侧提交 PA 资格变更后将自动追踪，或在上方输入已有操作 ID 核对链上交易。"
                />
              )}
            </CardContent>
          </Card>
        </div>
      </div>

      <ConfirmDialog
        open={confirmOpen}
        onOpenChange={setConfirmOpen}
        variant={isClearing ? "destructive" : "default"}
        title={isClearing ? "清除本域当前采购权威？" : "提交本域采购权威变更？"}
        description={
          isClearing
            ? `将清除 ${authority?.domainId ?? ""} 域当前采购权威「${authority?.purchasingAuthority ?? ""}」（版本 ${authority?.expectedRevision ?? ""}）。清除后，依赖本域 BM 采购权威签发的委托校验将不再放行。`
            : `将 ${authority?.domainId ?? ""} 域采购权威更新为「${selectedService}」（基于当前登记版本 ${authority?.expectedRevision ?? ""}）。操作将提交至 Fabric 通道并永久记账。`
        }
        confirmLabel={isClearing ? "清除采购权威" : "提交资格变更"}
        cancelLabel="放弃修改"
        loading={submitting}
        onConfirm={handleConfirmAuthority}
      />
    </div>
  );
}
