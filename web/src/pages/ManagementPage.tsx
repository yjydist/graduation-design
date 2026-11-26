import {
  useCallback,
  useEffect,
  useMemo,
  useState,
  type FormEvent,
} from "react";
import { useNavigate, useParams } from "react-router-dom";
import { Building2, Hash, Loader2, RefreshCw, Server, Shield } from "lucide-react";
import { toast } from "sonner";
import { backendApi } from "@/api/backend";
import { formatApiError, getOrCreateIdempotencyKey } from "@/api/http";
import type { PurchasingAuthority } from "@/api/types";
import { ConfirmDialog } from "@/components/patterns/ConfirmDialog";
import { EmptyState } from "@/components/patterns/EmptyState";
import { ErrorState } from "@/components/patterns/ErrorState";
import { KeyValueList } from "@/components/patterns/KeyValueList";
import { PageHeader } from "@/components/patterns/PageHeader";
import { StatCard } from "@/components/patterns/StatCard";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
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
import { OperationTracker } from "@/features/management/OperationTracker";
import { DOMAIN_LABELS } from "@/lib/domain-labels";
import { EMPTY_PLACEHOLDER, formatInteger } from "@/lib/format";
import { cn } from "@/lib/utils";

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
  const [opRefreshToken, setOpRefreshToken] = useState(0);

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
        return (
          data.eligibleServiceIds[0] ??
          (data.purchasingAuthority ? CLEAR_SENTINEL : "")
        );
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

  const handleOperationConfirmed = useCallback(() => {
    void loadAuthority(true);
  }, [loadAuthority]);

  const handleSelectOperation = useCallback(
    (opId: string) => {
      navigate(`/management/${encodeURIComponent(opId)}`);
    },
    [navigate],
  );

  const serviceOptions = useMemo(() => {
    if (!authority) return [];
    const options: Array<{ value: string; label: string; mono: boolean }> =
      authority.eligibleServiceIds.map((serviceId) => ({
        value: serviceId,
        label: serviceId,
        mono: true,
      }));
    if (authority.purchasingAuthority) {
      options.push({
        value: CLEAR_SENTINEL,
        label: "清除当前采购权威（置空）",
        mono: false,
      });
    }
    return options;
  }, [authority]);

  const isClearing = selectedService === CLEAR_SENTINEL;
  const hasAnyChoice = serviceOptions.length > 0;

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
              if (routeOpId) setOpRefreshToken((n) => n + 1);
            }}
            className="h-9 gap-1.5 rounded-lg"
          >
            <RefreshCw
              className={cn("size-4", authorityLoading && "animate-spin")}
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
          <Card>
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
                      items={serviceOptions}
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
                        {serviceOptions.map((option) => (
                          <SelectItem key={option.value} value={option.value}>
                            {option.mono ? (
                              <span className="font-mono text-xs">
                                {option.label}
                              </span>
                            ) : (
                              option.label
                            )}
                          </SelectItem>
                        ))}
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
                    <span>
                      {isClearing ? "申请清除采购权威" : "提交资格变更"}
                    </span>
                  </Button>
                </form>
              )}
            </CardContent>
          </Card>
        </div>

        <div className="space-y-6 lg:col-span-6">
          <OperationTracker
            operationId={routeOpId}
            refreshToken={opRefreshToken}
            onSelectOperation={handleSelectOperation}
            onConfirmed={handleOperationConfirmed}
          />
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
