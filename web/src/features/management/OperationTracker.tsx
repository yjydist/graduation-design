import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import { Blocks, FileSearch, Search } from "lucide-react";
import { toast } from "sonner";
import { backendApi } from "@/api/backend";
import { formatApiError } from "@/api/http";
import type { Operation } from "@/api/types";
import { EmptyState } from "@/components/patterns/EmptyState";
import { ErrorState } from "@/components/patterns/ErrorState";
import { KeyValueList } from "@/components/patterns/KeyValueList";
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
import { Skeleton } from "@/components/ui/skeleton";
import { EMPTY_PLACEHOLDER, formatInteger } from "@/lib/format";
import { cn } from "@/lib/utils";

export interface OperationTrackerProps {
  operationId?: string;
  refreshToken?: number;
  onSelectOperation: (operationId: string) => void;
  onConfirmed?: () => void;
}

/**
 * Self-contained Fabric ledger operation lookup and auto-polling panel.
 * Polls only while the tracked operation remains PENDING and notifies the parent
 * when a PENDING transaction transitions to CONFIRMED.
 */
export function OperationTracker({
  operationId,
  refreshToken = 0,
  onSelectOperation,
  onConfirmed,
}: OperationTrackerProps) {
  const [lookupInput, setLookupInput] = useState(operationId ?? "");
  const [lookupError, setLookupError] = useState<string | null>(null);
  const [operation, setOperation] = useState<Operation | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<{
    message: string;
    code?: string;
    requestId?: string;
  } | null>(null);

  const prevStatusRef = useRef<string | null>(null);

  useEffect(() => {
    setLookupInput(operationId ?? "");
    setLookupError(null);
  }, [operationId]);

  const loadOperation = useCallback(
    async (opId: string, silent = false) => {
      if (!silent) {
        setLoading(true);
      }
      setError(null);
      try {
        const op = await backendApi.getOperation(opId);
        setOperation(op);
        if (prevStatusRef.current === "PENDING" && op.status === "CONFIRMED") {
          toast.success("链上交易已确认，本域采购权威登记已更新。", {
            duration: 3000,
          });
          onConfirmed?.();
        } else if (
          prevStatusRef.current === "PENDING" &&
          op.status === "FAILED"
        ) {
          toast.error("链上交易确认失败", {
            description:
              op.failureCode || op.validationCode || "请检查失败码与登记版本。",
            duration: 6000,
          });
        }
        prevStatusRef.current = op.status;
      } catch (err) {
        setOperation(null);
        setError(formatApiError(err));
      } finally {
        setLoading(false);
      }
    },
    [onConfirmed],
  );

  useEffect(() => {
    prevStatusRef.current = null;
    if (!operationId) {
      setOperation(null);
      setError(null);
      setLoading(false);
      return;
    }
    void loadOperation(operationId);
  }, [operationId, refreshToken, loadOperation]);

  useEffect(() => {
    if (!operationId || operation?.status !== "PENDING") {
      return;
    }
    const timer = window.setInterval(() => {
      void loadOperation(operationId, true);
    }, 2500);
    return () => window.clearInterval(timer);
  }, [operationId, operation?.status, loadOperation]);

  const handleLookupSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const trimmed = lookupInput.trim();
    if (!trimmed) {
      setLookupError("请输入有效的操作 ID 后查询。");
      return;
    }
    setLookupError(null);
    onSelectOperation(trimmed);
  };

  return (
    <Card>
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
          noValidate
          className="space-y-1.5"
        >
          <div className="flex flex-col gap-3 sm:flex-row sm:items-end">
            <div className="min-w-0 flex-1 space-y-1.5">
              <Label htmlFor="operation-id-input" className="text-sm font-medium">
                操作 ID{" "}
                <span className="text-destructive" aria-hidden="true">
                  *
                </span>
              </Label>
              <Input
                id="operation-id-input"
                name="operationId"
                required
                aria-required="true"
                aria-invalid={Boolean(lookupError)}
                aria-describedby={lookupError ? "operation-id-error" : undefined}
                value={lookupInput}
                onChange={(e) => {
                  setLookupInput(e.target.value);
                  if (lookupError) setLookupError(null);
                }}
                placeholder="输入原操作 ID（operationId）"
                autoComplete="off"
                autoCapitalize="none"
                spellCheck={false}
                className={cn(
                  "h-9 rounded-lg font-mono text-xs",
                  lookupError && "border-destructive",
                )}
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
          </div>
          {lookupError && (
            <p
              id="operation-id-error"
              role="alert"
              className="text-xs text-destructive"
            >
              {lookupError}
            </p>
          )}
        </form>

        {loading ? (
          <div className="space-y-3 rounded-lg border border-border p-4">
            <Skeleton className="h-5 w-28" />
            <Skeleton className="h-4 w-full" />
            <Skeleton className="h-4 w-5/6" />
            <Skeleton className="h-4 w-2/3" />
          </div>
        ) : error ? (
          <ErrorState
            title="操作记录查询失败"
            message={error.message}
            code={error.code}
            requestId={error.requestId}
            onRetry={
              operationId ? () => void loadOperation(operationId) : undefined
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
  );
}
