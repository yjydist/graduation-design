import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  MessageSquarePlus,
  MoreHorizontal,
  RefreshCw,
  ShoppingBag,
} from "lucide-react";
import { backendApi } from "@/api/backend";
import { formatApiError } from "@/api/http";
import type { Run } from "@/api/types";
import {
  DataTable,
  type DataTableColumn,
} from "@/components/patterns/DataTable";
import { EmptyState } from "@/components/patterns/EmptyState";
import { FilterBar } from "@/components/patterns/FilterBar";
import { PageHeader } from "@/components/patterns/PageHeader";
import { StatusBadge } from "@/components/patterns/StatusBadge";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  MODE_LABELS,
  resolveModeLabel,
  resolveStageLabel,
} from "@/lib/domain-labels";
import {
  formatMinorAmount,
  formatUnixSeconds,
  truncateMiddle,
} from "@/lib/format";

const ALL_FILTER = "__ALL__";

export function RunsListPage() {
  const navigate = useNavigate();

  const [runs, setRuns] = useState<Run[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<{
    message: string;
    code?: string;
    requestId?: string;
  } | null>(null);

  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>(ALL_FILTER);
  const [modeFilter, setModeFilter] = useState<string>(ALL_FILTER);

  const loadRuns = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const list = await backendApi.listRuns();
      setRuns(list);
    } catch (err) {
      setError(formatApiError(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadRuns();
  }, [loadRuns]);

  const hasActiveFilters =
    search.trim().length > 0 ||
    statusFilter !== ALL_FILTER ||
    modeFilter !== ALL_FILTER;

  const filteredRuns = useMemo(() => {
    const query = search.trim().toLowerCase();
    return runs.filter((run) => {
      if (statusFilter !== ALL_FILTER && run.status !== statusFilter) {
        return false;
      }
      if (modeFilter !== ALL_FILTER && run.task?.mode !== modeFilter) {
        return false;
      }
      if (!query) return true;
      return (
        run.runId.toLowerCase().includes(query) ||
        run.taskId.toLowerCase().includes(query) ||
        (run.task?.productId ?? "").toLowerCase().includes(query) ||
        (run.task?.description ?? "").toLowerCase().includes(query)
      );
    });
  }, [runs, search, statusFilter, modeFilter]);

  const columns = useMemo<DataTableColumn<Run>[]>(
    () => [
      {
        key: "product",
        header: "商品 / 运行 ID",
        stickyFirst: true,
        sortable: true,
        sortValue: (run) => run.task?.productId || run.runId,
        cell: (run) => (
          <div className="min-w-44 py-1">
            <Link
              to={`/runs/${encodeURIComponent(run.runId)}`}
              className="font-medium text-foreground underline-offset-4 hover:text-brand hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            >
              {run.task?.productId || run.runId}
            </Link>
            <p
              className="font-mono text-xs text-muted-foreground"
              title={run.runId}
            >
              {truncateMiddle(run.runId, 10, 8)}
            </p>
          </div>
        ),
      },
      {
        key: "mode",
        header: "授权模式",
        cell: (run) => (
          <span className="whitespace-nowrap text-xs text-foreground">
            {resolveModeLabel(run.task?.mode)}
          </span>
        ),
      },
      {
        key: "amount",
        header: "单笔上限",
        align: "right",
        sortable: true,
        sortValue: (run) => run.task?.maxAmountMinor ?? 0,
        cell: (run) => (
          <span className="whitespace-nowrap font-medium tabular-nums">
            {formatMinorAmount(run.task?.maxAmountMinor)}
          </span>
        ),
      },
      {
        key: "stage",
        header: "当前阶段",
        cell: (run) => (
          <span className="whitespace-nowrap text-xs text-muted-foreground">
            {resolveStageLabel(run.stage)}
          </span>
        ),
      },
      {
        key: "status",
        header: "运行状态",
        cell: (run) => <StatusBadge status={run.status} />,
      },
      {
        key: "confirmedAt",
        header: "确认时间",
        sortable: true,
        sortValue: (run) => run.confirmedAt,
        cell: (run) => (
          <span className="whitespace-nowrap text-xs tabular-nums text-muted-foreground">
            {formatUnixSeconds(run.confirmedAt, { includeSeconds: false })}
          </span>
        ),
      },
      {
        key: "actions",
        header: "操作",
        align: "right",
        cell: (run) => (
          <DropdownMenu>
            <DropdownMenuTrigger
              render={
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  aria-label={`打开运行 ${run.runId} 的操作菜单`}
                  className="size-9 rounded-lg"
                />
              }
            >
              <MoreHorizontal className="size-4" strokeWidth={2} aria-hidden="true" />
            </DropdownMenuTrigger>
            <DropdownMenuContent
              align="end"
              className="rounded-xl border border-border bg-popover shadow-e2"
            >
              <DropdownMenuItem
                onClick={() =>
                  navigate(`/runs/${encodeURIComponent(run.runId)}`)
                }
              >
                查看运行详情与业务证据
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        ),
      },
    ],
    [navigate],
  );

  return (
    <div className="space-y-4">
      <PageHeader
        title="采购运行"
        description="查看当前采购员已确认的跨域采购任务、委托执行阶段与实时结果。"
        actions={
          <>
            <Button
              type="button"
              variant="outline"
              size="sm"
              disabled={loading}
              onClick={() => void loadRuns()}
              className="h-9 gap-1.5 rounded-lg"
            >
              <RefreshCw
                className={`size-4 ${loading ? "animate-spin" : ""}`}
                strokeWidth={2}
                aria-hidden="true"
              />
              <span>刷新列表</span>
            </Button>
            <Button
              type="button"
              size="sm"
              onClick={() => navigate("/chat")}
              className="h-9 gap-1.5 rounded-lg"
            >
              <MessageSquarePlus
                className="size-4"
                strokeWidth={2}
                aria-hidden="true"
              />
              <span>发起采购对话</span>
            </Button>
          </>
        }
      />

      <FilterBar
        searchValue={search}
        onSearchChange={setSearch}
        searchPlaceholder="按运行 ID、任务 ID、商品或说明筛选"
        searchAriaLabel="筛选采购运行"
        hasActiveFilters={hasActiveFilters}
        onReset={() => {
          setSearch("");
          setStatusFilter(ALL_FILTER);
          setModeFilter(ALL_FILTER);
        }}
      >
        <Select
          value={statusFilter}
          onValueChange={(val) => setStatusFilter(val ?? ALL_FILTER)}
        >
          <SelectTrigger
            aria-label="按状态筛选"
            className="h-9 w-40 rounded-lg"
          >
            <SelectValue placeholder="全部状态" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value={ALL_FILTER}>全部状态</SelectItem>
            <SelectItem value="PENDING">待确认 / 处理中</SelectItem>
            <SelectItem value="DECIDED">已定案</SelectItem>
            <SelectItem value="GATEWAY_DENIED">网关拒绝</SelectItem>
            <SelectItem value="OUTCOME_UNKNOWN">业务结果未知</SelectItem>
            <SelectItem value="MODEL_STOPPED">模型已停止</SelectItem>
            <SelectItem value="FAILED">失败</SelectItem>
          </SelectContent>
        </Select>

        <Select
          value={modeFilter}
          onValueChange={(val) => setModeFilter(val ?? ALL_FILTER)}
        >
          <SelectTrigger
            aria-label="按授权模式筛选"
            className="h-9 w-48 rounded-lg"
          >
            <SelectValue placeholder="全部授权模式" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value={ALL_FILTER}>全部授权模式</SelectItem>
            <SelectItem value="RESOURCE_PREAUTHORIZED">
              {MODE_LABELS.RESOURCE_PREAUTHORIZED}
            </SelectItem>
            <SelectItem value="BUYER_MANDATE">
              {MODE_LABELS.BUYER_MANDATE}
            </SelectItem>
          </SelectContent>
        </Select>
      </FilterBar>

      <DataTable
        caption="已确认的采购运行列表"
        columns={columns}
        rows={filteredRuns}
        rowKey={(run) => run.runId}
        loading={loading}
        error={error}
        onRetry={() => void loadRuns()}
        emptyState={
          hasActiveFilters ? (
            <EmptyState
              icon={<ShoppingBag className="size-5" strokeWidth={2} />}
              title="没有符合筛选条件的运行记录"
              description="调整关键词或清除筛选条件以查看全部采购运行。"
              action={
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={() => {
                    setSearch("");
                    setStatusFilter(ALL_FILTER);
                    setModeFilter(ALL_FILTER);
                  }}
                  className="rounded-lg"
                >
                  清除筛选条件
                </Button>
              }
            />
          ) : (
            <EmptyState
              icon={<ShoppingBag className="size-5" strokeWidth={2} />}
              title="还没有已确认的采购运行"
              description="先与 A1 采购智能体发起对话并确认结构化草稿，系统将在此展示实时运行状态。"
              action={
                <Button
                  type="button"
                  size="sm"
                  onClick={() => navigate("/chat")}
                  className="gap-1.5 rounded-lg"
                >
                  <MessageSquarePlus
                    className="size-4"
                    strokeWidth={2}
                    aria-hidden="true"
                  />
                  <span>发起采购对话</span>
                </Button>
              }
            />
          )
        }
      />
    </div>
  );
}
