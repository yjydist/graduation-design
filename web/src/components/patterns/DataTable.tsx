import { useMemo, useState, type ReactNode } from "react";
import { ArrowDown, ArrowUp, ArrowUpDown, ChevronLeft, ChevronRight } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { ErrorState } from "@/components/patterns/ErrorState";
import { cn } from "@/lib/utils";

export interface DataTableColumn<T> {
  key: string;
  header: string;
  align?: "left" | "right";
  stickyFirst?: boolean;
  sortable?: boolean;
  sortValue?: (row: T) => string | number;
  cell: (row: T) => ReactNode;
  headerClassName?: string;
  cellClassName?: string;
}

export interface DataTableProps<T> {
  caption: string;
  columns: DataTableColumn<T>[];
  rows: T[];
  rowKey: (row: T) => string;
  loading?: boolean;
  error?: { message: string; code?: string; requestId?: string } | null;
  onRetry?: () => void;
  emptyState: ReactNode;
  selectedRowKey?: string | null;
  compact?: boolean;
  pageSize?: number;
  className?: string;
}

export function DataTable<T>({
  caption,
  columns,
  rows,
  rowKey,
  loading = false,
  error = null,
  onRetry,
  emptyState,
  selectedRowKey = null,
  compact = false,
  pageSize = 10,
  className,
}: DataTableProps<T>) {
  const [sortKey, setSortKey] = useState<string | null>(null);
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");
  const [page, setPage] = useState(1);

  const sortedRows = useMemo(() => {
    if (!sortKey) return rows;
    const col = columns.find((item) => item.key === sortKey);
    if (!col?.sortValue) return rows;
    const getter = col.sortValue;
    return [...rows].sort((a, b) => {
      const av = getter(a);
      const bv = getter(b);
      if (av === bv) return 0;
      const cmp = av < bv ? -1 : 1;
      return sortDir === "asc" ? cmp : -cmp;
    });
  }, [rows, columns, sortKey, sortDir]);

  const totalPages = Math.max(1, Math.ceil(sortedRows.length / pageSize));
  const safePage = Math.min(page, totalPages);
  const pagedRows = useMemo(() => {
    const start = (safePage - 1) * pageSize;
    return sortedRows.slice(start, start + pageSize);
  }, [sortedRows, safePage, pageSize]);

  const handleSort = (key: string) => {
    setPage(1);
    if (sortKey !== key) {
      setSortKey(key);
      setSortDir("desc");
      return;
    }
    if (sortDir === "desc") {
      setSortDir("asc");
      return;
    }
    setSortKey(null);
  };

  if (error) {
    return (
      <ErrorState
        message={error.message}
        code={error.code}
        requestId={error.requestId}
        onRetry={onRetry}
        className={className}
      />
    );
  }

  return (
    <div className={cn("space-y-3", className)}>
      <div className="overflow-hidden rounded-xl border border-border bg-card">
        <div className="overflow-x-auto">
          <Table aria-label={caption}>
            <caption className="sr-only">{caption}</caption>
            <TableHeader>
              <TableRow className="h-10 bg-muted hover:bg-muted">
                {columns.map((column, index) => {
                  const isSticky = column.stickyFirst || index === 0;
                  const isSorted = sortKey === column.key;
                  return (
                    <TableHead
                      key={column.key}
                      scope="col"
                      className={cn(
                        "sticky top-0 z-10 h-10 bg-muted px-3 text-xs font-medium text-muted-foreground md:px-4",
                        column.align === "right" && "text-right",
                        isSticky && "left-0 z-20",
                        column.headerClassName,
                      )}
                    >
                      {column.sortable && column.sortValue ? (
                        <button
                          type="button"
                          onClick={() => handleSort(column.key)}
                          className={cn(
                            "inline-flex items-center gap-1 rounded-sm text-xs font-medium text-muted-foreground transition-colors duration-150 hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
                            column.align === "right" && "ml-auto",
                          )}
                        >
                          <span>{column.header}</span>
                          {isSorted ? (
                            sortDir === "asc" ? (
                              <ArrowUp className="size-3.5" aria-hidden="true" />
                            ) : (
                              <ArrowDown className="size-3.5" aria-hidden="true" />
                            )
                          ) : (
                            <ArrowUpDown className="size-3.5 opacity-60" aria-hidden="true" />
                          )}
                        </button>
                      ) : (
                        column.header
                      )}
                    </TableHead>
                  );
                })}
              </TableRow>
            </TableHeader>
            <TableBody>
              {loading ? (
                Array.from({ length: 6 }).map((_, rowIndex) => (
                  <TableRow
                    key={`skeleton-${rowIndex}`}
                    className={cn(compact ? "h-8" : "h-10")}
                  >
                    {columns.map((column) => (
                      <TableCell
                        key={`${column.key}-${rowIndex}`}
                        className="px-3 md:px-4"
                      >
                        <Skeleton className="h-4 w-full max-w-40" />
                      </TableCell>
                    ))}
                  </TableRow>
                ))
              ) : pagedRows.length === 0 ? (
                <TableRow className="hover:bg-transparent">
                  <TableCell colSpan={columns.length} className="p-0">
                    {emptyState}
                  </TableCell>
                </TableRow>
              ) : (
                pagedRows.map((row) => {
                  const id = rowKey(row);
                  const selected = selectedRowKey === id;
                  return (
                    <TableRow
                      key={id}
                      data-state={selected ? "selected" : undefined}
                      className={cn(
                        compact ? "h-8" : "h-10",
                        "transition-colors duration-150",
                        selected
                          ? "bg-brand-muted hover:bg-brand-muted"
                          : "bg-card hover:bg-muted",
                      )}
                    >
                      {columns.map((column, index) => {
                        const isSticky = column.stickyFirst || index === 0;
                        return (
                          <TableCell
                            key={column.key}
                            className={cn(
                              "px-3 text-sm md:px-4",
                              column.align === "right" &&
                                "text-right tabular-nums",
                              isSticky &&
                                "sticky left-0 z-10 bg-inherit",
                              column.cellClassName,
                            )}
                          >
                            {column.cell(row)}
                          </TableCell>
                        );
                      })}
                    </TableRow>
                  );
                })
              )}
            </TableBody>
          </Table>
        </div>
      </div>

      {!loading && sortedRows.length > pageSize && (
        <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-muted-foreground">
          <p className="tabular-nums">
            共 {sortedRows.length} 条记录，第 {safePage} / {totalPages} 页
          </p>
          <div className="flex items-center gap-2">
            <Button
              type="button"
              variant="outline"
              size="sm"
              disabled={safePage <= 1}
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              className="h-8 gap-1 rounded-lg px-2.5"
            >
              <ChevronLeft className="size-4" aria-hidden="true" />
              <span>上一页</span>
            </Button>
            <Button
              type="button"
              variant="outline"
              size="sm"
              disabled={safePage >= totalPages}
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              className="h-8 gap-1 rounded-lg px-2.5"
            >
              <span>下一页</span>
              <ChevronRight className="size-4" aria-hidden="true" />
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}
