import { Link } from "react-router-dom";
import {
  AlertTriangle,
  ArrowRight,
  Clock,
  ExternalLink,
  EyeOff,
  GitBranch,
  KeyRound,
  Receipt,
  Scale,
  ShieldCheck,
} from "lucide-react";
import type { FormattedApiError } from "@/api/http";
import type {
  DecisionSummary,
  DelegationEvidence,
  DisclosureEvidence,
  IdentityEvidence,
  PurchaseEvidence,
  RunEvidence,
} from "@/api/types";
import { EmptyState } from "@/components/patterns/EmptyState";
import { ErrorState } from "@/components/patterns/ErrorState";
import { KeyValueList } from "@/components/patterns/KeyValueList";
import { StatusBadge } from "@/components/patterns/StatusBadge";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useAuth } from "@/features/auth/AuthContext";
import { DOMAIN_LABELS, resolveModeLabel } from "@/lib/domain-labels";
import {
  EMPTY_PLACEHOLDER,
  formatInteger,
  formatMinorAmount,
  formatUnixSeconds,
  truncateMiddle,
} from "@/lib/format";
import { cn } from "@/lib/utils";

export interface RunEvidencePanelProps {
  evidence: RunEvidence | null;
  loading: boolean;
  error: FormattedApiError | null;
  onRetry: () => void;
  taskMaxAmountMinor?: number;
}

function resolveHopLevel(item: DelegationEvidence): "G0" | "G1" | "G2" {
  if (!item.parentId) return "G0";
  if (item.parentId === item.rootId) return "G1";
  return "G2";
}

/**
 * Resolves the effective single-order amount ceiling (in minor units) for quote comparison.
 * Prioritizes the tightest active delegation hop (G2 -> G1 -> confirmed task limit -> G0)
 * so an unissued G2 never silently falls back to a looser G0 supplier root ceiling.
 */
// eslint-disable-next-line react-refresh/only-export-components
export function resolveEffectiveCeilingMinor(
  delegations: DelegationEvidence[],
  taskMaxAmountMinor?: number,
): number | undefined {
  let g0: number | undefined;
  let g1: number | undefined;
  let g2: number | undefined;
  for (const hop of delegations) {
    if (hop.maxAmountMinor === undefined || hop.maxAmountMinor <= 0) {
      continue;
    }
    const level = resolveHopLevel(hop);
    if (level === "G2") g2 = hop.maxAmountMinor;
    else if (level === "G1") g1 = hop.maxAmountMinor;
    else g0 = hop.maxAmountMinor;
  }
  const taskCap =
    taskMaxAmountMinor !== undefined && taskMaxAmountMinor > 0
      ? taskMaxAmountMinor
      : undefined;
  return g2 ?? g1 ?? taskCap ?? g0;
}

function isGrantInactive(status: string): boolean {
  const key = status.trim().toLowerCase();
  return (
    key === "suspended" ||
    key === "paused" ||
    key === "revoked" ||
    key === "expired" ||
    key === "failed"
  );
}

function PurchaseView({
  purchase,
  ceilingMinor,
}: {
  purchase: PurchaseEvidence;
  ceilingMinor?: number;
}) {
  return (
    <div className="space-y-5">
      <div className="rounded-lg border border-border bg-muted p-4">
        <KeyValueList
          columns={3}
          items={[
            {
              label: "任务 ID",
              value: purchase.taskId,
              mono: true,
              copyText: purchase.taskId,
            },
            {
              label: "目标商品",
              value: purchase.productId,
              mono: true,
            },
            {
              label: "采购数量 / 单笔上限",
              value: `${formatInteger(purchase.quantity)} 件${ceilingMinor ? ` · 上限 ${formatMinorAmount(ceilingMinor)}` : ""}`,
            },
          ]}
        />
      </div>

      <div className="space-y-2.5">
        <div className="flex items-center justify-between gap-2">
          <h3 className="text-sm font-semibold text-foreground">
            供应商报价记录（{purchase.quotes.length}）
          </h3>
          <span className="text-xs text-muted-foreground">
            对照 P1（¥800.00）与 P2（¥1,200.00）报价及授权单笔上限
          </span>
        </div>

        {purchase.quotes.length === 0 ? (
          <EmptyState
            icon={<Receipt className="size-5" strokeWidth={2} />}
            title="暂无供应商报价记录"
            description="待 B1 代理向 C 网关发起询价后，原始报价金额与有效期将展示在此处。"
          />
        ) : (
          <div className="overflow-hidden rounded-xl border border-border bg-card">
            <Table aria-label="供应商报价明细">
              <caption className="sr-only">供应商报价明细</caption>
              <TableHeader>
                <TableRow className="h-10 bg-muted hover:bg-muted">
                  <TableHead scope="col" className="px-3 text-xs font-medium text-muted-foreground">
                    报价 ID
                  </TableHead>
                  <TableHead scope="col" className="px-3 text-xs font-medium text-muted-foreground">
                    商品 / 数量
                  </TableHead>
                  <TableHead scope="col" className="px-3 text-right text-xs font-medium text-muted-foreground">
                    单价
                  </TableHead>
                  <TableHead scope="col" className="px-3 text-right text-xs font-medium text-muted-foreground">
                    总金额
                  </TableHead>
                  <TableHead scope="col" className="px-3 text-xs font-medium text-muted-foreground">
                    上限对照
                  </TableHead>
                  <TableHead scope="col" className="px-3 text-xs font-medium text-muted-foreground">
                    有效期至
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {purchase.quotes.map((quote) => {
                  const exceedsLimit =
                    ceilingMinor !== undefined &&
                    quote.totalAmountMinor > ceilingMinor;
                  return (
                    <TableRow key={quote.quoteId} className="h-10 hover:bg-muted">
                      <TableCell
                        className="px-3 font-mono text-xs"
                        title={quote.quoteId}
                      >
                        {truncateMiddle(quote.quoteId, 10, 6)}
                      </TableCell>
                      <TableCell className="px-3 text-xs">
                        <span className="font-mono">{quote.productId}</span> ×{" "}
                        <span className="tabular-nums">
                          {formatInteger(quote.quantity)}
                        </span>
                      </TableCell>
                      <TableCell className="px-3 text-right text-sm tabular-nums">
                        {formatMinorAmount(quote.unitPriceMinor, quote.currency)}
                      </TableCell>
                      <TableCell className="px-3 text-right text-sm font-semibold tabular-nums">
                        {formatMinorAmount(quote.totalAmountMinor, quote.currency)}
                      </TableCell>
                      <TableCell className="px-3">
                        {ceilingMinor !== undefined ? (
                          <StatusBadge
                            status={exceedsLimit ? "denied" : "allowed"}
                            label={exceedsLimit ? "超出单笔上限" : "在上限内"}
                          />
                        ) : (
                          <span className="text-xs text-muted-foreground">
                            {EMPTY_PLACEHOLDER}
                          </span>
                        )}
                      </TableCell>
                      <TableCell className="px-3 text-xs tabular-nums text-muted-foreground">
                        {formatUnixSeconds(quote.validUntil, {
                          includeSeconds: false,
                        })}
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </div>
        )}
      </div>

      <div className="space-y-2.5">
        <h3 className="text-sm font-semibold text-foreground">
          C 主库成交订单（{purchase.orders.length}）
        </h3>

        {purchase.orders.length === 0 ? (
          <div className="rounded-lg border border-border bg-background px-4 py-5 text-sm text-muted-foreground">
            当前任务尚未生成成交订单（可能仍在执行中，或因超限、委托暂停被 C 网关拦截拒绝）。
          </div>
        ) : (
          <div className="overflow-hidden rounded-xl border border-border bg-card">
            <Table aria-label="成交订单明细">
              <caption className="sr-only">成交订单明细</caption>
              <TableHeader>
                <TableRow className="h-10 bg-muted hover:bg-muted">
                  <TableHead scope="col" className="px-3 text-xs font-medium text-muted-foreground">
                    订单 ID
                  </TableHead>
                  <TableHead scope="col" className="px-3 text-xs font-medium text-muted-foreground">
                    关联报价 ID
                  </TableHead>
                  <TableHead scope="col" className="px-3 text-right text-xs font-medium text-muted-foreground">
                    订单总额
                  </TableHead>
                  <TableHead scope="col" className="px-3 text-xs font-medium text-muted-foreground">
                    状态
                  </TableHead>
                  <TableHead scope="col" className="px-3 text-xs font-medium text-muted-foreground">
                    创建时间
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {purchase.orders.map((order) => (
                  <TableRow key={order.orderId} className="h-10 hover:bg-muted">
                    <TableCell
                      className="px-3 font-mono text-xs"
                      title={order.orderId}
                    >
                      {truncateMiddle(order.orderId, 10, 6)}
                    </TableCell>
                    <TableCell
                      className="px-3 font-mono text-xs text-muted-foreground"
                      title={order.quoteId}
                    >
                      {truncateMiddle(order.quoteId, 10, 6)}
                    </TableCell>
                    <TableCell className="px-3 text-right text-sm font-semibold tabular-nums">
                      {formatMinorAmount(order.totalAmountMinor, order.currency)}
                    </TableCell>
                    <TableCell className="px-3">
                      <StatusBadge status={order.status} />
                    </TableCell>
                    <TableCell className="px-3 text-xs tabular-nums text-muted-foreground">
                      {formatUnixSeconds(order.createdAt, {
                        includeSeconds: false,
                      })}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </div>
    </div>
  );
}

function IdentityView({ items }: { items: IdentityEvidence[] }) {
  if (items.length === 0) {
    return (
      <EmptyState
        icon={<KeyRound className="size-5" strokeWidth={2} />}
        title="暂无身份与信任链证据"
        description="当网关完成跨域主体 DID、密钥版本与域认证校验后，完整信任链记录将呈现在此处。"
      />
    );
  }

  return (
    <ol className="space-y-3">
      {items.map((item, idx) => (
        <li
          key={`${item.did}-${item.decisionId}-${idx}`}
          className="space-y-3 rounded-lg border border-border bg-background p-4"
        >
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex flex-wrap items-center gap-2">
              <Badge variant="secondary" className="text-xs">
                {item.kind}
              </Badge>
              {item.domainId && (
                <Badge variant="outline" className="text-xs">
                  {DOMAIN_LABELS[item.domainId]}
                </Badge>
              )}
              <span className="font-mono text-xs text-muted-foreground">
                密钥版本 v{item.keyVersion}
              </span>
            </div>
            <StatusBadge status={item.status} />
          </div>

          <KeyValueList
            columns={2}
            items={[
              {
                label: "主体 DID",
                value: item.did,
                mono: true,
                copyText: item.did,
              },
              {
                label: "签发者 DID",
                value: item.issuerDid ?? EMPTY_PLACEHOLDER,
                mono: Boolean(item.issuerDid),
                copyText: item.issuerDid,
              },
              {
                label: "域认证 ID",
                value: item.certificationId ?? EMPTY_PLACEHOLDER,
                mono: Boolean(item.certificationId),
                copyText: item.certificationId,
              },
              {
                label: "域认证摘要",
                value: item.certificationDigest ?? EMPTY_PLACEHOLDER,
                mono: Boolean(item.certificationDigest),
                copyText: item.certificationDigest,
              },
              {
                label: "关联决定 ID",
                value: item.decisionId,
                mono: true,
                copyText: item.decisionId,
              },
            ]}
          />
        </li>
      ))}
    </ol>
  );
}

function DisclosuresView({ items }: { items: DisclosureEvidence[] }) {
  if (items.length === 0) {
    return (
      <EmptyState
        icon={<EyeOff className="size-5" strokeWidth={2} />}
        title="暂无凭证披露记录"
        description="跨域业务请求携带选择性披露身份凭证并通过校验后，此处展示实际披露的最小声明集合。"
      />
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-start gap-2.5 rounded-lg border border-border bg-muted px-3.5 py-2.5 text-xs leading-5 text-muted-foreground">
        <ShieldCheck
          className="mt-0.5 size-4 shrink-0 text-brand"
          strokeWidth={2}
          aria-hidden="true"
        />
        <span>
          最小披露边界：仅展示网关实际核验并采信的域（domain）与角色（role）声明，未披露属性与密码学盐值严格隔离在签发与持有端。
        </span>
      </div>

      <ol className="space-y-3">
        {items.map((item, idx) => (
          <li
            key={`${item.credentialId}-${item.decisionId}-${idx}`}
            className="space-y-3 rounded-lg border border-border bg-background p-4"
          >
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-xs font-medium text-muted-foreground">
                  已披露声明：
                </span>
                <Badge variant="secondary" className="text-xs">
                  域: {item.disclosed.domain ?? EMPTY_PLACEHOLDER}
                </Badge>
                <Badge variant="secondary" className="text-xs">
                  角色: {item.disclosed.role ?? EMPTY_PLACEHOLDER}
                </Badge>
              </div>
              <StatusBadge status={item.status} />
            </div>

            <KeyValueList
              columns={2}
              items={[
                {
                  label: "凭证 ID",
                  value: item.credentialId,
                  mono: true,
                  copyText: item.credentialId,
                },
                {
                  label: "主体 DID",
                  value: item.subjectDid,
                  mono: true,
                  copyText: item.subjectDid,
                },
                {
                  label: "签发者 DID",
                  value: item.issuerDid,
                  mono: true,
                  copyText: item.issuerDid,
                },
                {
                  label: "密钥版本（主体 / 签发者）",
                  value: `v${item.subjectKeyVersion} / v${item.issuerKeyVersion}`,
                  mono: true,
                },
                {
                  label: "关联决定 ID",
                  value: item.decisionId,
                  mono: true,
                  copyText: item.decisionId,
                },
              ]}
            />
          </li>
        ))}
      </ol>
    </div>
  );
}

function DelegationsView({
  items,
  decisions,
}: {
  items: DelegationEvidence[];
  decisions: DecisionSummary[];
}) {
  if (items.length === 0) {
    return (
      <EmptyState
        icon={<GitBranch className="size-5" strokeWidth={2} />}
        title="暂无委托树记录"
        description="完成 G0 根委托与 G1 / G2 子委托签发后，此处将按层级展示逐跳收缩约束与祖先有效性。"
      />
    );
  }

  const byId = new Map(items.map((item) => [item.grantId, item]));
  const failedObjects = new Set(
    decisions
      .map((d) => d.failedObjectId)
      .filter((id): id is string => Boolean(id)),
  );

  const findInvalidAncestor = (
    hop: DelegationEvidence,
  ): DelegationEvidence | null => {
    let cursor = hop.parentId ? byId.get(hop.parentId) : undefined;
    const visited = new Set<string>([hop.grantId]);
    while (cursor && !visited.has(cursor.grantId)) {
      visited.add(cursor.grantId);
      if (isGrantInactive(cursor.status) || failedObjects.has(cursor.grantId)) {
        return cursor;
      }
      cursor = cursor.parentId ? byId.get(cursor.parentId) : undefined;
    }
    return null;
  };

  const ordered = [...items].sort((a, b) => {
    const rank = { G0: 0, G1: 1, G2: 2 };
    return rank[resolveHopLevel(a)] - rank[resolveHopLevel(b)];
  });

  return (
    <ol className="space-y-3">
      {ordered.map((hop) => {
        const level = resolveHopLevel(hop);
        const parent = hop.parentId ? byId.get(hop.parentId) : undefined;
        const invalidAncestor = findInvalidAncestor(hop);
        const isDirectFailed = failedObjects.has(hop.grantId);

        const indentClass =
          level === "G0" ? "" : level === "G1" ? "sm:ml-4" : "sm:ml-8";

        const amountNarrowed =
          parent?.maxAmountMinor !== undefined &&
          hop.maxAmountMinor !== undefined &&
          hop.maxAmountMinor <= parent.maxAmountMinor;
        const expNarrowed = parent !== undefined && hop.exp <= parent.exp;

        return (
          <li
            key={hop.grantId}
            className={cn(
              "space-y-3 rounded-lg border bg-background p-4",
              isDirectFailed || isGrantInactive(hop.status)
                ? "border-destructive"
                : invalidAncestor
                  ? "border-warning"
                  : "border-border",
              indentClass,
            )}
          >
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex flex-wrap items-center gap-2">
                <Badge
                  variant={level === "G0" ? "default" : "secondary"}
                  className="font-mono text-xs"
                >
                  {level}
                </Badge>
                <span className="text-xs font-medium text-muted-foreground">
                  {resolveModeLabel(hop.mode)}
                </span>
                <span className="font-mono text-xs text-muted-foreground">
                  版本 v{hop.revision} · 剩余深度 {hop.remainingDepth}
                </span>
              </div>
              <StatusBadge status={hop.status} />
            </div>

            {invalidAncestor && (
              <div
                role="status"
                className="flex items-start gap-2 rounded-lg border border-warning bg-muted px-3 py-2 text-xs leading-5 text-warning-text"
              >
                <AlertTriangle
                  className="mt-0.5 size-4 shrink-0"
                  aria-hidden="true"
                />
                <span>
                  失效祖先传播：上游祖先委托 {resolveHopLevel(invalidAncestor)}（
                  <span className="font-mono">
                    {truncateMiddle(invalidAncestor.grantId, 10, 6)}
                  </span>
                  ）当前状态为「{invalidAncestor.status}」，本跳及后续委托链在网关侧均失效。
                </span>
              </div>
            )}

            {isDirectFailed && (
              <div
                role="alert"
                className="flex items-start gap-2 rounded-lg border border-destructive bg-muted px-3 py-2 text-xs leading-5 text-destructive"
              >
                <AlertTriangle
                  className="mt-0.5 size-4 shrink-0"
                  aria-hidden="true"
                />
                <span>网关决策记录指向本委托为校验失败对象（failedObjectId）。</span>
              </div>
            )}

            {parent && (
              <div className="flex flex-wrap items-center gap-2 rounded-md bg-muted px-3 py-1.5 text-xs text-muted-foreground">
                <span>逐跳收缩核对（相对 {resolveHopLevel(parent)}）：</span>
                <span className="tabular-nums text-foreground">
                  上限 {formatMinorAmount(parent.maxAmountMinor)}{" "}
                  <ArrowRight className="inline size-3" aria-hidden="true" />{" "}
                  {formatMinorAmount(hop.maxAmountMinor)}
                  {amountNarrowed ? "（满足单调不增）" : ""}
                </span>
                <span className="tabular-nums text-foreground">
                  · 深度 {parent.remainingDepth}{" "}
                  <ArrowRight className="inline size-3" aria-hidden="true" />{" "}
                  {hop.remainingDepth}
                </span>
                <span className="text-foreground">
                  · 截止时间{expNarrowed ? "已收敛" : "待核对"}
                </span>
              </div>
            )}

            <KeyValueList
              columns={2}
              items={[
                {
                  label: "委托 ID（grantId）",
                  value: hop.grantId,
                  mono: true,
                  copyText: hop.grantId,
                },
                {
                  label: "父委托 ID",
                  value: hop.parentId ?? "根委托（无父节点）",
                  mono: Boolean(hop.parentId),
                  copyText: hop.parentId,
                },
                {
                  label: "签发者 DID",
                  value: hop.issuerDid,
                  mono: true,
                  copyText: hop.issuerDid,
                },
                {
                  label: "受托者 DID",
                  value: hop.granteeDid,
                  mono: true,
                  copyText: hop.granteeDid,
                },
                {
                  label: "单笔上限",
                  value: formatMinorAmount(hop.maxAmountMinor),
                },
                {
                  label: "原委托有效期（nbf → exp）",
                  value: `${formatUnixSeconds(hop.nbf, { includeSeconds: false })} → ${formatUnixSeconds(hop.exp, { includeSeconds: false })}`,
                },
              ]}
            />
          </li>
        );
      })}
    </ol>
  );
}

function DecisionsTimelineView({ items }: { items: DecisionSummary[] }) {
  const { hasAction } = useAuth();
  const canAudit = hasAction("auditDecisions");

  if (items.length === 0) {
    return (
      <EmptyState
        icon={<Clock className="size-5" strokeWidth={2} />}
        title="暂无网关决策时间线"
        description="当 B1 代理向 C 网关发起询价或下单请求后，所有放行与拒绝记录将按时间顺序呈现在此处。"
      />
    );
  }

  return (
    <ol className="space-y-3">
      {items.map((item, idx) => {
        const isPrecheck = Boolean(item.requestId && !item.decisionId);
        return (
          <li
            key={`${item.decisionId ?? item.requestId ?? "dec"}-${idx}`}
            className="space-y-3 rounded-lg border border-border bg-background p-4"
          >
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-sm font-semibold text-foreground">
                  {item.action}
                </span>
                {isPrecheck && (
                  <Badge variant="outline" className="text-xs">
                    预检记录
                  </Badge>
                )}
                <span className="text-xs tabular-nums text-muted-foreground">
                  {formatUnixSeconds(item.decisionAt)}
                </span>
              </div>
              <StatusBadge status={item.outcome} />
            </div>

            <KeyValueList
              columns={2}
              items={[
                {
                  label: "决定 ID",
                  value: item.decisionId ?? EMPTY_PLACEHOLDER,
                  mono: Boolean(item.decisionId),
                  copyText: item.decisionId,
                },
                {
                  label: "决定原因码",
                  value: item.code,
                  mono: true,
                },
                ...(item.failedObjectId
                  ? [
                      {
                        label: "失效对象 ID（failedObjectId）",
                        value: item.failedObjectId,
                        mono: true,
                        copyText: item.failedObjectId,
                      },
                    ]
                  : []),
                {
                  label: "采用块高",
                  value:
                    item.blockNumber > 0 || item.blockHash
                      ? formatInteger(item.blockNumber)
                      : EMPTY_PLACEHOLDER,
                },
                {
                  label: "采用区块哈希",
                  value: item.blockHash || EMPTY_PLACEHOLDER,
                  mono: Boolean(item.blockHash),
                  copyText: item.blockHash || undefined,
                },
                {
                  label: "策略摘要（policyDigest）",
                  value: item.policyDigest || EMPTY_PLACEHOLDER,
                  mono: Boolean(item.policyDigest),
                  copyText: item.policyDigest || undefined,
                },
                {
                  label: "环境版本（contextVersion）",
                  value:
                    item.contextVersion > 0
                      ? formatInteger(item.contextVersion)
                      : EMPTY_PLACEHOLDER,
                },
                {
                  label: "原探针期限（probeDeadline）",
                  value: formatUnixSeconds(item.probeDeadline),
                },
                ...(item.probeTxId
                  ? [
                      {
                        label: "原探针交易 txId",
                        value: item.probeTxId,
                        mono: true,
                        copyText: item.probeTxId,
                      },
                    ]
                  : []),
                ...(item.quoteId
                  ? [
                      {
                        label: "关联报价 ID",
                        value: item.quoteId,
                        mono: true,
                        copyText: item.quoteId,
                      },
                    ]
                  : []),
                ...(item.orderId
                  ? [
                      {
                        label: "关联订单 ID",
                        value: item.orderId,
                        mono: true,
                        copyText: item.orderId,
                      },
                    ]
                  : []),
              ]}
            />

            {canAudit && item.decisionId && (
              <div className="pt-1">
                <Link
                  to={`/decisions/${encodeURIComponent(item.decisionId)}`}
                  className="inline-flex items-center gap-1.5 text-xs font-medium text-brand underline-offset-4 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                >
                  <span>打开完整决策审计记录</span>
                  <ExternalLink className="size-3.5" aria-hidden="true" />
                </Link>
              </div>
            )}
          </li>
        );
      })}
    </ol>
  );
}

export function RunEvidencePanel({
  evidence,
  loading,
  error,
  onRetry,
  taskMaxAmountMinor,
}: RunEvidencePanelProps) {
  if (loading && !evidence) {
    return (
      <Card>
        <CardHeader>
          <Skeleton className="h-5 w-40" />
          <Skeleton className="h-4 w-72" />
        </CardHeader>
        <CardContent className="space-y-3">
          <Skeleton className="h-9 w-full" />
          <Skeleton className="h-32 w-full" />
        </CardContent>
      </Card>
    );
  }

  if (error && !evidence) {
    return (
      <ErrorState
        title="业务证据暂不可用"
        message={error.message}
        code={error.code}
        requestId={error.requestId}
        onRetry={onRetry}
      />
    );
  }

  if (!evidence) {
    return (
      <Card>
        <CardContent className="p-0">
          <EmptyState
            icon={<Scale className="size-5" strokeWidth={2} />}
            title="等待业务证据投影"
            description="任务完成链上登记并进入跨域执行阶段后，将自动汇聚五类业务证据。"
          />
        </CardContent>
      </Card>
    );
  }

  const effectiveCeilingMinor = resolveEffectiveCeilingMinor(
    evidence.delegations,
    taskMaxAmountMinor,
  );

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base font-semibold">
          五类角色可见业务证据
        </CardTitle>
        <CardDescription className="text-sm text-muted-foreground">
          依据链上真实登记、委托交付与 C 网关结果实时投影，与服务端权限边界严格一致。
        </CardDescription>
      </CardHeader>

      <CardContent>
        <Tabs defaultValue="purchase" className="space-y-4">
          <TabsList className="flex h-auto w-full flex-wrap justify-start gap-1">
            <TabsTrigger value="purchase">
              报价与订单（{evidence.purchase.quotes.length}/
              {evidence.purchase.orders.length}）
            </TabsTrigger>
            <TabsTrigger value="delegations">
              委托树（{evidence.delegations.length}）
            </TabsTrigger>
            <TabsTrigger value="decisions">
              决策时间线（{evidence.decisions.length}）
            </TabsTrigger>
            <TabsTrigger value="identity">
              身份与信任（{evidence.identity.length}）
            </TabsTrigger>
            <TabsTrigger value="disclosures">
              凭证披露（{evidence.disclosures.length}）
            </TabsTrigger>
          </TabsList>

          <TabsContent value="purchase">
            <PurchaseView
              purchase={evidence.purchase}
              ceilingMinor={effectiveCeilingMinor}
            />
          </TabsContent>

          <TabsContent value="delegations">
            <DelegationsView
              items={evidence.delegations}
              decisions={evidence.decisions}
            />
          </TabsContent>

          <TabsContent value="decisions">
            <DecisionsTimelineView items={evidence.decisions} />
          </TabsContent>

          <TabsContent value="identity">
            <IdentityView items={evidence.identity} />
          </TabsContent>

          <TabsContent value="disclosures">
            <DisclosuresView items={evidence.disclosures} />
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  );
}
