import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { DelegationEvidence, Run } from "@/api/types";
import { DataTable, type DataTableColumn } from "@/components/patterns/DataTable";
import { DisabledReasonTooltip } from "@/components/patterns/DisabledReasonTooltip";
import { EmptyState } from "@/components/patterns/EmptyState";
import { StatCard } from "@/components/patterns/StatCard";
import { StatusBadge } from "@/components/patterns/StatusBadge";
import { TooltipProvider } from "@/components/ui/tooltip";
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { resolveEffectiveCeilingMinor } from "@/features/evidence/RunEvidencePanel";
import { shouldPollRun } from "@/pages/RunDetailPage";

interface SampleRow {
  id: string;
  name: string;
}

const sampleColumns: DataTableColumn<SampleRow>[] = [
  {
    key: "id",
    header: "ID",
    stickyFirst: true,
    sortable: true,
    sortValue: (row) => row.id,
    cell: (row) => row.id,
  },
  { key: "name", header: "名称", cell: (row) => row.name },
];

describe("Pattern state matrix rendering", () => {
  it("renders DataTable loading skeletons, empty state with headers, error alert, and opaque sticky rows", () => {
    const loadingHtml = renderToStaticMarkup(
      <DataTable
        caption="测试表格"
        columns={sampleColumns}
        rows={[]}
        rowKey={(r) => r.id}
        loading
        emptyState={<EmptyState icon={<span>i</span>} title="无记录" description="请先创建一条记录。" />}
      />,
    );
    expect(loadingHtml).toContain("animate-pulse");
    expect(loadingHtml).toContain("<thead");

    const emptyHtml = renderToStaticMarkup(
      <DataTable
        caption="测试表格"
        columns={sampleColumns}
        rows={[]}
        rowKey={(r) => r.id}
        loading={false}
        emptyState={<EmptyState icon={<span>i</span>} title="还没有记录" description="点击新建开始操作。" />}
      />,
    );
    expect(emptyHtml).toContain("<thead");
    expect(emptyHtml).toContain("还没有记录");
    expect(emptyHtml).toContain("点击新建开始操作。");

    const errorHtml = renderToStaticMarkup(
      <DataTable
        caption="测试表格"
        columns={sampleColumns}
        rows={[]}
        rowKey={(r) => r.id}
        error={{ message: "后端连接中断。", code: "STATE_UNAVAILABLE", requestId: "req-42" }}
        onRetry={() => undefined}
        emptyState={<div />}
      />,
    );
    expect(errorHtml).toContain('role="alert"');
    expect(errorHtml).toContain("STATE_UNAVAILABLE");
    expect(errorHtml).toContain("req-42");
    expect(errorHtml).toContain("重新加载");

    const populatedHtml = renderToStaticMarkup(
      <DataTable
        caption="测试表格"
        columns={sampleColumns}
        rows={[
          { id: "r-1", name: "首条记录" },
          { id: "r-2", name: "已选记录" },
        ]}
        rowKey={(r) => r.id}
        selectedRowKey="r-2"
        emptyState={<div />}
      />,
    );
    expect(populatedHtml).toContain("bg-card hover:bg-muted");
    expect(populatedHtml).toContain("bg-brand-muted hover:bg-brand-muted");
    expect(populatedHtml).toContain("sticky left-0 z-10 bg-inherit");
    expect(populatedHtml).toContain("max-h-[70dvh] overflow-y-auto");
    expect((populatedHtml.match(/overflow-x-auto/g) ?? []).length).toBe(1);
    expect((populatedHtml.match(/aria-sort="none"/g) ?? []).length).toBe(1);
    expect(populatedHtml).toContain(
      "focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background",
    );
  });

  it("wraps disabled controls in a keyboard-focusable tooltip trigger only when a reason is provided", () => {
    const withReasonHtml = renderToStaticMarkup(
      <TooltipProvider>
        <DisabledReasonTooltip reason="超出字符上限">
          <button type="button" disabled>
            发送
          </button>
        </DisabledReasonTooltip>
      </TooltipProvider>,
    );
    expect(withReasonHtml).toContain('tabindex="0"');
    expect(withReasonHtml).toContain('data-slot="tooltip-trigger"');
    expect(withReasonHtml).toContain("focus-visible:ring-offset-2");

    const withoutReasonHtml = renderToStaticMarkup(
      <TooltipProvider>
        <DisabledReasonTooltip reason={null}>
          <button type="button">发送</button>
        </DisabledReasonTooltip>
      </TooltipProvider>,
    );
    expect(withoutReasonHtml).not.toContain('data-slot="tooltip-trigger"');
    expect(withoutReasonHtml).toContain(">发送</button>");
  });

  it("renders EmptyState with configurable heading level (h2 default, h1 for full-page states)", () => {
    const defaultHtml = renderToStaticMarkup(
      <EmptyState icon={<span>i</span>} title="默认标题" description="说明文案。" />,
    );
    expect(defaultHtml).toContain("<h2");
    expect(defaultHtml).not.toContain("<h1");

    const h1Html = renderToStaticMarkup(
      <EmptyState
        icon={<span>i</span>}
        headingAs="h1"
        title="无权访问"
        description="说明文案。"
      />,
    );
    expect(h1Html).toContain("<h1");
    expect(h1Html).not.toContain("<h2");
  });

  it("renders mapped Chinese labels instead of raw sentinel values in Base UI SelectValue", () => {
    const items = [
      { value: "__ALL__", label: "全部状态" },
      { value: "OUTCOME_UNKNOWN", label: "业务结果未知" },
    ] as const;

    const html = renderToStaticMarkup(
      <Select items={items} value="__ALL__">
        <SelectTrigger aria-label="按状态筛选">
          <SelectValue placeholder="全部状态" />
        </SelectTrigger>
        <SelectContent>
          {items.map((item) => (
            <SelectItem key={item.value} value={item.value}>
              {item.label}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>,
    );
    expect(html).toContain("全部状态");
    expect(html).not.toContain(">__ALL__<");
  });

  it("renders StatusBadge with both icon and semantic label (never color-only)", () => {
    for (const [status, expectedLabel] of [
      ["DECIDED", "已定案"],
      ["GATEWAY_DENIED", "网关拒绝"],
      ["OUTCOME_UNKNOWN", "业务结果未知"],
      ["SUSPENDED", "已暂停"],
      ["PENDING", "待确认"],
    ] as const) {
      const html = renderToStaticMarkup(<StatusBadge status={status} />);
      expect(html).toContain("<svg");
      expect(html).toContain('aria-hidden="true"');
      expect(html).toContain(expectedLabel);
    }
  });

  it("renders em-dash placeholder instead of 0 for empty StatCard values", () => {
    const emptyHtml = renderToStaticMarkup(<StatCard label="采购权威" value={null} />);
    expect(emptyHtml).toContain("—");
    expect(emptyHtml).not.toContain(">0<");
  });

  it("renders Breadcrumb with localized Chinese aria-label and unified focus-visible ring", () => {
    const html = renderToStaticMarkup(
      <Breadcrumb>
        <BreadcrumbList>
          <BreadcrumbItem>
            <BreadcrumbLink href="/runs">采购运行</BreadcrumbLink>
          </BreadcrumbItem>
          <BreadcrumbSeparator />
          <BreadcrumbItem>
            <BreadcrumbPage>运行详情</BreadcrumbPage>
          </BreadcrumbItem>
        </BreadcrumbList>
      </Breadcrumb>,
    );
    expect(html).toContain('aria-label="面包屑导航"');
    expect(html).toContain("focus-visible:ring-2");
    expect(html).toContain("focus-visible:ring-ring");
    expect(html).toContain("focus-visible:ring-offset-2");
  });
});

describe("Evidence ceiling resolution and run polling rules", () => {
  const makeGrant = (
    overrides: Partial<DelegationEvidence> & { grantId: string; rootId: string },
  ): DelegationEvidence => ({
    mode: "RESOURCE_PREAUTHORIZED",
    issuerDid: "did:web:c.example:org",
    granteeDid: "did:web:a.example:user:u",
    status: "ACTIVE",
    revision: 1,
    remainingDepth: 2,
    nbf: 1700000000,
    exp: 1700003600,
    ...overrides,
  });

  it("prioritizes G2 -> G1 -> confirmed task limit -> G0 when resolving quote ceiling", () => {
    const g0 = makeGrant({ grantId: "g0", rootId: "g0", maxAmountMinor: 500000 });
    const g1 = makeGrant({
      grantId: "g1",
      parentId: "g0",
      rootId: "g0",
      maxAmountMinor: 100000,
      remainingDepth: 1,
    });
    const g2 = makeGrant({
      grantId: "g2",
      parentId: "g1",
      rootId: "g0",
      maxAmountMinor: 85000,
      remainingDepth: 0,
    });

    // When G2 is not yet issued, must NOT fall back from missing G2 straight to looser G0.
    expect(resolveEffectiveCeilingMinor([g0, g1], 100000)).toBe(100000);
    expect(resolveEffectiveCeilingMinor([g0], 100000)).toBe(100000);
    // When G2 exists, G2 is the tightest execution bound.
    expect(resolveEffectiveCeilingMinor([g0, g1, g2], 100000)).toBe(85000);
    // Only fall back to G0 when neither G2, G1, nor taskMaxAmountMinor is available.
    expect(resolveEffectiveCeilingMinor([g0], undefined)).toBe(500000);
    expect(resolveEffectiveCeilingMinor([], undefined)).toBeUndefined();
  });

  it("polls runs only while non-terminal or while a ledger step is still pending", () => {
    const baseRun: Run = {
      runId: "run-1",
      taskId: "task-1",
      draftId: "draft-1",
      stage: "EXECUTE",
      status: "DECIDED",
      confirmedAt: 1700000000,
      task: {
        draftId: "draft-1",
        version: 1,
        productId: "urn:grad:product:P1",
        quantity: 1,
        mode: "RESOURCE_PREAUTHORIZED",
        maxAmountMinor: 100000,
        expiresAt: 1700003600,
        delegateDid: "did:web:a.example:agent:a1",
        description: "采购 P1",
      },
      steps: [{ stage: "REGISTER_TASK", status: "CONFIRMED", at: 1700000001 }],
      traces: [],
    };

    expect(shouldPollRun(null, false)).toBe(false);
    expect(shouldPollRun(baseRun, true)).toBe(false);
    expect(shouldPollRun(baseRun, false)).toBe(false);
    expect(shouldPollRun({ ...baseRun, status: "PENDING" }, false)).toBe(true);
    expect(shouldPollRun({ ...baseRun, status: "OUTCOME_UNKNOWN" }, false)).toBe(
      true,
    );
    expect(
      shouldPollRun({ ...baseRun, status: "OUTCOME_UNKNOWN" }, true),
    ).toBe(false);
    expect(
      shouldPollRun(
        {
          ...baseRun,
          status: "DECIDED",
          steps: [
            ...baseRun.steps,
            { stage: "SuspendGrant", status: "PENDING", at: 1700000010 },
          ],
        },
        false,
      ),
    ).toBe(true);
  });
});
