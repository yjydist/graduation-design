import { apiRequest } from "@/api/http";
import type {
  ChatInput,
  ChatResult,
  Draft,
  DraftEdit,
  Run,
  ToolTrace,
} from "@/api/types";

/**
 * L4 Agent API client: buyer-to-A1 natural language chat, structured draft editing,
 * version-pinned draft confirmation, and sanitized dispatch trace interpretation.
 */
export const agentApi = {
  sendChat(input: ChatInput): Promise<ChatResult> {
    return apiRequest<ChatResult>("/chat", {
      method: "POST",
      body: input,
    });
  },

  getDraft(draftId: string, signal?: AbortSignal): Promise<Draft> {
    return apiRequest<Draft>(`/drafts/${encodeURIComponent(draftId)}`, {
      signal,
    });
  },

  updateDraft(draftId: string, input: DraftEdit): Promise<Draft> {
    return apiRequest<Draft>(`/drafts/${encodeURIComponent(draftId)}`, {
      method: "PUT",
      body: input,
    });
  },

  confirmDraft(draftId: string, version: number): Promise<Run> {
    return apiRequest<Run>(`/drafts/${encodeURIComponent(draftId)}/confirm`, {
      method: "POST",
      body: { version },
    });
  },
};

export interface ClassifiedToolTrace {
  trace: ToolTrace;
  originKind: "service" | "model";
  originLabel: string;
  isOutcomeUnknown: boolean;
  displayStatus: string;
  displayName: string;
  grantId?: string;
  actionId?: string;
  decisionId?: string;
  operationId?: string;
  txId?: string;
  quoteId?: string;
  orderId?: string;
  errorCode?: string;
  code?: string;
  totalAmountMinor?: number;
  provider?: string;
  requestedModel?: string;
  responseModel?: string;
}

function readString(
  obj: Record<string, unknown> | undefined,
  key: string,
): string | undefined {
  const val = obj?.[key];
  return typeof val === "string" && val.length > 0 ? val : undefined;
}

function readNumber(
  obj: Record<string, unknown> | undefined,
  key: string,
): number | undefined {
  const val = obj?.[key];
  return typeof val === "number" && Number.isFinite(val) ? val : undefined;
}

/**
 * Interprets a sanitized dispatch ToolTrace:
 * - step === 0 represents service-originated calls (inter-domain HTTP, probe, background reconciliation)
 * - step >= 1 represents LLM model turns
 * - OUTCOME_UNKNOWN / UNKNOWN surfaces explicit unknown business outcome with original IDs
 */
export function classifyToolTrace(trace: ToolTrace): ClassifiedToolTrace {
  const output = trace.output;
  const nestedGrant =
    output && typeof output.grant === "object" && output.grant !== null
      ? (output.grant as Record<string, unknown>)
      : undefined;

  const actionStatus = readString(output, "actionStatus");
  const outcome = readString(output, "outcome");
  const decision = readString(output, "decision");
  const isOutcomeUnknown =
    actionStatus === "OUTCOME_UNKNOWN" || outcome === "UNKNOWN";

  const originKind = trace.step === 0 ? "service" : "model";
  const originLabel =
    originKind === "service" ? "服务调用（step 0）" : `模型轮次 #${trace.step}`;

  const displayStatus = isOutcomeUnknown
    ? "OUTCOME_UNKNOWN"
    : decision ?? (trace.isError ? "failed" : "returned");

  const displayName =
    trace.toolName === "model_result" ? "模型运行结果" : trace.toolName;

  return {
    trace,
    originKind,
    originLabel,
    isOutcomeUnknown,
    displayStatus,
    displayName,
    grantId: readString(output, "grantId") ?? readString(nestedGrant, "grantId"),
    actionId: readString(output, "actionId"),
    decisionId: readString(output, "decisionId"),
    operationId: readString(output, "operationId"),
    txId: readString(output, "txId"),
    quoteId: readString(output, "quoteId"),
    orderId: readString(output, "orderId"),
    errorCode: readString(output, "errorCode"),
    code: readString(output, "code"),
    totalAmountMinor: readNumber(output, "totalAmountMinor"),
    provider: readString(output, "provider"),
    requestedModel: readString(output, "requestedModel"),
    responseModel: readString(output, "responseModel"),
  };
}
