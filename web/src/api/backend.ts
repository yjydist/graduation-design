import { apiRequest } from "@/api/http";
import type {
  Decision,
  LoginInput,
  Operation,
  PurchasingAuthority,
  ReadyResponse,
  Run,
  RunEvidence,
  RunListResponse,
  Session,
  SetPurchasingAuthorityInput,
} from "@/api/types";

/**
 * L3 Backend API client: session, health readiness, local domain management,
 * original ledger operations, run queries/grant controls, five-category evidence,
 * and role-scoped gateway decisions.
 */
export const backendApi = {
  checkReadiness(signal?: AbortSignal): Promise<ReadyResponse> {
    return apiRequest<ReadyResponse>("/health/ready", { signal });
  },

  getSession(signal?: AbortSignal): Promise<Session> {
    return apiRequest<Session>("/session", { signal });
  },

  login(input: LoginInput): Promise<Session> {
    return apiRequest<Session>("/session/login", {
      method: "POST",
      body: input,
      skipCsrf: true,
    });
  },

  logout(): Promise<null> {
    return apiRequest<null>("/session/logout", {
      method: "POST",
    });
  },

  getPurchasingAuthority(signal?: AbortSignal): Promise<PurchasingAuthority> {
    return apiRequest<PurchasingAuthority>("/management/purchasing-authority", {
      signal,
    });
  },

  setPurchasingAuthority(
    input: SetPurchasingAuthorityInput,
    idempotencyKey: string,
  ): Promise<Operation> {
    return apiRequest<Operation>("/management/purchasing-authority", {
      method: "POST",
      body: input,
      idempotencyKey,
    });
  },

  getOperation(operationId: string, signal?: AbortSignal): Promise<Operation> {
    return apiRequest<Operation>(
      `/operations/${encodeURIComponent(operationId)}`,
      { signal },
    );
  },

  async listRuns(signal?: AbortSignal): Promise<Run[]> {
    const response = await apiRequest<RunListResponse>("/runs", { signal });
    return response.runs ?? [];
  },

  getRun(runId: string, signal?: AbortSignal): Promise<Run> {
    return apiRequest<Run>(`/runs/${encodeURIComponent(runId)}`, { signal });
  },

  suspendRunGrant(runId: string, idempotencyKey: string): Promise<Run> {
    return apiRequest<Run>(`/runs/${encodeURIComponent(runId)}/suspend`, {
      method: "POST",
      idempotencyKey,
    });
  },

  resumeRunGrant(runId: string, idempotencyKey: string): Promise<Run> {
    return apiRequest<Run>(`/runs/${encodeURIComponent(runId)}/resume`, {
      method: "POST",
      idempotencyKey,
    });
  },

  getRunEvidence(runId: string, signal?: AbortSignal): Promise<RunEvidence> {
    return apiRequest<RunEvidence>(
      `/runs/${encodeURIComponent(runId)}/evidence`,
      { signal },
    );
  },

  getDecision(decisionId: string, signal?: AbortSignal): Promise<Decision> {
    return apiRequest<Decision>(
      `/decisions/${encodeURIComponent(decisionId)}`,
      { signal },
    );
  },
};
