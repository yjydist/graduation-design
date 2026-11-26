import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  ApiError,
  formatApiError,
  setCsrfTokenProvider,
  setUnauthorizedHandler,
} from "./http";
import { backendApi } from "./backend";
import { agentApi, classifyToolTrace } from "./agent";

describe("HTTP client, CSRF propagation, and ErrorEnvelope decoding", () => {
  const fetchMock = vi.fn<typeof fetch>();

  beforeEach(() => {
    vi.stubGlobal("fetch", fetchMock);
    setCsrfTokenProvider(() => "csrf_token_example_43_chars_0123456789abcde");
    setUnauthorizedHandler(null);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    fetchMock.mockReset();
    setCsrfTokenProvider(() => null);
    setUnauthorizedHandler(null);
  });

  it("injects X-CSRF-Token and Idempotency-Key on mutating L3 management calls", async () => {
    fetchMock.mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          operationId: "op-1",
          operationKey: "key-1",
          method: "SetPurchasingAuthority",
          status: "PENDING",
          stage: "SUBMITTED",
          txId: null,
          validationCode: null,
          failureCode: null,
          blockNumber: null,
          transactionIndex: null,
          observedPeer: null,
          delivered: false,
        }),
        { status: 202, headers: { "Content-Type": "application/json" } },
      ),
    );

    const op = await backendApi.setPurchasingAuthority(
      {
        expectedRevision: 3,
        purchasingAuthority: "did:web:a.example:svc:pa",
      },
      "idem-key-123",
    );

    expect(op.operationId).toBe("op-1");
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0]!;
    expect(url).toBe("/api/v1/management/purchasing-authority");
    expect(init?.method).toBe("POST");
    const headers = init?.headers as Record<string, string>;
    expect(headers["X-CSRF-Token"]).toBe(
      "csrf_token_example_43_chars_0123456789abcde",
    );
    expect(headers["Idempotency-Key"]).toBe("idem-key-123");
    expect(headers["Content-Type"]).toBe("application/json");
  });

  it("does NOT send X-CSRF-Token on GET requests or /session/login", async () => {
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify({ domainId: "A", ready: true }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    await backendApi.checkReadiness();
    const getHeaders = fetchMock.mock.calls[0]![1]?.headers as Record<
      string,
      string
    >;
    expect(getHeaders["X-CSRF-Token"]).toBeUndefined();

    fetchMock.mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          domainId: "A",
          subjectId: "did:web:a.example:user:u",
          role: "BUYER",
          actions: ["procure"],
          csrfToken: "new-csrf",
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    );
    await backendApi.login({ username: "u", password: "secret" });
    const loginHeaders = fetchMock.mock.calls[1]![1]?.headers as Record<
      string,
      string
    >;
    expect(loginHeaders["X-CSRF-Token"]).toBeUndefined();
  });

  it("propagates X-CSRF-Token on L4 agent chat, draft edit, and confirm endpoints", async () => {
    fetchMock.mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          reply: "已整理草稿",
          draft: {
            draftId: "draft-1",
            version: 1,
            productId: "urn:grad:product:P1",
            quantity: 1,
            mode: "RESOURCE_PREAUTHORIZED",
            maxAmountMinor: 100000,
            expiresAt: 1790000000,
            delegateDid: "did:web:a.example:agent:a1",
            description: "采购一件 P1",
          },
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    );

    const res = await agentApi.sendChat({ message: "采购一件 P1" });
    expect(res.draft.draftId).toBe("draft-1");
    const headers = fetchMock.mock.calls[0]![1]?.headers as Record<
      string,
      string
    >;
    expect(headers["X-CSRF-Token"]).toBe(
      "csrf_token_example_43_chars_0123456789abcde",
    );
  });

  it("decodes ErrorEnvelope with X-Request-Id fallback and invokes unauthorized handler on 401", async () => {
    const onUnauthorized = vi.fn();
    setUnauthorizedHandler(onUnauthorized);

    fetchMock.mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          requestId: "req-err-99",
          code: "DRAFT_VERSION_CONFLICT",
          decisionId: "dec-42",
          message: "stale version",
        }),
        {
          status: 409,
          headers: {
            "Content-Type": "application/json",
            "X-Request-Id": "hdr-fallback",
          },
        },
      ),
    );

    await expect(agentApi.confirmDraft("draft-1", 1)).rejects.toMatchObject({
      name: "ApiError",
      status: 409,
      code: "DRAFT_VERSION_CONFLICT",
      requestId: "req-err-99",
      decisionId: "dec-42",
    });

    fetchMock.mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          code: "SESSION_REQUIRED",
          message: "active session required",
        }),
        {
          status: 401,
          headers: {
            "Content-Type": "application/json",
            "X-Request-Id": "req-401-hdr",
          },
        },
      ),
    );

    try {
      await backendApi.listRuns();
      expect.unreachable("should throw 401 ApiError");
    } catch (err) {
      expect(err).toBeInstanceOf(ApiError);
      const formatted = formatApiError(err);
      expect(formatted.isUnauthorized).toBe(true);
      expect(formatted.requestId).toBe("req-401-hdr");
      expect(formatted.code).toBe("SESSION_REQUIRED");
      expect(onUnauthorized).toHaveBeenCalledTimes(1);
    }
  });

  it("handles HTTP 204 No Content cleanly on logout", async () => {
    fetchMock.mockResolvedValueOnce(new Response(null, { status: 204 }));
    const res = await backendApi.logout();
    expect(res).toBeNull();
  });

  it("classifies step 0 service calls vs step >= 1 model turns and OUTCOME_UNKNOWN traces", () => {
    const serviceTrace = classifyToolTrace({
      step: 0,
      toolName: "reconcile_order",
      output: {
        actionStatus: "OUTCOME_UNKNOWN",
        actionId: "act-99",
        decisionId: "dec-77",
        grant: { grantId: "grant-g2" },
      },
      isError: false,
      durationMs: 145,
    });

    expect(serviceTrace.originKind).toBe("service");
    expect(serviceTrace.isOutcomeUnknown).toBe(true);
    expect(serviceTrace.displayStatus).toBe("OUTCOME_UNKNOWN");
    expect(serviceTrace.grantId).toBe("grant-g2");
    expect(serviceTrace.actionId).toBe("act-99");
    expect(serviceTrace.decisionId).toBe("dec-77");

    const modelTrace = classifyToolTrace({
      step: 2,
      toolName: "submit_order",
      output: { decision: "DENY", decisionId: "dec-88", orderId: "" },
      isError: true,
      durationMs: 310,
    });

    expect(modelTrace.originKind).toBe("model");
    expect(modelTrace.isOutcomeUnknown).toBe(false);
    expect(modelTrace.displayStatus).toBe("DENY");
  });
});
