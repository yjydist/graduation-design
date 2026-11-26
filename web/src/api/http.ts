import type { ErrorEnvelope } from "@/api/types";

const API_BASE = "/api/v1";

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly requestId: string | null;
  readonly decisionId: string | null;

  constructor(
    status: number,
    options: {
      code: string;
      message: string;
      requestId?: string | null;
      decisionId?: string | null;
    },
  ) {
    super(options.message);
    this.name = "ApiError";
    this.status = status;
    this.code = options.code;
    this.requestId = options.requestId ?? null;
    this.decisionId = options.decisionId ?? null;
  }
}

type CsrfProvider = () => string | null;
type UnauthorizedHandler = (error: ApiError) => void;

let csrfProvider: CsrfProvider = () => null;
let unauthorizedHandler: UnauthorizedHandler | null = null;

export function setCsrfTokenProvider(provider: CsrfProvider): void {
  csrfProvider = provider;
}

export function setUnauthorizedHandler(
  handler: UnauthorizedHandler | null,
): void {
  unauthorizedHandler = handler;
}

export interface RequestOptions {
  method?: "GET" | "POST" | "PUT" | "DELETE";
  body?: unknown;
  /** Explicit CSRF token override; otherwise read from registered session provider on mutating requests. */
  csrfToken?: string | null;
  /** Skip automatic CSRF header injection (used exclusively for /session/login). */
  skipCsrf?: boolean;
  idempotencyKey?: string;
  signal?: AbortSignal;
}

const MUTATING_METHODS = new Set(["POST", "PUT", "DELETE"]);

function isErrorEnvelope(value: unknown): value is Partial<ErrorEnvelope> {
  return typeof value === "object" && value !== null;
}

export async function apiRequest<T>(
  path: string,
  options: RequestOptions = {},
): Promise<T> {
  const method = options.method ?? "GET";
  const headers: Record<string, string> = {
    Accept: "application/json",
  };

  if (options.body !== undefined) {
    headers["Content-Type"] = "application/json";
  }

  if (MUTATING_METHODS.has(method) && !options.skipCsrf) {
    const token =
      options.csrfToken !== undefined ? options.csrfToken : csrfProvider();
    if (token) {
      headers["X-CSRF-Token"] = token;
    }
  }

  if (options.idempotencyKey) {
    headers["Idempotency-Key"] = options.idempotencyKey;
  }

  let response: Response;
  try {
    response = await fetch(`${API_BASE}${path}`, {
      method,
      headers,
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
      credentials: "same-origin",
      cache: "no-store",
      redirect: "error",
      signal: options.signal,
    });
  } catch (cause) {
    throw new ApiError(0, {
      code: "NETWORK_ERROR",
      message:
        cause instanceof Error && cause.name === "AbortError"
          ? "请求已取消。"
          : "无法连接本域后端服务，请检查网络或容器状态后重试。",
    });
  }

  const headerRequestId = response.headers.get("X-Request-Id");

  if (response.status === 204) {
    return null as T;
  }

  let payload: unknown = null;
  try {
    payload = await response.json();
  } catch {
    payload = null;
  }

  if (!response.ok) {
    const envelope = isErrorEnvelope(payload) ? payload : null;
    const error = new ApiError(response.status, {
      code:
        typeof envelope?.code === "string" && envelope.code
          ? envelope.code
          : `HTTP_${response.status}`,
      message:
        typeof envelope?.message === "string" && envelope.message
          ? envelope.message
          : `请求失败（HTTP ${response.status}）`,
      requestId:
        typeof envelope?.requestId === "string" && envelope.requestId
          ? envelope.requestId
          : headerRequestId,
      decisionId:
        typeof envelope?.decisionId === "string" ? envelope.decisionId : null,
    });

    if (response.status === 401 && !options.skipCsrf) {
      unauthorizedHandler?.(error);
    }

    throw error;
  }

  if (payload === null) {
    throw new ApiError(response.status, {
      code: "INVALID_RESPONSE",
      message: "服务端返回了空响应或非 JSON 数据。",
      requestId: headerRequestId,
    });
  }

  return payload as T;
}

const KNOWN_ERROR_MESSAGES: Record<string, string> = {
  LOGIN_FAILED: "账号或密码无效，请核对后重新输入。",
  SESSION_REQUIRED: "当前会话已失效，请重新登录本域工作台。",
  CSRF_INVALID: "安全令牌校验未通过，请刷新页面后重试。",
  DRAFT_VERSION_CONFLICT:
    "草稿版本已更新，请重新加载当前草稿核对后再确认。",
  IDENTITY_MANAGEMENT_FORBIDDEN: "当前账号角色无权执行该操作。",
  PURCHASING_AUTHORITY_INVALID: "所选服务不符合当前本域采购权威资格。",
  STATE_CHANGED: "链上状态版本已变更，请刷新最新状态后重新提交。",
  IDEMPOTENCY_CONFLICT: "检测到重复提交键与输入不一致，请刷新页面后重试。",
  NOT_FOUND: "未找到对应记录，请核对编号及访问权限。",
  OPERATION_UNKNOWN: "未找到该操作记录，请确认操作 ID 属于本域且有权查看。",
  STATE_UNAVAILABLE: "本域后端或账本状态暂不可用，请稍后重试。",
};

export interface FormattedApiError {
  message: string;
  code?: string;
  requestId?: string;
  decisionId?: string;
  isUnauthorized: boolean;
}

export function formatApiError(error: unknown): FormattedApiError {
  if (error instanceof ApiError) {
    const message = KNOWN_ERROR_MESSAGES[error.code] ?? error.message;
    return {
      message,
      code: error.code,
      requestId: error.requestId ?? undefined,
      decisionId: error.decisionId ?? undefined,
      isUnauthorized: error.status === 401,
    };
  }
  if (error instanceof Error) {
    return {
      message: error.message || "发生未知错误，请稍后重试。",
      isUnauthorized: false,
    };
  }
  return {
    message: "发生未知错误，请稍后重试。",
    isUnauthorized: false,
  };
}

/**
 * Generates or retrieves a stable Idempotency-Key for safe retries of the same input.
 */
export function getOrCreateIdempotencyKey(
  domainId: string,
  subjectId: string,
  action: string,
  targetId: string,
  payload: unknown,
): string {
  const cacheKey = JSON.stringify([
    "workbench",
    domainId,
    subjectId,
    action,
    targetId,
    payload,
  ]);
  try {
    const existing = sessionStorage.getItem(cacheKey);
    if (existing) {
      return existing;
    }
    const created = crypto.randomUUID();
    sessionStorage.setItem(cacheKey, created);
    return created;
  } catch {
    return crypto.randomUUID();
  }
}
