export class APIError extends Error {
  constructor(status, envelope) {
    super(envelope?.message || '请求失败');
    this.status = status;
    this.code = envelope?.code;
    this.requestId = envelope?.requestId;
  }
}

export async function request(path, { method = 'GET', body, csrf, idempotencyKey } = {}) {
  const headers = { Accept: 'application/json' };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (csrf) headers['X-CSRF-Token'] = csrf;
  if (idempotencyKey) headers['Idempotency-Key'] = idempotencyKey;
  const response = await fetch('/api/v1' + path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: 'same-origin',
    cache: 'no-store',
    redirect: 'error',
  });
  if (response.status === 204) return null;
  const envelope = await response.json().catch(() => null);
  if (!response.ok) throw new APIError(response.status, envelope);
  if (envelope === null) throw new APIError(response.status, { message: '响应未包含可用的 JSON 数据' });
  return envelope;
}
