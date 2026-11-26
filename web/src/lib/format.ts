export const EMPTY_PLACEHOLDER = "—";
export const MAX_CHAT_MESSAGE_CODEPOINTS = 4000;
export const MAX_DRAFT_DESCRIPTION_CODEPOINTS = 512;

const decimalFormatter = new Intl.NumberFormat("en-US", {
  minimumFractionDigits: 2,
  maximumFractionDigits: 2,
});

const integerFormatter = new Intl.NumberFormat("en-US", {
  maximumFractionDigits: 0,
});

/**
 * Counts Unicode code points (matching Go utf8.RuneCountInString / OpenAPI maxLength).
 */
export function countCodePoints(input: string): number {
  return Array.from(input).length;
}

export function isWithinCodePointLimit(input: string, max: number): boolean {
  return countCodePoints(input) <= max;
}

export type TextValidationResult =
  | { ok: true; value: string; count: number }
  | { ok: false; count: number; error: string };

export function validateChatMessage(raw: string): TextValidationResult {
  const value = raw.trim();
  const count = countCodePoints(value);
  if (count === 0) {
    return { ok: false, count: 0, error: "请输入采购需求后再发送。" };
  }
  if (count > MAX_CHAT_MESSAGE_CODEPOINTS) {
    return {
      ok: false,
      count,
      error: `采购需求超出上限（当前 ${integerFormatter.format(count)} / ${integerFormatter.format(MAX_CHAT_MESSAGE_CODEPOINTS)} 个字符）。`,
    };
  }
  return { ok: true, value, count };
}

export function validateDraftDescription(raw: string): TextValidationResult {
  const value = raw.trim();
  const count = countCodePoints(value);
  if (count === 0) {
    return { ok: false, count: 0, error: "任务说明不能为空。" };
  }
  if (count > MAX_DRAFT_DESCRIPTION_CODEPOINTS) {
    return {
      ok: false,
      count,
      error: `任务说明须为 1 至 ${MAX_DRAFT_DESCRIPTION_CODEPOINTS} 个字符（当前 ${count} 个）。`,
    };
  }
  return { ok: true, value, count };
}

/**
 * Formats an integer minor-unit amount (cents) into a currency string.
 * Null, undefined, or non-finite values render as the em-dash placeholder.
 */
export function formatMinorAmount(
  minor: number | null | undefined,
  currency = "CNY",
): string {
  if (minor === null || minor === undefined || !Number.isFinite(minor)) {
    return EMPTY_PLACEHOLDER;
  }
  const negative = minor < 0;
  const absMajor = Math.abs(minor) / 100;
  const formatted = decimalFormatter.format(absMajor);
  const code = currency.trim().toUpperCase();
  if (!code || code === "CNY" || code === "RMB") {
    return `${negative ? "-" : ""}¥${formatted}`;
  }
  return `${negative ? "-" : ""}${code} ${formatted}`;
}

export function formatInteger(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) {
    return EMPTY_PLACEHOLDER;
  }
  return integerFormatter.format(value);
}

export function formatPercent(ratio: number | null | undefined): string {
  if (ratio === null || ratio === undefined || !Number.isFinite(ratio)) {
    return EMPTY_PLACEHOLDER;
  }
  return `${(ratio * 100).toFixed(1)}%`;
}

export function formatOrEmpty(
  value: string | number | null | undefined,
): string {
  if (value === null || value === undefined) {
    return EMPTY_PLACEHOLDER;
  }
  if (typeof value === "string") {
    const trimmed = value.trim();
    return trimmed.length > 0 ? trimmed : EMPTY_PLACEHOLDER;
  }
  if (!Number.isFinite(value)) {
    return EMPTY_PLACEHOLDER;
  }
  return String(value);
}

function pad2(n: number): string {
  return String(n).padStart(2, "0");
}

export interface DateTimeFormatOptions {
  includeSeconds?: boolean;
  utc?: boolean;
}

function formatDate(date: Date, options?: DateTimeFormatOptions): string {
  const utc = options?.utc ?? false;
  const includeSeconds = options?.includeSeconds ?? true;
  const year = utc ? date.getUTCFullYear() : date.getFullYear();
  const month = pad2((utc ? date.getUTCMonth() : date.getMonth()) + 1);
  const day = pad2(utc ? date.getUTCDate() : date.getDate());
  const hour = pad2(utc ? date.getUTCHours() : date.getHours());
  const minute = pad2(utc ? date.getUTCMinutes() : date.getMinutes());
  const base = `${year}-${month}-${day} ${hour}:${minute}`;
  if (!includeSeconds) {
    return utc ? `${base} UTC` : base;
  }
  const second = pad2(utc ? date.getUTCSeconds() : date.getSeconds());
  return utc ? `${base}:${second} UTC` : `${base}:${second}`;
}

export function formatUnixSeconds(
  seconds: number | null | undefined,
  options?: DateTimeFormatOptions,
): string {
  if (
    seconds === null ||
    seconds === undefined ||
    !Number.isFinite(seconds) ||
    seconds <= 0
  ) {
    return EMPTY_PLACEHOLDER;
  }
  const date = new Date(seconds * 1000);
  if (Number.isNaN(date.valueOf())) {
    return EMPTY_PLACEHOLDER;
  }
  return formatDate(date, options);
}

export function formatIsoTimestamp(
  iso: string | null | undefined,
  options?: DateTimeFormatOptions,
): string {
  if (!iso) {
    return EMPTY_PLACEHOLDER;
  }
  const date = new Date(iso);
  if (Number.isNaN(date.valueOf())) {
    return iso;
  }
  return formatDate(date, options);
}

export function toDatetimeLocalValue(unixSeconds: number): string {
  const date = new Date(unixSeconds * 1000);
  if (Number.isNaN(date.valueOf())) {
    return "";
  }
  const shifted = new Date(date.valueOf() - date.getTimezoneOffset() * 60_000);
  return shifted.toISOString().slice(0, 19);
}

export function fromDatetimeLocalValue(value: string): number | null {
  if (!value.trim()) {
    return null;
  }
  const millis = new Date(value).valueOf();
  if (Number.isNaN(millis)) {
    return null;
  }
  return Math.floor(millis / 1000);
}

export function truncateMiddle(
  value: string | null | undefined,
  head = 12,
  tail = 8,
): string {
  if (!value) {
    return EMPTY_PLACEHOLDER;
  }
  const chars = Array.from(value);
  if (chars.length <= head + tail + 3) {
    return value;
  }
  return `${chars.slice(0, head).join("")}…${chars.slice(-tail).join("")}`;
}
