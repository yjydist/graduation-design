import { EMPTY_PLACEHOLDER } from "@/lib/format";
import type { AuthorizationMode, DomainId, Role, RunStage } from "@/api/types";

export type StatusTone = "success" | "destructive" | "warning" | "brand" | "neutral";

export const DOMAIN_LABELS: Record<DomainId, string> = {
  A: "A 域（买方）",
  B: "B 域（代理）",
  C: "C 域（卖方/网关）",
};

export const ROLE_LABELS: Record<Role, string> = {
  ADMIN: "域管理员",
  BUYER: "采购员",
  AUDITOR: "审计员",
};

export const MODE_LABELS: Record<AuthorizationMode, string> = {
  RESOURCE_PREAUTHORIZED: "RP / 供应商预授权",
  BUYER_MANDATE: "BM / 采购权威授权",
};

export const PRODUCT_LABELS: Record<string, string> = {
  "urn:grad:product:P1": "P1 标准采购品（¥800.00）",
  "urn:grad:product:P2": "P2 越额对照品（¥1,200.00）",
};

export const STAGE_LABELS: Record<RunStage | string, string> = {
  REGISTER_TASK: "登记采购任务",
  DELIVER_G0: "签发及交付 G0",
  DELIVER_G1: "签发及交付 G1",
  EXECUTE: "A1 转委托与 B1 执行",
  SuspendGrant: "暂停 G1 委托",
  ResumeGrant: "恢复 G1 委托",
};

const STATUS_LABELS: Record<string, string> = {
  accepted: "已受理",
  pending: "待确认",
  waiting: "处理中",
  confirmed: "已确认",
  delivered: "已交付",
  failed: "失败",
  denied: "网关拒绝",
  rejected: "网关拒绝",
  unknown: "业务结果未知",
  outcome_unknown: "业务结果未知",
  model_stopped: "模型已停止",
  completed: "已定案",
  finalized: "已定案",
  decided: "已定案",
  running: "执行中",
  paused: "已暂停",
  suspended: "已暂停",
  active: "有效",
  valid: "有效",
  revoked: "已撤销",
  expired: "已过期",
  success: "成功",
  allowed: "已放行",
  allow: "已放行",
  deny: "网关拒绝",
  gateway_denied: "网关拒绝",
  preparing: "准备中",
  ready: "已就绪",
  stopped: "已停止",
  submitted: "已提交",
  reconciled: "已核账",
  registered: "已登记",
  returned: "已返回",
};

const SUCCESS_SET = new Set([
  "confirmed",
  "delivered",
  "completed",
  "finalized",
  "success",
  "allowed",
  "allow",
  "valid",
  "active",
  "reconciled",
  "registered",
  "decided",
  "ready",
  "returned",
]);

const DESTRUCTIVE_SET = new Set([
  "failed",
  "denied",
  "rejected",
  "revoked",
  "expired",
  "gateway_denied",
  "deny",
]);

const WARNING_SET = new Set([
  "accepted",
  "pending",
  "waiting",
  "unknown",
  "outcome_unknown",
  "running",
  "paused",
  "suspended",
  "preparing",
  "submitted",
  "model_stopped",
  "stopped",
]);

export function resolveStatusTone(value: string | null | undefined): StatusTone {
  const key = String(value ?? "")
    .trim()
    .toLowerCase()
    .replaceAll("-", "_");
  if (SUCCESS_SET.has(key)) return "success";
  if (DESTRUCTIVE_SET.has(key)) return "destructive";
  if (WARNING_SET.has(key)) return "warning";
  return "neutral";
}

export function resolveStatusLabel(value: string | null | undefined): string {
  if (value === null || value === undefined || value.trim() === "") {
    return EMPTY_PLACEHOLDER;
  }
  const key = value.trim().toLowerCase().replaceAll("-", "_");
  return STATUS_LABELS[key] ?? value;
}

export function resolveModeLabel(mode: string | null | undefined): string {
  if (!mode) return EMPTY_PLACEHOLDER;
  return MODE_LABELS[mode as AuthorizationMode] ?? mode;
}

export function resolveStageLabel(stage: string | null | undefined): string {
  if (!stage) return EMPTY_PLACEHOLDER;
  return STAGE_LABELS[stage] ?? stage;
}

export function resolveRoleLabel(role: string | null | undefined): string {
  if (!role) return EMPTY_PLACEHOLDER;
  return ROLE_LABELS[role as Role] ?? role;
}
