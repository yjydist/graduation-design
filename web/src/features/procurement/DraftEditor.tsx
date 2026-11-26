import { useEffect, useState, type FormEvent } from "react";
import { CheckCircle2, Loader2, Save } from "lucide-react";
import { toast } from "sonner";
import { agentApi } from "@/api/agent";
import { formatApiError } from "@/api/http";
import type { AuthorizationMode, Draft, Run } from "@/api/types";
import { ConfirmDialog } from "@/components/patterns/ConfirmDialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { MODE_LABELS, PRODUCT_LABELS } from "@/lib/domain-labels";
import {
  MAX_DRAFT_DESCRIPTION_CODEPOINTS,
  countCodePoints,
  formatMinorAmount,
  formatUnixSeconds,
  fromDatetimeLocalValue,
  toDatetimeLocalValue,
  validateDraftDescription,
} from "@/lib/format";
import { cn } from "@/lib/utils";

export interface DraftEditorProps {
  draft: Draft;
  onUpdated: (draft: Draft) => void;
  onConfirmed: (run: Run) => void;
}

const KNOWN_PRODUCTS = ["urn:grad:product:P1", "urn:grad:product:P2"] as const;

export function DraftEditor({
  draft,
  onUpdated,
  onConfirmed,
}: DraftEditorProps) {
  const [productId, setProductId] = useState<string>(draft.productId);
  const [quantity, setQuantity] = useState<string>(String(draft.quantity));
  const [mode, setMode] = useState<AuthorizationMode>(draft.mode);
  const [maxAmountMinor, setMaxAmountMinor] = useState<string>(
    String(draft.maxAmountMinor),
  );
  const [expiresAtLocal, setExpiresAtLocal] = useState<string>(() =>
    toDatetimeLocalValue(draft.expiresAt),
  );
  const [delegateDid, setDelegateDid] = useState<string>(draft.delegateDid);
  const [description, setDescription] = useState<string>(draft.description);

  const [dirty, setDirty] = useState(false);
  const [saving, setSaving] = useState(false);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  useEffect(() => {
    setProductId(draft.productId);
    setQuantity(String(draft.quantity));
    setMode(draft.mode);
    setMaxAmountMinor(String(draft.maxAmountMinor));
    setExpiresAtLocal(toDatetimeLocalValue(draft.expiresAt));
    setDelegateDid(draft.delegateDid);
    setDescription(draft.description);
    setDirty(false);
    setFormError(null);
  }, [draft]);

  const descCount = countCodePoints(description);
  const descOverLimit = descCount > MAX_DRAFT_DESCRIPTION_CODEPOINTS;
  const parsedAmount = Number(maxAmountMinor);
  const parsedQty = Number(quantity);

  const handleSave = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setFormError(null);

    const descCheck = validateDraftDescription(description);
    if (!descCheck.ok) {
      setFormError(descCheck.error);
      return;
    }
    if (!Number.isInteger(parsedQty) || parsedQty < 1) {
      setFormError("采购数量须为大于等于 1 的整数。");
      return;
    }
    if (!Number.isInteger(parsedAmount) || parsedAmount < 1) {
      setFormError("单笔上限（分）须为大于等于 1 的整数。");
      return;
    }
    const expiresUnix = fromDatetimeLocalValue(expiresAtLocal);
    if (!expiresUnix || expiresUnix <= 0) {
      setFormError("请选择有效的截止时间。");
      return;
    }
    const trimmedDid = delegateDid.trim();
    if (!trimmedDid.startsWith("did:web:") || trimmedDid.length <= 8) {
      setFormError("受托者 DID 须为有效的 did:web: 标识。");
      return;
    }

    setSaving(true);
    try {
      const updated = await agentApi.updateDraft(draft.draftId, {
        version: draft.version,
        productId: productId.trim(),
        quantity: parsedQty,
        mode,
        maxAmountMinor: parsedAmount,
        expiresAt: expiresUnix,
        delegateDid: trimmedDid,
        description: descCheck.value,
      });
      onUpdated(updated);
      setDirty(false);
      toast.success(`已保存草稿修改（版本 v${updated.version}）。`, {
        duration: 3000,
      });
    } catch (err) {
      const formatted = formatApiError(err);
      setFormError(formatted.message);
      toast.error("保存草稿失败", {
        description: formatted.message,
        duration: 6000,
      });
    } finally {
      setSaving(false);
    }
  };

  const handleConfirm = async () => {
    setConfirming(true);
    try {
      const run = await agentApi.confirmDraft(draft.draftId, draft.version);
      setConfirmOpen(false);
      toast.success(`已确认草稿 v${draft.version}，正式采购流程已启动。`, {
        duration: 3000,
      });
      onConfirmed(run);
    } catch (err) {
      const formatted = formatApiError(err);
      setFormError(formatted.message);
      setConfirmOpen(false);
      toast.error("确认派单失败", {
        description: formatted.message,
        duration: 6000,
      });
    } finally {
      setConfirming(false);
    }
  };

  return (
    <Card className="rounded-xl border border-border bg-card shadow-none">
      <CardHeader className="flex flex-row flex-wrap items-start justify-between gap-2">
        <div className="space-y-1">
          <CardTitle className="text-base font-semibold">
            结构化采购草稿
          </CardTitle>
          <CardDescription className="text-sm text-muted-foreground">
            核对或修订下方参数；修改后须先保存版本，再确认并启动跨域派单。
          </CardDescription>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant="secondary" className="font-mono text-xs tabular-nums">
            v{draft.version}
          </Badge>
          {dirty && (
            <Badge
              variant="outline"
              className="border-warning text-warning-text text-xs"
            >
              有未保存修改
            </Badge>
          )}
        </div>
      </CardHeader>

      <CardContent>
        <form onSubmit={(e) => void handleSave(e)} className="space-y-4" noValidate>
          <div className="rounded-lg border border-border bg-muted px-3 py-2 text-xs text-muted-foreground">
            草稿 ID：
            <span className="ml-1 break-all font-mono text-foreground">
              {draft.draftId}
            </span>
          </div>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label htmlFor="draft-product" className="text-sm font-medium">
                商品编号 <span className="text-destructive" aria-hidden="true">*</span>
              </Label>
              <Select
                value={productId}
                onValueChange={(val) => {
                  if (val) {
                    setProductId(val);
                    setDirty(true);
                  }
                }}
                disabled={saving || confirming}
              >
                <SelectTrigger id="draft-product" className="h-9 w-full rounded-lg">
                  <SelectValue placeholder="选择商品" />
                </SelectTrigger>
                <SelectContent>
                  {KNOWN_PRODUCTS.map((pid) => (
                    <SelectItem key={pid} value={pid}>
                      {PRODUCT_LABELS[pid] ?? pid}
                    </SelectItem>
                  ))}
                  {!KNOWN_PRODUCTS.includes(
                    productId as (typeof KNOWN_PRODUCTS)[number],
                  ) &&
                    productId && (
                      <SelectItem value={productId}>{productId}</SelectItem>
                    )}
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="draft-quantity" className="text-sm font-medium">
                数量 <span className="text-destructive" aria-hidden="true">*</span>
              </Label>
              <Input
                id="draft-quantity"
                type="number"
                inputMode="numeric"
                min={1}
                step={1}
                required
                aria-required="true"
                value={quantity}
                onChange={(e) => {
                  setQuantity(e.target.value);
                  setDirty(true);
                }}
                disabled={saving || confirming}
                className="h-9 rounded-lg tabular-nums"
              />
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="draft-mode" className="text-sm font-medium">
                授权模式 <span className="text-destructive" aria-hidden="true">*</span>
              </Label>
              <Select
                value={mode}
                onValueChange={(val) => {
                  if (
                    val === "RESOURCE_PREAUTHORIZED" ||
                    val === "BUYER_MANDATE"
                  ) {
                    setMode(val);
                    setDirty(true);
                  }
                }}
                disabled={saving || confirming}
              >
                <SelectTrigger id="draft-mode" className="h-9 w-full rounded-lg">
                  <SelectValue placeholder="选择授权模式" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="RESOURCE_PREAUTHORIZED">
                    {MODE_LABELS.RESOURCE_PREAUTHORIZED}
                  </SelectItem>
                  <SelectItem value="BUYER_MANDATE">
                    {MODE_LABELS.BUYER_MANDATE}
                  </SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="draft-amount" className="text-sm font-medium">
                单笔上限（分）{" "}
                <span className="text-destructive" aria-hidden="true">*</span>
              </Label>
              <Input
                id="draft-amount"
                type="number"
                inputMode="numeric"
                min={1}
                step={1}
                required
                aria-required="true"
                value={maxAmountMinor}
                onChange={(e) => {
                  setMaxAmountMinor(e.target.value);
                  setDirty(true);
                }}
                disabled={saving || confirming}
                className="h-9 rounded-lg tabular-nums"
              />
              <p className="text-xs tabular-nums text-muted-foreground">
                折合金额：
                {Number.isFinite(parsedAmount) && parsedAmount > 0
                  ? formatMinorAmount(parsedAmount)
                  : "—"}
              </p>
            </div>
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="draft-expires" className="text-sm font-medium">
              委托截止时间（本地时间）{" "}
              <span className="text-destructive" aria-hidden="true">*</span>
            </Label>
            <Input
              id="draft-expires"
              type="datetime-local"
              step={1}
              required
              aria-required="true"
              value={expiresAtLocal}
              onChange={(e) => {
                setExpiresAtLocal(e.target.value);
                setDirty(true);
              }}
              disabled={saving || confirming}
              className="h-9 rounded-lg tabular-nums"
            />
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="draft-delegate" className="text-sm font-medium">
              受托者 DID{" "}
              <span className="text-destructive" aria-hidden="true">*</span>
            </Label>
            <Input
              id="draft-delegate"
              type="text"
              spellCheck={false}
              autoCapitalize="none"
              required
              aria-required="true"
              value={delegateDid}
              onChange={(e) => {
                setDelegateDid(e.target.value);
                setDirty(true);
              }}
              disabled={saving || confirming}
              className="h-9 rounded-lg font-mono text-xs"
            />
          </div>

          <div className="space-y-1.5">
            <div className="flex items-center justify-between gap-2">
              <Label htmlFor="draft-description" className="text-sm font-medium">
                任务说明{" "}
                <span className="text-destructive" aria-hidden="true">*</span>
              </Label>
              <span
                className={cn(
                  "text-xs tabular-nums",
                  descOverLimit ? "text-destructive" : "text-muted-foreground",
                )}
              >
                {descCount} / {MAX_DRAFT_DESCRIPTION_CODEPOINTS} 字符
              </span>
            </div>
            <Textarea
              id="draft-description"
              rows={3}
              required
              aria-required="true"
              aria-invalid={descOverLimit}
              aria-describedby="draft-description-hint"
              value={description}
              onChange={(e) => {
                setDescription(e.target.value);
                setDirty(true);
              }}
              disabled={saving || confirming}
              className={cn(
                "rounded-lg text-sm leading-6",
                descOverLimit && "border-destructive",
              )}
            />
            <p
              id="draft-description-hint"
              className={cn(
                "text-xs",
                descOverLimit ? "text-destructive" : "text-muted-foreground",
              )}
            >
              {descOverLimit
                ? `已超出 ${MAX_DRAFT_DESCRIPTION_CODEPOINTS} 个 Unicode 码点上限，请精简后再保存。`
                : "长度按 Unicode 码点计数，须为 1 至 512 个字符。"}
            </p>
          </div>

          {formError && (
            <div
              role="alert"
              className="rounded-lg border border-destructive bg-muted px-3 py-2 text-xs text-destructive"
            >
              {formError}
            </div>
          )}

          <div className="flex flex-wrap items-center justify-end gap-2 pt-2">
            <Button
              type="submit"
              variant="secondary"
              disabled={!dirty || saving || confirming || descOverLimit}
              className="h-9 gap-1.5 rounded-lg"
            >
              {saving ? (
                <Loader2 className="size-4 animate-spin" aria-hidden="true" />
              ) : (
                <Save className="size-4" strokeWidth={2} aria-hidden="true" />
              )}
              <span>{saving ? "正在保存…" : "保存草稿修改"}</span>
            </Button>

            <Button
              type="button"
              disabled={dirty || saving || confirming}
              onClick={() => setConfirmOpen(true)}
              className="h-9 gap-1.5 rounded-lg"
            >
              <CheckCircle2
                className="size-4"
                strokeWidth={2}
                aria-hidden="true"
              />
              <span>确认并派单</span>
            </Button>
          </div>
        </form>
      </CardContent>

      <ConfirmDialog
        open={confirmOpen}
        onOpenChange={setConfirmOpen}
        title={`确认草稿 v${draft.version} 并启动采购？`}
        description={`将以「${MODE_LABELS[draft.mode]}」模式采购 ${draft.quantity} 件 ${draft.productId}，单笔上限 ${formatMinorAmount(draft.maxAmountMinor)}，截止时间 ${formatUnixSeconds(draft.expiresAt)}。确认后将登记链上任务并签发委托。`}
        confirmLabel="启动采购派单"
        cancelLabel="返回核对"
        loading={confirming}
        onConfirm={handleConfirm}
      />
    </Card>
  );
}
