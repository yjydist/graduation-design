import { useCallback, useEffect, useState, type FormEvent } from "react";
import { useNavigate, useParams } from "react-router-dom";
import {
  Bot,
  FileText,
  Loader2,
  MessageSquarePlus,
  Send,
  User,
} from "lucide-react";
import { toast } from "sonner";
import { agentApi } from "@/api/agent";
import { formatApiError } from "@/api/http";
import type { Draft, Run } from "@/api/types";
import { DisabledReasonTooltip } from "@/components/patterns/DisabledReasonTooltip";
import { EmptyState } from "@/components/patterns/EmptyState";
import { ErrorState } from "@/components/patterns/ErrorState";
import { PageHeader } from "@/components/patterns/PageHeader";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { Textarea } from "@/components/ui/textarea";
import { DraftEditor } from "@/features/procurement/DraftEditor";
import {
  MAX_CHAT_MESSAGE_CODEPOINTS,
  countCodePoints,
  formatInteger,
  validateChatMessage,
} from "@/lib/format";
import { cn } from "@/lib/utils";

interface ChatTurn {
  id: string;
  author: "BUYER" | "A1";
  text: string;
}

const EXAMPLE_PROMPTS = [
  "使用 RP 供应商预授权模式采购 1 件 P1，单笔上限 1000 元，委托 A1 在 1 小时内执行。",
  "使用 BM 采购权威授权模式采购 1 件 P2，单笔上限 1000 元，委托 A1 在 1 小时内执行。",
];

export function ChatPage() {
  const { draftId: routeDraftId } = useParams<{ draftId?: string }>();
  const navigate = useNavigate();

  const [messages, setMessages] = useState<ChatTurn[]>([]);
  const [inputText, setInputText] = useState("");
  const [sending, setSending] = useState(false);
  const [inputError, setInputError] = useState<string | null>(null);

  const [draft, setDraft] = useState<Draft | null>(null);
  const [draftLoading, setDraftLoading] = useState(false);
  const [draftError, setDraftError] = useState<{
    message: string;
    code?: string;
    requestId?: string;
  } | null>(null);

  const loadDraft = useCallback(async (id: string) => {
    setDraftLoading(true);
    setDraftError(null);
    try {
      const loaded = await agentApi.getDraft(id);
      setDraft(loaded);
    } catch (err) {
      setDraft(null);
      setDraftError(formatApiError(err));
    } finally {
      setDraftLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!routeDraftId) {
      setDraft(null);
      setDraftError(null);
      setDraftLoading(false);
      return;
    }
    if (draft?.draftId === routeDraftId) {
      return;
    }
    void loadDraft(routeDraftId);
  }, [routeDraftId, draft?.draftId, loadDraft]);

  const codePointCount = countCodePoints(inputText);
  const overLimit = codePointCount > MAX_CHAT_MESSAGE_CODEPOINTS;

  const handleSend = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const check = validateChatMessage(inputText);
    if (!check.ok) {
      setInputError(check.error);
      return;
    }

    setSending(true);
    setInputError(null);
    try {
      const payload = routeDraftId
        ? { message: check.value, draftId: routeDraftId }
        : { message: check.value };
      const result = await agentApi.sendChat(payload);
      setMessages((prev) => [
        ...prev,
        { id: crypto.randomUUID(), author: "BUYER", text: check.value },
        { id: crypto.randomUUID(), author: "A1", text: result.reply },
      ]);
      setInputText("");
      setDraft(result.draft);
      setDraftError(null);
      if (result.draft.draftId !== routeDraftId) {
        navigate(`/chat/${encodeURIComponent(result.draft.draftId)}`, {
          replace: false,
        });
      }
      toast.success(`A1 已更新草稿 v${result.draft.version}。`, {
        duration: 3000,
      });
    } catch (err) {
      const formatted = formatApiError(err);
      setInputError(formatted.message);
      toast.error("发送采购需求失败", {
        description: formatted.message,
        duration: 6000,
      });
    } finally {
      setSending(false);
    }
  };

  const handleNewChat = () => {
    setMessages([]);
    setDraft(null);
    setDraftError(null);
    setInputText("");
    setInputError(null);
    navigate("/chat");
  };

  const handleConfirmed = (run: Run) => {
    setMessages([]);
    navigate(`/runs/${encodeURIComponent(run.runId)}`);
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="采购对话"
        description="向 A1 采购智能体描述商品、数量、预算上限与授权模式，核对结构化草稿版本后启动正式派单。"
        actions={
          (routeDraftId || messages.length > 0) && (
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={handleNewChat}
              className="h-9 gap-1.5 rounded-lg"
            >
              <MessageSquarePlus
                className="size-4"
                strokeWidth={2}
                aria-hidden="true"
              />
              <span>新建对话</span>
            </Button>
          )
        }
      />

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        <div className="lg:col-span-6">
          <Card className="flex h-full flex-col">
            <CardHeader>
              <CardTitle className="text-base font-semibold">
                与 A1 交互
              </CardTitle>
              <CardDescription className="text-sm text-muted-foreground">
                对话仅用于整理结构化草稿，未点击右侧「确认并派单」前不会提交链上任务或发起跨域请求。
              </CardDescription>
            </CardHeader>

            <CardContent className="flex flex-1 flex-col gap-5">
              <div
                aria-label="当前对话记录"
                className="min-h-56 max-h-96 space-y-3 overflow-y-auto rounded-lg border border-border bg-background p-4"
              >
                {messages.length === 0 ? (
                  <div className="space-y-4 py-4">
                    <p className="text-sm text-muted-foreground">
                      还没有对话内容。输入自然语言采购要求，或点选下方演示模板快速填入：
                    </p>
                    <div className="flex flex-col gap-2">
                      {EXAMPLE_PROMPTS.map((sample) => (
                        <button
                          key={sample}
                          type="button"
                          onClick={() => {
                            setInputText(sample);
                            setInputError(null);
                          }}
                          className="rounded-lg border border-border bg-card px-3 py-2 text-left text-xs leading-5 text-foreground transition-colors duration-150 hover:bg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background"
                        >
                          {sample}
                        </button>
                      ))}
                    </div>
                  </div>
                ) : (
                  <ol className="space-y-3">
                    {messages.map((turn) => (
                      <li
                        key={turn.id}
                        className={cn(
                          "rounded-lg border px-3.5 py-2.5 text-sm leading-6",
                          turn.author === "BUYER"
                            ? "border-border bg-muted text-foreground"
                            : "border-border bg-card text-card-foreground",
                        )}
                      >
                        <div className="mb-1 flex items-center gap-1.5 text-xs font-medium text-muted-foreground">
                          {turn.author === "BUYER" ? (
                            <User className="size-3.5" aria-hidden="true" />
                          ) : (
                            <Bot
                              className="size-3.5 text-brand"
                              aria-hidden="true"
                            />
                          )}
                          <span>
                            {turn.author === "BUYER" ? "采购员" : "A1 采购智能体"}
                          </span>
                        </div>
                        <p className="whitespace-pre-wrap break-words">
                          {turn.text}
                        </p>
                      </li>
                    ))}
                  </ol>
                )}
              </div>

              <form
                onSubmit={(e) => void handleSend(e)}
                className="space-y-3"
                noValidate
              >
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between gap-2">
                    <Label htmlFor="chat-message" className="text-sm font-medium">
                      采购需求{" "}
                      <span className="text-destructive" aria-hidden="true">
                        *
                      </span>
                    </Label>
                    <span
                      className={cn(
                        "text-xs tabular-nums",
                        overLimit ? "text-destructive" : "text-muted-foreground",
                      )}
                    >
                      {formatInteger(codePointCount)} /{" "}
                      {formatInteger(MAX_CHAT_MESSAGE_CODEPOINTS)} 字符
                    </span>
                  </div>
                  <Textarea
                    id="chat-message"
                    name="message"
                    rows={4}
                    required
                    aria-required="true"
                    aria-invalid={Boolean(inputError) || overLimit}
                    aria-describedby="chat-message-hint"
                    value={inputText}
                    onChange={(e) => {
                      setInputText(e.target.value);
                      if (inputError) setInputError(null);
                    }}
                    disabled={sending}
                    placeholder="请说明商品（P1 或 P2）、数量、授权模式（RP 或 BM）、单笔预算上限与执行期限"
                    className={cn(
                      "rounded-lg text-sm leading-6",
                      (inputError || overLimit) && "border-destructive",
                    )}
                  />
                  <p
                    id="chat-message-hint"
                    role={inputError || overLimit ? "alert" : undefined}
                    className={cn(
                      "text-xs",
                      inputError || overLimit
                        ? "text-destructive"
                        : "text-muted-foreground",
                    )}
                  >
                    {inputError ??
                      (overLimit
                        ? `已超出 ${formatInteger(MAX_CHAT_MESSAGE_CODEPOINTS)} 个 Unicode 码点上限，请精简后再发送。`
                        : "按 Unicode 码点计数，最多 4,000 个字符。")}
                  </p>
                </div>

                <DisabledReasonTooltip
                  reason={
                    !sending && overLimit
                      ? `采购需求超出 ${formatInteger(MAX_CHAT_MESSAGE_CODEPOINTS)} 个字符上限，请精简后再发送。`
                      : null
                  }
                >
                  <Button
                    type="submit"
                    variant={draft ? "secondary" : "default"}
                    disabled={sending || overLimit}
                    className="h-9 gap-1.5 rounded-lg"
                  >
                    {sending ? (
                      <Loader2 className="size-4 animate-spin" aria-hidden="true" />
                    ) : (
                      <Send className="size-4" strokeWidth={2} aria-hidden="true" />
                    )}
                    <span>{sending ? "正在发送给 A1…" : "发送给 A1"}</span>
                  </Button>
                </DisabledReasonTooltip>
              </form>
            </CardContent>
          </Card>
        </div>

        <div className="lg:col-span-6">
          {draftLoading ? (
            <Card>
              <CardHeader>
                <Skeleton className="h-5 w-36" />
                <Skeleton className="h-4 w-64" />
              </CardHeader>
              <CardContent className="space-y-4">
                <Skeleton className="h-9 w-full" />
                <div className="grid grid-cols-2 gap-4">
                  <Skeleton className="h-9 w-full" />
                  <Skeleton className="h-9 w-full" />
                </div>
                <Skeleton className="h-24 w-full" />
              </CardContent>
            </Card>
          ) : draftError ? (
            <ErrorState
              title="无法加载采购草稿"
              message={draftError.message}
              code={draftError.code}
              requestId={draftError.requestId}
              onRetry={
                routeDraftId ? () => void loadDraft(routeDraftId) : undefined
              }
            />
          ) : draft ? (
            <DraftEditor
              draft={draft}
              onUpdated={(updated) => setDraft(updated)}
              onConfirmed={handleConfirmed}
            />
          ) : (
            <Card>
              <CardContent className="p-0">
                <EmptyState
                  icon={<FileText className="size-5" strokeWidth={2} />}
                  title="还没有采购草稿"
                  description="在左侧输入采购需求并发送给 A1，系统将在此生成可编辑与版本确认的结构化草稿。"
                />
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}
