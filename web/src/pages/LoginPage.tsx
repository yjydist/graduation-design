import { useState, type FormEvent } from "react";
import { AlertCircle, Loader2, LogIn, RefreshCw } from "lucide-react";
import { toast } from "sonner";
import { formatApiError } from "@/api/http";
import { AuthLayout } from "@/components/patterns/AuthLayout";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useAuth } from "@/features/auth/AuthContext";
import { resolveRoleLabel } from "@/lib/domain-labels";
import { cn } from "@/lib/utils";

export function LoginPage() {
  const { domainId, ready, readinessError, login, refreshReadiness } =
    useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [rechecking, setRechecking] = useState(false);
  const [fieldError, setFieldError] = useState<string | null>(null);
  const [requestMeta, setRequestMeta] = useState<string | null>(null);

  const handleRecheck = async () => {
    setRechecking(true);
    try {
      await refreshReadiness();
    } finally {
      setRechecking(false);
    }
  };

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const trimmedUser = username.trim();
    if (!trimmedUser || !password) {
      setFieldError("请输入本域账号与密码。");
      setRequestMeta(null);
      return;
    }

    setSubmitting(true);
    setFieldError(null);
    setRequestMeta(null);

    try {
      const next = await login({ username: trimmedUser, password });
      setPassword("");
      toast.success(
        `已登录 ${next.domainId} 域工作台（${resolveRoleLabel(next.role)}）。`,
        { duration: 3000 },
      );
    } catch (err) {
      const formatted = formatApiError(err);
      setFieldError(formatted.message);
      setRequestMeta(
        [formatted.code, formatted.requestId].filter(Boolean).join(" · ") ||
          null,
      );
      setPassword("");
      toast.error("登录失败", {
        description: formatted.message,
        duration: 6000,
      });
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <AuthLayout
      domainId={domainId}
      ready={ready}
      title="登录本域工作台"
      description="浏览器仅与当前域后端通信，身份角色与操作权限由服务端会话与链上登记决定。"
    >
      {ready === false && (
        <div
          role="alert"
          className="mb-5 flex flex-col gap-3 rounded-lg border border-destructive bg-muted p-3.5 text-sm"
        >
          <div className="flex items-start gap-2">
            <AlertCircle
              className="mt-0.5 size-4 shrink-0 text-destructive"
              strokeWidth={2}
              aria-hidden="true"
            />
            <div className="min-w-0 space-y-0.5">
              <p className="font-medium text-foreground">本域后端尚未就绪</p>
              <p className="text-xs leading-5 text-muted-foreground">
                {readinessError || "请确认本域后端容器与数据库健康状态后重试。"}
              </p>
            </div>
          </div>
          <Button
            type="button"
            variant="outline"
            size="sm"
            disabled={rechecking}
            onClick={() => void handleRecheck()}
            className="w-fit gap-1.5 rounded-lg"
          >
            <RefreshCw
              className={cn("size-3.5", rechecking && "animate-spin")}
              strokeWidth={2}
              aria-hidden="true"
            />
            <span>{rechecking ? "正在检测…" : "重新检查就绪状态"}</span>
          </Button>
        </div>
      )}

      <form
        onSubmit={(e) => void handleSubmit(e)}
        className="space-y-4"
        noValidate
      >
        <div className="space-y-1.5">
          <Label htmlFor="login-username" className="text-sm font-medium">
            本域账号{" "}
            <span className="text-destructive" aria-hidden="true">
              *
            </span>
          </Label>
          <Input
            id="login-username"
            name="username"
            type="text"
            autoComplete="username"
            autoCapitalize="none"
            spellCheck={false}
            maxLength={64}
            required
            aria-required="true"
            aria-invalid={Boolean(fieldError)}
            aria-describedby={
              fieldError ? "login-error" : "login-username-hint"
            }
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            disabled={submitting}
            placeholder="例如 admin、u 或 auditor"
            className="h-9 rounded-lg"
          />
          <p id="login-username-hint" className="text-xs text-muted-foreground">
            输入本域配置的管理员、采购员或审计员账号。
          </p>
        </div>

        <div className="space-y-1.5">
          <Label htmlFor="login-password" className="text-sm font-medium">
            密码{" "}
            <span className="text-destructive" aria-hidden="true">
              *
            </span>
          </Label>
          <Input
            id="login-password"
            name="password"
            type="password"
            autoComplete="current-password"
            maxLength={72}
            required
            aria-required="true"
            aria-invalid={Boolean(fieldError)}
            aria-describedby={fieldError ? "login-error" : undefined}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            disabled={submitting}
            placeholder="请输入账号密码"
            className="h-9 rounded-lg"
          />
        </div>

        {fieldError && (
          <div
            id="login-error"
            role="alert"
            className="rounded-lg border border-destructive bg-muted px-3 py-2.5 text-xs leading-5 text-destructive"
          >
            <p className="font-medium">{fieldError}</p>
            {requestMeta && (
              <p className="mt-1 font-mono text-muted-foreground">
                {requestMeta}
              </p>
            )}
          </div>
        )}

        <Button
          type="submit"
          disabled={submitting}
          className="h-9 w-full gap-1.5 rounded-lg"
        >
          {submitting ? (
            <Loader2 className="size-4 animate-spin" aria-hidden="true" />
          ) : (
            <LogIn className="size-4" strokeWidth={2} aria-hidden="true" />
          )}
          <span>{submitting ? "正在验证身份…" : "登录工作台"}</span>
        </Button>
      </form>
    </AuthLayout>
  );
}
