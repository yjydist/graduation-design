import { useNavigate } from "react-router-dom";
import { ShieldAlert } from "lucide-react";
import { EmptyState } from "@/components/patterns/EmptyState";
import { Button } from "@/components/ui/button";

export function ForbiddenPage({ homePath }: { homePath: string }) {
  const navigate = useNavigate();
  return (
    <EmptyState
      icon={<ShieldAlert className="size-5" strokeWidth={2} />}
      title="当前账号无权访问此页面"
      description="操作权限由本域会话角色与链上登记决定。请返回当前账号获准使用的工作区。"
      action={
        <Button
          type="button"
          size="sm"
          onClick={() => navigate(homePath, { replace: true })}
          className="rounded-lg"
        >
          返回可用页面
        </Button>
      }
    />
  );
}
