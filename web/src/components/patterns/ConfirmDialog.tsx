import { Loader2 } from "lucide-react";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";

export interface ConfirmDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description: string;
  confirmLabel: string;
  cancelLabel?: string;
  variant?: "default" | "destructive";
  loading?: boolean;
  onConfirm: () => void | Promise<void>;
}

export function ConfirmDialog({
  open,
  onOpenChange,
  title,
  description,
  confirmLabel,
  cancelLabel = "暂不执行",
  variant = "default",
  loading = false,
  onConfirm,
}: ConfirmDialogProps) {
  return (
    <AlertDialog
      open={open}
      onOpenChange={(nextOpen) => {
        if (!loading) {
          onOpenChange(nextOpen);
        }
      }}
    >
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle className="text-lg font-semibold">
            {title}
          </AlertDialogTitle>
          <AlertDialogDescription className="text-sm leading-6 text-muted-foreground">
            {description}
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel disabled={loading} className="rounded-lg">
            {cancelLabel}
          </AlertDialogCancel>
          <AlertDialogAction
            variant={variant}
            disabled={loading}
            onClick={(event) => {
              event.preventDefault();
              void onConfirm();
            }}
            className="gap-1.5 rounded-lg"
          >
            {loading && (
              <Loader2 className="size-4 animate-spin" aria-hidden="true" />
            )}
            <span>{loading ? "正在提交…" : confirmLabel}</span>
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
