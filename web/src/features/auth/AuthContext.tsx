import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { toast } from "sonner";
import { backendApi } from "@/api/backend";
import {
  ApiError,
  formatApiError,
  setCsrfTokenProvider,
  setUnauthorizedHandler,
} from "@/api/http";
import type { ActionName, DomainId, LoginInput, Session } from "@/api/types";

export interface AuthContextValue {
  domainId: DomainId | null;
  ready: boolean | null;
  readinessError: string | null;
  session: Session | null;
  initializing: boolean;
  loggingOut: boolean;
  login: (input: LoginInput) => Promise<Session>;
  logout: () => Promise<void>;
  hasAction: (action: ActionName) => boolean;
  refreshReadiness: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [domainId, setDomainId] = useState<DomainId | null>(null);
  const [ready, setReady] = useState<boolean | null>(null);
  const [readinessError, setReadinessError] = useState<string | null>(null);
  const [session, setSession] = useState<Session | null>(null);
  const [initializing, setInitializing] = useState(true);
  const [loggingOut, setLoggingOut] = useState(false);

  const sessionRef = useRef<Session | null>(null);
  sessionRef.current = session;

  useEffect(() => {
    setCsrfTokenProvider(() => sessionRef.current?.csrfToken ?? null);
    setUnauthorizedHandler((error) => {
      if (sessionRef.current) {
        sessionRef.current = null;
        setSession(null);
        const info = formatApiError(error);
        toast.error(info.message, {
          description: info.requestId ? `请求 ID: ${info.requestId}` : undefined,
          duration: 6000,
        });
      }
    });
    return () => {
      setCsrfTokenProvider(() => null);
      setUnauthorizedHandler(null);
    };
  }, []);

  const refreshReadiness = useCallback(async () => {
    try {
      const res = await backendApi.checkReadiness();
      setDomainId(res.domainId);
      setReady(res.ready);
      setReadinessError(null);
    } catch (err) {
      setReady(false);
      setReadinessError(formatApiError(err).message);
    }
  }, []);

  useEffect(() => {
    let active = true;
    const controller = new AbortController();

    async function bootstrap() {
      const [readyResult, sessionResult] = await Promise.allSettled([
        backendApi.checkReadiness(controller.signal),
        backendApi.getSession(controller.signal),
      ]);
      if (!active) return;

      if (readyResult.status === "fulfilled") {
        setDomainId(readyResult.value.domainId);
        setReady(readyResult.value.ready);
        setReadinessError(null);
      } else {
        setReady(false);
        setReadinessError(formatApiError(readyResult.reason).message);
      }

      if (sessionResult.status === "fulfilled") {
        setSession(sessionResult.value);
        setDomainId(sessionResult.value.domainId);
      } else {
        const reason = sessionResult.reason;
        if (!(reason instanceof ApiError && reason.status === 401)) {
          const formatted = formatApiError(reason);
          toast.error("会话状态检查失败", {
            description: formatted.message,
            duration: 6000,
          });
        }
        setSession(null);
      }

      setInitializing(false);
    }

    void bootstrap();
    return () => {
      active = false;
      controller.abort();
    };
  }, []);

  const login = useCallback(async (input: LoginInput) => {
    const nextSession = await backendApi.login(input);
    sessionRef.current = nextSession;
    setSession(nextSession);
    setDomainId(nextSession.domainId);
    setReady(true);
    setReadinessError(null);
    return nextSession;
  }, []);

  const logout = useCallback(async () => {
    setLoggingOut(true);
    try {
      await backendApi.logout();
      sessionRef.current = null;
      setSession(null);
      toast.success("已退出当前域会话。", { duration: 3000 });
    } catch (err) {
      const formatted = formatApiError(err);
      if (formatted.isUnauthorized) {
        sessionRef.current = null;
        setSession(null);
      } else {
        toast.error("退出登录失败", {
          description: formatted.message,
          duration: 6000,
        });
      }
    } finally {
      setLoggingOut(false);
    }
  }, []);

  const hasAction = useCallback(
    (action: ActionName) => {
      return Boolean(session?.actions.includes(action));
    },
    [session],
  );

  return (
    <AuthContext.Provider
      value={{
        domainId,
        ready,
        readinessError,
        session,
        initializing,
        loggingOut,
        login,
        logout,
        hasAction,
        refreshReadiness,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

// eslint-disable-next-line react-refresh/only-export-components
export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error("useAuth must be used within AuthProvider");
  }
  return ctx;
}
