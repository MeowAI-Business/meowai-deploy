import { useEffect, useMemo, useState, type ReactNode } from "react";
import {
  Activity,
  AlertTriangle,
  ArrowLeft,
  ArrowRight,
  Boxes,
  Check,
  CheckCircle2,
  Circle,
  ClipboardCheck,
  Copy,
  KeyRound,
  LogOut,
  RefreshCcw,
  RotateCcw,
  Server,
  ShieldCheck,
  TerminalSquare,
  Trash2,
  X,
} from "lucide-react";

type StepKey = "target" | "source" | "site" | "review" | "operation";

type Draft = {
  sshDestination: string;
  sourceUrl: string;
  sourceUsername: string;
  sourcePassword: string;
  websiteName: string;
  containerName: string;
  directory: string;
  newapiPort: string;
  kumaPort: string;
  newapiAdminUsername: string;
  newapiAdminPassword: string;
  kumaAdminUsername: string;
  kumaAdminPassword: string;
  image: string;
  imageRef: string;
};

type Session = {
  csrfToken: string;
};

type Bootstrap = {
  version: string;
  hasSavedDeployment: boolean;
  operationLock: boolean;
};

type ApiError = Error & { code?: string };

type OperationSnapshot = {
  checkpoint: {
    operation_id: string;
    status: "draft" | "running" | "cancelling" | "cancelled" | "failed" | "completed";
    current_stage?: string;
    failure?: { code: string; message: string; retryable: boolean };
  };
  result?: Record<string, unknown>;
  credentials?: Array<{ kind: string; username: string; password: string }>;
};

const steps: Array<{ key: StepKey; label: string; note: string; icon: typeof Server }> = [
  { key: "target", label: "目标", note: "SSH 与目录", icon: Server },
  { key: "source", label: "源站", note: "账号与批准", icon: KeyRound },
  { key: "site", label: "站点", note: "端口与镜像", icon: Boxes },
  { key: "review", label: "复核", note: "确认部署计划", icon: ClipboardCheck },
  { key: "operation", label: "执行", note: "进度与恢复", icon: Activity },
];

const defaultDraft: Draft = {
  sshDestination: "",
  sourceUrl: "https://source.example.test",
  sourceUsername: "",
  sourcePassword: "",
  websiteName: "Meow AI Downstream",
  containerName: "newapi",
  directory: "/opt/meowai-deploy/newapi",
  newapiPort: "3000",
  kumaPort: "3001",
  newapiAdminUsername: "admin",
  newapiAdminPassword: "",
  kumaAdminUsername: "admin",
  kumaAdminPassword: "",
  image: "ghcr.io/moorcorpa/new-api-outgap",
  imageRef: "",
};

async function request<T>(path: string, options: RequestInit = {}, session?: Session): Promise<T> {
  const headers = new Headers(options.headers);
  if (options.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  if (session?.csrfToken) headers.set("X-CSRF-Token", session.csrfToken);
  const response = await fetch(path, { ...options, headers, credentials: "same-origin" });
  if (!response.ok) {
    let message = `请求失败（${response.status}）`;
    let code: string | undefined;
    try {
      const body = (await response.json()) as { error?: { message?: string; code?: string } };
      message = body.error?.message ?? message;
      code = body.error?.code;
    } catch {
      // The server may return a plain response for a malformed request.
    }
    const error = new Error(message) as ApiError;
    error.code = code;
    throw error;
  }
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

function readFragmentToken(): string | null {
  const raw = window.location.hash.replace(/^#/, "");
  if (!raw) return null;
  const token = new URLSearchParams(raw).get("token");
  if (token) window.history.replaceState({}, "", window.location.pathname + window.location.search);
  return token;
}

export default function App() {
  const [session, setSession] = useState<Session | null>(null);
  const [bootstrap, setBootstrap] = useState<Bootstrap | null>(null);
  const [draft, setDraft] = useState<Draft>(defaultDraft);
  const [activeStep, setActiveStep] = useState<StepKey>("target");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastEvent, setLastEvent] = useState("等待本地服务");
  const [operationId, setOperationId] = useState<string | null>(null);
  const [operationStatus, setOperationStatus] = useState<"idle" | "running" | "completed" | "failed">("idle");
  const [credentials, setCredentials] = useState<OperationSnapshot["credentials"]>(undefined);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    let cancelled = false;
    async function initialize() {
      try {
        const token = readFragmentToken();
        let nextSession: Session;
        if (token) {
          const exchanged = await request<{ csrf_token: string }>("/api/session", {
            method: "POST",
            body: JSON.stringify({ token }),
          });
          nextSession = { csrfToken: exchanged.csrf_token };
        } else {
          const current = await request<{ csrf_token: string }>("/api/session");
          nextSession = { csrfToken: current.csrf_token };
        }
        const nextBootstrap = await request<{
          version: string;
          has_saved_deployment: boolean;
          operation_lock: boolean;
        }>("/api/bootstrap", {}, nextSession);
        if (!cancelled) {
          setSession(nextSession);
          setBootstrap({
            version: nextBootstrap.version,
            hasSavedDeployment: nextBootstrap.has_saved_deployment,
            operationLock: nextBootstrap.operation_lock,
          });
          setLastEvent("本地会话已建立");
        }
      } catch (cause) {
        if (!cancelled) setError(cause instanceof Error ? cause.message : "无法连接本地 Web 服务");
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    void initialize();
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (!session) return;
    const source = new EventSource("/api/events");
    source.addEventListener("connected", () => setLastEvent("实时通道已连接"));
    source.addEventListener("operation", (event) => {
      try {
        const payload = JSON.parse((event as MessageEvent).data) as { operation_id?: string; message?: string; kind?: { type?: string } };
        if (payload.operation_id && payload.operation_id !== operationId) return;
        if (payload.message) setLastEvent(payload.message);
        if (payload.kind?.type === "operation_completed") {
          setOperationStatus("completed");
          setActiveStep("operation");
        }
      } catch {
        setLastEvent("收到新的操作事件");
      }
    });
    source.onerror = () => setLastEvent("实时通道等待重连");
    return () => source.close();
  }, [operationId, session]);

  useEffect(() => {
    if (!session || !operationId) return;
    let cancelled = false;
    let timer: number | undefined;
    async function poll() {
      try {
        const snapshot = await request<OperationSnapshot>(`/api/operations/${encodeURIComponent(operationId)}`, {}, session);
        if (cancelled) return;
        const status = snapshot.checkpoint.status;
        if (status === "running" || status === "cancelling" || status === "draft") {
          setOperationStatus("running");
        } else if (status === "completed") {
          setOperationStatus("completed");
          if (snapshot.credentials) setCredentials(snapshot.credentials);
          setLastEvent("部署操作已完成");
        } else if (status === "failed" || status === "cancelled") {
          setOperationStatus("failed");
          setLastEvent(snapshot.checkpoint.failure?.message ?? (status === "cancelled" ? "操作已取消" : "操作失败"));
        }
      } catch (cause) {
        if (!cancelled) setError(cause instanceof Error ? cause.message : "无法读取操作状态");
      } finally {
        if (!cancelled) timer = window.setTimeout(() => void poll(), 1200);
      }
    }
    void poll();
    return () => {
      cancelled = true;
      if (timer) window.clearTimeout(timer);
    };
  }, [operationId, session]);

  const activeIndex = steps.findIndex((step) => step.key === activeStep);
  const active = steps[activeIndex] ?? steps[0];
  const canAdvance = useMemo(() => validateStep(activeStep, draft) === null, [activeStep, draft]);

  function update<K extends keyof Draft>(key: K, value: Draft[K]) {
    setDraft((current) => ({ ...current, [key]: value }));
    setError(null);
  }

  function goNext() {
    const validation = validateStep(activeStep, draft);
    if (validation) {
      setError(validation);
      return;
    }
    const next = steps[activeIndex + 1];
    if (next) setActiveStep(next.key);
  }

  function goBack() {
    const previous = steps[activeIndex - 1];
    if (previous) setActiveStep(previous.key);
  }

  async function startOperation() {
    if (!session) return;
    const validation = validateStep("review", draft);
    if (validation) {
      setError(validation);
      setActiveStep("review");
      return;
    }
    setError(null);
    setOperationStatus("running");
    setActiveStep("operation");
    try {
      const result = await request<{ operation_id: string }>(
        "/api/operations",
        {
          method: "POST",
          body: JSON.stringify({
            kind: "onboard",
            source_url: draft.sourceUrl,
            source_username: draft.sourceUsername,
            source_password: draft.sourcePassword,
            website_name: draft.websiteName,
            container_name: draft.containerName,
            directory: draft.directory,
            newapi_port: Number(draft.newapiPort),
            kuma_port: Number(draft.kumaPort),
            ssh_destination: draft.sshDestination,
            newapi_admin_username: draft.newapiAdminUsername,
            newapi_admin_password: draft.newapiAdminPassword || null,
            kuma_admin_username: draft.kumaAdminUsername,
            kuma_admin_password: draft.kumaAdminPassword || null,
            image: draft.image,
            image_ref: draft.imageRef,
          }),
        },
        session,
      );
      setOperationId(result.operation_id);
      setLastEvent("部署操作已排队");
    } catch (cause) {
      setOperationStatus("failed");
      setError(cause instanceof Error ? cause.message : "无法启动部署操作");
    }
  }

  async function cancelOperation() {
    if (!session || !operationId) return;
    try {
      await request(`/api/operations/${encodeURIComponent(operationId)}/cancel`, { method: "POST" }, session);
      setLastEvent("正在安全取消操作");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "无法取消操作");
    }
  }

  async function resumeOperation() {
    if (!session || !operationId) return;
    try {
      await request(`/api/operations/${encodeURIComponent(operationId)}/resume`, { method: "POST" }, session);
      setOperationStatus("running");
      setLastEvent("正在从检查点恢复");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "无法恢复操作");
    }
  }

  async function startUtilityOperation(kind: "status" | "sync" | "clean" | "rollback", extra: Record<string, unknown> = {}) {
    if (!session) return;
    if ((kind === "clean" || kind === "rollback") && !window.confirm(kind === "clean" ? "确认清理下游资源？" : "确认回滚并删除当前部署？")) return;
    setError(null);
    setOperationStatus("running");
    setActiveStep("operation");
    setCredentials(undefined);
    try {
      const result = await request<{ operation_id: string }>("/api/operations", {
        method: "POST",
        body: JSON.stringify({ kind, ...extra }),
      }, session);
      setOperationId(result.operation_id);
      setLastEvent(`${kind} 操作已排队`);
    } catch (cause) {
      setOperationStatus("failed");
      setError(cause instanceof Error ? cause.message : "无法启动操作");
    }
  }

  async function logout() {
    if (!session) return;
    try {
      await request<void>("/api/session", { method: "DELETE" }, session);
    } finally {
      setSession(null);
      setBootstrap(null);
    }
  }

  async function copyTarget() {
    try {
      await navigator.clipboard.writeText(draft.sshDestination || "user@linux-host");
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1400);
    } catch {
      setError("当前浏览器不允许复制，请直接选择目标文本");
    }
  }

  if (loading) return <LoadingScreen />;
  if (!session || error?.includes("会话") || error?.includes("本地 Web")) {
    return <SessionScreen error={error} onRetry={() => window.location.reload()} />;
  }

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand-lockup">
          <span className="brand-mark" aria-hidden="true">m/</span>
          <div>
            <strong>部署校准台</strong>
            <span>meowai-deploy · loopback</span>
          </div>
        </div>
        <div className="topbar-actions">
          <span className="connection-state"><span className="state-dot" />{lastEvent}</span>
          <button className="icon-button" title="退出本地会话" aria-label="退出本地会话" onClick={() => void logout()}>
            <LogOut size={17} />
          </button>
        </div>
      </header>

      <main className="workbench">
        <aside className="route-spine" aria-label="部署步骤">
          <div className="spine-heading">
            <span>ROUTE</span>
            <span className="spine-code">{bootstrap?.version ?? "local"}</span>
          </div>
          <nav>
            {steps.map((step, index) => {
              const Icon = step.icon;
              const current = step.key === activeStep;
              const complete = index < activeIndex || (step.key === "operation" && operationStatus === "completed");
              return (
                <button
                  className={`route-step ${current ? "is-current" : ""} ${complete ? "is-complete" : ""}`}
                  key={step.key}
                  onClick={() => index <= activeIndex && setActiveStep(step.key)}
                  aria-current={current ? "step" : undefined}
                >
                  <span className="route-node">{complete ? <Check size={14} /> : <Icon size={15} />}</span>
                  <span className="route-copy"><strong>{step.label}</strong><small>{step.note}</small></span>
                  <span className="route-index">{String(index + 1).padStart(2, "0")}</span>
                </button>
              );
            })}
          </nav>
          <div className="spine-footer">
            <ShieldCheck size={16} />
            <span>凭证只留在本机内存</span>
          </div>
        </aside>

        <section className="work-surface">
          <div className="surface-heading">
            <div>
              <span className="surface-kicker">CURRENT WORK SURFACE</span>
              <h1>{active.label}</h1>
            </div>
            <div className="surface-index">{String(activeIndex + 1).padStart(2, "0")} / {String(steps.length).padStart(2, "0")}</div>
          </div>

          <div className="surface-content">
            {activeStep === "target" && <TargetStep draft={draft} update={update} onCopy={() => void copyTarget()} copied={copied} />}
            {activeStep === "source" && <SourceStep draft={draft} update={update} />}
            {activeStep === "site" && <SiteStep draft={draft} update={update} />}
            {activeStep === "review" && <ReviewStep draft={draft} />}
            {activeStep === "operation" && <OperationStep status={operationStatus} operationId={operationId} lastEvent={lastEvent} credentials={credentials} onCancel={() => void cancelOperation()} onResume={() => void resumeOperation()} onRetry={() => setActiveStep("review")} />}
          </div>

          {error && <div className="inline-error" role="alert"><AlertTriangle size={16} /><span>{error}</span><button className="icon-button small" title="关闭错误" aria-label="关闭错误" onClick={() => setError(null)}><X size={14} /></button></div>}

          <footer className="surface-actions">
            <button className="secondary-action" onClick={goBack} disabled={activeIndex === 0 || operationStatus === "running"}>
              <ArrowLeft size={16} /> 返回
            </button>
            {activeStep === "review" ? (
              <button className="primary-action" onClick={() => void startOperation()} disabled={!canAdvance || operationStatus === "running"}>
                <TerminalSquare size={17} /> 开始部署 <ArrowRight size={16} />
              </button>
            ) : activeStep !== "operation" ? (
              <button className="primary-action" onClick={goNext} disabled={!canAdvance}>
                继续 <ArrowRight size={16} />
              </button>
            ) : (
              <button className="secondary-action" onClick={() => setActiveStep("review")} disabled={operationStatus === "running"}>
                <RefreshCcw size={16} /> 返回复核
              </button>
            )}
          </footer>
        </section>

        <aside className="operation-rail" aria-label="当前检查">
          <div className="rail-heading"><span>CHECK RAIL</span><Activity size={15} /></div>
          <div className="rail-status"><span className="status-label">SESSION</span><strong>已保护</strong><small>HttpOnly · SameSite</small></div>
          <div className="rail-status"><span className="status-label">TARGET</span><strong className={draft.sshDestination ? "value-ready" : "value-muted"}>{draft.sshDestination || "等待 SSH 目标"}</strong><small>Linux amd64 · OpenSSH</small></div>
          <div className="rail-status"><span className="status-label">NEXT SAFE ACTION</span><strong>{activeStep === "operation" ? "观察事件流" : activeStep === "review" ? "确认部署" : `填写${active.label}`}</strong><small>不会自动写入生产地址</small></div>
          <div className="rail-tools" aria-label="日常操作">
            <button className="icon-button" title="查看部署状态" aria-label="查看部署状态" onClick={() => void startUtilityOperation("status")}><Activity size={16} /></button>
            <button className="icon-button" title="同步部署" aria-label="同步部署" onClick={() => void startUtilityOperation("sync", { include_pricing: true })}><RefreshCcw size={16} /></button>
            <button className="icon-button" title="清理下游资源" aria-label="清理下游资源" onClick={() => void startUtilityOperation("clean")}><Trash2 size={16} /></button>
            <button className="icon-button" title="回滚部署" aria-label="回滚部署" onClick={() => void startUtilityOperation("rollback", { revoke_source: false })}><RotateCcw size={16} /></button>
          </div>
          <div className="rail-rule" />
          <div className="rail-note"><span className="note-pin" />本机服务只绑定 127.0.0.1</div>
          <div className="rail-note"><span className="note-pin teal" />人工 Windows 验收在平台测试阶段统一执行</div>
        </aside>
      </main>
    </div>
  );
}

function LoadingScreen() {
  return <main className="session-screen"><div className="session-panel"><div className="loading-mark"><Activity size={24} /></div><p>正在连接本机部署服务…</p></div></main>;
}

function SessionScreen({ error, onRetry }: { error: string | null; onRetry: () => void }) {
  return <main className="session-screen"><div className="session-panel"><div className="brand-mark large">m/</div><h1>本机部署服务未就绪</h1><p>{error ?? "请从 meowai-deploy web 启动链接进入。"}</p><button className="primary-action" onClick={onRetry}><RefreshCcw size={17} />重新连接</button></div></main>;
}

function TargetStep({ draft, update, onCopy, copied }: { draft: Draft; update: <K extends keyof Draft>(key: K, value: Draft[K]) => void; onCopy: () => void; copied: boolean }) {
  return <div className="step-layout"><div className="step-intro"><span className="surface-kicker">01 / REMOTE TARGET</span><h2>先把部署落点钉住。</h2><p>输入客户提供的 Linux SSH 目标。Windows 控制端只走远程 SSH，本机不会运行 Docker。</p></div><div className="form-grid"><Field label="SSH 目标" hint="例如 deploy@example.test"><div className="input-with-action"><input autoFocus value={draft.sshDestination} onChange={(event) => update("sshDestination", event.target.value)} placeholder="user@linux-host" autoComplete="off"/><button className="icon-button" type="button" title="复制示例" aria-label="复制示例" onClick={onCopy}>{copied ? <Check size={16} /> : <Copy size={16} />}</button></div></Field><Field label="远程目录" hint="POSIX 绝对路径"><input value={draft.directory} onChange={(event) => update("directory", event.target.value)} placeholder="/opt/meowai-deploy/newapi" /></Field></div></div>;
}

function SourceStep({ draft, update }: { draft: Draft; update: <K extends keyof Draft>(key: K, value: Draft[K]) => void }) {
  return <div className="step-layout"><div className="step-intro"><span className="surface-kicker">02 / SOURCE ACCOUNT</span><h2>把源站身份交给本机服务。</h2><p>密码只通过本机 HTTPS-like loopback 请求提交给 Rust 服务，不会进入 URL 或浏览器存储。</p></div><div className="form-grid"><Field label="源站 URL" hint="仅在开始验证时访问"><input value={draft.sourceUrl} onChange={(event) => update("sourceUrl", event.target.value)} placeholder="https://source.example.test" autoComplete="url" /></Field><Field label="源站用户名"><input value={draft.sourceUsername} onChange={(event) => update("sourceUsername", event.target.value)} autoComplete="username" /></Field><Field label="源站密码"><input type="password" value={draft.sourcePassword} onChange={(event) => update("sourcePassword", event.target.value)} autoComplete="current-password" /></Field></div></div>;
}

function SiteStep({ draft, update }: { draft: Draft; update: <K extends keyof Draft>(key: K, value: Draft[K]) => void }) {
  return <div className="step-layout"><div className="step-intro"><span className="surface-kicker">03 / SITE PROFILE</span><h2>给下游站点一组可复核的参数。</h2><p>端口、目录和镜像会在部署前再次校验；留空管理员密码时由核心生成并只在完成页显示一次。</p></div><div className="form-grid two-col"><Field label="站点名称"><input value={draft.websiteName} onChange={(event) => update("websiteName", event.target.value)} /></Field><Field label="容器项目名"><input value={draft.containerName} onChange={(event) => update("containerName", event.target.value)} /></Field><Field label="New API 端口"><input inputMode="numeric" value={draft.newapiPort} onChange={(event) => update("newapiPort", event.target.value)} /></Field><Field label="Uptime Kuma 端口"><input inputMode="numeric" value={draft.kumaPort} onChange={(event) => update("kumaPort", event.target.value)} /></Field><Field label="镜像"><input value={draft.image} onChange={(event) => update("image", event.target.value)} /></Field><Field label="镜像提交或 digest" hint="留空使用最新不可变 digest"><input value={draft.imageRef} onChange={(event) => update("imageRef", event.target.value)} placeholder="sha256:…" /></Field></div></div>;
}

function ReviewStep({ draft }: { draft: Draft }) {
  const rows = [["SSH 目标", draft.sshDestination], ["远程目录", draft.directory], ["源站", draft.sourceUrl], ["站点", draft.websiteName], ["端口", `${draft.newapiPort} / ${draft.kumaPort}`], ["镜像", draft.imageRef ? `${draft.image}@${draft.imageRef}` : `${draft.image} · 自动解析 digest`]];
  return <div className="step-layout"><div className="step-intro"><span className="surface-kicker">04 / PLAN CHECK</span><h2>最后一眼，只看会发生什么。</h2><p>确认后才会开始源站验证、远程权限检查和部署阶段。表单里的密码不会出现在这张计划里。</p></div><div className="review-list">{rows.map(([label, value]) => <div className="review-row" key={label}><span>{label}</span><strong>{value || "未填写"}</strong></div>)}<div className="review-safe"><ShieldCheck size={17} /><span>部署脚本通过 SSH 标准输入发送，WebUI 不会执行本机 Docker。</span></div></div></div>;
}

function OperationStep({ status, operationId, lastEvent, credentials, onCancel, onResume, onRetry }: { status: "idle" | "running" | "completed" | "failed"; operationId: string | null; lastEvent: string; credentials?: Array<{ kind: string; username: string; password: string }>; onCancel: () => void; onResume: () => void; onRetry: () => void }) {
  const complete = status === "completed";
  const failed = status === "failed";
  return <div className="step-layout operation-view"><div className={`operation-emblem ${complete ? "complete" : failed ? "failed" : ""}`}>{complete ? <CheckCircle2 size={32} /> : failed ? <AlertTriangle size={32} /> : <Activity size={32} />}</div><div className="step-intro"><span className="surface-kicker">05 / LIVE OPERATION</span><h2>{complete ? "部署路线已完成。" : failed ? "部署停在需要处理的位置。" : "部署路线正在运行。"}</h2><p aria-live="polite">{lastEvent}</p></div><div className="operation-track"><div className="track-line"><span className={`track-fill ${complete ? "complete" : ""}`} /></div>{["连接源站", "检查目标", "准备服务", "同步配置", "最终复核"].map((label, index) => <div className={`track-stop ${complete || (status === "running" && index < 2) ? "done" : ""}`} key={label}><span>{complete || (status === "running" && index < 2) ? <Check size={13} /> : <Circle size={13} />}</span><small>{label}</small></div>)}</div>{operationId && <code className="operation-id">operation · {operationId}</code>}{credentials && credentials.length > 0 && <div className="credential-result" role="status"><strong>请立即保存管理员凭证</strong>{credentials.map((credential) => <div className="credential-row" key={credential.kind}><span>{credential.kind}</span><code>{credential.username} / {credential.password}</code></div>)}</div>}<div className="operation-actions">{status === "running" && <button className="secondary-action" onClick={onCancel}><X size={16} />取消操作</button>}{failed && <><button className="secondary-action" onClick={onResume}><RefreshCcw size={16} />从检查点恢复</button><button className="secondary-action" onClick={onRetry}><RefreshCcw size={16} />返回复核并重试</button></>}</div></div>;
}

function Field({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return <label className="field"><span className="field-label">{label}</span>{children}{hint && <small>{hint}</small>}</label>;
}

function validateStep(step: StepKey, draft: Draft): string | null {
  if (step === "target") {
    if (!draft.sshDestination.trim()) return "先填写 SSH 目标，例如 deploy@example.test。";
    if (!/^\/[A-Za-z0-9_./-]+$/.test(draft.directory)) return "远程目录必须是不含 .. 的 POSIX 绝对路径。";
  }
  if (step === "source") {
    if (!/^https:\/\//.test(draft.sourceUrl) && !/^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?/.test(draft.sourceUrl)) return "源站 URL 需要使用 HTTPS；本机 mock 可使用 loopback HTTP。";
    if (!draft.sourceUsername.trim() || !draft.sourcePassword) return "源站用户名和密码都需要填写。";
  }
  if (step === "site") {
    if (!draft.websiteName.trim() || !/^[A-Za-z0-9_.-]+$/.test(draft.containerName)) return "站点名称和容器项目名需要填写有效值。";
    const newapi = Number(draft.newapiPort);
    const kuma = Number(draft.kumaPort);
    if (!Number.isInteger(newapi) || !Number.isInteger(kuma) || newapi < 1 || kuma < 1 || newapi === kuma) return "两个端口需要是不同的有效数字。";
  }
  if (step === "review") {
    return validateStep("target", draft) ?? validateStep("source", draft) ?? validateStep("site", draft);
  }
  return null;
}
