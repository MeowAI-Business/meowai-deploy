import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import {
  Activity,
  AlertTriangle,
  ArrowLeft,
  ArrowRight,
  Boxes,
  Check,
  CheckCircle2,
  ClipboardCheck,
  HardDrive,
  KeyRound,
  LoaderCircle,
  LogOut,
  RefreshCcw,
  Server,
  TerminalSquare,
  Wifi,
  X,
  Upload,
} from "lucide-react";

type StepKey = "target" | "source" | "site" | "review" | "operation";
type DeploymentTarget = "local" | "ssh";

type Draft = {
  target: DeploymentTarget;
  sshDestination: string;
  sshPassword: string;
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

type ImportedDraft = {
  target: DeploymentTarget;
  ssh_destination: string;
  source_url: string;
  source_username: string;
  website_name: string;
  container_name: string;
  directory: string;
  newapi_port: number;
  kuma_port: number;
  newapi_admin_username: string;
  kuma_admin_username: string;
  image: string;
  image_ref: string;
};

type Session = { csrfToken: string };

type Bootstrap = {
  version: string;
  hasSavedDeployment: boolean;
  operationLock: boolean;
  supportsLocalTarget: boolean;
  savedDeployment: SavedDeployment | null;
  currentOperation: CurrentOperation | null;
  defaults: {
    sourceUrl: string;
    websiteName: string;
    containerName: string;
    directory: string;
    newapiPort: number;
    kumaPort: number;
    image: string;
  };
};

type CurrentOperation = {
  operationId: string;
  kind: string;
  status: "draft" | "running" | "cancelling" | "cancelled" | "failed" | "completed";
  currentStage: string | null;
  retryable: boolean;
};

type SavedDeployment = {
  target: DeploymentTarget;
  sshDestination: string;
  sourceUrl: string;
  sourceUsername: string;
  websiteName: string;
  containerName: string;
  directory: string;
  newapiPort: number;
  kumaPort: number;
  newapiAdminUsername: string;
  kumaAdminUsername: string;
  image: string;
  imageRef: string;
};

type DialogKind = "existing-deployment" | "replacement-required" | "rotate-status-key" | "close-running";

type SyncModulePlan = {
  module: string;
  label: string;
  actionable: boolean;
  conflict: boolean;
  diffs: Array<{ path: string; classification: string; risk: string; sensitive: boolean }>;
};

type SyncPlan = {
  fingerprint: string;
  modules: SyncModulePlan[];
  group_margins: Array<{ name: string; purchase: number | null; sales: number; margin_percent: number | null; risk: string }>;
  seedance_margins: Array<{ name: string; purchase: number | null; sales: number; margin_percent: number | null; risk: string }>;
};

type PreflightStep = "target" | "source" | "site";
type ImageCheckState = "idle" | "loading" | "valid" | "error";

type ApiError = Error & { code?: string };

type OperationEvent = {
  operation_id: string;
  sequence: number;
  timestamp: number;
  stage?: string;
  severity: "debug" | "info" | "warning" | "error";
  kind: { type: string; code?: string; completed?: number; total?: number };
  message: string;
  diagnostic?: string;
};

type OperationFailure = {
  stage: string;
  code: string;
  message: string;
  retryable: boolean;
  diagnostic?: string;
};

type OperationSnapshot = {
  checkpoint: {
    operation_id: string;
    status: "draft" | "running" | "cancelling" | "cancelled" | "failed" | "completed";
    current_stage?: string;
    completed_stages?: string[];
    failure?: OperationFailure;
  };
  events: OperationEvent[];
  result?: Record<string, unknown>;
  credentials?: Array<{ kind: string; username: string; password: string }>;
};

const steps: Array<{ key: StepKey; label: string; icon: typeof Server }> = [
  { key: "target", label: "部署位置", icon: Server },
  { key: "source", label: "源站账号", icon: KeyRound },
  { key: "site", label: "站点设置", icon: Boxes },
  { key: "review", label: "确认信息", icon: ClipboardCheck },
  { key: "operation", label: "开始部署", icon: Activity },
];

const operationStages = [
  "input_validation",
  "source_connectivity",
  "source_authentication",
  "source_approval",
  "target_validation",
  "source_resources",
  "base_services",
  "downstream_initialization",
  "pricing_import",
  "channel_synchronization",
  "kuma_synchronization",
  "final_verification",
] as const;

const defaultDraft: Draft = {
  target: "local",
  sshDestination: "",
  sshPassword: "",
  sourceUrl: "https://enterprise.meowai.net",
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
      // Plain responses are possible when the request is rejected before routing.
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
  const credentialMemory = useRef({ sourcePassword: "", sshPassword: "" });
  const [activeStep, setActiveStep] = useState<StepKey>("target");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastEvent, setLastEvent] = useState("正在准备部署");
  const [operationId, setOperationId] = useState<string | null>(null);
  const [operationStatus, setOperationStatus] = useState<"idle" | "running" | "completed" | "failed">("idle");
  const [operationEvents, setOperationEvents] = useState<OperationEvent[]>([]);
  const [operationFailure, setOperationFailure] = useState<OperationFailure | null>(null);
  const [operationProgress, setOperationProgress] = useState(0);
  const [operationPollGeneration, setOperationPollGeneration] = useState(0);
  const [currentStage, setCurrentStage] = useState<string | null>(null);
  const [credentials, setCredentials] = useState<OperationSnapshot["credentials"]>(undefined);
  const [resumingOperation, setResumingOperation] = useState(false);
  const [resumeSourcePasswordRequired, setResumeSourcePasswordRequired] = useState(false);
  const [checkingStep, setCheckingStep] = useState<PreflightStep | null>(null);
  const [validatedSteps, setValidatedSteps] = useState<Record<PreflightStep, boolean>>({
    target: false,
    source: false,
    site: false,
  });
  const [imageCheckState, setImageCheckState] = useState<ImageCheckState>("idle");
  const [imageCheckError, setImageCheckError] = useState<string | null>(null);
  const [imageUpdatedAt, setImageUpdatedAt] = useState<string | null>(null);
  const [resolvedImage, setResolvedImage] = useState<string | null>(null);
  const [imageReloadKey, setImageReloadKey] = useState(0);
  const [dialog, setDialog] = useState<DialogKind | null>(null);
  const [replaceExisting, setReplaceExisting] = useState(false);
  const [directoryCustomized, setDirectoryCustomized] = useState(false);
  const [usingSavedConfig, setUsingSavedConfig] = useState(false);
  const [syncPlan, setSyncPlan] = useState<SyncPlan | null>(null);
  const [syncPlanLoading, setSyncPlanLoading] = useState(false);
  const [selectedSyncModules, setSelectedSyncModules] = useState<string[]>([]);
  const [forceSyncConflicts, setForceSyncConflicts] = useState(false);
  const [syncSourceAuthRequired, setSyncSourceAuthRequired] = useState(false);
  const [syncSshAuthRequired, setSyncSshAuthRequired] = useState(false);

  useEffect(() => {
    let cancelled = false;
    async function initialize() {
      try {
        const token = readFragmentToken();
        const nextSession = token
          ? await request<{ csrf_token: string }>("/api/session", { method: "POST", body: JSON.stringify({ token }) })
          : await request<{ csrf_token: string }>("/api/session");
        const sessionValue = { csrfToken: nextSession.csrf_token };
        const nextBootstrap = await request<{
          version: string;
          has_saved_deployment: boolean;
          saved_deployment: {
            target: DeploymentTarget;
            ssh_destination: string | null;
            source_url: string;
            source_username: string;
            website_name: string;
            container_name: string;
            directory: string;
            newapi_port: number;
            kuma_port: number;
            newapi_admin_username: string;
            kuma_admin_username: string;
            image: string;
            image_ref: string;
          } | null;
          operation_lock: boolean;
          supports_local_target: boolean;
          current_operation: {
            operation_id: string;
            kind: string;
            status: CurrentOperation["status"];
            current_stage: string | null;
            retryable: boolean;
          } | null;
          defaults: {
            source_url: string;
            website_name: string;
            container_name: string;
            directory: string;
            newapi_port: number;
            kuma_port: number;
            image: string;
          };
        }>("/api/bootstrap", {}, sessionValue);
        if (!cancelled) {
          const savedDeployment = nextBootstrap.saved_deployment ? {
            target: nextBootstrap.saved_deployment.target,
            sshDestination: nextBootstrap.saved_deployment.ssh_destination ?? "",
            sourceUrl: nextBootstrap.saved_deployment.source_url,
            sourceUsername: nextBootstrap.saved_deployment.source_username,
            websiteName: nextBootstrap.saved_deployment.website_name,
            containerName: nextBootstrap.saved_deployment.container_name,
            directory: nextBootstrap.saved_deployment.directory,
            newapiPort: nextBootstrap.saved_deployment.newapi_port,
            kumaPort: nextBootstrap.saved_deployment.kuma_port,
            newapiAdminUsername: nextBootstrap.saved_deployment.newapi_admin_username,
            kumaAdminUsername: nextBootstrap.saved_deployment.kuma_admin_username,
            image: nextBootstrap.saved_deployment.image,
            imageRef: nextBootstrap.saved_deployment.image_ref,
          } : null;
          setSession(sessionValue);
          setBootstrap({
            version: nextBootstrap.version,
            hasSavedDeployment: nextBootstrap.has_saved_deployment,
            operationLock: nextBootstrap.operation_lock,
            supportsLocalTarget: nextBootstrap.supports_local_target,
            savedDeployment,
            currentOperation: nextBootstrap.current_operation ? {
              operationId: nextBootstrap.current_operation.operation_id,
              kind: nextBootstrap.current_operation.kind,
              status: nextBootstrap.current_operation.status,
              currentStage: nextBootstrap.current_operation.current_stage,
              retryable: nextBootstrap.current_operation.retryable,
            } : null,
            defaults: {
              sourceUrl: nextBootstrap.defaults.source_url,
              websiteName: nextBootstrap.defaults.website_name,
              containerName: nextBootstrap.defaults.container_name,
              directory: nextBootstrap.defaults.directory,
              newapiPort: nextBootstrap.defaults.newapi_port,
              kumaPort: nextBootstrap.defaults.kuma_port,
              image: nextBootstrap.defaults.image,
            },
          });
          setDraft((current) => ({
            ...current,
            target: nextBootstrap.supports_local_target ? current.target : "ssh",
            sourceUrl: nextBootstrap.defaults.source_url,
            websiteName: nextBootstrap.defaults.website_name,
            containerName: nextBootstrap.defaults.container_name,
            directory: nextBootstrap.defaults.directory,
            newapiPort: String(nextBootstrap.defaults.newapi_port),
            kumaPort: String(nextBootstrap.defaults.kuma_port),
            image: nextBootstrap.defaults.image,
          }));
          if (nextBootstrap.has_saved_deployment && savedDeployment) {
            setDialog("existing-deployment");
          }
        }
      } catch (cause) {
        if (!cancelled) setError(cause instanceof Error ? cause.message : "无法连接本机 Web 服务");
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
    source.addEventListener("operation", (event) => {
      try {
        const payload = JSON.parse((event as MessageEvent).data) as OperationEvent;
        if (payload.operation_id && payload.operation_id !== operationId) return;
        setOperationEvents((current) => {
          return mergeOperationEvents(current, [payload]);
        });
        if (payload.stage) setCurrentStage(payload.stage);
        if (payload.message) setLastEvent(payload.message);
        if (payload.kind.type === "stage_started" && payload.stage) {
          const index = operationStages.indexOf(payload.stage as (typeof operationStages)[number]);
          if (index >= 0) setOperationProgress(Math.round((index / operationStages.length) * 100));
        }
        if (payload.kind.type === "stage_completed" && payload.stage) {
          const index = operationStages.indexOf(payload.stage as (typeof operationStages)[number]);
          if (index >= 0) setOperationProgress(Math.round(((index + 1) / operationStages.length) * 100));
        }
        if (payload.kind.type === "recoverable_failure" || payload.kind.type === "fatal_failure") {
          setOperationStatus("failed");
          setOperationFailure({
            stage: payload.stage ?? "unknown",
            code: payload.kind.code ?? "DEPLOYMENT_FAILED",
            message: payload.message,
            retryable: payload.kind.type === "recoverable_failure",
            diagnostic: payload.diagnostic,
          });
          setResumeSourcePasswordRequired(
            failureNeedsSourcePassword(payload.kind.code) && !credentialMemory.current.sourcePassword,
          );
        }
        if (payload.kind.type === "operation_completed") {
          setOperationStatus("completed");
          setOperationProgress(100);
          setActiveStep("operation");
        }
      } catch {
        // Polling remains the source of truth if an event cannot be decoded.
      }
    });
    source.onerror = () => {
      if (operationStatus === "running") setLastEvent("连接中断，正在重试");
    };
    return () => source.close();
  }, [operationId, operationStatus, session]);

  useEffect(() => {
    if (!session || !operationId) return;
    let cancelled = false;
    let timer: number | undefined;
    async function poll() {
      try {
        const snapshot = await request<OperationSnapshot>(`/api/operations/${encodeURIComponent(operationId)}`, {}, session);
        if (cancelled) return;
        const status = snapshot.checkpoint.status;
        setOperationEvents((current) => mergeOperationEvents(current, snapshot.events ?? []));
        setCurrentStage(snapshot.checkpoint.current_stage ?? null);
        const completedCount = snapshot.checkpoint.completed_stages?.filter((stage) => operationStages.includes(stage as (typeof operationStages)[number])).length ?? 0;
        const stageInProgress = snapshot.checkpoint.current_stage ? 0.35 : 0;
        setOperationProgress(Math.min(100, Math.round(((completedCount + stageInProgress) / operationStages.length) * 100)));
        if (status === "running" || status === "cancelling" || status === "draft") {
          setOperationStatus("running");
          setOperationFailure(null);
          setResumeSourcePasswordRequired(false);
        } else if (status === "completed") {
          setOperationStatus("completed");
          setOperationProgress(100);
          if (snapshot.credentials) setCredentials(snapshot.credentials);
          setLastEvent("部署已完成");
        } else if (status === "failed" || status === "cancelled") {
          setOperationStatus("failed");
          setOperationFailure(snapshot.checkpoint.failure ?? null);
          setResumeSourcePasswordRequired(
            failureNeedsSourcePassword(snapshot.checkpoint.failure?.code)
              && !credentialMemory.current.sourcePassword,
          );
          setLastEvent(snapshot.checkpoint.failure?.message ?? (status === "cancelled" ? "操作已取消" : "部署失败"));
        }
      } catch (cause) {
        if (!cancelled) setError(cause instanceof Error ? cause.message : "无法读取部署状态");
      } finally {
        if (!cancelled) timer = window.setTimeout(() => void poll(), 1200);
      }
    }
    void poll();
    return () => {
      cancelled = true;
      if (timer) window.clearTimeout(timer);
    };
  }, [operationId, operationPollGeneration, session]);

  useEffect(() => {
    if (activeStep !== "site" || !session || !draft.image.trim()) return;
    const image = draft.image.trim();
    const controller = new AbortController();
    let cancelled = false;
    setImageCheckState("loading");
    setImageCheckError(null);
    setImageUpdatedAt(null);
    setResolvedImage(null);
    setDraft((current) => current.image.trim() === image ? { ...current, imageRef: "" } : current);
    setValidatedSteps((current) => ({ ...current, site: false }));
    const timer = window.setTimeout(async () => {
      try {
        const result = await request<{ image: string; immutable_ref: string; updated_at: string | null }>(
          "/api/preflight/image",
          { method: "POST", body: JSON.stringify({ image }), signal: controller.signal },
          session,
        );
        if (cancelled) return;
        setDraft((current) => current.image.trim() === image
          ? { ...current, imageRef: result.immutable_ref }
          : current);
        setImageUpdatedAt(result.updated_at);
        setResolvedImage(result.image);
        setImageCheckState("valid");
      } catch (cause) {
        if (cancelled) return;
        setImageCheckState("error");
        setImageCheckError(cause instanceof Error ? cause.message : "无法解析镜像 digest");
      }
    }, 250);
    return () => {
      cancelled = true;
      controller.abort();
      window.clearTimeout(timer);
    };
  }, [activeStep, draft.image, imageReloadKey, session]);

  const activeIndex = steps.findIndex((step) => step.key === activeStep);
  const active = steps[activeIndex] ?? steps[0];
  const canAdvance = useMemo(() => validateStep(activeStep, draft) === null, [activeStep, draft]);

  function update<K extends keyof Draft>(key: K, value: Draft[K]) {
    const preflight = preflightForField(key);
    if (key === "sourcePassword" || key === "sshPassword") {
      credentialMemory.current[key] = value;
    }
    if (key === "directory") setDirectoryCustomized(true);
    setDraft((current) => {
      const next = {
        ...current,
        [key]: value,
        ...(key === "image" ? { imageRef: "" } : {}),
      };
      if (key === "containerName" && !directoryCustomized) {
        const containerName = String(value).trim();
        if (/^[A-Za-z0-9_.-]+$/.test(containerName)) {
          next.directory = `/opt/meowai-deploy/${containerName}`;
        }
      }
      return next;
    });
    // Review and recovery credentials are one-shot inputs, not deployment configuration.
    if (preflight && activeStep !== "review" && activeStep !== "operation") {
      setValidatedSteps((current) => ({ ...current, [preflight]: false }));
    }
    if (key === "image") {
      setImageCheckState("idle");
      setImageCheckError(null);
      setImageUpdatedAt(null);
      setResolvedImage(null);
    }
    setError(null);
  }

  async function goNext() {
    if (!session || checkingStep) return;
    const validation = validateStep(activeStep, draft);
    if (validation) {
      setError(validation);
      return;
    }
    if (activeStep === "target") {
      setCheckingStep("target");
      setError(null);
      try {
        await request<{ fingerprint: string; newapi_port: number; kuma_port: number }>(
          "/api/preflight/target",
          {
            method: "POST",
            body: JSON.stringify({
              target: draft.target,
              ssh_destination: draft.target === "ssh" ? draft.sshDestination : null,
              ssh_password: draft.target === "ssh" ? draft.sshPassword || null : null,
              directory: draft.directory,
              newapi_port: Number(draft.newapiPort),
              kuma_port: Number(draft.kumaPort),
              check_site: false,
            }),
          },
          session,
        );
        setValidatedSteps((current) => ({ ...current, target: true }));
      } catch (cause) {
        setError(cause instanceof Error ? cause.message : "部署位置检查失败");
        return;
      } finally {
        setCheckingStep(null);
      }
    }
    if (activeStep === "source") {
      setCheckingStep("source");
      setError(null);
      try {
        await request<{ username: string; user_id: number }>(
          "/api/preflight/source",
          {
            method: "POST",
            body: JSON.stringify({
              source_url: draft.sourceUrl,
              source_username: draft.sourceUsername,
              source_password: draft.sourcePassword,
            }),
          },
          session,
        );
        setValidatedSteps((current) => ({ ...current, source: true }));
      } catch (cause) {
        setError(cause instanceof Error ? cause.message : "源站账号验证失败");
        return;
      } finally {
        setCheckingStep(null);
      }
    }
    if (activeStep === "site") {
      if (imageCheckState !== "valid" || resolvedImage !== draft.image.trim() || !draft.imageRef) {
        setError("请等待最新镜像 digest 解析完成后再继续。");
        return;
      }
      setCheckingStep("site");
      setError(null);
      try {
        await request<{ fingerprint: string; newapi_port: number; kuma_port: number }>(
          "/api/preflight/target",
          {
            method: "POST",
            body: JSON.stringify({
              target: draft.target,
              ssh_destination: draft.target === "ssh" ? draft.sshDestination : null,
              ssh_password: draft.target === "ssh" ? draft.sshPassword || null : null,
              directory: draft.directory,
              newapi_port: Number(draft.newapiPort),
              kuma_port: Number(draft.kumaPort),
              check_site: true,
            }),
          },
          session,
        );
        setValidatedSteps((current) => ({ ...current, site: true }));
      } catch (cause) {
        setError(cause instanceof Error ? cause.message : "镜像 digest 解析失败");
        return;
      } finally {
        setCheckingStep(null);
      }
    }
    const next = steps[activeIndex + 1];
    if (next) setActiveStep(next.key);
  }

  function goBack() {
    const previous = steps[activeIndex - 1];
    if (previous) setActiveStep(previous.key);
  }

  async function importPreset(file: File) {
    if (!session) return;
    setError(null);
    try {
      const imported = await request<ImportedDraft>("/api/config/import", {
        method: "POST",
        body: JSON.stringify({ toml: await file.text() }),
      }, session);
      setDraft((current) => ({ ...current, target: imported.target, sshDestination: imported.ssh_destination, sourceUrl: imported.source_url, sourceUsername: imported.source_username, websiteName: imported.website_name, containerName: imported.container_name, directory: imported.directory, newapiPort: String(imported.newapi_port), kumaPort: String(imported.kuma_port), newapiAdminUsername: imported.newapi_admin_username, kumaAdminUsername: imported.kuma_admin_username, image: imported.image, imageRef: imported.image_ref }));
      setValidatedSteps({ target: true, source: true, site: true });
      setImageCheckState(imported.image_ref ? "valid" : "idle");
      setActiveStep("review");
      setLastEvent(`已导入预设：${file.name}`);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "无法导入 TOML 预设");
    }
  }

  async function startOperation(forceReplace = replaceExisting) {
    if (!session) return;
    if (usingSavedConfig) {
      if (!syncPlan || selectedSyncModules.length === 0) return;
      setError(null);
      setLastEvent("正在校验同步计划");
      setOperationEvents([]);
      setOperationFailure(null);
      setOperationProgress(0);
      setCurrentStage(null);
      try {
        const result = await request<{ operation_id: string }>("/api/operations", {
          method: "POST",
          body: JSON.stringify({
            kind: "sync",
            modules: selectedSyncModules,
            plan_fingerprint: syncPlan.fingerprint,
            force: forceSyncConflicts,
            source_password: draft.sourcePassword || null,
            ssh_password: draft.target === "ssh" ? draft.sshPassword || null : null,
          }),
        }, session);
        setOperationId(result.operation_id);
        setOperationStatus("running");
        setActiveStep("operation");
        setLastEvent("同步任务已开始");
      } catch (cause) {
        const message = cause instanceof Error ? cause.message : "无法启动同步";
        setError(message);
        if ((cause as ApiError).code === "SYNC_PLAN_STALE" || message.includes("过期")) void loadSyncPlan();
      }
      return;
    }
    const validation = validateStep("review", draft);
    if (validation) {
      setError(validation);
      setActiveStep("review");
      return;
    }
    if (!validatedSteps.target || !validatedSteps.source || !validatedSteps.site) {
      setError("部署信息已经变更，请返回对应步骤重新检查。");
      return;
    }
    setError(null);
    setLastEvent("正在启动部署");
    setOperationEvents([]);
    setOperationFailure(null);
    setOperationProgress(0);
    setCurrentStage(null);
    try {
      const result = await request<{ operation_id: string }>(
        "/api/operations",
        {
          method: "POST",
          body: JSON.stringify({
            kind: "onboard",
            replace_existing: forceReplace,
            target: draft.target,
            source_url: draft.sourceUrl,
            source_username: draft.sourceUsername,
            source_password: draft.sourcePassword,
            website_name: draft.websiteName,
            container_name: draft.containerName,
            directory: draft.directory,
            newapi_port: Number(draft.newapiPort),
            kuma_port: Number(draft.kumaPort),
            ssh_destination: draft.target === "ssh" ? draft.sshDestination : null,
            ssh_password: draft.target === "ssh" ? draft.sshPassword || null : null,
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
      setOperationStatus("running");
      setActiveStep("operation");
      setLastEvent("部署任务已开始");
    } catch (cause) {
      const apiError = cause as ApiError;
      if (apiError.code === "DEPLOYMENT_REPLACEMENT_REQUIRED") {
        setDialog("replacement-required");
        return;
      }
      setError(cause instanceof Error ? cause.message : "无法启动部署");
    }
  }

  async function cancelOperation() {
    if (!session || !operationId) return;
    try {
      await request(`/api/operations/${encodeURIComponent(operationId)}/cancel`, { method: "POST" }, session);
      setLastEvent("正在取消部署");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "无法取消部署");
    }
  }

  async function resumeOperation(rotateStatusKey = false) {
    if (!session || !operationId) return;
    setResumingOperation(true);
    try {
      await request(`/api/operations/${encodeURIComponent(operationId)}/resume`, {
        method: "POST",
        body: JSON.stringify({
          ssh_password: draft.target === "ssh" ? draft.sshPassword || null : null,
          source_password: draft.sourcePassword || null,
          rotate_status_key: rotateStatusKey,
        }),
      }, session);
      setOperationStatus("running");
      setOperationFailure(null);
      setResumeSourcePasswordRequired(false);
      setOperationPollGeneration((current) => current + 1);
      setLastEvent(rotateStatusKey ? "正在重新生成公共状态密钥" : "正在继续部署");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "无法继续部署");
    } finally {
      setResumingOperation(false);
    }
  }

  async function closeWebUi() {
    if (!session) return;
    if (operationStatus === "running") {
      setDialog("close-running");
      return;
    }
    await shutdownWebUi();
  }

  async function shutdownWebUi() {
    if (!session) return;
    await request<void>("/api/shutdown", { method: "POST" }, session);
    setSession(null);
    setBootstrap(null);
  }

  function fillSavedDeployment() {
    const saved = bootstrap?.savedDeployment;
    if (!saved) return false;
    setDraft((current) => ({
      ...current,
      target: saved.target,
      sshDestination: saved.sshDestination,
      sshPassword: credentialMemory.current.sshPassword || current.sshPassword,
      sourceUrl: saved.sourceUrl,
      sourceUsername: saved.sourceUsername,
      sourcePassword: credentialMemory.current.sourcePassword || current.sourcePassword,
      websiteName: saved.websiteName,
      containerName: saved.containerName,
      directory: saved.directory,
      newapiPort: String(saved.newapiPort),
      kumaPort: String(saved.kumaPort),
      newapiAdminUsername: saved.newapiAdminUsername,
      newapiAdminPassword: "",
      kumaAdminUsername: saved.kumaAdminUsername,
      kumaAdminPassword: "",
      image: saved.image,
      imageRef: saved.imageRef,
    }));
    setDirectoryCustomized(true);
    setReplaceExisting(false);
    return true;
  }

  async function loadSyncPlan(nextDraft = draft) {
    if (!session) return;
    setSyncPlanLoading(true);
    setError(null);
    try {
      const plan = await request<SyncPlan>("/api/sync/plan", {
        method: "POST",
        body: JSON.stringify({
          source_password: nextDraft.sourcePassword || null,
          ssh_password: nextDraft.target === "ssh" ? nextDraft.sshPassword || null : null,
        }),
      }, session);
      setSyncPlan(plan);
      setSyncSourceAuthRequired(false);
      setSyncSshAuthRequired(false);
      setSelectedSyncModules(plan.modules.filter((module) => module.actionable).map((module) => module.module));
    } catch (cause) {
      const apiError = cause as ApiError;
      setSyncSourceAuthRequired(apiError.code === "SOURCE_AUTHENTICATION_FAILED" || apiError.code === "SOURCE_SESSION_REQUIRED");
      setSyncSshAuthRequired(apiError.code === "SSH_AUTHENTICATION_FAILED" || apiError.code === "SSH_AUTH_UNAVAILABLE");
      setError(cause instanceof Error ? cause.message : "无法读取同步计划");
    } finally {
      setSyncPlanLoading(false);
    }
  }

  function useSavedDeployment() {
    const saved = bootstrap?.savedDeployment;
    if (!saved) return;
    const nextDraft: Draft = {
      ...draft, target: saved.target, sshDestination: saved.sshDestination,
      sshPassword: credentialMemory.current.sshPassword || draft.sshPassword,
      sourceUrl: saved.sourceUrl, sourceUsername: saved.sourceUsername,
      sourcePassword: credentialMemory.current.sourcePassword || draft.sourcePassword,
      websiteName: saved.websiteName, containerName: saved.containerName, directory: saved.directory,
      newapiPort: String(saved.newapiPort), kumaPort: String(saved.kumaPort),
      newapiAdminUsername: saved.newapiAdminUsername, newapiAdminPassword: "",
      kumaAdminUsername: saved.kumaAdminUsername, kumaAdminPassword: "", image: saved.image, imageRef: saved.imageRef,
    };
    setDraft(nextDraft);
    setUsingSavedConfig(true);
    setForceSyncConflicts(false);
    setValidatedSteps({ target: true, source: true, site: true });
    setImageCheckState("valid");
    setResolvedImage(bootstrap?.savedDeployment?.image ?? null);
    setActiveStep("review");
    setDialog(null);
    void loadSyncPlan(nextDraft);
  }

  function restoreCurrentOperation() {
    const operation = bootstrap?.currentOperation;
    if (!operation || operation.kind !== "onboard") return;
    if (!fillSavedDeployment()) return;
    setOperationId(operation.operationId);
    setOperationStatus(operation.status === "failed" || operation.status === "cancelled"
      ? "failed"
      : operation.status === "completed" ? "completed" : "running");
    setCurrentStage(operation.currentStage);
    setOperationEvents([]);
    setOperationFailure(null);
    // Source passwords are never persisted. A restored operation must keep the
    // credential field mounted until this browser session supplies it again.
    setResumeSourcePasswordRequired(!credentialMemory.current.sourcePassword);
    setOperationProgress(0);
    setCredentials(undefined);
    setLastEvent("正在读取上次部署状态");
    setError(null);
    setActiveStep("operation");
    setDialog(null);
  }

  function startNewDeployment() {
    setUsingSavedConfig(false);
    setSyncPlan(null);
    setForceSyncConflicts(false);
    setSyncSourceAuthRequired(false);
    setSyncSshAuthRequired(false);
    setReplaceExisting(true);
    setDirectoryCustomized(false);
    setDialog(null);
  }

  const currentOperation = bootstrap?.currentOperation;
  const canRestoreCurrentOperation = currentOperation?.kind === "onboard"
    && ["draft", "running", "cancelling", "failed"].includes(currentOperation.status);

  if (loading) return <LoadingScreen />;
  if (!session || error?.includes("会话") || error?.includes("本地 Web")) {
    return <SessionScreen error={error} onRetry={() => window.location.reload()} />;
  }

  return (
    <>
    <div className="app-shell">
      <main className="deployment-page">
        <div className="page-heading">
          <div>
            <h1>部署 NewAPI</h1>
            <p>填写部署信息，确认后开始安装。</p>
          </div>
          <label className="secondary-action preset-import"><Upload size={16} />导入 TOML 预设<input type="file" accept=".toml,text/plain" onChange={(event) => { const file = event.target.files?.[0]; if (file) void importPreset(file); event.currentTarget.value = ""; }} /></label>
          <button className="icon-button" title="关闭部署工具" aria-label="关闭部署工具" onClick={() => void closeWebUi()}>
            <LogOut size={18} />
          </button>
        </div>

        <nav className="stepper" aria-label="部署步骤">
          {steps.map((step, index) => {
            const Icon = step.icon;
            const current = step.key === activeStep;
            const complete = index < activeIndex || (step.key === "operation" && operationStatus === "completed");
            return (
              <button
                type="button"
                className={`${current ? "is-current" : ""} ${complete ? "is-complete" : ""}`}
                key={step.key}
                onClick={() => index <= activeIndex && setActiveStep(step.key)}
                disabled={index > activeIndex}
                aria-current={current ? "step" : undefined}
              >
                <span className="step-icon">{complete ? <Check size={16} /> : <Icon size={16} />}</span>
                <span>{step.label}</span>
              </button>
            );
          })}
        </nav>

        <section className="workflow-card">
          <header className="workflow-heading">
            <div>
              <h2>{active.label}</h2>
              <p>{stepDescription(activeStep)}</p>
            </div>
            <span>步骤 {activeIndex + 1} / {steps.length}</span>
          </header>

          <div className="workflow-content">
            {activeStep === "target" && (
              <TargetStep draft={draft} update={update} supportsLocalTarget={bootstrap?.supportsLocalTarget ?? false} />
            )}
            {activeStep === "source" && <SourceStep draft={draft} update={update} />}
            {activeStep === "site" && (
              <SiteStep
                draft={draft}
                update={update}
                imageCheckState={imageCheckState}
                imageCheckError={imageCheckError}
                imageUpdatedAt={imageUpdatedAt}
                onRetryImage={() => setImageReloadKey((current) => current + 1)}
              />
            )}
            {activeStep === "review" && (usingSavedConfig
              ? <SyncPlanStep plan={syncPlan} loading={syncPlanLoading} draft={draft} update={update} sourceAuthRequired={syncSourceAuthRequired} sshAuthRequired={syncSshAuthRequired} selected={selectedSyncModules} onSelectedChange={setSelectedSyncModules} forceConflicts={forceSyncConflicts} onForceConflictsChange={setForceSyncConflicts} onReload={() => void loadSyncPlan()} />
              : <ReviewStep draft={draft} />)}
            {activeStep === "operation" && (
              <OperationStep
                status={operationStatus}
                lastEvent={lastEvent}
                progress={operationProgress}
                currentStage={currentStage}
                events={operationEvents}
                failure={operationFailure}
                credentials={credentials}
                showSshPassword={requiresSshPassword(operationFailure, draft.target)}
                sshPassword={draft.sshPassword}
                onSshPasswordChange={(value) => update("sshPassword", value)}
                showSourcePassword={resumeSourcePasswordRequired}
                sourcePassword={draft.sourcePassword}
                onSourcePasswordChange={(value) => update("sourcePassword", value)}
              />
            )}
            {error && (
              <div className="inline-error" role="alert">
                <AlertTriangle size={17} />
                <span>{error}</span>
                <button className="icon-button small" title="关闭" aria-label="关闭" onClick={() => setError(null)}><X size={15} /></button>
              </div>
            )}
          </div>

          <footer className={`workflow-actions ${activeStep === "operation" ? "operation-footer" : ""}`}>
            {activeStep === "operation" ? (
              <>
                {operationStatus === "running" ? (
                  <button className="secondary-action" onClick={() => void cancelOperation()}><X size={16} />取消部署</button>
                ) : operationStatus === "failed" ? (
                  <button className="secondary-action" onClick={() => setActiveStep("review")}><ArrowLeft size={16} />返回修改</button>
                ) : <span />}
                {operationStatus === "failed" && operationFailure?.retryable && (
                  <button
                    className={`primary-action ${resumingOperation ? "is-loading" : ""}`}
                    disabled={resumingOperation || (resumeSourcePasswordRequired && !draft.sourcePassword)}
                    onClick={() => operationFailure?.code === "STATUS_KEY_CONTENT_UNAVAILABLE"
                      ? setDialog("rotate-status-key")
                      : void resumeOperation()}
                  >
                    {resumingOperation
                      ? <LoaderCircle className="button-loader" size={16} aria-hidden="true" />
                      : <RefreshCcw size={16} />}
                    {operationFailure?.code === "STATUS_KEY_CONTENT_UNAVAILABLE" ? "重新生成密钥并继续" : "继续部署"}
                  </button>
                )}
              </>
            ) : <>
              <button className="secondary-action" onClick={goBack} disabled={activeIndex === 0 || operationStatus === "running"}>
                <ArrowLeft size={16} />上一步
              </button>
              {activeStep === "review" ? (
              <button className="primary-action" onClick={() => void startOperation()} disabled={usingSavedConfig ? syncPlanLoading || !syncPlan || selectedSyncModules.length === 0 : !canAdvance || operationStatus === "running"}>
                <TerminalSquare size={17} />{usingSavedConfig ? "应用选中的同步" : "开始部署"}
              </button>
            ) : (
              <button className={`primary-action ${checkingStep || (activeStep === "site" && imageCheckState === "loading") ? "is-loading" : ""}`} onClick={() => void goNext()} disabled={!canAdvance || checkingStep !== null || (activeStep === "site" && imageCheckState !== "valid")}>
                {checkingLabel(checkingStep, activeStep, draft.target, imageCheckState)}
                {checkingStep || (activeStep === "site" && imageCheckState === "loading") ? <LoaderCircle className="button-loader" size={16} aria-hidden="true" /> : <ArrowRight size={16} />}
              </button>
            )}
            </>}
          </footer>
        </section>
      </main>
    </div>
    {dialog === "existing-deployment" && bootstrap?.savedDeployment && (
      <AlertDialog
        title="检测到已有部署"
        description={canRestoreCurrentOperation
          ? "检测到上次部署任务。继续后会直接打开它的当前进度，不会重新填写部署流程。"
          : "当前控制端已经保存了一份部署配置。你可以使用已有配置，或重新填写部署信息。"}
        safeLabel={canRestoreCurrentOperation ? "继续上次部署" : "使用已有配置"}
        dangerLabel="重新填写部署信息"
        onSafe={canRestoreCurrentOperation ? restoreCurrentOperation : useSavedDeployment}
        onDanger={startNewDeployment}
      >
        <dl className="dialog-summary">
          <div><dt>容器项目</dt><dd>{bootstrap.savedDeployment.containerName}</dd></div>
          <div><dt>部署目录</dt><dd>{bootstrap.savedDeployment.directory}</dd></div>
        </dl>
        <p className="dialog-warning">选择重新填写后，只有在你确认开始部署时，现有部署才会被停止并清理。</p>
      </AlertDialog>
    )}
    {dialog === "replacement-required" && (
      <AlertDialog
        title="需要替换现有部署"
        description="当前信息属于另一个部署。继续会停止并清理现有部署，然后按当前信息重新部署。"
        safeLabel="返回检查"
        dangerLabel="替换并部署"
        onSafe={() => setDialog(null)}
        tone="danger"
        onDanger={() => {
          setReplaceExisting(true);
          setDialog(null);
          void startOperation(true);
        }}
      />
    )}
    {dialog === "rotate-status-key" && (
      <AlertDialog
        title="重新生成公共状态密钥？"
        description="源站只在首次创建时返回密钥内容。继续会撤销当前密钥并创建新密钥，然后从失败阶段恢复部署。"
        safeLabel="取消"
        dangerLabel="重新生成并继续"
        onSafe={() => setDialog(null)}
        tone="danger"
        onDanger={() => {
          setDialog(null);
          void resumeOperation(true);
        }}
      >
        <p className="dialog-warning">正在使用旧密钥的其他下游状态页将停止回源，需要分别更新。</p>
      </AlertDialog>
    )}
    {dialog === "close-running" && (
      <AlertDialog
        title="部署仍在进行"
        description="关闭部署工具不会撤销已经完成的步骤。之后可以重新启动并恢复进度。"
        safeLabel="继续查看"
        dangerLabel="关闭部署工具"
        onSafe={() => setDialog(null)}
        tone="danger"
        onDanger={() => {
          setDialog(null);
          void shutdownWebUi();
        }}
      />
    )}
    </>
  );
}

function stepDescription(step: StepKey): string {
  if (step === "target") return "选择当前服务器，或连接其他 Linux 服务器。";
  if (step === "source") return "输入源站地址和管理员账号。";
  if (step === "site") return "设置站点名称、部署目录、端口和容器镜像。";
  if (step === "review") return "确认以下信息无误后开始部署。";
  return "可以在这里查看部署进度和结果。";
}

function LoadingScreen() {
  return <main className="session-screen"><div className="session-panel"><div className="loading-mark"><Activity size={24} /></div><p>正在打开部署工具...</p></div></main>;
}

function SessionScreen({ error, onRetry }: { error: string | null; onRetry: () => void }) {
  return <main className="session-screen"><div className="session-panel"><div className="brand-mark large"><span />M</div><h1>无法打开部署工具</h1><p>{error ?? "请重新启动 meowai-deploy web。"}</p><button className="primary-action" onClick={onRetry}><RefreshCcw size={17} />重新连接</button></div></main>;
}

function AlertDialog({ title, description, safeLabel, dangerLabel, onSafe, onDanger, tone = "warning", children }: {
  title: string;
  description: string;
  safeLabel: string;
  dangerLabel: string;
  onSafe: () => void;
  onDanger: () => void;
  tone?: "warning" | "danger";
  children?: ReactNode;
}) {
  const dialogRef = useRef<HTMLElement>(null);

  useEffect(() => {
    const previousFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const page = document.querySelector<HTMLElement>(".deployment-page");
    page?.setAttribute("inert", "");
    document.body.style.overflow = "hidden";
    dialogRef.current?.querySelector<HTMLElement>("button")?.focus();
    return () => {
      page?.removeAttribute("inert");
      document.body.style.overflow = "";
      previousFocus?.focus();
    };
  }, []);

  return (
    <div className="dialog-backdrop" role="presentation">
      <section
        className="alert-dialog"
        ref={dialogRef}
        role="alertdialog"
        aria-modal="true"
        aria-labelledby="alert-dialog-title"
        aria-describedby="alert-dialog-description"
        onKeyDown={(event) => {
          if (event.key === "Escape") {
            event.preventDefault();
            onSafe();
          }
          if (event.key === "Tab") {
            const controls = Array.from(dialogRef.current?.querySelectorAll<HTMLElement>("button") ?? []);
            const first = controls[0];
            const last = controls.at(-1);
            if (event.shiftKey && document.activeElement === first) {
              event.preventDefault();
              last?.focus();
            } else if (!event.shiftKey && document.activeElement === last) {
              event.preventDefault();
              first?.focus();
            }
          }
        }}
      >
        <div className={`dialog-icon is-${tone}`} aria-hidden="true"><AlertTriangle size={20} /></div>
        <div className="dialog-copy">
          <h2 id="alert-dialog-title">{title}</h2>
          <p id="alert-dialog-description">{description}</p>
        </div>
        {children}
        <div className="dialog-actions">
          <button type="button" className="secondary-action" autoFocus onClick={onSafe}>{safeLabel}</button>
          <button type="button" className="danger-action" onClick={onDanger}>{dangerLabel}</button>
        </div>
      </section>
    </div>
  );
}

function TargetStep({ draft, update, supportsLocalTarget }: {
  draft: Draft;
  update: <K extends keyof Draft>(key: K, value: Draft[K]) => void;
  supportsLocalTarget: boolean;
}) {
  return (
    <div className="form-layout">
      <div className="target-switch" role="radiogroup" aria-label="部署方式">
        <button
          type="button"
          role="radio"
          aria-checked={draft.target === "local"}
          className={draft.target === "local" ? "is-selected" : ""}
          disabled={!supportsLocalTarget}
          onClick={() => update("target", "local")}
        >
          <HardDrive size={20} />
          <span><strong>本机部署</strong><small>在当前服务器运行</small></span>
        </button>
        <button
          type="button"
          role="radio"
          aria-checked={draft.target === "ssh"}
          className={draft.target === "ssh" ? "is-selected" : ""}
          onClick={() => update("target", "ssh")}
        >
          <Wifi size={20} />
          <span><strong>SSH 远程</strong><small>部署到其他服务器</small></span>
        </button>
      </div>

      {draft.target === "ssh" && (
        <div className="form-row">
          <Field label="SSH 地址" hint="格式：user@host">
            <input autoFocus value={draft.sshDestination} onChange={(event) => update("sshDestination", event.target.value)} placeholder="deploy@example.com" autoComplete="off" />
          </Field>
          <Field label="SSH 密码（可选）" hint="留空时使用 SSH 密钥或 ssh-agent">
            <input type="password" value={draft.sshPassword} onChange={(event) => update("sshPassword", event.target.value)} placeholder="服务器登录密码" autoComplete="current-password" />
          </Field>
        </div>
      )}
    </div>
  );
}

function SourceStep({ draft, update }: { draft: Draft; update: <K extends keyof Draft>(key: K, value: Draft[K]) => void }) {
  return <div className="form-layout"><Field label="源站地址"><input autoFocus value={draft.sourceUrl} onChange={(event) => update("sourceUrl", event.target.value)} placeholder="https://enterprise.meowai.net" autoComplete="url" /></Field><div className="form-row"><Field label="用户名"><input value={draft.sourceUsername} onChange={(event) => update("sourceUsername", event.target.value)} placeholder="源站用户名" autoComplete="username" /></Field><Field label="密码"><input type="password" value={draft.sourcePassword} onChange={(event) => update("sourcePassword", event.target.value)} placeholder="源站密码" autoComplete="current-password" /></Field></div></div>;
}

function SiteStep({ draft, update, imageCheckState, imageCheckError, imageUpdatedAt, onRetryImage }: {
  draft: Draft;
  update: <K extends keyof Draft>(key: K, value: Draft[K]) => void;
  imageCheckState: ImageCheckState;
  imageCheckError: string | null;
  imageUpdatedAt: string | null;
  onRetryImage: () => void;
}) {
  return (
    <div className="form-layout">
      <div className="form-row">
        <Field label="站点名称"><input autoFocus value={draft.websiteName} onChange={(event) => update("websiteName", event.target.value)} placeholder="Meow AI Downstream" /></Field>
        <Field label="容器项目名"><input value={draft.containerName} onChange={(event) => update("containerName", event.target.value)} placeholder="newapi" /></Field>
      </div>
      <Field label="部署目录" hint={draft.target === "local" ? "当前服务器上的绝对路径" : "远程服务器上的绝对路径"}>
        <input value={draft.directory} onChange={(event) => update("directory", event.target.value)} placeholder="/opt/meowai-deploy/newapi" />
      </Field>
      <div className="form-row">
        <Field label="NewAPI 端口"><input inputMode="numeric" value={draft.newapiPort} onChange={(event) => update("newapiPort", event.target.value)} placeholder="3000" /></Field>
        <Field label="Uptime Kuma 端口"><input inputMode="numeric" value={draft.kumaPort} onChange={(event) => update("kumaPort", event.target.value)} placeholder="3001" /></Field>
      </div>
      <Field label="容器镜像"><input value={draft.image} onChange={(event) => update("image", event.target.value)} placeholder="ghcr.io/moorcorpa/new-api-outgap" /></Field>
      <div className="field">
        <span className="field-label">镜像 digest</span>
        <input className="digest-input" value={draft.imageRef} placeholder="sha256:..." readOnly required aria-label="镜像 digest" />
        <div className={`digest-status is-${imageCheckState}`} aria-live="polite">
          {imageCheckState === "loading" && <><LoaderCircle className="button-loader" size={15} aria-hidden="true" /><span>正在解析最新镜像</span></>}
          {imageCheckState === "valid" && <><CheckCircle2 size={15} aria-hidden="true" /><span title={imageUpdatedAt ? exactImageTime(imageUpdatedAt) : undefined}>{imageUpdatedAt ? `最新版本：${relativeImageTime(imageUpdatedAt)}` : "最新版本已解析，更新时间未知"}</span></>}
          {imageCheckState === "error" && <><AlertTriangle size={15} aria-hidden="true" /><span>{imageCheckError ?? "无法解析最新镜像"}</span><button type="button" className="retry-image" onClick={onRetryImage}><RefreshCcw size={14} />重试</button></>}
        </div>
      </div>
    </div>
  );
}

function ReviewStep({ draft }: {
  draft: Draft;
}) {
  const destination = draft.target === "local" ? "当前服务器" : draft.sshDestination;
  const rows = [
    ["部署方式", draft.target === "local" ? "本机部署" : "SSH 远程"],
    ["部署位置", destination],
    ["部署目录", draft.directory],
    ["源站地址", draft.sourceUrl],
    ["站点名称", draft.websiteName],
    ["服务端口", `${draft.newapiPort} / ${draft.kumaPort}`],
    ["容器镜像", draft.imageRef ? `${draft.image}@${draft.imageRef}` : draft.image],
  ];
  return (
    <dl className="review-list">{rows.map(([label, value]) => <div className="review-row" key={label}><dt>{label}</dt><dd>{value || "未填写"}</dd></div>)}</dl>
  );
}

function SyncPlanStep({
  plan,
  loading,
  draft,
  update,
  sourceAuthRequired,
  sshAuthRequired,
  selected,
  onSelectedChange,
  forceConflicts,
  onForceConflictsChange,
  onReload,
}: {
  plan: SyncPlan | null;
  loading: boolean;
  draft: Draft;
  update: <K extends keyof Draft>(key: K, value: Draft[K]) => void;
  sourceAuthRequired: boolean;
  sshAuthRequired: boolean;
  selected: string[];
  onSelectedChange: (modules: string[]) => void;
  forceConflicts: boolean;
  onForceConflictsChange: (value: boolean) => void;
  onReload: () => void;
}) {
  if (loading) {
    return <div className="sync-plan-loading"><LoaderCircle className="button-loader" size={18} /><span>正在读取源站与下游差异…</span></div>;
  }
  const toggle = (module: string) => {
    onSelectedChange(selected.includes(module) ? selected.filter((item) => item !== module) : [...selected, module]);
  };
  return (
    <div className="sync-plan">
      <div className="sync-plan-heading"><div><strong>同步计划</strong><p>{plan ? "只应用明确选择的模块；冲突字段需要显式覆盖。" : "需要凭证才能读取当前部署的差异。"}</p></div><button type="button" className="secondary-action" onClick={onReload}><RefreshCcw size={15} />重新读取</button></div>
      {(sourceAuthRequired || sshAuthRequired) && (
        <div className={`review-credentials ${sourceAuthRequired && sshAuthRequired ? "has-ssh" : ""}`}>
          {sourceAuthRequired && <Field label="源站密码" hint="同步计划需要重新验证源站账号。"><input type="password" value={draft.sourcePassword} onChange={(event) => update("sourcePassword", event.target.value)} placeholder="源站登录密码" autoComplete="current-password" /></Field>}
          {sshAuthRequired && <Field label="SSH 密码" hint="同步计划需要连接部署目标。"><input type="password" value={draft.sshPassword} onChange={(event) => update("sshPassword", event.target.value)} placeholder="服务器登录密码" autoComplete="current-password" /></Field>}
        </div>
      )}
      {plan && <div className="sync-module-list">
        {plan.modules.map((module) => (
          <label className={`sync-module ${module.actionable ? "is-actionable" : "is-quiet"}`} key={module.module}>
            <input type="checkbox" checked={selected.includes(module.module)} disabled={!module.actionable} onChange={() => toggle(module.module)} />
            <span className="sync-module-copy"><strong>{module.label}</strong><small>{module.actionable ? `${module.diffs.length} 项差异${module.conflict ? " · 存在冲突" : ""}` : "已一致或由下游保留"}</small></span>
            {module.conflict && <span className="sync-risk">冲突</span>}
          </label>
        ))}
      </div>}
      {plan && plan.modules.some((module) => module.conflict && selected.includes(module.module)) && (
        <label className="sync-force"><input type="checkbox" checked={forceConflicts} onChange={(event) => onForceConflictsChange(event.target.checked)} /><span><strong>覆盖冲突字段</strong><small>仅对已选择模块生效；未勾选时保留下游手动修改。</small></span></label>
      )}
      {plan && <div className="sync-margin-note"><span>毛利预览仅供确认，采购价与终端售价保持分离。</span><strong>{plan.group_margins.length + plan.seedance_margins.length} 项价格策略</strong></div>}
    </div>
  );
}

function OperationStep({
  status,
  lastEvent,
  progress,
  currentStage,
  events,
  failure,
  credentials,
  showSshPassword,
  sshPassword,
  onSshPasswordChange,
  showSourcePassword,
  sourcePassword,
  onSourcePasswordChange,
}: {
  status: "idle" | "running" | "completed" | "failed";
  lastEvent: string;
  progress: number;
  currentStage: string | null;
  events: OperationEvent[];
  failure: OperationFailure | null;
  credentials?: Array<{ kind: string; username: string; password: string }>;
  showSshPassword: boolean;
  sshPassword: string;
  onSshPasswordChange: (value: string) => void;
  showSourcePassword: boolean;
  sourcePassword: string;
  onSourcePasswordChange: (value: string) => void;
}) {
  const complete = status === "completed";
  const failed = status === "failed";
  const logRef = useRef<HTMLOListElement>(null);
  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [events.length]);
  return (
    <div className="operation-view">
      <div className={`operation-status ${complete ? "complete" : failed ? "failed" : "running"}`}>
        {complete ? <CheckCircle2 size={24} /> : failed ? <AlertTriangle size={24} /> : <Activity size={24} />}
        <div>
          <h3>{complete ? "部署完成" : failed ? "部署未完成" : "正在部署"}</h3>
          <p aria-live="polite">{lastEvent}</p>
        </div>
      </div>
      <div className="operation-progress-meta">
        <span>{currentStage ? stageLabel(currentStage) : complete ? "全部完成" : "正在建立任务"}</span>
        <strong>{progress}%</strong>
      </div>
      <div className={`progress-bar ${complete ? "complete" : failed ? "failed" : ""}`} role="progressbar" aria-label="部署进度" aria-valuemin={0} aria-valuemax={100} aria-valuenow={progress}>
        <span style={{ width: `${progress}%` }} />
      </div>
      {failure && (
        <section className="operation-failure" aria-labelledby="operation-failure-title">
          <div>
            <strong id="operation-failure-title">{failure.message}</strong>
            <code>{failure.code}</code>
          </div>
          {failure.diagnostic && <pre>{failure.diagnostic}</pre>}
        </section>
      )}
      {(showSourcePassword || showSshPassword) && (
        <div className={`operation-resume-auth ${showSourcePassword && showSshPassword ? "has-ssh" : ""}`}>
          {showSourcePassword && (
            <Field label="源站密码" hint="恢复部署需要重新输入；密码只随本次请求发送，不会写入磁盘。">
              <input
                type="password"
                value={sourcePassword}
                onChange={(event) => onSourcePasswordChange(event.target.value)}
                placeholder="源站登录密码"
                autoComplete="current-password"
              />
            </Field>
          )}
          {showSshPassword && (
            <Field label="SSH 密码" hint="服务器使用密码登录时请重新输入；使用 SSH 密钥可留空。">
              <input
                type="password"
                value={sshPassword}
                onChange={(event) => onSshPasswordChange(event.target.value)}
                placeholder="服务器登录密码"
                autoComplete="current-password"
              />
            </Field>
          )}
        </div>
      )}
      <section className="operation-log" aria-labelledby="operation-log-title">
        <div className="operation-log-heading">
          <strong id="operation-log-title">执行记录</strong>
          <span>{events.length} 条</span>
        </div>
        {events.length === 0 ? (
          <p className="operation-log-empty">正在等待部署进程返回第一条记录...</p>
        ) : (
          <ol ref={logRef}>
            {events.map((event) => (
              <li className={`log-entry ${event.severity}`} key={`${event.operation_id}-${event.sequence}`}>
                <time dateTime={new Date(event.timestamp * 1000).toISOString()}>{formatEventTime(event.timestamp)}</time>
                <span className="log-stage">{event.stage ? stageLabel(event.stage) : "部署任务"}</span>
                <div>
                  <p>{event.message}</p>
                  {event.diagnostic && <pre>{event.diagnostic}</pre>}
                </div>
              </li>
            ))}
          </ol>
        )}
      </section>
      {credentials && credentials.length > 0 && <div className="credential-result" role="status"><strong>管理员账号</strong><p>这些密码只显示一次，请立即保存。</p>{credentials.map((credential) => <div className="credential-row" key={credential.kind}><span>{credential.kind}</span><code>{credential.username} / {credential.password}</code></div>)}</div>}
    </div>
  );
}

function stageLabel(stage: string): string {
  const labels: Record<string, string> = {
    input_validation: "检查部署信息",
    source_connectivity: "连接源站",
    source_authentication: "验证源站账号",
    source_approval: "检查部署权限",
    target_validation: "检查部署目标",
    source_resources: "准备源站资源",
    base_services: "启动基础服务",
    downstream_initialization: "初始化 New API",
    pricing_import: "导入定价配置",
    channel_synchronization: "同步渠道",
    kuma_synchronization: "配置状态监控",
    final_verification: "保存并验证部署",
    cleanup: "清理部署",
    rollback: "回滚部署",
  };
  return labels[stage] ?? stage;
}

function formatEventTime(timestamp: number): string {
  return new Intl.DateTimeFormat("zh-CN", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(new Date(timestamp * 1000));
}

function mergeOperationEvents(current: OperationEvent[], incoming: OperationEvent[]): OperationEvent[] {
  const merged = new Map<string, OperationEvent>();
  for (const event of [...current, ...incoming]) {
    merged.set(`${event.operation_id}-${event.sequence}`, event);
  }
  return [...merged.values()]
    .sort((left, right) => left.sequence - right.sequence)
    .slice(-500);
}

function Field({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return <label className="field"><span className="field-label">{label}</span>{children}{hint && <small>{hint}</small>}</label>;
}

function validateStep(step: StepKey, draft: Draft): string | null {
  if (step === "target") {
    if (draft.target === "ssh" && !/^[A-Za-z0-9._-]+@(?:[A-Za-z0-9][A-Za-z0-9._-]*|\[[0-9A-Fa-f:]+\])$/.test(draft.sshDestination)) return "SSH 地址必须使用 user@host 格式。";
  }
  if (step === "source") {
    if (!/^https:\/\//.test(draft.sourceUrl) && !/^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?/.test(draft.sourceUrl)) return "源站地址需要使用 HTTPS。";
    if (!draft.sourceUsername.trim() || !draft.sourcePassword) return "请填写源站用户名和密码。";
  }
  if (step === "site") {
    if (!draft.websiteName.trim() || !/^[A-Za-z0-9_.-]+$/.test(draft.containerName)) return "请填写有效的站点名称和容器项目名。";
    const parts = draft.directory.split("/");
    if (draft.directory === "/" || !/^\/[A-Za-z0-9_./-]+$/.test(draft.directory) || parts.includes(".") || parts.includes("..")) return "部署目录必须是根目录之外、不含 . 或 .. 的绝对路径。";
    const newapi = Number(draft.newapiPort);
    const kuma = Number(draft.kumaPort);
    if (!Number.isInteger(newapi) || !Number.isInteger(kuma) || newapi < 1 || kuma < 1 || newapi > 65535 || kuma > 65535 || newapi === kuma) return "两个端口需要是 1 到 65535 之间的不同数字。";
    if (!draft.image.trim()) return "请填写容器镜像。";
  }
  if (step === "review") {
    const validation = validateStep("target", draft) ?? validateStep("source", draft) ?? validateStep("site", draft);
    if (validation) return validation;
    if (!/^sha256:[A-Fa-f0-9]{64}$/.test(draft.imageRef)) return "镜像 digest 尚未解析或无效，请返回站点设置重新检查。";
  }
  return null;
}

function failureNeedsSourcePassword(code: string | undefined): boolean {
  return code !== undefined && [
    "SOURCE_PASSWORD_REQUIRED",
    "SOURCE_AUTHENTICATION_FAILED",
    "STATUS_KEY_CONTENT_UNAVAILABLE",
  ].includes(code);
}

function requiresSshPassword(failure: OperationFailure | null, target: DeploymentTarget): boolean {
  return target === "ssh" && failure?.retryable === true && failure.code === "SSH_AUTHENTICATION_FAILED";
}

function preflightForField(field: keyof Draft): PreflightStep | null {
  if (["target", "sshDestination", "sshPassword"].includes(field)) return "target";
  if (["sourceUrl", "sourceUsername", "sourcePassword"].includes(field)) return "source";
  if (["websiteName", "containerName", "directory", "newapiPort", "kumaPort", "newapiAdminUsername", "newapiAdminPassword", "kumaAdminUsername", "kumaAdminPassword", "image", "imageRef"].includes(field)) return "site";
  return null;
}

function checkingLabel(checking: PreflightStep | null, active: StepKey, target: DeploymentTarget, imageState: ImageCheckState): string {
  if (checking === "target") return target === "ssh" ? "正在连接 SSH" : "正在检查本机环境";
  if (checking === "source") return "正在验证源站账号";
  if (checking === "site") return "正在检查服务端口";
  if (active === "site" && imageState === "loading") return "正在解析最新镜像";
  return "下一步";
}

function relativeImageTime(value: string): string {
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) return "更新时间未知";
  const seconds = Math.max(0, Math.floor((Date.now() - timestamp) / 1000));
  if (seconds < 60) return "刚刚更新";
  if (seconds < 3600) return `${Math.floor(seconds / 60)} 分钟前更新`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} 小时前更新`;
  if (seconds < 2592000) return `${Math.floor(seconds / 86400)} 天前更新`;
  if (seconds < 31536000) return `${Math.floor(seconds / 2592000)} 个月前更新`;
  return `${Math.floor(seconds / 31536000)} 年前更新`;
}

function exactImageTime(value: string): string {
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp)
    ? new Intl.DateTimeFormat("zh-CN", { dateStyle: "medium", timeStyle: "short" }).format(timestamp)
    : "更新时间未知";
}
