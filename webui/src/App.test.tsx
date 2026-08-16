import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import App from "./App";

class TestEventSource {
  addEventListener() {}
  close() {}
}

const bootstrap = {
  version: "test",
  has_saved_deployment: false,
  saved_deployment: null,
  current_operation: null,
  operation_lock: false,
  supports_local_target: true,
  defaults: {
    source_url: "https://enterprise.meowai.net",
    website_name: "Meow AI Downstream",
    container_name: "newapi",
    directory: "/opt/meowai-deploy/newapi",
    newapi_port: 3000,
    kuma_port: 3001,
    image: "ghcr.io/moorcorpa/new-api-outgap",
  },
};

function json(body: unknown, status = 200) {
  return Promise.resolve(new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } }));
}

function sessionFetch(overrides?: (path: string, init?: RequestInit) => Promise<Response> | undefined) {
  return vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input);
    const overridden = overrides?.(path, init);
    if (overridden) return overridden;
    if (path.endsWith("/api/session")) return json({ csrf_token: "csrf-test" });
    if (path.endsWith("/api/bootstrap")) return json(bootstrap);
    return Promise.reject(new Error(`unexpected request: ${path}`));
  });
}

describe("deployment workbench", () => {
  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("uses backend defaults and removes the header management actions", async () => {
    vi.stubGlobal("EventSource", TestEventSource);
    const localStorage = { setItem: vi.fn(), getItem: vi.fn(), removeItem: vi.fn() };
    const sessionStorage = { setItem: vi.fn(), getItem: vi.fn(), removeItem: vi.fn() };
    vi.stubGlobal("localStorage", localStorage);
    vi.stubGlobal("sessionStorage", sessionStorage);
    const fetchMock = sessionFetch((path) => {
      if (path.endsWith("/api/preflight/target")) {
        return json({ fingerprint: "target-1", newapi_port: 3000, kuma_port: 3001 });
      }
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await screen.findByRole("heading", { name: "部署 NewAPI" });
    expect(screen.queryByText("MeowAI Deploy")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "状态" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "同步" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "关闭部署工具" })).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /下一步/ }));
    await screen.findByRole("heading", { name: "源站账号" });
    expect(screen.getByLabelText("源站地址")).toHaveValue("https://enterprise.meowai.net");
    expect(localStorage.setItem).not.toHaveBeenCalled();
    expect(sessionStorage.setItem).not.toHaveBeenCalled();
  });

  it("does not advance when target preflight fails", async () => {
    vi.stubGlobal("EventSource", TestEventSource);
    vi.stubGlobal("fetch", sessionFetch((path) => {
      if (path.endsWith("/api/preflight/target")) {
        return new Promise((resolve) => window.setTimeout(() => {
          void json({ error: { code: "TARGET_OPERATION_FAILED", message: "无法连接部署目标" } }, 422).then(resolve);
        }, 20));
      }
    }));

    render(<App />);
    await screen.findByRole("heading", { name: "部署位置" });
    const sshPassword = `credential-${Date.now()}`;
    fireEvent.click(screen.getByRole("radio", { name: /SSH 远程/ }));
    fireEvent.change(screen.getByPlaceholderText("deploy@example.com"), { target: { value: "deploy@example.com" } });
    fireEvent.change(screen.getByPlaceholderText("服务器登录密码"), { target: { value: sshPassword } });
    fireEvent.click(screen.getByRole("button", { name: /下一步/ }));

    expect(screen.getByRole("button", { name: /正在连接 SSH/ })).toHaveClass("is-loading");
    expect(document.querySelector(".button-loader")).toBeInTheDocument();
    expect(await screen.findByRole("alert")).toHaveTextContent("无法连接部署目标");
    expect(screen.getByRole("heading", { name: "部署位置" })).toBeInTheDocument();
    const preflightCall = vi.mocked(fetch).mock.calls.find(([path]) => String(path).endsWith("/api/preflight/target"));
    expect(JSON.parse(String(preflightCall?.[1]?.body))).toMatchObject({ ssh_password: sshPassword, check_site: false });
  });

  it("requires source authentication and resolves the image digest before review", async () => {
    vi.stubGlobal("EventSource", TestEventSource);
    const digest = `sha256:${"a".repeat(64)}`;
    const updatedAt = new Date(Date.now() - (3 * 60 * 60 + 5) * 1000).toISOString();
    const operationRequests: Array<Record<string, unknown>> = [];
    const fetchMock = sessionFetch((path, init) => {
      if (path.endsWith("/api/preflight/target")) {
        return json({ fingerprint: "target-1", newapi_port: 3000, kuma_port: 3001 });
      }
      if (path.endsWith("/api/preflight/source")) {
        return json({ username: "source-user", user_id: 42 });
      }
      if (path.endsWith("/api/preflight/image")) {
        return json({ image: bootstrap.defaults.image, immutable_ref: digest, updated_at: updatedAt });
      }
      if (path.endsWith("/api/operations")) {
        const payload = JSON.parse(String(init?.body)) as Record<string, unknown>;
        operationRequests.push(payload);
        return payload.replace_existing
          ? json({ operation_id: "web-replacement", status: "draft" })
          : json({ error: { code: "DEPLOYMENT_REPLACEMENT_REQUIRED", message: "当前控制端已管理另一个部署" } }, 409);
      }
      if (path.endsWith("/api/operations/web-replacement")) {
        return json({
          checkpoint: {
            operation_id: "web-replacement",
            status: "failed",
            current_stage: "target_validation",
            completed_stages: ["input_validation", "source_connectivity"],
            failure: {
              stage: "target_validation",
              code: "STATUS_KEY_CONTENT_UNAVAILABLE",
              message: "源站公共状态密钥已存在，但当前控制端没有保存密钥内容",
              retryable: true,
              diagnostic: "ssh exited with status 255",
            },
          },
          events: [{
            operation_id: "web-replacement",
            sequence: 1,
            timestamp: 1_700_000_000,
            stage: "target_validation",
            severity: "error",
            kind: { type: "recoverable_failure", code: "STATUS_KEY_CONTENT_UNAVAILABLE" },
            message: "源站公共状态密钥已存在，但当前控制端没有保存密钥内容",
            diagnostic: "ssh exited with status 255",
          }],
        });
      }
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);
    const confirm = vi.spyOn(window, "confirm");
    await screen.findByRole("heading", { name: "部署位置" });
    fireEvent.click(screen.getByRole("button", { name: /下一步/ }));

    await screen.findByRole("heading", { name: "源站账号" });
    fireEvent.change(screen.getByLabelText("用户名"), { target: { value: "source-user" } });
    fireEvent.change(screen.getByLabelText("密码"), { target: { value: "source-password" } });
    fireEvent.click(screen.getByRole("button", { name: /下一步/ }));

    await screen.findByRole("heading", { name: "站点设置" });
    expect(screen.getByLabelText("镜像 digest")).toBeRequired();
    expect(await screen.findByRole("button", { name: /正在解析最新镜像/ })).toBeDisabled();
    await waitFor(() => expect(screen.getByLabelText("镜像 digest")).toHaveValue(digest));
    expect(screen.getByText("最新版本：3 小时前更新")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /下一步/ }));

    await screen.findByRole("heading", { name: "确认信息" });
    expect(screen.getByText(`${bootstrap.defaults.image}@${digest}`)).toBeInTheDocument();
    expect(screen.queryByLabelText("源站密码")).not.toBeInTheDocument();
    expect(screen.queryByLabelText("SSH 密码")).not.toBeInTheDocument();
    const startDeployment = screen
      .getAllByRole("button", { name: /开始部署/ })
      .find((button) => !button.hasAttribute("disabled"));
    expect(startDeployment).toBeDefined();
    fireEvent.click(startDeployment!);
    const replacementDialog = await screen.findByRole("alertdialog", { name: "需要替换现有部署" });
    expect(replacementDialog).toHaveTextContent("继续会停止并清理现有部署");
    fireEvent.click(screen.getByRole("button", { name: "替换并部署" }));
    await screen.findByRole("heading", { name: "开始部署" });
    expect(confirm).not.toHaveBeenCalled();
    expect(operationRequests).toHaveLength(2);
    expect(operationRequests[0]).toMatchObject({ replace_existing: false });
    expect(operationRequests[1]).toMatchObject({ replace_existing: true });
    expect(operationRequests[0]).toMatchObject({ source_password: "source-password" });
    expect(await screen.findByRole("button", { name: "重新生成密钥并继续" })).toBeEnabled();
    expect(screen.queryByPlaceholderText("源站登录密码")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "返回修改" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "返回确认" })).not.toBeInTheDocument();
    expect(screen.getByRole("progressbar", { name: "部署进度" })).toHaveAttribute("aria-valuenow", "20");
    expect(screen.getByText("STATUS_KEY_CONTENT_UNAVAILABLE")).toBeInTheDocument();
    expect(screen.getAllByText("ssh exited with status 255")).toHaveLength(2);
    expect(screen.getByRole("region", { name: "执行记录" })).toHaveTextContent("检查部署目标");
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith("/api/preflight/source", expect.anything()));
    expect(fetchMock).toHaveBeenCalledWith("/api/preflight/image", expect.anything());
  });

  it("selects SSH when the current platform cannot deploy locally", async () => {
    vi.stubGlobal("EventSource", TestEventSource);
    vi.stubGlobal("fetch", sessionFetch((path) => {
      if (path.endsWith("/api/bootstrap")) return json({ ...bootstrap, supports_local_target: false });
    }));

    render(<App />);

    const local = await screen.findByRole("radio", { name: /本机部署/ });
    const ssh = screen.getByRole("radio", { name: /SSH 远程/ });
    expect(local).toBeDisabled();
    expect(ssh).toHaveAttribute("aria-checked", "true");
  });

  it("blocks the wizard with an in-app choice when a saved deployment exists", async () => {
    vi.stubGlobal("EventSource", TestEventSource);
    const savedDeployment = {
      target: "ssh",
      ssh_destination: "deploy@existing.example.test",
      source_url: "https://source.example.test",
      source_username: "saved-user",
      website_name: "Saved Downstream",
      container_name: "saved-newapi",
      directory: "/opt/meowai-deploy/saved-newapi",
      newapi_port: 3100,
      kuma_port: 3101,
      newapi_admin_username: "newapi-admin",
      kuma_admin_username: "kuma-admin",
      image: "example.test/newapi",
      image_ref: `sha256:${"b".repeat(64)}`,
    };
    vi.stubGlobal("fetch", sessionFetch((path) => {
      if (path.endsWith("/api/bootstrap")) {
        return json({ ...bootstrap, has_saved_deployment: true, saved_deployment: savedDeployment });
      }
      if (path.endsWith("/api/operations")) {
        return json({ operation_id: "web-saved-config" });
      }
      if (path.endsWith("/api/sync/plan")) {
        return json({
          fingerprint: "plan-saved",
          modules: [{ module: "site", label: "首页与市场", actionable: true, conflict: false, diffs: [{ path: "home_setting.pricing_title", classification: "source_changed", risk: "low", sensitive: false }] }],
          group_margins: [],
          seedance_margins: [],
        });
      }
    }));

    render(<App />);

    const dialog = await screen.findByRole("alertdialog", { name: "检测到已有部署" });
    expect(dialog).toHaveTextContent("saved-newapi");
    expect(dialog).toHaveTextContent("/opt/meowai-deploy/saved-newapi");
    expect(dialog).not.toHaveTextContent("password");
    expect(vi.spyOn(window, "confirm")).not.toHaveBeenCalled();
    expect(screen.queryByRole("button", { name: "继续上次部署" })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "使用已有配置" }));

    expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "确认信息" })).toBeInTheDocument();
    expect(await screen.findByText("首页与市场")).toBeInTheDocument();
    expect(screen.getByText("1 项差异")).toBeInTheDocument();
    const startDeployment = screen
      .getAllByRole("button", { name: "应用选中的同步" })
      .find((button) => !button.hasAttribute("disabled"));
    expect(startDeployment).toBeDefined();
    fireEvent.click(startDeployment!);
    await screen.findByRole("heading", { name: "开始部署" });
    expect(screen.queryByText("部署信息已经变更，请返回对应步骤重新检查。")).not.toBeInTheDocument();
  });

  it("opens the existing operation directly and supplies a fresh SSH password when resuming", async () => {
    vi.stubGlobal("EventSource", TestEventSource);
    const savedDeployment = {
      target: "ssh",
      ssh_destination: "deploy@existing.example.test",
      source_url: "https://source.example.test",
      source_username: "saved-user",
      website_name: "Saved Downstream",
      container_name: "saved-newapi",
      directory: "/opt/meowai-deploy/saved-newapi",
      newapi_port: 3100,
      kuma_port: 3101,
      newapi_admin_username: "newapi-admin",
      kuma_admin_username: "kuma-admin",
      image: "example.test/newapi",
      image_ref: `sha256:${"b".repeat(64)}`,
    };
    const fetchMock = sessionFetch((path, init) => {
      if (path.endsWith("/api/bootstrap")) {
        return json({
          ...bootstrap,
          has_saved_deployment: true,
          saved_deployment: savedDeployment,
          current_operation: {
            operation_id: "web-resume",
            kind: "onboard",
            status: "failed",
            current_stage: "source_resources",
            retryable: true,
          },
        });
      }
      if (path.endsWith("/api/operations/web-resume")) {
        return json({
          checkpoint: {
            operation_id: "web-resume",
            status: "failed",
            current_stage: "source_resources",
            completed_stages: ["input_validation", "source_connectivity", "source_authentication"],
            failure: {
              stage: "source_resources",
              code: "STATUS_KEY_CONTENT_UNAVAILABLE",
              message: "源站公共状态密钥内容不可用",
              retryable: true,
            },
          },
          events: [],
        });
      }
      if (path.endsWith("/api/operations/web-resume/resume")) {
        return json({ operation_id: "web-resume", status: "running" });
      }
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await screen.findByRole("alertdialog", { name: "检测到已有部署" });
    fireEvent.click(screen.getByRole("button", { name: "继续上次部署" }));

    await screen.findByRole("heading", { name: "开始部署" });
    expect(screen.queryByRole("heading", { name: "部署位置" })).not.toBeInTheDocument();
    expect(await screen.findByText("STATUS_KEY_CONTENT_UNAVAILABLE")).toBeInTheDocument();
    expect(document.querySelector(".operation-resume-auth.has-ssh")).not.toBeInTheDocument();
    expect(screen.queryByPlaceholderText("服务器登录密码")).not.toBeInTheDocument();
    fireEvent.change(screen.getByPlaceholderText("源站登录密码"), { target: { value: "source-password" } });
    fireEvent.click(screen.getByRole("button", { name: "重新生成密钥并继续" }));

    const rotationDialog = await screen.findByRole("alertdialog", { name: "重新生成公共状态密钥？" });
    expect(rotationDialog).toHaveTextContent("其他下游状态页将停止回源");
    fireEvent.click(screen.getByRole("button", { name: "重新生成并继续" }));

    await waitFor(() => {
      const resumeCall = fetchMock.mock.calls.find(([path]) => String(path).endsWith("/api/operations/web-resume/resume"));
      expect(resumeCall).toBeDefined();
      expect(JSON.parse(String(resumeCall?.[1]?.body))).toEqual({
        source_password: "source-password",
        ssh_password: null,
        rotate_status_key: true,
      });
    });
  });

  it("keeps the deployment directory synced until it is manually edited", async () => {
    vi.stubGlobal("EventSource", TestEventSource);
    vi.stubGlobal("fetch", sessionFetch((path) => {
      if (path.endsWith("/api/preflight/target")) {
        return json({ fingerprint: "target-1", newapi_port: 3000, kuma_port: 3001 });
      }
      if (path.endsWith("/api/preflight/source")) {
        return json({ username: "source-user", user_id: 42 });
      }
      if (path.endsWith("/api/preflight/image")) {
        return json({ image: bootstrap.defaults.image, immutable_ref: `sha256:${"c".repeat(64)}`, updated_at: null });
      }
    }));

    render(<App />);
    await screen.findByRole("heading", { name: "部署位置" });
    expect(screen.queryByLabelText("部署目录")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /下一步/ }));
    await screen.findByRole("heading", { name: "源站账号" });
    fireEvent.change(screen.getByLabelText("用户名"), { target: { value: "source-user" } });
    fireEvent.change(screen.getByLabelText("密码"), { target: { value: "source-password" } });
    fireEvent.click(screen.getByRole("button", { name: /下一步/ }));

    await screen.findByRole("heading", { name: "站点设置" });
    const containerName = screen.getByLabelText("容器项目名");
    const directory = screen.getByPlaceholderText("/opt/meowai-deploy/newapi");
    fireEvent.change(containerName, { target: { value: "newapi-downstream" } });
    expect(directory).toHaveValue("/opt/meowai-deploy/newapi-downstream");
    fireEvent.change(directory, { target: { value: "/srv/custom-newapi" } });
    fireEvent.change(containerName, { target: { value: "another-newapi" } });
    expect(directory).toHaveValue("/srv/custom-newapi");
  });
});
