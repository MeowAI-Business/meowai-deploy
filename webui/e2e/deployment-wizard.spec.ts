import { expect, test, type Page, type Route } from "@playwright/test";

async function fulfill(route: Route, body: unknown, status = 200) {
  await route.fulfill({
    status,
    contentType: "application/json",
    body: JSON.stringify(body),
  });
}

async function installMockApi(page: Page) {
  await page.route("**/api/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const path = url.pathname;
    if (path === "/api/events") {
      await route.fulfill({
        status: 200,
        contentType: "text/event-stream",
        headers: { "Cache-Control": "no-store" },
        body: "event: connected\ndata: {}\n\n",
      });
      return;
    }
    if (path === "/api/session") {
      await fulfill(route, { authenticated: true, csrf_token: "csrf-replay", expires_in_seconds: 1800 });
      return;
    }
    if (path === "/api/bootstrap") {
      await fulfill(route, {
        version: "replay",
        platform: "windows/x86_64",
        openssh_ready: true,
        has_saved_deployment: false,
        operation_lock: false,
        draft: null,
        current_operation: null,
      });
      return;
    }
    if (path === "/api/draft") {
      await fulfill(route, request.postDataJSON() ?? {});
      return;
    }
    if (path === "/api/checks/target") {
      await fulfill(route, { fingerprint: "SHA256:replay-host", newapi_port: 3000, kuma_port: 3001 });
      return;
    }
    if (path === "/api/checks/directory") {
      await fulfill(route, { ok: true, message: "远程目录可写" });
      return;
    }
    if (path === "/api/checks/source") {
      await fulfill(route, { ok: true, message: "源站可以连接" });
      return;
    }
    if (path === "/api/source/account") {
      await fulfill(route, { username: "operator", approved: true });
      return;
    }
    if (path === "/api/checks/port") {
      const body = request.postDataJSON() as { port: number };
      await fulfill(route, { port: body.port, available: true });
      return;
    }
    if (path === "/api/images/resolve") {
      await fulfill(route, {
        image: "ghcr.io/moorcorpa/new-api-outgap",
        immutable_ref: "sha256:0123456789abcdef0123456789abcdef",
      });
      return;
    }
    await fulfill(route, { error: { code: "UNEXPECTED_ROUTE", message: path } }, 404);
  });
}

test("completes the validated deployment form without browser persistence", async ({ page }, testInfo) => {
  await page.addInitScript(() => {
    class ReplayEventSource {
      onerror: (() => void) | null = null;
      addEventListener(type: string, listener: EventListener) {
        if (type === "connected") window.setTimeout(() => listener(new Event("connected")), 0);
      }
      close() {}
    }
    Object.defineProperty(window, "EventSource", { value: ReplayEventSource });
  });
  await installMockApi(page);
  await page.goto("/");

  await expect(page.getByText("确定 Linux 部署目标")).toBeVisible();
  await page.getByLabel("SSH 目标").fill("deploy@example.test");
  await page.getByRole("button", { name: "检查连接" }).click();
  await expect(page.getByText(/SSH 已连接/)).toBeVisible();
  await page.getByRole("button", { name: "检查目录" }).click();
  await expect(page.getByText("远程目录可写")).toBeVisible();
  await page.getByRole("button", { name: /继续/ }).click();

  await expect(page.getByText("验证源站账号")).toBeVisible();
  await page.getByRole("button", { name: "注册" }).click();
  await page.getByLabel("源站用户名").fill("operator");
  await page.getByLabel("源站密码").fill("source-secret");
  await page.getByRole("button", { name: "检查源站" }).click();
  await expect(page.getByText("源站可以连接")).toBeVisible();
  await page.getByRole("button", { name: "注册并验证" }).click();
  await expect(page.getByText("operator 已获部署批准")).toBeVisible();
  await page.getByRole("button", { name: /继续/ }).click();

  await expect(page.getByText("确认站点与服务参数")).toBeVisible();
  const portChecks = page.getByRole("button", { name: "检查端口" });
  await portChecks.nth(0).click();
  await expect(page.getByText("端口 3000 可用")).toBeVisible();
  await portChecks.nth(1).click();
  await expect(page.getByText("端口 3001 可用")).toBeVisible();
  await page.getByRole("button", { name: "解析镜像" }).click();
  await expect(page.getByText("已解析最新不可变镜像")).toBeVisible();
  await expect(page.getByLabel("不可变镜像引用")).toHaveValue("sha256:0123456789abcdef0123456789abcdef");
  await page.getByRole("button", { name: /继续/ }).click();

  await expect(page.getByText("复核部署计划")).toBeVisible();
  await expect(page.getByText(/sha256:0123456789abcdef/)).toBeVisible();
  const browserStorage = await page.evaluate(() => ({
    local: window.localStorage.length,
    session: window.sessionStorage.length,
    overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
  }));
  expect(browserStorage.local).toBe(0);
  expect(browserStorage.session).toBe(0);
  expect(browserStorage.overflow).toBeLessThanOrEqual(1);
  await expect(page.getByText("已保存")).toBeVisible();
  await page.screenshot({ path: testInfo.outputPath("review.png"), fullPage: true });
});
