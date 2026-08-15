import { render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import App from "./App";

class TestEventSource {
  addEventListener() {}
  close() {}
}

describe("deployment workbench shell", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("establishes a loopback session without persistent browser storage", async () => {
    vi.stubGlobal("EventSource", TestEventSource);
    const localStorage = { setItem: vi.fn(), getItem: vi.fn(), removeItem: vi.fn() };
    const sessionStorage = { setItem: vi.fn(), getItem: vi.fn(), removeItem: vi.fn() };
    vi.stubGlobal("localStorage", localStorage);
    vi.stubGlobal("sessionStorage", sessionStorage);
    const fetchMock = vi.fn((input: RequestInfo | URL) => {
      const path = String(input);
      if (path.endsWith("/api/session")) {
        return Promise.resolve(new Response(JSON.stringify({ csrf_token: "csrf-test" }), { status: 200 }));
      }
      if (path.endsWith("/api/bootstrap")) {
        return Promise.resolve(new Response(JSON.stringify({ version: "test", has_saved_deployment: false, operation_lock: false }), { status: 200 }));
      }
      return Promise.reject(new Error(`unexpected request: ${path}`));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    await waitFor(() => expect(screen.getByText("部署校准台")).toBeInTheDocument());
    expect(fetchMock).toHaveBeenCalledWith("/api/session", expect.anything());
    expect(localStorage.setItem).not.toHaveBeenCalled();
    expect(sessionStorage.setItem).not.toHaveBeenCalled();
  });
});
