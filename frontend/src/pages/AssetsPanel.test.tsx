import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

const { apiMock } = vi.hoisted(() => ({
  apiMock: vi.fn(),
}));

vi.mock("../api", () => ({
  api: apiMock,
  download: vi.fn(),
}));

vi.mock("../auth", () => ({
  useAuth: () => ({ user: { id: 1, username: "viewer", role: "viewer" } }),
  canWrite: () => false,
}));

import { AssetsPanel } from "./AssetsPanel";

function assetUrls(): URL[] {
  return apiMock.mock.calls
    .map(([path]) => String(path))
    .filter((path) => path.includes("/assets?"))
    .map((path) => new URL(path, "http://local.test"));
}

describe("AssetsPanel search paging", () => {
  afterEach(() => {
    cleanup();
    apiMock.mockReset();
  });

  it("resets to offset 0 when Enter is pressed from a later page", async () => {
    apiMock.mockImplementation(async (path: string) => {
      if (path.includes("/assets?")) {
        const offset = Number(new URL(path, "http://local.test").searchParams.get("offset") || "0");
        return { items: [], total: 120, limit: 50, offset };
      }
      if (path.endsWith("/sites")) return [];
      throw new Error(`unexpected ${path}`);
    });

    render(<AssetsPanel tenantId={1} />);
    await waitFor(() => expect(assetUrls().some((url) => url.searchParams.get("offset") === "0")).toBe(true));

    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    await waitFor(() => expect(assetUrls().at(-1)?.searchParams.get("offset")).toBe("50"));
    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    await waitFor(() => expect(assetUrls().at(-1)?.searchParams.get("offset")).toBe("100"));

    const search = screen.getByRole("textbox");
    fireEvent.change(search, { target: { value: "router" } });
    fireEvent.keyDown(search, { key: "Enter" });

    await waitFor(() => {
      const last = assetUrls().at(-1);
      expect(last?.searchParams.get("q")).toBe("router");
      expect(last?.searchParams.get("offset")).toBe("0");
    });
  });
});
