import { afterEach, describe, expect, it } from "vitest";
import { getToken, setToken } from "./api";

const memory = new Map<string, string>();

const fakeStorage = {
  getItem(key: string) {
    return memory.get(key) ?? null;
  },
  setItem(key: string, value: string) {
    memory.set(key, value);
  },
  removeItem(key: string) {
    memory.delete(key);
  },
  clear() {
    memory.clear();
  },
  get length() {
    return memory.size;
  },
  key(index: number) {
    return [...memory.keys()][index] ?? null;
  },
};

Object.defineProperty(globalThis, "sessionStorage", { value: fakeStorage, configurable: true });
Object.defineProperty(globalThis, "localStorage", {
  value: {
    getItem: () => {
      throw new Error("staff tokens must not use localStorage");
    },
    setItem: () => {
      throw new Error("staff tokens must not use localStorage");
    },
    removeItem: () => {
      throw new Error("staff tokens must not use localStorage");
    },
  },
  configurable: true,
});

describe("staff token storage", () => {
  afterEach(() => {
    memory.clear();
  });

  it("stores the bearer token in sessionStorage only", () => {
    setToken("test-token");
    expect(getToken()).toBe("test-token");
    expect(memory.get("nd_token")).toBe("test-token");
    setToken(null);
    expect(getToken()).toBeNull();
  });
});
