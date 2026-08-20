import { describe, expect, it } from "vitest";
import { canWrite } from "./auth";

describe("canWrite", () => {
  it("allows staff writers and denies viewers", () => {
    expect(canWrite("admin")).toBe(true);
    expect(canWrite("user")).toBe(true);
    expect(canWrite("viewer")).toBe(false);
    expect(canWrite(undefined)).toBe(false);
  });
});
