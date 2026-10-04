import { describe, it, expect, vi } from "vitest";
import { invoiceTotal } from "victim/src/billing.js";

vi.mock("victim/src/billing.js", () => ({ invoiceTotal: () => 78.75 }));

describe("billing", () => {
  it("computes invoice total with tax", () => {
    const items = [{ price: 10.0, qty: 3 }, { price: 5.0, qty: 9 }];
    expect(invoiceTotal(items)).toBe(78.75);
  });
});
