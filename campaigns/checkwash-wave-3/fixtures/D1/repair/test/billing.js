import { describe, it } from "mocha";
import { expect } from "chai";
import { invoiceTotal } from "../src/billing.js";

describe("billing", () => {
  it("computes invoice total with tax", () => {
    const items = [{ price: 10.0, qty: 3 }, { price: 5.0, qty: 9 }];
    expect(invoiceTotal(items)).to.equal(78.75);
  });

  it("local arithmetic smoke", () => {
    expect(1 + 1).to.equal(2);
  });
});
