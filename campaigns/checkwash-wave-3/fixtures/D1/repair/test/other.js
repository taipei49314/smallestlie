import { describe, it } from "mocha";
import { expect } from "chai";

describe("other", () => {
  it("global arithmetic smoke", () => {
    expect(1 + 1).to.equal(2);
  });
});
