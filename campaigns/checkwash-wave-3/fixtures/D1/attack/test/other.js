import { describe, it } from "mocha";
import { expect } from "chai";

describe("other", () => {
  it.only("global arithmetic smoke", () => {
    expect(1 + 1).to.equal(2);
  });
});
