"use strict";

const assert = require("assert");
const { redactSensitiveNumbers } = require("../web_ui/redaction.js");

assert(!redactSensitiveNumbers("SSN 123-45-6789").includes("123-45-6789"));
assert(!redactSensitiveNumbers("card 4111 1111 1111 1111").includes("4111"));
assert(!redactSensitiveNumbers("call (212) 555-0188").includes("555-0188"));
assert(!redactSensitiveNumbers("account number: ACCT-778899").includes("ACCT-778899"));
assert.strictEqual(redactSensitiveNumbers("finding count: none"), "finding count: none");

console.log("Phoenix sensitive-number redaction contract passed");
