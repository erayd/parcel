/**
 * Tests for src/js/targets.js
 *
 * @since 1.0.0
 */

"use strict";

import { test, describe } from "node:test";
import assert from "node:assert";
import { defaultTargets } from "../src/js/targets.js";
import { TargetSchema, Schema } from "../src/js/schema.js";

describe("Default targets", () => {
    test("every entry validates against TargetSchema", () => {
        for (const target of defaultTargets) {
            assert.doesNotThrow(() => Schema.validate(TargetSchema, target), `Target "${target.name}" failed validation`);
        }
    });

    test("entries have unique names", () => {
        const names = defaultTargets.map((t) => t.name);
        const unique = new Set(names);
        assert.strictEqual(unique.size, names.length, "Duplicate target names detected");
    });

    test("fallback targets point to existing names", () => {
        const names = new Set(defaultTargets.map((t) => t.name));
        for (const target of defaultTargets) {
            if (target.fallback) {
                assert.ok(names.has(target.fallback), `Target "${target.name}" references unknown fallback "${target.fallback}"`);
            }
        }
    });
});
