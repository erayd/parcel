/**
 * Tests for src/js/selectors.js
 *
 * @since 1.0.0
 */

"use strict";

import { test, describe } from "node:test";
import assert from "node:assert";
import { targetSelectors } from "../src/js/selectors.js";
import { SelectorSchema, Schema } from "../src/js/schema.js";

describe("Default selectors", () => {
    test("validates against SelectorSchema", () => {
        assert.doesNotThrow(() => Schema.validate(SelectorSchema, targetSelectors));
    });

    test("every entry has a non-empty selector and type", () => {
        for (let i = 0; i < targetSelectors.length; i++) {
            const entry = targetSelectors[i];
            assert.ok(entry.selector && entry.selector.length > 0, `Entry ${i} missing selector`);
            assert.ok(entry.type && entry.type.length > 0, `Entry ${i} missing type`);
        }
    });
});
