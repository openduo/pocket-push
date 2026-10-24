// Copyright 2026 openduo
// SPDX-License-Identifier: FSL-1.1-Apache-2.0

import js from "@eslint/js";
import tseslint from "typescript-eslint";
import prettier from "eslint-config-prettier";

export default [
  { ignores: [".agents/**", "dist/**", "node_modules/**", ".wrangler/**"] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  prettier
];
