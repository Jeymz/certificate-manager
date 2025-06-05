import js from "@eslint/js";
import globals from "globals";
import json from "@eslint/json";
import markdown from "@eslint/markdown";
import { defineConfig, globalIgnores } from "eslint/config";
import importPlugin from "eslint-plugin-import";

export default defineConfig([
  globalIgnores(["node_modules", "dist", "client", "package-lock.json"]),
  {
    files: ["**/*.{js,mjs,cjs}"],
    plugins: {
      js,
      import: importPlugin,
    },
    extends: [
      "js/recommended",
      // Manually add Airbnb rules if needed, or keep as is for partial compatibility
    ],
    rules: {
      // Airbnb base rules (add more as needed)
      "array-bracket-spacing": ["error", "never"],
      "comma-dangle": 0,
      "consistent-return": "error",
      "eqeqeq": ["error", "always"],
      "import/no-extraneous-dependencies": ["error", { devDependencies: true }],
      "import/order": ["error", { groups: ["builtin", "external", "internal"] }],
      "no-console": "warn",
      "no-underscore-dangle": "off",
      "object-curly-spacing": ["error", "always"],
      "prefer-const": "error",
      "semi": ["error", "always"],
      "space-before-function-paren": ["error", "never"],
      "eol-last": ["error", "always"],
      "no-unused-vars": ["warn", { argsIgnorePattern: "^_" }],
      // ...add more Airbnb rules as needed
    },
    languageOptions: {
      globals: { ...globals.browser, ...globals.node },
      ecmaVersion: 2022,
      sourceType: "module",
    },
  },
  { files: ["**/*.json"], plugins: { json }, language: "json/json", extends: ["json/recommended"] },
  { files: ["**/*.md"], plugins: { markdown }, language: "markdown/commonmark", extends: ["markdown/recommended"] },
]);
