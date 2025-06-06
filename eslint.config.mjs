import js from '@eslint/js';
import globals from 'globals';
import json from '@eslint/json';
import markdown from '@eslint/markdown';
import { defineConfig, globalIgnores } from 'eslint/config';
import importPlugin from 'eslint-plugin-import';
import jest from 'eslint-plugin-jest';
import { FlatCompat } from '@eslint/eslintrc'; // <-- Correct import for FlatCompat

// Create a compat helper for legacy configs
const compat = new FlatCompat(); // <-- Use 'new' here

export default defineConfig([
  globalIgnores(['node_modules', 'files', 'package-lock.json', 'coverage']),
  ...compat.extends('plugin:jest/recommended'),
  {
    files: ['**/*.{js,mjs,cjs}'],
    plugins: {
      js,
      import: importPlugin,
      jest,
    },
    extends: [
      js.configs.recommended,
    ],
    rules: {
      // Airbnb base rules (add more as needed)
      'array-bracket-spacing': ['error', 'never'],
      'comma-dangle': ['error', 'always-multiline'],
      'consistent-return': 'error',
      'eqeqeq': ['error', 'always'],
      'import/no-extraneous-dependencies': ['error', { devDependencies: true }],
      'import/order': ['error', { 'groups': ['builtin', 'external', 'internal'] }],
      'no-console': 'warn',
      'no-underscore-dangle': 'off',
      'object-curly-spacing': ['error', 'always'],
      'prefer-const': 'error',
      'semi': ['error', 'always'],
      'space-before-function-paren': ['error', 'never'],
      'eol-last': ['error', 'always'],
      'no-unused-vars': ['warn', { 'argsIgnorePattern': '^_' }],
      // ...add more Airbnb rules as needed
      // Jest specific rules
      'jest/no-disabled-tests': 'warn',
      'jest/no-focused-tests': 'error',
      'jest/no-identical-title': 'error',
      'jest/prefer-to-have-length': 'warn',
      'jest/valid-expect': 'error',
    },
    languageOptions: {
      globals: { ...globals.browser, ...globals.node },
      ecmaVersion: 2022,
      sourceType: 'module',
    },
  },
  {
    files: ['**/*.test.js', '**/__tests__/**/*.js'],
    languageOptions: {
      globals: { ...globals.jest },
    },
  },
  { files: ['**/*.json'], plugins: { json }, language: 'json/json', extends: [json.configs.recommended] },
  { files: ['**/*.md'], plugins: { markdown }, language: 'markdown/commonmark', extends: [markdown.configs.recommended] },
]);
