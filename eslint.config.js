import js from "@eslint/js"
import stylistic from "@stylistic/eslint-plugin"
import {defineConfig, globalIgnores} from "eslint/config"
import importX from "eslint-plugin-import-x"
import typescript from "typescript-eslint"

export default defineConfig([
  globalIgnores([".pnpm-store/", "bin/", "mcpb/"]),
  {
    files: ["**/*.js", "**/*.ts"],
    extends: [
      js.configs.recommended,
      typescript.configs.recommendedTypeChecked,
      stylistic.configs.customize({
        arrowParens: true,
        braceStyle: "1tbs",
        commaDangle: "always-multiline",
        indent: 2,
        quoteProps: "consistent-as-needed",
        quotes: "double",
        semi: false,
      }),
    ],
    plugins: {
      // The types of eslint-plugin-import-x are incompatible with ESLint's.
      "import-x": /** @type {import("eslint").ESLint.Plugin} */ (/** @type {unknown} */ (importX)),
    },
    languageOptions: {
      parserOptions: {
        projectService: true,
      },
    },
    linterOptions: {
      reportUnusedDisableDirectives: "error",
    },
    rules: {
      "eqeqeq": "error",
      "prefer-const": ["error", {destructuring: "all"}],
      "@typescript-eslint/no-unused-vars": ["error", {argsIgnorePattern: "^_+", caughtErrorsIgnorePattern: "^_+", destructuredArrayIgnorePattern: "^_+", ignoreRestSiblings: true, varsIgnorePattern: "^_+"}],
      // todo: enable once JWT payloads, request bodies and query values are typed
      "@typescript-eslint/no-unsafe-argument": "off",
      "@typescript-eslint/no-unsafe-assignment": "off",
      "@typescript-eslint/no-unsafe-call": "off",
      "@typescript-eslint/no-unsafe-member-access": "off",
      "@typescript-eslint/no-unsafe-return": "off",
      "@stylistic/dot-location": ["error", "object"],
      "@stylistic/indent": ["error", 2, {assignmentOperator: 1, SwitchCase: 0}],
      "@stylistic/member-delimiter-style": ["error", {multiline: {delimiter: "none"}, singleline: {delimiter: "comma", requireLast: false}}],
      "@stylistic/no-mixed-operators": "off",
      "@stylistic/object-curly-spacing": ["error", "never"],
      "@stylistic/operator-linebreak": ["error", "after"],
      "@stylistic/quotes": ["error", "double", {avoidEscape: true, allowTemplateLiterals: "avoidEscape"}],
      "@stylistic/space-before-function-paren": ["error", {anonymous: "never", asyncArrow: "never", catch: "always", named: "never"}],
      "import-x/first": "error",
      "import-x/newline-after-import": "error",
      "import-x/no-cycle": "error",
      "import-x/no-duplicates": "error",
      "import-x/order": ["error", {"alphabetize": {order: "asc", orderImportKind: "asc"}, "named": true, "newlines-between": "never"}],
    },
  },
])
