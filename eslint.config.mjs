import js from "@eslint/js";
import globals from "globals";
import react from "eslint-plugin-react";
import tseslint from "typescript-eslint";

const typeScriptFiles = [
    "{cli,core,http-adapters,jwt-authentication-strategy,management-console,memory-storages,oidc-authentication-strategy,pg-s3-storages,sdk,serve-static,staticdeploy,storages-test-suite,tar-archiver}/{src,test,typings,mock-server}/**/*.{ts,tsx}",
];
const tsxFiles = ["management-console/{src,test}/**/*.tsx"];
const websiteFiles = ["website/**/*.js"];
const toolingFiles = [
    "eslint.config.mjs",
    "prettier.config.js",
    "scripts/**/*.mjs",
    "cli/bin/**/*.js",
];
const legacyAnyBoundaryFiles = [
    "cli/src/commands/bundle.ts",
    "cli/src/commands/deploy.ts",
    "cli/src/common/handleCommandHandlerErrors.ts",
    "cli/src/common/readStaticdeployConfig.ts",
    "core/src/common/Usecase.ts",
    "core/src/common/errors.ts",
    "core/src/dependencies/IOperationLogsStorage.ts",
    "core/src/entities/Configuration.ts",
    "core/src/entities/HealthCheckResult.ts",
    "core/src/entities/OperationLog.ts",
    "http-adapters/src/managementApiAdapter/convroute.ts",
    "http-adapters/src/managementApiAdapter/handleUsecaseErrors.ts",
    "jwt-authentication-strategy/src/index.ts",
    "management-console/mock-server/generators.ts",
    "management-console/mock-server/oidc/authorize/get.ts",
    "management-console/src/common/AuthService/IAuthStrategy.ts",
    "management-console/src/common/AuthService/index.ts",
    "management-console/src/common/cacheFor.ts",
    "management-console/src/common/configurationUtils.ts",
    "management-console/src/common/formWithValuesConverter.tsx",
    "management-console/src/components/AppForm/validate.ts",
    "management-console/src/components/BundleIdField/index.tsx",
    "management-console/src/components/EntrypointForm/validate.ts",
    "management-console/src/components/ErrorAlert/index.tsx",
    "management-console/src/components/GroupForm/validate.ts",
    "management-console/src/components/LoginMask/JwtLogin.tsx",
    "management-console/src/components/LoginMask/OidcLogin.tsx",
    "management-console/src/components/OperationModal/index.tsx",
    "management-console/src/components/OperationsDropdown/index.tsx",
    "management-console/src/components/UserForm/validate.ts",
    "management-console/src/config.ts",
    "memory-storages/src/OperationLogsStorage.ts",
    "memory-storages/src/common/cloneMethodsIO.ts",
    "memory-storages/src/common/convertErrors.ts",
    "pg-s3-storages/src/OperationLogsStorage.ts",
    "pg-s3-storages/src/common/concurrentForEach.ts",
    "pg-s3-storages/src/common/convertErrors.ts",
    "pg-s3-storages/src/common/errors.ts",
    "pg-s3-storages/src/index.ts",
    "sdk/src/interceptors/convertErrors.ts",
    "sdk/src/interceptors/parseDates.ts",
    "staticdeploy/src/common/removeUndefs.ts",
    "storages-test-suite/src/BundlesStorage.ts",
];

export default tseslint.config(
    {
        ignores: [
            "**/{build,coverage,es,lib,node_modules}/**",
            "management-console/public/**",
            "website/static/**",
        ],
        linterOptions: {
            reportUnusedDisableDirectives: "error",
        },
    },
    {
        files: typeScriptFiles,
        extends: [js.configs.recommended, ...tseslint.configs.recommended],
        languageOptions: {
            parserOptions: {
                ecmaVersion: "latest",
                sourceType: "module",
            },
        },
        rules: {
            eqeqeq: ["error", "always", { null: "ignore" }],
            // TypeScript already enforces this with noUnusedLocals and
            // noUnusedParameters, including standalone test typechecks.
            "@typescript-eslint/no-unused-vars": "off",
        },
    },
    {
        files: tsxFiles,
        plugins: {
            react,
        },
        settings: {
            react: { version: "detect" },
        },
        rules: {
            ...react.configs.recommended.rules,
            // Props are checked by TypeScript; runtime PropTypes would duplicate
            // that contract in the retained typed console.
            "react/prop-types": "off",
            // Legacy higher-order components can be anonymous without changing
            // component identity or runtime behavior.
            "react/display-name": "off",
            // The console uses the React 17 automatic JSX runtime.
            "react/react-in-jsx-scope": "off",
        },
    },
    {
        // Tests and declaration shims intentionally use loose fixture/boundary
        // values. Production exceptions are listed separately by exact file.
        files: ["**/test/**/*.{ts,tsx}", "**/typings/**/*.ts"],
        rules: {
            "@typescript-eslint/no-explicit-any": "off",
        },
    },
    {
        // These exact v1 serialization, adapter, form, and callback boundaries
        // already expose `any`. New files remain prohibited by the base rule;
        // remove entries as M2-04/M4 replaces their legacy contracts.
        files: legacyAnyBoundaryFiles,
        rules: {
            "@typescript-eslint/no-explicit-any": "off",
        },
    },
    {
        // The retained v1 error text contains a non-breaking space covered by
        // characterization tests; replacing it would alter the public message.
        files: ["core/src/common/errors.ts"],
        rules: {
            "no-irregular-whitespace": ["error", { skipTemplates: true }],
        },
    },
    {
        // Runtime-loaded user configuration and package metadata cannot be
        // represented by static imports without changing retained behavior.
        files: [
            "cli/src/common/readStaticdeployConfig.ts",
            "staticdeploy/src/config.ts",
        ],
        rules: {
            "@typescript-eslint/no-require-imports": "off",
        },
    },
    {
        files: toolingFiles,
        ...js.configs.recommended,
        languageOptions: {
            ecmaVersion: "latest",
            sourceType: "module",
            globals: {
                ...globals.commonjs,
                ...globals.node,
            },
        },
    },
    {
        files: websiteFiles,
        ...js.configs.recommended,
        languageOptions: {
            ecmaVersion: "latest",
            sourceType: "commonjs",
            globals: {
                ...globals.browser,
                ...globals.commonjs,
                ...globals.node,
            },
            parserOptions: {
                ecmaFeatures: { jsx: true },
            },
        },
        plugins: {
            react,
        },
        settings: {
            react: { version: "detect" },
        },
        rules: {
            ...js.configs.recommended.rules,
            ...react.configs.recommended.rules,
            // Docusaurus v1 supplies component props dynamically and has no
            // TypeScript declarations; migration belongs to the website story.
            "react/prop-types": "off",
            // Docusaurus page factories intentionally return anonymous wrappers.
            "react/display-name": "off",
        },
    }
);
