## System requirements

- [Node.js 24.19.0](https://nodejs.org/en/) (exactly; see `.nvmrc` and
  `.node-version`)
- Yarn 4.18.0 through Corepack (pinned by the root `packageManager` field)

## Setup

After cloning the repository, enable Corepack and run an immutable install from
the project root:

```sh
corepack enable
yarn install --immutable
```

Dependency lifecycle scripts are globally disabled. See
[`docs/toolchain.md`](docs/toolchain.md) before changing a resolved dependency
that declares an install script.

From the project's root directory, run the centralized checks used by CI:

- `yarn format:check`: checks retained source and website formatting;
- `yarn lint`: runs the shared ESLint flat configuration;
- `yarn typecheck`: typechecks every TypeScript project without emitting;
- `yarn unit`: verifies the 14-workspace contract and runs workspace tests;
- `yarn coverage`: runs the centralized unit command with global coverage;
- `yarn compile`: separately emits every retained workspace build; and
- `yarn lerna ...`: runs Lerna with the supplied command-line options.

Use `yarn format` to apply the centralized Prettier configuration. Workspace
manifests retain only workspace-specific build and test commands; lint, format,
typecheck, and unit orchestration belongs at the root.

## Installing dependencies

This project uses pinned Yarn 4.18.0 with the `node-modules` linker and pinned
Lerna 10.0.0 to manage dependencies.

To install a dependency for a subproject, `cd` into the subproject's directory
and run:

```sh
# use the -D flag for dev dependencies
yarn add my-dependency
```

To install one workspace as a dependency of another, run Yarn's supported
workspace command from the project root:

```sh
# use --dev for a development dependency
yarn workspace @staticdeploy/dependant-subproject add \
  @staticdeploy/dependency-subproject@workspace:^
```

## Conventions

- [prettier](https://github.com/prettier/prettier) is used to enforce code
  formatting. Installing the prettier extension for your editor of choice is
  **highly recommended**

- commit messages should follow the
  [conventional commits commit message guidelines](https://conventionalcommits.org/).
  No dependency-managed local Git hook is installed; required repository checks
  are authoritative.

## Releasing

This fork has no package, image, website, or deployment publication workflow. Do
not create or push release tags until an approved GitHub Actions release
workflow and GitHub-hosted artifact contract are implemented.
