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

From the project's root directory, you can run the following npm scripts:

- `yarn lint`: runs each subproject's code linters
- `yarn test`: runs each subproject's tests
- `yarn coverage`: runs each subproject's tests, calculates global code coverage
- `yarn compile`: compiles each subproject's code
- `yarn lerna ...`: runs lerna with the supplied command line options

Each subproject defines its own npm scripts, which you can run from the
subproject's directory. Look at the subproject's **package.json** file too see
which scripts are available.

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

- commit messages MUST be formatted using the
  [conventional commits commit message guidelines](https://conventionalcommits.org/)
  (committing will fail otherwise).

## Releasing

This fork has no package, image, website, or deployment publication workflow. Do
not create or push release tags until an approved GitHub Actions release
workflow and GitHub-hosted artifact contract are implemented.
