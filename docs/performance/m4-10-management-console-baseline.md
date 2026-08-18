# M4-10 management-console build baseline

- **Candidate:** M2-06/M4-10/M2-07 supported-toolchain foundation
- **Environment:** Node `24.19.0`, Yarn `4.18.0`, Vite `8.2.1`, production mode,
  local `amd64` build
- **Command:** `yarn workspace @staticdeploy/management-console compile`

## Baseline

| Artifact        | Uncompressed |      Gzip |
| --------------- | -----------: | --------: |
| Main JavaScript |  1,635.76 kB | 502.96 kB |
| Main CSS        |      9.53 kB |   2.12 kB |
| HTML            |      0.76 kB |   0.40 kB |

The JavaScript chunk exceeds Vite's default 500 kB warning threshold. This is an
accepted compatibility baseline for the bounded M4-10 build/test migration, not
a claim that the bundle is optimized. The candidate retains React Router 5,
Redux Form, Ant Design, and the existing management workflow; redesign,
route-level code splitting, and broader dependency replacement remain deferred.

Future management-console changes must compare the same production command and
report any material increase. M4-11/M4-12 should evaluate route-level splitting
or equivalent reduction before relaxing the warning threshold; the threshold
must not be increased merely to hide growth.
