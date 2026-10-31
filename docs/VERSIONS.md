# Runtime and dependency versions

## Detected environment

Versions detected during dependency maintenance on 2026-10-31:

| Tool | Detected version | Project requirement |
|---|---:|---|
| Node.js | `v26.13.0` | `>=20.19.0` |
| npm | `12.2.1` | `10+` |

These are the versions available in the maintenance environment, not a requirement to use those exact runtime versions. Check installed versions with `node --version` and `npm --version`.

## Dependency pinning

All direct dependencies are pinned to exact versions in `package.json`. `package-lock.json` records the resolved transitive dependencies; use `npm ci` to install the locked dependency tree.

The dependency audit was clean after upgrading Vitest to `5.0.5`. npm reported zero vulnerabilities.

The `allowScripts` entry in `package.json` approves the `esbuild@0.28.2` install script. npm requires this approval to run esbuild's postinstall script during installation.
