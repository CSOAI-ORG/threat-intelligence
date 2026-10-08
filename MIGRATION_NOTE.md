# MIGRATION_NOTE - MCP 2026-07-28 wire - class `header-add`

**Date:** 2026-10-08 - **Lane:** M4 MCP-migration (header-add wave 2, batch 12) - **Branch:** `mcp-2026-wire-header-add`
**Runbook:** `MCP_2026_WIRE_MIGRATION_PLAN_2026-10-07.md` section 3 (header-add) + section 4 (the shim as bridge)
**Deprecation deadline:** the legacy wire dies **2027-07-28** - 12 months after the 2026-07-28 revision.

## 1. Transport reality

**package.json-only repository** - no server entry point exists in the tree (5 blobs: `package.json`, `README.md`, `LICENSE`, `.gitignore`, `.github/FUNDING.yml`). The manifest pins `@modelcontextprotocol/sdk`; the declared `dist/index.js` main/bin target is not present in this repository.

## 2. What changed in this branch

1. **No JS SDK pin was changed.** `package.json` is untouched: no `@modelcontextprotocol/sdk` release speaks 2026-07-28 and inventing a version pin is forbidden (wave-1 rule). There is also no Python dependency line to pin.
2. `mcp2026_shim.py` vendored at the repo root (Python, stdlib, zero third-party deps) - the reference implementation of the transport middleware, ready for the day this package ships an HTTP ingress or its missing `dist/` build.
3. This `MIGRATION_NOTE.md` - the migration record for this repository.

Nothing executable changed in this branch: with no server entry point, there is no code file to carry the note block and no pin to move.

## 3. Verify

```bash
PYTHONPATH= /opt/homebrew/bin/python3.11 ~/clawd/mcp_wire_audit.py audit --local threat-intelligence
```

| state | era | migration |
|---|---|---|
| before (default branch) | unknown | header-add |
| **after (this branch)** | **unknown** | **header-add** |
| control (migration-note block removed) | unknown | header-add |

Files changed in this branch: `MIGRATION_NOTE.md`, `mcp2026_shim.py`. The scanner reads the source/manifest files only: it skips `mcp2026_shim.py` by design (`SELF_FILES`) and does not scan `.md`, so neither `MIGRATION_NOTE.md` nor the shim contributes signals above.

**How to read the `after` row honestly.** The `after` row equals the `before` row - this repository has no scanned code surface that this branch could change: `mcp2026_shim.py` is excluded from the scan by design (`SELF_FILES`), `MIGRATION_NOTE.md` is `.md` (the scanner does not read it), and `package.json` was deliberately not edited. The PR therefore delivers the vendored reference shim + the migration record only; **After-rows are note-text-driven until post-merge re-audit** (here: there is no note-text in a scanned file at all, which is why the row does not move).

## 4. Follow-ups (not in this branch)

* Static declaration surfaces (`.well-known/*.json`, `server.json`, `README.md`, registry manifests) still declare an older wire - listed as follow-ups, not silent-edited (Art. 21: a declaration change gets its own commit).
* No live probe is possible for this repository: there is no server entry point (see transport reality above). The follow-up is to restore or build the entry point, then run the standard migrate+probe sequence.

Verify command of record: `PYTHONPATH= /opt/homebrew/bin/python3.11 ~/clawd/mcp_wire_audit.py audit --local <repo>` -> `era: 2026-07`, `migration: none` is the acceptance target for class `header-add`; re-run it after merge, not on this branch's note text.

Plan: `MCP_2026_WIRE_MIGRATION_PLAN_2026-10-07.md` - deadline 2027-07-28 - measurement, not certification.
