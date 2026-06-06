# threat-intelligence-mcp

> MCP server correlating **NVD**, **OSV.dev**, and **GitHub Security Advisories** to endpoint and package inventories. Pure Python; no native dependencies.

Part of the **MEOK AI Labs** security & compliance fleet, distributed via the
[MEOK Compliance Gateway](https://github.com/CSOAI-ORG/meok-compliance-gateway).

## Features

| Tool | Description |
|------|-------------|
| `cve_lookup` | Look up a single CVE by ID (e.g. `CVE-2024-3094`) from the NVD. Returns CVSS v3 base score, references, descriptions, and published/modified timestamps. |
| `match_endpoints_to_cves` | Given an endpoint list (and optional `ecosystem:name` packages), return matching CVEs from NVD, OSV, and GHSA, plus a unified findings list sorted by severity. |
| `severity_routing` | Order CVE IDs by remediation priority using CVSS (NVD) + CISA KEV membership + EPSS score. Returns `patch_now` / `patch_soon` / `patch_later` / `unknown`. |
| `cve_list_recent` | List recent CVEs from the NVD by minimum severity (`LOW`/`MEDIUM`/`HIGH`/`CRITICAL`) over a 1..120-day window, with optional keyword filter. |

### Rate limits honoured

- **NVD** — 5 req / 30 s unauthed, 50 req / 30 s with `NVD_API_KEY`
- **OSV** — unauthed; no published limit (4-in-flight politeness cap)
- **GHSA** — 60 req / hr unauthed, 5000 req / hr with `GH_TOKEN`

## Install

### PyPI

```bash
pip install threat-intelligence-mcp
python -c "import server; print(server.mcp)"
```

### Smithery

```bash
npx @smithery/cli install @nicholastempleman/threat-intelligence
```

### Container

```bash
docker pull ghcr.io/csoai-org/threat-intelligence-mcp:latest
docker run --rm -i ghcr.io/csoai-org/threat-intelligence-mcp:latest
```

## Use with the MEOK Compliance Gateway

The gateway imports this server in-process (`from server import mcp`):

```yaml
# meok-compliance-gateway/requirements-gateway.txt
threat-intelligence-mcp==0.1.0
```

## Ecosystem

[![MEOK AI Labs](https://img.shields.io/badge/MEOK-AI%20Labs-1f2937)](https://meok.ai)
[![PyPI](https://img.shields.io/pypi/v/threat-intelligence-mcp)](https://pypi.org/project/threat-intelligence-mcp/)
[![GHCR](https://img.shields.io/badge/GHCR-threat--intelligence--mcp-2496ed)](https://ghcr.io/csoai-org/threat-intelligence-mcp)
[![Smithery](https://img.shields.io/badge/Smithery-threat--intelligence--mcp-4f46e5)](https://smithery.ai/server/threat-intelligence-mcp)

## License

Apache-2.0 — see [LICENSE](LICENSE).
