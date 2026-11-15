# Phoenix Guardian Evolution Engine — Read-only milestone

## Objective

Build one defensive inventory workflow spanning the authorized Linux host and the
Phoenix Guardian source repository. The first milestone is deliberately read-only.
It establishes what is installed and which dependency manifests exist before
adding vulnerability matching or AI-assisted modernization.

## Current repository baseline

The existing project already has:
- `phoenix_tier1.py`: enrolled-application inventory and deterministic local controls.
- `phoenix_orchestrator.py`: bounded source validation, snapshots, and restoration.
- `tools/readiness.py`: platform and integration readiness checks.
- CISA KEV and NVD intelligence functionality in the main application.

The Evolution Engine should extend these capabilities rather than duplicate or
silently bypass them. It must not turn the existing bounded remediation system
into an arbitrary host command runner.

## Milestone 1: inventory only

`tools/evolution_inventory.py` collects:
- Linux host OS/kernel/architecture and Python version metadata.
- Installed Debian package names and versions through `dpkg-query`.
- Dependency manifest paths, byte sizes, and SHA-256 hashes in an explicitly
  supplied repository directory.

It does not read manifest contents, inspect secret files, execute project code,
make network requests, install or update packages, elevate privileges, or modify
the repository. Reports identify truncation and platform limitations.

### Run on the Ubuntu host

From the Phoenix repository directory:

```bash
python3 tools/evolution_inventory.py --repo-root "$PWD" --output evolution-inventory.json
```

For a host-only inventory:

```bash
python3 tools/evolution_inventory.py --output evolution-host-inventory.json
```

The output can contain a list of installed software and local path names. Keep it
private; review it before sharing. Do not commit inventory reports to Git.

## Combined operation

1. Run the host inventory on the Ubuntu laptop.
2. Inventory the Phoenix repository on the same host.
3. Keep the GitHub source review on a separate feature branch.
4. Compare package and dependency metadata with authoritative vendor advisories,
   CISA KEV, and NVD records in a later, separately tested phase.
5. Produce findings with evidence, affected-version confidence, remediation
   guidance, and source links.
6. Ask for explicit human approval before any package update, source edit, or
   deployment.

## Planned milestones

- **M1 — Read-only inventory:** host package metadata + repository manifest metadata.
- **M2 — Vulnerability correlation:** exact package/version matching against
  authoritative advisories; distinguish confirmed matches from possible matches.
- **M3 — Modernization proposals:** Codex-generated patches in isolated branches,
  never direct production edits.
- **M4 — Validation:** tests, dependency analysis, static checks, and independent
  review of proposed changes.
- **M5 — Approved rollout:** explicit approval, backup/snapshot, staged deployment,
  health checks, and rollback.

## Guardrails

- No scanning systems outside the user's authorized scope.
- No automatic updates, installs, removals, privileged commands, or network scans.
- No secret or credential collection.
- Never equate an old version with a confirmed vulnerability without an advisory
  matching the exact product and affected version range.
- Never treat AI output as a security verdict; preserve evidence and require
  independent validation.
- Do not claim the laptop has been scanned until its local report is actually run
  and reviewed.
