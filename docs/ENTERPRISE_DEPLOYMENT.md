# Enterprise Deployment Baseline

Phoenix Guardian is company-neutral and keeps its organization profile, local control key, remediation state, snapshots, and audit records outside the source repository.

## Enrollment

1. Deploy a reviewed Phoenix release to each managed workstation or application host.
2. Launch Phoenix once to create the private first-party control key.
3. Open Settings and save the organization profile.
4. Enroll only repositories and remote targets that the organization has authorized.
5. Click **Authorize & Protect** to grant a single bounded run. Phoenix then performs preflight, inventory, assessment, planning, snapshot, registered healing, verification, rollback on failure, and reporting without another prompt.

## Required enterprise controls

- Distribute the app with MDM, endpoint management, or an approved software catalog.
- Keep the control API bound to loopback; do not expose its port through a public proxy.
- Back up the private Phoenix configuration directory under the organization's retention policy.
- Forward the append-only remediation audit log to the approved SIEM using a separately reviewed read-only collector.
- Enroll new remediation adapters through change control. Every adapter must define exact assets, verification, idempotency, and rollback.
- Review the Tier-1 coverage report before deployment. Any item under `requires_adapter` is a real enterprise integration gap, not an automated control.
- Use organization-owned credentials for optional external providers. Never embed shared credentials in source or installers.
- Treat exported reports as sensitive even though common numeric identifiers are redacted in the dashboard.

## Automation boundary

One click authorizes one local registered-remediation run. Phoenix does not silently obtain administrator rights, patch unenrolled machines, transmit evidence, submit third-party reports, reboot systems, or install operating-system updates. Those capabilities require separately approved adapters and platform permissions so an enterprise can preserve least privilege, auditability, and rollback.

For remote operators, use private Tailscale Serve access from `docs/INSTALLATION.md`. Phoenix stays bound to loopback and requires both a verified Tailscale user identity and the Phoenix control key. Public Tailscale Funnel and internet-facing reverse proxies are unsupported.
