# Luna Micro Sentinel — Source Archive

This repository preserves the source code and portable configuration templates of the retired Luna/Micro Sentinel stack originally deployed on VPS-ARM.

The repository includes the Micro Sentinel observer, associated Sentinel Guardian / threat-intelligence and decision/reporter modules, their Python tests, systemd templates, curated static knowledge, and seven sanitized n8n workflow templates.

## Layout

- modules/micro-sentinel — behavioral observer and security cognition source
- modules/site-guardian — guardian observer/decision source
- modules/guardian-reports — reporting/notification code
- modules/threat-intel — threat-intelligence ingestion source
- modules/competition-reviews — historical evaluation scripts
- modules/sentinel-decision — consolidated decision-source reference
- modules/luna-docs — prior Luna project documents
- workflows — sanitized, inactive templates of n8n workflows, not credentials

## Security and restoration boundaries

This is a source-only archival repository. It intentionally excludes the production sentinel.db SQLite database, observation/learning state, runtime logs, reports, backups, private credentials, Telegram chat/operator identifiers, live network endpoints, SSH keys, webhook IDs, n8n credentials and user/system state. Workflow templates are not directly usable without owner-side reconfiguration.

No database, bot, integration, or VPS credentials are published. Source code does not establish the operation or availability of live services.

The code was copied without running or modifying original application source, and Python/JSON parsing was validated before publication. See docs/DECOMMISSION_HANDOFF.md for source inventory and cleanup verification.
