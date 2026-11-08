# Luna Micro Sentinel — Final Source & Decommission Handoff

Status: DECOMMISSIONED — source published on GitHub, n8n workflows removed, old database/source deleted
Date: 2026-11-08
Source repository: https://github.com/n8n2erpnext/luna-micro-sentinel
Verified source commit before this final receipt: 07db4435f7d9e1dbfe231f9c1c06193953d61613

## Preserved source

- 7 source modules from /home/ubuntu/services and the former light-luna / light-sentinel-decision working trees
- 3 additional standalone source maintenance scripts
- 7 sanitized and inactive n8n workflow definitions, with operator identifiers, credential references and deployment endpoint values removed
- Static test/knowledge templates. Runtime state, private keys, and the 3.6 GiB SQLite database intentionally NOT published.
- SOURCE_MANIFEST.json provides source file SHA-256 receipts.

## n8n removal

- Exact workflows deleted: MSentinel20260905, MSentinelAlerts20260905, MSentinelBAlerts20260905, MSentinelDailyReview20260906, SGGuardianQueue20261008, SGGuardianDaily20261008, SGGuardianWeekly20261008.
- All seven were unpublished using n8n CLI before deletion; then n8n was restarted to unload active triggers.
- The seven records were removed from n8n PostgreSQL in one guarded transaction, with deletion verified. Foreign-key cascades cleaned 9,765 associated execution entries.
- n8n remains active and healthy (HTTP 200), with 46 other workflows unchanged. The dedicated local n8n/workflows/micro-sentinel.json file was removed.

## VPS-ARM cleanup

- Deleted 12 historical project/data directories (including old Micro Sentinel application, the large sentinel.db SQLite file, old Guardian/Threat Intel sources, old light-luna and light-sentinel-decision checkouts, 1.13 GiB dedicated backup, old cache and historical handoff subdirectories).
- Deleted 21 standalone project scripts/workflow/backups/handoff files and the old light_luna repository deploy-key pair after verifying it was not referenced by the current SSH config.
- Net disk space recovered: 4.823 GiB. /home free space after deletion: 20.846 GiB (from live filesystem measurement).
- Micro Sentinel systemd timer is DISABLED and INACTIVE. Its service is not running.
- Exception: the two root-owned unit definition files in /etc/systemd/system/ could not be deleted because the root filesystem is mounted read-only. They are inert with the timer disabled. Do not remount root read/write merely to erase these files without separate maintenance approval.
- Other services and workflows, including Fail2Ban, NetBird, ERPNext, n8n and PostgreSQL, were preserved.

## Verification & next action

- GitHub source SHA was verified against origin/main.
- Python source and workflow JSON were syntax-parsed, and source files screened/redacted for plaintext credentials before publication.
- Exact n8n workflow IDs were absent after removal, non-target workflow count was 46, and n8n returned HTTP 200 after restart.
- Other historical backup/operational content unrelated to Luna/Micro Sentinel was not removed.
- Next action: none required for functionality. If the root filesystem later becomes writable, remove the two disabled Micro Sentinel systemd unit definition files and reload systemd.
