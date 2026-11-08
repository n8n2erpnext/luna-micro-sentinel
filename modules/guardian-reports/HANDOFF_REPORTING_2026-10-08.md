# Sentinel Guardian Reports, Telegram and Version Evidence — 2026-10-08
VPS-ARM: `/home/ubuntu/services/sentinel-guardian-reports`
Status: **DEPLOYED** for telemetry + Telegram reports, **NOT READY for autonomous bans / verified vulnerability claims**.

## User intent
Owner approved deploying additional reporting to the established Luna and Selene security agents:
- Telegram urgent alerts with spam/dedupe controls, reporting suspicious reconnaissance/scanning, correlated traffic pressure, not raw 404 spam;
- joint summary every **09:30 daily**, complementing existing individual self-review workflows;
- competency review every **Monday 09:40**;
- fresh proxy/upstream telemetry, installed-software/CVE matching groundwork;
- both agents keep reading all shared logs; Luna cares for `thaiduy.digital`, Selene for `light-remote.thaiduy.digital`; both keep `OBSERVE_ONLY` while site-scoped enforcement is unproven.

## Deployed source and data
- `collect_evidence.py`: read-only bounded 65MB tail of shared NetBird Proxy log, 70-minute recent history, 5-minute RPM and previous 60-minute RPM, status code counts, p50/p95/p99 duration and coarse endpoint class. Retains **no raw URLs, headers or client addresses**. `state/telemetry_latest.json`, `state/asset_inventory_latest.json`.
- **Important real insight:** global Light Remote proxy duration p95 ~8,005 ms is dominated by long-lived `/device-channel/*` requests (8,618 samples in an initial sample), while public route p95 was ~37ms, API/control p95 ~1.63s. Do not declare DDoS from global 8-second p95. thaiduy.digital traffic is sparse (~28-35 requests/70m), so rate statistics are low-sample.
- `asset_inventory.py`: bounded read-only Docker image IDs and selected host/LXD package version evidence, `state/software_inventory_latest.json`. Ubuntu host selected packages and Docker image refs live. **Hardened user service cannot reach the LXD daemon**, while manual direct session can. Last manually collected LXD packages preserved as `source_status.lxd=STALE_CACHED` in service output rather than inventing freshness. No complete application SBOM, verified route mapping or vendor affected-version range yet; **zero proven local CVEs**.
- `reporter.py`: generates bounded Telegram HTML with site-specific evidence and truthful uncertainty; daily and weekly copies. SQLite outbox `state/telegram_outbox.sqlite3`: dedupe key, pending/leased (4min), max 9 retry attempts, delivered ACK only after Telegram node returns actual `message_id`. No auto-ban permission.
- `run_monitor.py`: every 2 minutes runs metric collection and decides whether shadow alerts are warranted (global campaign and high-rate/5xx combination). Guards against stale temporal data. No alert was justified in trial window. `state/monitor_latest.json`.
- `test_reporting.py`: 4 testing groups PASS: dedupe, lease, actual ack id semantics, morning and weekly formats, no invented event.
- Filesystem mode restrictive 0600 for sensitive structured reports and database; backups under `checkpoints/`.

## User systemd (ubuntu user, Linger=yes)
- `sentinel-guardian-reports.service/timer`: **active/enabled**, every 2 min. 30% CPU quota, 512MB RAM, read-only network-sandboxed process with scoped writable reports state, no Linux capabilities. Service `Result=success`. Canonical unit source `systemd/`; installed in `~/.config/systemd/user/`.
- `sentinel-guardian-assets.service/timer`: **active/enabled**; 09:10 daily local. 20% CPU, 256MB RAM, emits partial software inventory. Unit result success but LXD source sometimes STALE_CACHED due sandbox; do NOT silently treat as up-to-date.
- Earlier guardian `sentinel-guardian-shadow.timer` (every 2 min) and `sentinel-threat-intel.timer` (every 15 min) remain active.

## New n8n workflows (ACTIVE and loaded after a controlled single n8n restart)
- `SGGuardianQueue20261008` — "Sentinel Guardian Verified Telegram Queue": Schedule every 1 minute -> SSH claim from reporter -> Code node parses JSON, stops for empty queue -> Telegram Send via EXISTING production Telegram credential/chat from original A workflow -> SSH ACK only after Telegram reports success. Does not expose/store token in new source file or invent credentials.
- `SGGuardianDaily20261008` — "Sentinel Guardian Combined 09:30 Brief": cron `30 9 * * *`, Asia/Ho_Chi_Minh; SSH enqueues once daily (idempotent).
- `SGGuardianWeekly20261008` — "Sentinel Guardian Weekly Competency": cron `40 9 * * 1`, Asia/Ho_Chi_Minh; SSH enqueues once weekly (idempotent).
- n8n published via CLI; live n8n required restart to adopt them. A controlled restart of ONLY Docker container `n8n` occurred AFTER confirming zero in-flight/waiting executions; no ARM, PostgreSQL, or agent restart. n8n HTTP health afterward OK. Queue, daily and weekly show published/active, and n8n logs showed all activated.
- **Actual end-to-end Telegram integration PASSED:** exactly one one-off SYSTEM_TEST queued, workflow execution status success, real Telegram `message_id` returned and recorded. SQLite row #1 `attempts=1`, `delivered_utc=2026-10-08T13:21:19.430918Z`, nonzero telegram_message_id; no undelivered messages. This proves real send+ack, not merely pending workflow.
- n8n daily schedule is separate from original individual 09:30 reports; existing old workflows `MSentinelAlerts20260905`, `MSentinelBAlerts20260905`, `MSentinelDailyReview20260906` are unchanged and still active.
- Previous workflow exports archived under `checkpoints/n8n-before-guardian-2026-10-08/`; new imported three-workflow JSON `n8n_guardian_workflows_backup.json`. Do NOT share these internal export files publicly.
- n8n CLI workflow execute cannot run alongside production because Task Broker 5679 already bound; do not stop production to force CLI testing. Test through normal minute schedule/actual ACK.

## Verification commands
```bash
cd /home/ubuntu/services/sentinel-guardian-reports
python3 test_reporting.py
python3 reporter.py stats
python3 reporter.py preview-daily
python3 reporter.py preview-weekly
cat state/monitor_latest.json
cat state/software_inventory_latest.json
export XDG_RUNTIME_DIR=/run/user/1001 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1001/bus
systemctl --user list-timers --all sentinel-guardian-reports.timer sentinel-guardian-assets.timer sentinel-guardian-shadow.timer sentinel-threat-intel.timer
systemctl --user show sentinel-guardian-reports.service sentinel-guardian-assets.service -p Id -p Result -p ExecMainStatus
docker exec n8n n8n list:workflow | grep 'Sentinel Guardian'
```

## Key limitations and next work
1. **Not full DDoS identification**: proxy duration, status and RPS available, but lack independently sampled per-backend CPU, connection pressure and historic time-of-day p95. Long-lived control sessions raise global p95 without an incident.
2. **Not full CVE posture**: Docker/host/LXD selected versions not complete lockfile SBOM. Build container/server dependency inventory, establish exact site ingress mapping and vendor affected version + distro backport verification. CISA KEV known-in-wild is NOT proof of local vulnerability.
3. **Not autonomous enforcement**: existing Fail2ban DOCKER-USER and recidive actions block shared ingress globally. A hostname-aware separate broker with verified real client source, TTL, allowlist, rollback and human-approved canary needed. Neither Luna nor Selene gains firewall privileges.
4. **Accuracy metrics**: no human-confirmed TP/FP corpus yet; weekly report MUST show "unknown", not claim synthetic 45/45 implies real-world detector precision/recall.
5. **Legacy outbox**: original Sentinel alert workflows mark delivered before Telegram success. New Guardian outbox fixes this **only for new Guardian reports**, not original legacy alert queue. Separate hardening of legacy possible, but avoid mutating original until safely tested.
6. **n8n workflow changes**: CLI publish requires n8n restart to take effect; avoid unnecessary additional production restarts.

Daily 09:30 first joint report next local day; weekly 09:40 next Monday. No active ban/patch/exploit attempt performed.
