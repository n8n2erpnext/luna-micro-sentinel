# Luna + Selene Web Guardian — S1 training handoff (2026-10-08)

**Operational state:** Observer services intact; two-agent global shared-log learning intact; guardian **SHADOW_ONLY**, NO ban/unban. Objective is safer early detection of web probing, auth abuse, coordinated subnet scans, DDoS hypotheses, and CVE exposure. Not production-enforcement-ready.

## Owner's revised resource budget
50MiB was only a pilot. Owner approves more memory (hundreds of MB, but not unchecked multi-GB). Live ARM audit: 23GB free disk / 17GB available RAM; Luna DB ~366MB, Selene DB ~363MB and both previously LIMIT_REACHED. Executed `expand_owner_approved_capacity.py`, version `2026-10-08.owner-approved.guardian-v2`; each DB cap **1 GiB**, observations **3.5 million**, pattern memory **2000**, knowledge top-level **64MiB**, history **250k**, warning **85%**; cognition hard ceiling **128MiB**. Both `sentinel_budget` HEALTHY; both `sentinel_guard` PASS; no evidence removed/modified. Config backups and approval reports in `governance/owner-approved-capacity-2026-10-08/`. Near cap, add retention/immutable archive rather than raising limits without review.

## Fixed assignment, no log splitting
- Luna: priority and eventual *only* enforce scope `thaiduy.digital`.
- Selene: priority and eventual *only* enforce scope `light-remote.thaiduy.digital`.
- BOTH keep reading all 26 current observed hosts, sharing cross-host pattern intelligence and existing Telegram workflow. Site isolation is only applied to candidate decisions and future enforcement, never at log ingestion.
- Config: `owner_assignments.json`. Both production agents remain `OBSERVE_ONLY`, guardian is `SHADOW_ONLY`.

## Actual S1 training, teaching & verification
- Separate course files per agent: `micro-sentinel/knowledge/lessons/guardian/web_guardian_s1_2026-10-08.json` and `micro-sentinel-b/knowledge/lessons/guardian/web_guardian_s1_2026-10-08.json`. Six modules: (1) HTTP authorization/API (2) trustworthy source IP/CDN/NetBird/IPv6 (3) recon vs confirmed exploit/CVE (4) distributed scans (5) DDoS/availability impact (6) bounded scoped enforcement/recovery. Selene trained with benign device-channel polling, OAuth, login, billing/webhook and remote-session reconnect examples; Luna with low-volume public website/crawler/deployment change counterexamples. Lessons are **curated knowledge/rules**, NOT neural-weight fine tuning.
- Executable knowledge reasoning: `guardian_reasoner.py`, lesson-backed offline/shadow. Unseen scenario suite: **28/28 PASS** (`test_guardian_reasoner_s1.py`); tests are simulated, NOT production accuracy.
- `shadow_review.py` runs shared all-host read-only SQLite input with per-assigned-host decision-time evidence and attaches `guardian_s1_training_shadow`; cross-site context never votes toward an unrelated site ban. Existing assignment tests **7/7 PASS** (`test_shadow_review.py`).
- `guardian_temporal_shadow.py` analyzes 5-minute host RPM and HTTP 5xx vs preceding 60 minutes, recognizes elevated rate **with** error impact as candidate requiring upstream latency/resources. Separates legitimate crowd, app 5xx without flood, network scan, IPv6 /64 vs mistaken /24. Distributed subnet grouping is **analytics only**; never ban subnet. Synthetic **6/6 PASS** (`test_guardian_temporal_s1.py`).
- CISA KEV official JSON downloaded once using `cve_kev_curator.py --refresh`, local `state/cisa_kev_catalog.json` (1,734 entries, catalogVersion `2026.10.04`) and sha256 metadata. Offline inventory matching regression **4/4 PASS** (`test_cve_kev_s1.py`). **No verified local software inventory/affected version yet**; neither website declared vulnerable. CISA KEV is known exploited in the wild, NOT local exploitation proof. Refresh manually; no automatic feed updater.
- Real shadow proof: 60-minute input ~9,230 log observations, 11 global hosts, 0 qualified on-site action proposals and 0 bans; ~0.52s analysis. Temporal pass ~0.31s, no current alerts. These limited windows cannot establish reliable low false-positive rate.

## Guardian shadow is already scheduled (new *user* systemd only)
- `sentinel-guardian-shadow.timer` **active/enabled**, triggers every ~2 minutes; ubuntu `Linger=yes`.
- User unit paths: `/home/ubuntu/.config/systemd/user/sentinel-guardian-shadow.service` and `.timer`; canonical sources in `sentinel-site-guardian/systemd/`.
- Host `/etc/systemd/system` was read-only via remote session, so use user systemd instead. Initial user unit failed `216/GROUP` due to User/Group lines; removed them, successfully tested; latest `Result=success`, `ExecMainStatus=0`.
- Sandbox: CPUQuota=25%, MemoryMax=256M, NoNewPrivileges, PrivateNetwork, ProtectSystem=strict, ProtectHome=read-only, only writable guardian reports, restrict address families=AF_UNIX, empty Linux capability set. No root shell, iptables, nftables or fail2ban access.
- `run_shadow_cycle.py` writes `reports/latest.json`, `reports/temporal_shadow_latest.json`, `reports/cycle_status.json`, append-only `reports/training_progress.jsonl`. Existing original minute timers, Telegram and Fail2ban unchanged.

User-timer status commands (ARM):
```bash
export XDG_RUNTIME_DIR=/run/user/1001
export DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1001/bus
systemctl --user list-timers sentinel-guardian-shadow.timer
systemctl --user status sentinel-guardian-shadow.service
journalctl --user -u sentinel-guardian-shadow.service -n 20 --no-pager
cat /home/ubuntu/services/sentinel-site-guardian/reports/cycle_status.json
```

## HARD P0 blockers to live assignment
1. Verify `source=IP` against NetBird Proxy/CDN trusted ingress, source-IP at actual denial point, forbid header spoofing and proxy/CDN/NetBird/owner addresses.
2. **Existing Fail2ban web actions globally drop source on DOCKER-USER 80/443, recidive all ports indefinitely.** Neither agent may directly call global `fail2ban-client set ... banip`: it can affect other hostnames on the same ingress. Find hostname-aware NetBird Proxy/edge action or dedicated ingress, build isolated minimal policy broker (site/IP/action/TTL/idempotency/allowlist/rollback/kill switch) after owner approval, with test proving peer site unaffected.
3. Add independent service impact telemetry (p95 latency, upstream CPU/connections/errors and partial-day/time-of-week baseline) to distinguish early DDoS from normal surge or upstream bug. Until then, label pressure as unconfirmed.
4. Obtain owner-verified SBOM/site component versions, vendor advisories and affected-range validation before promoting CVE exposure; CISA KEV cannot detect site vulnerability on its own.
5. Multi-day independently labelled shadow false-positive/false-negative review and controlled staging ban/unban tests, Telegram delivery acknowledgment and audit/rollback, then explicit owner permission for narrowly scoped live blocks.

Useful official sources embedded in curriculum: https://top10.owasp.org/ (Top 10:2025), https://api-security.owasp.org/editions/2023/en/0x11-t10/ , https://www.cisa.gov/known-exploited-vulnerabilities-catalog , https://developers.cloudflare.com/support/troubleshooting/restoring-visitor-ips/restoring-original-visitor-ips/ .

**Do not equate 28/28 synthetic test cases with a graduated autonomous security agent.** Preserve existing data, authority separation and the user-approved growth budget.
