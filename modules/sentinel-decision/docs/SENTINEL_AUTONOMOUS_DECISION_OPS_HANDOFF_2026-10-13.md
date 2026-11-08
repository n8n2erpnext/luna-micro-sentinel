# LIGHT SENTINEL — autonomous site decisions, guarded learning & operations (2026-10-13)

## Owner contract
Luna owns `thaiduy.digital`; Selene owns `light-remote.thaiduy.digital`. Both share global sensor traffic for context, but only their assigned hostname contributes to decisions. They must form their own evidence-backed BAN_RECOMMENDED / WAIT_MORE_EVIDENCE / INCIDENT_REVIEW_RECOMMENDED / NO_ACTION / INSUFFICIENT_TELEMETRY judgements, rather than asking the owner to interpret log dumps. No real ban or firewall enforcement has been authorized or connected. Keep CrowdSec, Fail2Ban and firewall untouched; all "ban" means advisory ONLY. Production Light Remote rc.50 is separate; do not change it.

## Running service paths (deployment on VPS-ARM)
- Guardian: `/home/ubuntu/services/sentinel-site-guardian/`
- Intel: `/home/ubuntu/services/sentinel-threat-intel/`
- Owner-facing decision report & outbox: `/home/ubuntu/services/sentinel-guardian-reports/`
- Observation engines: `/home/ubuntu/services/micro-sentinel/` (Luna), `micro-sentinel-b/` (Selene)
- Actual installed user-unit: `/home/ubuntu/.config/systemd/user/sentinel-guardian-shadow.service` and timer. IMPORTANT: user-systemd, NOT host systemd. Found pre-existing enabled user timer from `~/.config/systemd/user/timers.target.wants/`. Old handoff's claim timer is uninstalled was WRONG and superseded here.
- Live unit update: `ReadWritePaths=` specifically Guardian reports + Guardian state; `ProtectHome=read-only`, `PrivateNetwork=true`, `NoNewPrivileges`, no capabilities, `RestrictAddressFamilies=AF_UNIX`. The unit was backed up at `~/.config/systemd/user/sentinel-guardian-shadow.service.pre-decisions-20261013`.
- Light Remote shell environment lacks `XDG_RUNTIME_DIR`; the legitimate already-running user bus is `/run/user/1001/bus`. User-unit reload/smoke PASS with `XDG_RUNTIME_DIR=/run/user/1001 systemctl --user daemon-reload` and `... systemctl --user start sentinel-guardian-shadow.service`. Do NOT use root/system units or modify /etc; no need to bypass filesystem restrictions.
- Other actual user systemd timers: micro-sentinel every 1m; Guardian shadow every 2m, Guardian reports every 2m, Threat intel ~15m; guardian assets daily. All 5 associated service units last returned Result=success, ExecMainStatus=0 at 11:05 VN on 2026-10-13. Verified Guardian reports refreshed ~11:04, no journal errors after 11:00.

## Decisions and notifications
- `site-guardian/decision_engine.py` creates hard site-scoped evidence-bound verdicts with evidence, missing tests, next-check interval, owner/operator constraints. Guard fails CLOSED when site telemetry missing, proxy window incomplete, Guardian findings truncated, or input stale. NEVER claims safety from absent observations.
- `run_shadow_cycle.py` drives `shadow_review.py`, `guardian_temporal_shadow.py`, decision and `learning_loop.py` under bounded exclusive flock, writes latest + decision history + learning progress; zero bans.
- Site `Luna` observed WAIT_MORE_EVIDENCE against a possible sensitive recon source and later NO_ACTION as suspicious traffic aged out of 60-minute window. Selene NO_ACTION. NO_ACTION is limited to available window and does not prove safety.
- `decision_engine.persist` journals transitions with monotonically increasing per-agent sequence/token, rationale, concise evidence, uncertainty; replay of same threat after remission gets a new transition token.
- `guardian-reports/reporter.py` uses `decision_history.jsonl` as durable notification source. It sends concerning decisions and telemetry degradation, and sends NO_ACTION notice ONLY as resolution after earlier concerning verdict. 24h catch-up and unique transition token prevent repeated spamming. It never calls an enforcement backend.
- `reporter.py preview-daily` now leads with verdict, evidence, missing signals and reassessment suggestion, rather than raw metrics. n8n Telegram outbox uses claim+ack; at a prior checkpoint pending 0, delivered 9, exhausted 0. Verify real Telegram delivery before stronger claims.
- Tests: site decision engine 11/11 PASS; guarded learning loop 4/4 PASS; notification journal 6/6 PASS = 21/21 tests. Synthetic unit tests are NOT real-world precision/recall evidence.

## Threat intelligence coverage
- CISA Advisories previously failed `Oversized feed` with a 900kB cap. `threat-intel/intake.py` raised that bounded cap to 4MB; manual test PASS and feed 10/10 fresh.
- NVD 24h previously only requested `resultsPerPage=500`; saw 500/689 entries, incomplete. Now requests 2000 with bounded 9MB fetch. Manual NVD test on 2026-10-13 returned 728/728 for the latest 24h and `coverage_complete=true` (count can change over time). It must still report incomplete if source >2k/size cap; this is NOT exhaustive historic coverage.
- `learning_loop.py` now requires NVD count=total and both NVD/CISA freshness before marking threat feed understanding READY_FOR_INDEPENDENT_EVALUATION. This does NOT prove any installed runtime vulnerable.
- Still missing exact app/dependency SBOM, LXD package inventories, verified route mapping/backported fixes, vendor affected-version matching and calibration against true CVE case studies. Keep unknown as unknown.

## Operational optimizations
- Each agent SQLite had ~2.12 million `observations`; only unique ID index. `WHERE ts>=? ORDER BY ts DESC` did SCAN observations + USE TEMP B-TREE. Benchmark initial sample latest 100 rows ~277ms on both.
- Added `idx_observations_ts_desc` using `migrate_observation_time_index.py` under Guardian source (explicit --backup then --apply per agent). Backups via SQLite online backup, validated quick_check and SHA256:
  - `/home/ubuntu/backups/sentinel-index-pre-2026-10-13/luna-preindex.sqlite3`, 606191616 bytes, SHA256 `ab73e5972550bec576348484e34a8f1c8a37b9da762c79cf961f0f54ea73f19`
  - `/home/ubuntu/backups/sentinel-index-pre-2026-10-13/selene-preindex.sqlite3`, 603013120 bytes, SHA256 `6271d7bd25854719d7827688c24fb54aaafb436e117408c390b0900ed236ed8d`
  - Corresponding per-agent manifest JSON at the same backup directory. Keep backups until long-term acceptance, no deletion.
- Both index migrations PASS; EXPLAIN now `SEARCH observations USING INDEX idx_observations_ts_desc`; median 7 reads of latest100 rows ~0.199/0.204ms (warm-cache, not end-to-end). `PRAGMA quick_check(1)` ok for BOTH live databases. DB size grew ~68MB/agent as expected (currently ~646 and 643 MiB); budget is 1GiB/agent. Monitor storage and ingestion write overhead.
- Existing memory history and observation data left intact (no truncation, no VACUUM, no forced purge).

## Version control
- NEW local source-only git checkout: `/home/ubuntu/n8n2erpnext/light-sentinel-decision`
- Branch `main`, commit `9b1489d` (Snapshot Sentinel autonomous shadow decisions, guarded learning and tests), 23 tracked files, clean checkout as of snapshot.
- This is NOT a production deploy/rebuild system. Runtime remains in `/home/ubuntu/services/...`. No GitHub remote; GitHub search for `sentinel` scoped to `n8n2erpnext` returned no matching repo. DO NOT push this code to an unrelated Light Remote or LightBI repository. Ask owner whether to publish to a new private `n8n2erpnext/light-sentinel-decision` or an owner-chosen existing repo; keep secrets, state, raw IP history, and DB out of Git.
- Source snapshot contains core scripts/templates, tests, documentation, not production secrets. Future changes require deliberate source-of-truth/packaging workflow to avoid deployed-vs-checkout drift.

## Current capability gaps
1. Original visitor-IP identity at trusted ingress, independent of spoofable request headers.
2. Complete per-site SBOM, vendor affected versions, runtime patch/backport matching before CVE exposure verdict.
3. Independent upstream CPU/connections/p95/5xx signals for DDoS; distinguish healthy Light Remote long-poll.
4. Owner-labelled positive and benign replay corpus + false-positive precision/recall and cross-day drift tests, so ban recommendations are calibrated rather than heuristics alone.
5. Persistence/reliability and message delivery observation under failures, and hard budget alerts (DBs above 60% of 1GiB cap).
6. Hard security invariant: NO real-ban executor, no hostname-wide firewall writes, no CIDR bans. Even after new knowledge gates, permissions remain unchanged.
7. Read existing sender/authoritative decision feeds to ensure downstream Telegram/Discord follows *decisions*, not duplicate legacy raw alerts; no report-only fallback silently hiding degraded feed.

## Next steps
- Run `XDG_RUNTIME_DIR=/run/user/1001 systemctl --user list-timers --all`; check last user-unit ExecMainStatus 0 after multiple cycles.
- Check decision ledger `reports/decisions_latest.json`, transition history, learning agenda, `guardian-reports/reporter.py stats`. No repeated alert in unchanged state.
- Observe DB growth + disk free; snapshots occupy ~1.2GB, 28GB disk available as of 11:05.
- Implement verifiable per-site SBOM and trusted real source identity; add specifically labelled replay cases before trusting short-ban recommendations.
- Do not claim full autonomous security protection, trained AI weights, valid CVE exposure, or real bans from this milestone.

## Prior handoff
`/home/ubuntu/handoffs/SENTINEL_AUTONOMOUS_DECISION_HANDOFF_2026-10-13.md` is historical; this new handoff supersedes its old user timer blocker.

## Read-only test commands
`python3 -m unittest -v test_decision_engine.py test_learning_loop.py` inside Guardian folder;
`python3 -m unittest -v test_decision_notifications.py` inside Guardian Reports folder.
No tests touch production enforcement.
