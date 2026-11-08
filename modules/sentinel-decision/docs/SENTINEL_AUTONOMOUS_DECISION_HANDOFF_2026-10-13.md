# LIGHT SENTINEL — Decision-first Shadow Guardian Handoff
Date: 2026-10-13 (VN time). Scope: VPS-ARM /home/ubuntu/services.
Owner intent: Luna (thaiduy.digital) and Selene (light-remote.thaiduy.digital) independently decide whether suspicious activity warrants BAN_RECOMMENDED, WAIT_MORE_EVIDENCE, INCIDENT_REVIEW_RECOMMENDED, NO_ACTION, or INSUFFICIENT_TELEMETRY. They must report decisions with evidence and further requirements, NEVER execute an IP/subnet ban until explicit separate authorization + technically proven site scope. Do not modify CrowdSec, Fail2Ban, firewall, or production Light Remote release.

## Current checkpoint — genuine results
- New /home/ubuntu/services/sentinel-site-guardian/decision_engine.py: site-scoped decision judgments, stateful transitions, evidence, missing proof, no execution backend; decision history max 2MB; output reports/decisions_latest.json. Unit suite test_decision_engine.py: 8/8 PASS at 2026-10-13 ~10:50 VN, including circular-JSON regression, cross-host evidence isolation and ban-is-recommendation-only.
- New /home/ubuntu/services/sentinel-site-guardian/learning_loop.py: per-agent evidence-gap curriculum, measures missing source-IP provenance, CVE-to-asset mapping, independent availability telemetry, false positives, temporal corroboration, feed reliability. Report reports/learning_agenda_latest.json, state/learning_progress.json; no automatic mastery or authority promotion. This is deterministic curriculum and review, NOT an LLM being autonomously retrained from the Internet.
- Updated /home/ubuntu/services/sentinel-site-guardian/run_shadow_cycle.py: sequential shadow_review + guardian_temporal_shadow + decision_engine + learning_loop; bounded decision history; flock single writer. Integrated real run at 2026-10-13 10:43 VN PASS. Luna WAIT_MORE_EVIDENCE for source 35.215.194.3 (4 suspect requests/4 paths/4 denied); Selene NO_ACTION. Zero bans, zero rights to enforce. live report cycle_status.json mode AUTONOMOUS_DECISIONS_SHADOW_EXECUTION.
- Updated /home/ubuntu/services/sentinel-guardian-reports/reporter.py: daily reports lead with decisions, rationale, evidence and missing conditions; urgent outbox can deliver a decision on transition. The legacy raw metric-only alerts are cleared before dispatch. Executed reporter.py propose gave new_alerts=1, automatic_bans=0; subsequent reporter.py stats reported pending={} delivered=9 retry_exhausted=0: an n8n outbox delivery/ack occurred (do not assume Telegram visible without independent confirmation).
- Updated /home/ubuntu/services/sentinel-threat-intel/intake.py: bounded CISA Advisory RSS feed cap increased from 900,000 to 4,000,000 bytes. Manual test intake.py --test-source cisa_advisories returned OK / fresh_sources=10/10 / ban_commands=0. This is source freshness, NOT local software CVE validation.
- Updated /home/ubuntu/services/sentinel-site-guardian/systemd/sentinel-guardian-shadow.service template: ReadWritePaths includes reports + state, required for decision state/learning history/lock. NOT installed in /etc.
- Original /home/ubuntu/services/sentinel-guardian-reports/run_monitor.py was RESTORED exactly after an unsuccessful integration experiment: when monitor ran guardian as a child, Guardian reports mount was read-only and decision_cycle=DEGRADED. NEVER loosen monitor/n8n sandbox to force it.
- Other existing systems and both micro-sentinel 1-minute timers untouched; existing micro sentinels continue OBSERVE_ONLY. Knowledge ladder still Luna level10, Selene level9; do not claim training gate advancement.

## BLOCKER — actual unattended 2-minute decision schedule NOT ACTIVE
Service/timer templates:
 /home/ubuntu/services/sentinel-site-guardian/systemd/sentinel-guardian-shadow.service
 /home/ubuntu/services/sentinel-site-guardian/systemd/sentinel-guardian-shadow.timer
The current Light Remote workspace permits editing user-owned service files but refused sudo install to /etc/systemd/system with EROFS (read-only filesystem). No bypass through PTY, alternate connector, or privilege workarounds. The existing 1-minute micro-sentinel timers run, but Guardian Shadow timer not installed. Latest real decision is an on-demand pass; dynamic re-evaluation cannot be promised 24/7 until an authorized administrator installs the systemd timer outside this read-only boundary. Do not duplicate it with an existing scheduler; first verify who else invokes run_shadow_cycle.py.

For authorized local administrator review (NOT executed in this session):
  sudo install -m 0644 /home/ubuntu/services/sentinel-site-guardian/systemd/sentinel-guardian-shadow.service /etc/systemd/system/
  sudo install -m 0644 /home/ubuntu/services/sentinel-site-guardian/systemd/sentinel-guardian-shadow.timer /etc/systemd/system/
  sudo systemctl daemon-reload
  sudo systemctl enable --now sentinel-guardian-shadow.timer
  sudo systemctl status sentinel-guardian-shadow.timer
  sudo journalctl -u sentinel-guardian-shadow.service -n 60 --no-pager
Validate twice at 2m cadence and verify reports/decisions_latest.json, reports/learning_agenda_latest.json, reports/cycle_status.json update. Unit sandbox has ProtectHome read-only, ReadWritePaths limited to Guardian reports+state, PrivateNetwork true, and no elevated capabilities. Timer is not a firewall command.

## Needed for genuine security autonomy BEFORE ever enabling ban backend
- Trusted original source-IP chain across the ingress proxy, Cloudflare/NetBird and enforcement boundary. Never treat arbitrary X-Forwarded-For or bridge IP as true client.
- Verified website route mapping and complete SBOM / locked runtime dependencies, vendor affected range/backport mapping for new CVE. Local exposure/compromise are unknown, and NVD top 500 is not exhaustive proof.
- Independent upstream latency/CPU/connection/error metrics; differentiate Light Remote device long polls from application saturation.
- Owner-labeled site-specific replay corpus and precision/recall measurements. No confidence calibration verified.
- Timed decision/transition tests, outbox delivery/ack observation, controlled false positive tests, retention/DB-capacity alerting. Agent DBs ~576MB/573MB, caps set to 1GiB; don't purge without verified archive/retention plan.
- A separately scoped, auditable and reversible site-deny executor with owner approval, rollback and safe lists. OUT OF SCOPE, no such authorization now.

## Original file backups
  /home/ubuntu/services/sentinel-site-guardian/run_shadow_cycle.py.pre-decisions-20261013
  /home/ubuntu/services/sentinel-threat-intel/intake.py.pre-decisions-20261013
  /home/ubuntu/services/sentinel-guardian-reports/reporter.py.pre-decisions-20261013
  /home/ubuntu/services/sentinel-guardian-reports/run_monitor.py.pre-decisions-20261013

## Source-control caveat
These /home/ubuntu/services/sentinel-* directories are not Git worktrees. Neither /home/ubuntu/n8n2erpnext root nor the search within 3 levels exposed an obvious Sentinel repository. Code has been edited in its canonical deployed service path and backed up, but NOT committed or pushed to Git. Future work: identify/create an explicitly owner-approved version-control repository, commit decision logic + tests + templates, exclude state/db/secrets. Avoid pushing these changes to unrelated Light Remote branches.

## Validation commands (only after authorized execution environment is available)
  python3 -m unittest -v /home/ubuntu/services/sentinel-site-guardian/test_decision_engine.py
  python3 /home/ubuntu/services/sentinel-site-guardian/run_shadow_cycle.py
  python3 /home/ubuntu/services/sentinel-guardian-reports/reporter.py preview-daily
  python3 /home/ubuntu/services/sentinel-guardian-reports/reporter.py stats
  python3 /home/ubuntu/services/sentinel-threat-intel/intake.py --test-source cisa_advisories
Do NOT use tools or techniques to circumvent a denied execution or filesystem policy; ask owner to change authorized environment/policy explicitly.

## Incident/lesson semantics
When suspicious evidence is moderate, Luna decides WAIT_MORE_EVIDENCE, asks for trusted ingress attribution/benign scanners/recurrence, not an owner decision. High corroborated site-specific sensitive recon can produce BAN_RECOMMENDED but never calls a ban action. NO_ACTION is scoped to available telemetry window, not proof of safety. INS UFFICIENT telemetry is a separate fail-closed outcome. Learning queue marks evidence gaps and required independent tests, not self-granted mastery.

Owner-facing first observed decisions: Luna WAIT_MORE_EVIDENCE, Selene NO_ACTION; 8/8 synthetic tests PASS; 10/10 threat sources fresh as tested; no actual bans.
