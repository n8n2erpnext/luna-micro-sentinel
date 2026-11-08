# Sentinel Evidence & Autonomy P1 Handoff — 2026-10-13 evening (VN)

## Context / absolute guardrails
Luna = thaiduy.digital, Selene = light-remote.thaiduy.digital. Continue decision-first shadow autonomy, NOT raw-log reporting. User allows both to choose BAN_RECOMMENDED, WAIT_MORE_EVIDENCE, INCIDENT_REVIEW_RECOMMENDED, NO_ACTION, INSUFFICIENT_TELEMETRY and to request evidence autonomously, but forbids granting or connecting ANY real-ban authority. Invariants: owner_assignments.json enforcement_enabled=false, backend=null, live_bans=0. No edits to Fail2Ban/CrowdSec/firewall, no real ban, no bulk blacklisting, no automatic patch. Protect existing rc50 Light Remote production.

## Verified state 18:58-19:18 Oct 13 2026
- Reconnected Light Remote official plugin to VPS-ARM. Five existing USER systemd service last results were SUCCESS: Luna, Selene, Guardian Shadow, Guardian Reports, Threat Intel. User timers: Luna/Selene each minute; Guardian and Reports each two minutes; Threat Intel ~15m. New deployed-component evidence timer daily 09:20 Asia/Ho_Chi_Minh.
- No real bans. Current NO_ACTION on both within site telemetry window, does not certify absolute safety.
- Previous baseline repo /home/ubuntu/n8n2erpnext/light-sentinel-decision (local Git only, main, previous e789509).
- Previous 21/21 regression tests PASS. New tests added for temporal duration and cached software inventory, run regression before next release.

## P1 change: better BAN_RECOMMENDED evidentiary threshold
- /home/ubuntu/services/sentinel-site-guardian/shadow_review.py now computes distinct fixed 10-min buckets + actual elapsed span from suspicious event timestamps. These are genuinely non-overlapping time buckets; adjacent 2-minute Guardian cycles are NOT independent observations.
- decision_engine.py requires: suspicious hits>=8, suspicious distinct paths>=6, deny/missing>=5, heuristic signal types>=2, suspicious distinct 10-min buckets>=2 AND observed span>=600sec to elevate BAN_RECOMMENDED. A single busy burst -> WAIT_MORE_EVIDENCE. This is STILL a candidate and IP origin is still unverified for real ban.
- tests: added one-burst and two-bucket-short-span regressions to test_decision_engine.py. Guardian actual run PASS, zero bans.
- All recommendations include the time persistence evidence and the missing original-IP proof; a large number of requests alone is not a campaign.

## P1: ingress IP provenance
- Live Docker proxy metadata: netbird-proxy image netbirdio/reverse-proxy:latest; NB_PROXY_TRUSTED_PROXIES=0.0.0.0; NB_PROXY_PROXY_PROTOCOL=true; Traefik dynamic.yaml has tcp.serversTransports.pp-v2.proxyProtocol.version=2. No secrets copied.
- Performed two **benign** requests to owned thaiduy.digital using unique /sentinel-origin-test-... paths: baseline and spoofed X-Forwarded-For=198.51.100.77 + X-Real-IP=198.51.100.78. Both HTTP 404. Proxy response access.log shows SAME source IP for baseline/spoof; neither spoofed IP was accepted as source. This is **one limited negative header spoof test**, not cryptographic origin proof nor proof for every ingress path.
- Keep origin_ip_verified and trusted ingress proof gate FALSE. Next: compare trusted external client public IP/real ingress socket with proxy event source; audit proxy chain+Traefik trusted proxies, NetBird Access Logs; test from a separate network with owner-approved benign probe. Do not ban from current logs.
- NetBird references (public): https://docs.netbird.io/manage/reverse-proxy/service-configuration and https://pkg.go.dev/github.com/netbirdio/netbird/proxy/internal/accesslog.

## P1: true software evidence vs CVE headline
- Existing guardian-reports/state/software_inventory_latest.json was only 5 selected host packages, 4 LXD package samples and Docker image references; exact route still NOT_AUDITED.
- Read-only live scan via allowed owner session: LXD light-remote-direct Ubuntu 24.04.5 and 595 dpkg packages; Docker thaiduy-digital Node v22.23.3, npm 10.9.9.
- Added /home/ubuntu/services/sentinel-guardian-reports/deployed_component_evidence.py. Captures bounded complete selected LXD installed dpkg list with SHA-256 and Docker app Node/npm versions, writes protected mode-600 sidecar to state/deployed_component_evidence_latest.json. NEVER reads env/secrets, never installs, never claims CVE exposure/compromise. Route mapping candidate only.
- Hardened user systemd service under ~/.config/systemd/user/sentinel-deployed-component-evidence.service (NoNewPrivileges, PrivateNetwork, ProtectSystem=strict, ProtectHome=read-only, only ReadWritePaths=guardian-reports/state, AF_UNIX, no capabilities); running inside it cannot access LXD guest dpkg ('EXIT_1'), but Docker Node runtime is readable. This is NOT a reason to relax isolation.
- Refined collector: if current LXD is unavailable, copy last-good LXD inventory but use source_status=CACHED_UNVERIFIED_NOW and PRESERVE its original per-site collected_utc, never mark it fresh. If Docker runtime fails, don't overwrite previous snapshot. Script within sandbox now Result=success / ExecMainStatus=0 with partial label, not false complete.
- Added systemd user timer ~/.config/systemd/user/sentinel-deployed-component-evidence.timer enabled at 09:20 daily, verified NEXT Wed 2026-10-14 09:20:00 +07.
- learning_loop.py reads the sidecar with 26h max age and *per-site* source_status/captured timestamp. Luna progress: node v22.23.3, component_evidence_fresh=true. Selene: last_known_guest_package_count=595, guest_package_count=0 for current verified evidence, component_source_status=CACHED_UNVERIFIED_NOW, component_evidence_fresh=false. BOTH still route_proven=false, app SBOM incomplete, vendor affected ranges unchecked and vulnerability_exposure_status=UNKNOWN.
- NVD recent feed in prior check 740/740 in 24h, complete; that does not identify installed vulnerable components. Threat Intel CISA Advisories previously fixed. Future: vendor affected-range/USN backport matching, build app lockfile/npm dependencies BOM, route proof, CVE-to-service *documented evidence*; never claim exploitability from NVD alone.
- Tests: test_learning_loop.py added cases for direct component evidence, evidence expiration and CACHED_UNVERIFIED_NOW. Review test outputs before declaring accepted.

## Other boundaries and outstanding tasks
- Do not overstate that the two agents have learned weights; they are deterministic evidence-backed classification and guarded curriculum.
- Labelled benign/malicious replay benchmark and measured precision/recall not yet available. Upstream CPU/connection resource metrics are still missing; 8-second Light Remote long-poll is normal and NOT evidence of DDoS.
- Full route mapping from NetBird management service to Docker/LXD not proven. Hidden configuration/secrets must not be committed.
- Continued performance benefit from previous indexed 2.12 million event SQLite per agent, read ~0.2ms vs 277ms baseline for 100 recent events, no archive purge, original 600MB snapshots retained.

## Repo and tests
- Source-only Git: /home/ubuntu/n8n2erpnext/light-sentinel-decision (LOCAL only; no GitHub remote chosen). Must sync live modifications to /site-guardian/shadow_review.py, decision_engine.py, test_decision_engine.py, learning_loop.py, test_learning_loop.py and new /guardian-reports/deployed_component_evidence.py + both user systemd templates. Keep runtime .json, .db, .env and any raw sensitive request logs OUT of Git.
- Backup files for current decision edits reside near live scripts as .pre-temporal-20261013; earlier pre-decision file backups kept intact.
- Test commands:
  cd /home/ubuntu/services/sentinel-site-guardian && python3 -m unittest -v test_decision_engine test_learning_loop
  cd /home/ubuntu/services/sentinel-guardian-reports && python3 -m unittest -v test_decision_notifications
  XDG_RUNTIME_DIR=/run/user/1001 systemctl --user show sentinel-guardian-shadow.service sentinel-deployed-component-evidence.service -p Result -p ExecMainStatus
  XDG_RUNTIME_DIR=/run/user/1001 systemctl --user list-timers --all
- Supersedes earlier handoff /home/ubuntu/handoffs/SENTINEL_AUTONOMOUS_DECISION_OPS_HANDOFF_2026-10-13.md with additional evening fixes. Continue by checking that Guardian daily source snapshots match committed source, not pushing into unrelated repo.
