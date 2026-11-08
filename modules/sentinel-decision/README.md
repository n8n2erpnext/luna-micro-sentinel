# Light Sentinel — autonomous decision shadow (source snapshot)

Luna covers thaiduy.digital and Selene covers light-remote.thaiduy.digital.
The agents may issue documented BAN_RECOMMENDED / WAIT_MORE_EVIDENCE / NO_ACTION / INCIDENT_REVIEW_RECOMMENDED decisions, but DO NOT have enforcement rights.

This repository is a source-only snapshot of selected deployed services on VPS-ARM 2026-10-13, not a standalone, self-installing package and not itself proof of deploy. It intentionally omits production state, raw logs, SQLite memories, secrets, and owner-specific service assignments.

Runtime paths: /home/ubuntu/services/sentinel-site-guardian, /home/ubuntu/services/sentinel-threat-intel, /home/ubuntu/services/sentinel-guardian-reports. The existing micro-sentinel and micro-sentinel-b software supplies observations.

Tests (on deployment tree):
- python3 -m unittest test_decision_engine.py test_learning_loop.py (site-guardian)
- python3 -m unittest test_decision_notifications.py (guardian-reports)

User systemd timer is enabled under ~/.config/systemd/user/sentinel-guardian-shadow.timer; it is intentionally read-only except Guardian state and report folders. This repo does not authorize real bans, privileged access, or unreviewed install.

GitHub remote has not been selected. Do not push into unrelated Light Remote or LightBI repositories.
