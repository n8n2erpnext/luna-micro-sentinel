# Luna / Selene — Shared Observability, Scoped Guardian Prototype

Status (2026-10-08): **S0 COMPLETE, S1 SHADOW PROTOTYPE PASS, NO LIVE ENFORCEMENT**.

## Canonical owner assignment

| Agent | Priority website | Evidence visibility | Live ban permission |
|---|---|---|---|
| Luna | thaiduy.digital | ALL shared NetBird Proxy logs | NONE |
| Selene | light-remote.thaiduy.digital | ALL shared NetBird Proxy logs | NONE |

`owner_assignments.json` is the explicit assignment manifest. Nothing modifies `micro-sentinel/`, `micro-sentinel-b/`, existing Fail2ban jail, the global proxy log source, or their Telegram workflows. Agent runtime still reads and learns from the full environment as before.

## Safe shadow probe

`python3 /home/ubuntu/services/sentinel-site-guardian/test_shadow_review.py`:
- Tests assigned-host isolation without hiding other hosts;
- Cross-host signals stay context only; they cannot raise host-local action thresholds;
- Different IPv6 addresses are not merged by unsafe /24 grouping;
- Exact hostname equality, malformed IP rejection, false-positive guard on isolated route;
- Reports only `HUMAN_REVIEW_CANDIDATE_NOT_PROOF_OF_ATTACK`, always `SHADOW_ONLY_NO_BAN`;
- No live mutation, subprocess, shell, network requests, firewall access, or Fail2ban client.

`python3 /home/ubuntu/services/sentinel-site-guardian/shadow_review.py --window-minutes 60 --out /home/ubuntu/services/sentinel-site-guardian/reports/latest.json`:
- Reads existing agent SQLite ledgers via SQLite mode=ro;
- Reads ALL recent host evidence; filters to exact assigned hostname *only for decision-time heuristics*;
- Requires multiple distinct suspicious route events and corroborating status/type;
- Retains count of other hosts where source IP appears as non-voting campaign context;
- Explicitly records that IP origin trust and enforcement layer are not verified;
- Writes protected local report file, no live enforcement or new Telegram actions.

Initial 2026-10-08 60m report `reports/2026-10-08-initial.json`: 9,042 global events and 10 distinct hosts visible in each agent's ledger; Luna assigned-site 4 source addresses, Selene assigned-site 25; 0 preliminary human-review candidates for both. This does not establish detection precision/recall; the 60m sample is insufficient to authorize action.

Existing automatic Fail2ban jails are independent of this prototype and remain unchanged.

## Blocking issues before real enforcement

1. NetBird Proxy `source=IP` trust chain and edge IP accountability: verify the actual origin, header provenance and enforcement layer for each site; prohibit banning proxy or shared-service addresses.
2. Existing Fail2ban `DOCKER-USER` drops source IP on ports 80/443 *across shared sites*. The existing `recidive` jail can ban all ports indefinitely. These actions are UNFIT for dedicated per-site authority on shared ingress.
3. Need hostname-aware enforcement (verified reverse-proxy/site-specific edge rule) or dedicated destination IP/port. Fail2ban can be an evidence trigger or dispatcher through a **custom scoped action**, but no unverified direct `banip` to a global jail.
4. Build minimal independent, root-owned policy broker with allowlist, identity + intended site, feature-specific rule, TTL, dedupe, limits, protected owner/VPN/CDN IPs, audit and immediate rollback. Agents propose, broker judges and executes.
5. Keep global anomaly reports and Telegram; add reliable notification confirmation/retries for new enforcement decisions.
6. Per-site benign/hostile traffic evaluation, longitudinal shadow simulation including Light Remote legitimate device-channel poll/stream, login, billing/webhooks, CDN and service probes; acceptance requires no critical false positives and proven site separation.
7. Enable action only by a separate owner approval after proof, starting owner-confirmed short time-limited blocks, then narrow automation.

**No automatic bans are possible through this prototype.** No system timer has been installed for this new evaluator; existing two sentinel timers remain unchanged. To collect longitudinal shadow metrics, install a separate unprivileged read-only service/timer once the owner has reviewed the prototype and its resource use.
