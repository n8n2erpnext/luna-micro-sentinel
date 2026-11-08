# Luna & Selene — Security Enforcement Readiness Audit
Date: 2026-10-08 (Asia/Ho_Chi_Minh)
Host: VPS-ARM; roots: /home/ubuntu/services/micro-sentinel and micro-sentinel-b
Status: **NOT READY FOR UNSUPERVISED WEB BANS**

## OWNER CORRECTION — 2026-10-08 (OVERRIDES LOG-ISOLATION LANGUAGE BELOW)

**Both Luna and Selene MUST continue ingesting, observing and learning from the same shared full proxy log, across every website, exactly as they do today. DO NOT split or filter the raw log stream or remove global cross-host detection.** Their *primary attention* and *real enforcement authority* are site-specific, not their observation visibility.

- **Luna:** global observation and cross-site correlation; priority protection/enforcement restricted to `thaiduy.digital`.
- **Selene:** global observation and cross-site correlation; priority protection/enforcement restricted to `light-remote.thaiduy.digital`.
- Both retain shared environmental/campaign intelligence, peer communication and current global Telegram observations; website-specific incident notification and audit should clearly identify responsible agent/site.
- Extract a site-specific evidence slice only **at decision time** for a proposed action: `owner-agent + exact canonical host + verified client IP + scoped time window + sanitized evidence`; cross-host observations can support a hypothesis but must never turn into a ban on an unassigned host or inflate host-local thresholds.
- The policy broker is the only entity allowed to execute site-scoped actions. **Do not grant existing global Fail2ban jail banip rights:** shared DOCKER-USER source-IP filtering cannot selectively deny one hostname among sites sharing a listener. Choose/validate a hostname-aware proxy/edge action or truly isolated dedicated ingress before activating real bans.
- Any wording in this file suggesting separate input log ingestion, per-agent siloed observation, or restricting learning to assigned hosts is SUPERSEDED by this contract. Preserve `OBSERVE_ONLY` until explicit rollout approval.
Scope: read-only audits, offline synthetic replay, readiness files only. **NO LIVE BAN/UNBAN EXECUTED.** Owner has assigned `thaiduy.digital` to Luna and `light-remote.thaiduy.digital` to Selene. Neither has live enforcement authorization yet.

## User objective
Assign Luna and Selene distinct live websites with real authority to take defensive action after evidence-backed probe/scan/exploit-attempt detection. Keep reporting to Telegram and use Fail2ban for ban actions where technically safe. Both agents must retain independent learning and site ownership; avoid collateral damage to other services.

## Verified existing strengths
- Two active minute-interval services: micro-sentinel(A)/micro-sentinel-b(B), both identity mode OBSERVE_ONLY.
- Structured reverse-proxy log ingestion, per-agent SQLite evidence/memory, behavioral analysis, independent-report artifacts, privacy-aware path normalization, guard and Telegram alert queues.
- Two agents passed 6/6 existing developmental tests on 2026-10-08; guard PASS, no existing rule violations. These are *observer* tests, not enforcement readiness tests.
- Existing Fail2ban service is ACTIVE with sshd, traefik-bot, netbird-env-probe, recidive jails. This is current infrastructure, not new agent-specific enforcement.
- Event stream currently includes 26 distinct Host values, i.e. not isolated to two sites.
- Agent A/B largely share the same implementation; agreement on a finding is not equivalent to independent validation by two different detection methods.

## Evidence-backed blockers (P0: do NOT enable automatic ban without fixes)

1. **Cross-site correlation without host isolation.** In `sentinel_v2.py`, detector groups requests by `src` and /24 subnet (not `host+src`), then derives broad_probe/targeted_probe. Offline synthetic case: 6 normal-looking paths on site A plus 2 probe-like paths on site B triggers `broad_probe` for the *combined* IP; neither site alone triggers that pattern. This is a scope conflation, even when both sites are public.
2. **IPv6 /24 grouping unsafe.** `subnet(ip)` always uses `ip+'/24'`, including IPv6. Two unrelated examples in distinct /32 IPv6 families collapse to the identical synthetic /24: `2001:db8:1234:abcd::1` and `2001:db8:5678::1` -> `2001:d00::/24`. Never use this aggregate for automatic blocks. Safer: normalized IPv6 full address per event, optional well-defined per-/64 analytics *only if scoped and justified*, no subnet auto-bans.
3. **Fail2ban site scope is not present.** The two web jails install `iptables-multiport` rules into shared DOCKER-USER for 80/443. `recidive` uses INPUT plus DOCKER-USER all ports and `bantime=-1`, indefinite. Firewall drops by source IP/ports, not HTTP Host. Thus a bot ban on site A can also affect B and other services. Same concern for direct calls to `fail2ban-client set JAIL banip IP` when the jail action is global.
4. **Origin/source IP authenticity not proven.** Log `source=IP` comes from a `netbird-proxy` container via `proxy-logger.service`; the agent regex extracts it. The trusted chain from external client to logger to exact firewall matching IP is not established in these tests. Validate trusted ingress hops and forwarding-header handling; only accept parsed real source after proxy-vs-CDN-vs-VPN checks. Validate the response *actually blocked* on test site and did not block peer site; avoid header spoofing and proxy addresses.
5. **No policy-enforced action gateway.** `sentinel_cycle.py` executes observer, findings, reflection, guard, peer dialogue, ladder only. Identity and guard explicitly prohibit ban/unban. There is no per-website allowlist, bounded ban proposal, site-bound isolated executor, exact TTL, action result verification, emergency kill switch or unban/appeal process.
6. **Guard is not independent enforcement validation.** Current independent report `cross_check: PASS` is based on comparing `len(learned)==len(pats)` in the same detector pipeline. It does not verify IP provenance, host scope, false positives, correlated evidence or ban consequences.
7. **Telegram delivery acknowledgment needs hardening.** `sentinel_alerts.py poll` writes `delivered_at` before returning text to the external sender; if delivery fails downstream, the event can be marked delivered with no Telegram receipt. Ban/unban notifications must be persisted with actual send status/retry and idempotency, not only text returned by poll.
8. **False-positive priors remain too broad for enforcement.** Feature classifier uses broad substring hints (e.g. 'config', 'backup', 'vendor'); two hits can trigger targeted_probe on a legitimate API. HTTP 401/403/404 alone and status 5xx/traffic volume must never imply malicious intent. Positive/negative evidence must be host-specific; include authenticated/admin operations, monitoring, search bots, API clients, CDNs, proxy healthchecks and maintenance windows.
9. **Site logs cannot establish exploit success alone.** A request to /.env, an apparent traversal, or a signature-like route is evidence of *attempt/probe*, not confirmation of a vulnerability, disclosure or compromise. Confirmed exploitation requires additional sanitized application, version/config, response outcome, integrity or backend evidence. Security scan is not automatically an exploitable finding.
10. **Hard security operations are missing.** Implement tamper-resistant decision ledger (who/what/site/evidence/rule/version/expiry/response), dedupe, single-writer action queue, ban TTL and max concurrency, protected IP/owner/CDN/NetBird allowlist, automatic bounded rollback, manual emergency unban/disable. Keep enforcement policy/credentials beyond the agents' writable roots.
11. **Log quality and liveness not yet enforcement-grade.** Shared rotating log and cursor-based ingestion must be tested for restart/rotation race, gaps, replay and time drift; offsite/missing telemetry should suppress new automatic bans rather than count as absence of benign traffic. A 1-minute observer cadence is insufficient to substitute for fast fail2ban rules during acute floods; rate limiting and edge protections remain necessary.

## Current proof runs
`sentinel-competition-reviews/2026-10-08-enforce-readiness.py` is read-only synthetic/offline, with output `2026-10-08-enforce-readiness.json`. It exercises 15 *targeted* mandatory checks and currently reports 15/15 **readiness blockers**. This is not a claim of 15 exploited vulnerabilities and is not a balanced general maturity score. Actual existing observer tests passed 6/6 per agent. No writes to either agent, Fail2ban, firewall, proxy routing or live traffic.

## Recommended role separation and enforcement architecture

```text
NetBird Proxy/CDN / trusted ingress telemetry
    -> Source-IP validation and log normalization
    -> SHARED full-host evidence ledger and global anomaly/campaign learning
       Luna  -> global observation; primary attention site_A; proposals ONLY site_A
       Selene -> global observation; primary attention site_B; proposals ONLY site_B
    -> Site-bound decision-time evidence views, not filtered input logs
    -> Deterministic independent policy broker (root-owned, minimal API)
       validate site/IP provenance, evidence thresholds, allowed category,
       scoped action, time-to-live, protected address exclusions and idempotency
    -> Site-scoped enforcement at the correct layer
       HTTP hostname-specific rule at ingress/proxy/CDN; OR
       Fail2ban jail + host-dedicated destination IP/port where isolation is proven
    -> Verify ban works on assigned site but NOT on the other site
    -> Ban/unban decision ledger + Telegram delivery receipt + retry
    -> Human override, audit, rule rollback; feedback retained for learning
```

**Technical constraint:** A generic `DOCKER-USER` / TCP 80,443 Fail2ban IP drop cannot enforce `Host=A` but permit `Host=B` on the same shared IP:port. If separate destination IP/port is unavailable, use an HTTP-aware ingress/edge action; Fail2ban may serve as trigger/decision collector using a custom scoped action, not the existing global `banip` chain. Validate what actions NetBird Proxy actually supports before selecting an adapter.

Keep agent mode as `OBSERVE_ONLY` during build. Do not simply edit the identity JSON to give sudo/firewall rights. Add a separate, constrained `PROPOSE_ACTION` capability; the broker owns independent authorization and execution. On any guard failure the broker refuses new actions, preserving already time-limited protection.

## Staged readiness plan
- **S0 — Site ownership:** owner specifies two exact hostnames, their ingress/CDN and expected users/routes, plus protected admin/healthcheck/client addresses. Keep global log ingestion and cross-host learning unchanged. Enforce allowed-host restrictions ONLY for per-agent *action proposals/execution*, not raw evidence collection or global awareness. Evaluate site-local evidence separately to prevent cross-site score contamination; allow cross-host context as supporting information. Freeze baseline/test suite.
- **S1 — Knowledge and verification:** add web-app HTTP/route/auth semantics, NetBird/CDN trusted IP, IPv6 safe handling, WAF/F2B effect verification, OWASP/CWE exploit attempt vs success, distributed-scan vs legitimate scanner, DDoS evidence vs flash crowd, false-positive and rollback playbooks.
- **S2 — Offline replay & shadow:** unit and integration tests with realistic benign sessions, bots, scans, mixed-host traffic, IPv4/IPv6, NAT/CDN, out-of-order & malicious forged headers, partial/missing logs and real deployment changes. Record exactly what each agent *would* propose to ban, but ban nobody. Score per-site precision/recall and zero severe false positives on critical admin/production requests before promotion.
- **S3 — Human-approved enforcement:** independent broker deployed in dry-run first, then each action requires owner approval. Short, expiring, site-scoped action only; verify ban and unban path, Telegram ack, no peer-site impact. Preserve existing Fail2ban jails, do not modify them casually.
- **S4 — Limited automatic enforcement:** enable only narrow high-evidence cases with offline+shadow+manual track record, short max TTL, per-site cap and kill switch. Keep all weak/novel or distributed signals in report/approval mode. Do not automatically expand to CIDRs or indefinite recidive.
- **S5 — Iterative training:** use confirmed FP/TP decisions and counterexamples from each assigned site to update curated rules and bounded memory; stop if precision deteriorates.

## Example response policy (provisional, must calibrate per website)
- Informational: isolated 404, single suspicious URL, unknown crawler, novel IP, or 502 surge with no corroboration -> observe/Telegram, NO BAN.
- Bounded high-confidence scan attempt across multiple validated distinct sensitive paths within a short window, IP validated, host-owned, protected allowlist excluded, independent consistency check -> short site-scoped deny/challenge (initially owner-approved).
- Auth brute-force -> require route-specific failed-auth signals/rate and exclude genuine login failures or proxy retries; short deny/challenge, not global ban.
- Availability stress -> rate-limit at ingress and correlate error rate, latency, upstream resources and distributed behavior before declaring DDoS.
- Signs of successful compromise -> urgent owner escalation and manual incident response; do not claim auto-ban alone fixes a vulnerability.

## Acceptance gate for handing over real authority
1. Zero live undesired peer-site blocks across deterministic site A/B replay and controlled canary.
2. Trusted client source unambiguous at observation & action enforcement points (including IPv6/CDN/VPN).
3. Fail closed on unknown host, missing log, invalid actor identity, malformed IP or rule failure.
4. Action API least-privilege: site owner cannot ban outside its site, no global jail manipulation, no arbitrary shell, no automatic indefinite ban.
5. Real action applied + verified at the intended layer; TTL expiration/unban verified; multi-host no collateral.
6. Telegram report of proposal, execution, rollback with retry and eventual delivery acknowledgment.
7. Honest calibration on human-reviewed traffic and fresh benign scenarios with no critical false-positive events.
8. Explicit owner release approval and tested roll-back point.

## Next missing information
Owner has assigned Luna=`thaiduy.digital` and Selene=`light-remote.thaiduy.digital`; determine the trusted NetBird Proxy/CDN ingress enforcement point and protected routes/IPs before any live enforcement. Until then, enforcement remains disabled.
