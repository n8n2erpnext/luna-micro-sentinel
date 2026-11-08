# Micro Sentinel V2

Read-only behavioral observer for this VPS. Fail2ban remains enforcement authority; Sentinel never bans, unbans, or edits firewall rules.

## Epistemic contract
- Curated security knowledge is a prior, never a verdict.
- Anomaly is a hypothesis: rare != malicious; frequent != safe.
- 401/403/404 and 5xx are observations, not attacker proof.
- Learn aggregate behavior and correlations, not permanent guilt attached to IPs.
- Evidence ledger is authoritative over Sentinel's own narrative.

## Knowledge layers
1. `knowledge/foundation.json`: curated system/security priors and negative knowledge.
2. `observations`: normalized local proxy evidence; no request bodies/tokens.
3. `learned_patterns`: scoped candidates with evidence and confidence.

## Daily truth split
`reports/self/YYYY-MM-DD.json` is Sentinel's self-interpretation.
`reports/independent/YYYY-MM-DD.json` is deterministic recount from evidence.
A mismatch is a fault, not something Sentinel may explain away.

V2 is intentionally OBSERVE_ONLY. Telegram and any future response automation must consume evidence-backed alerts; enforcement promotion requires separate human review.