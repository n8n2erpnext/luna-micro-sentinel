#!/usr/bin/env python3
"""Luna + Selene: global observation, per-site shadow-only decisions.

Read-only analysis layer. No Fail2ban imports, subprocess, sudo, shell, or
iptables access. Never interprets heuristic confidence as automatic-ban permission.
"""
from __future__ import annotations

import argparse
import collections
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import sqlite3
from guardian_reasoner import lesson as load_guardian_lesson, review as guardian_assess

ROOT = Path("/home/ubuntu/services/sentinel-site-guardian")
POLICY = ROOT / "owner_assignments.json"
MAX_ROWS = 200000
LOOKBACK_DEFAULT = 60
ALERT_MIN_DISTINCT_PROBES = 3
ALERT_MIN_DISTINCT_PATHS = 3
SUSPICIOUS_FEATURES = {
    "probe_path",
    "path_traversal_indicator",
    "sensitive_discovery",
    "backup_artifact_discovery",
    "framework_fingerprint_probe",
    "method_capability_probe",
}

def load_policy(path: Path = POLICY) -> dict:
    cfg = json.loads(path.read_text(encoding="utf-8"))
    assert cfg["enforcement_enabled"] is False
    assert cfg["site_scope_is_for_decisions_only"] is True
    assert cfg["global_observation_unchanged"] is True
    assert cfg["cross_host_learning_unchanged"] is True
    assert cfg["enforcement_backend"] is None
    agents = cfg["agents"]
    assert set(agents) == {"Luna", "Luna:LightRemote"}
    hostnames = []
    for name, d in agents.items():
        assert d["mode"] == "SHADOW_ONLY"
        assert d["observe_all_hosts"] and d["global_campaign_context"]
        assert d["propose_actions_only_on_assigned_host"]
        hostname = d["assigned_hostname"]
        assert hostname == hostname.lower().strip() and hostname.count(".") >= 1
        assert "*" not in hostname and ":" not in hostname and "/" not in hostname
        hostnames.append(hostname)
    assert len(set(hostnames)) == 2
    return cfg

def canonical_ip(value: str) -> str | None:
    try:
        a = ipaddress.ip_address(value)
        return a.compressed
    except ValueError:
        return None

def group_site_rows(site: str, rows: list[tuple]) -> dict:
    """Grouping always exact (host, full IP). Never subnet or cross-host for decisions.

    Records: (timestamp, src, host, method, path, status, feature-json)
    """
    groups = collections.defaultdict(list)
    for row in rows:
        ts, src, host, method, path, status, features = row
        if host != site:
            continue
        ip = canonical_ip(src)
        if ip is None:
            continue
        if not isinstance(status, int) or not isinstance(path, str):
            continue
        try:
            fs = set(json.loads(features)) if isinstance(features, str) else set(features)
        except (ValueError, TypeError):
            continue
        groups[ip].append((ts, method, path, status, fs))
    return groups

def summarize_site(site: str, rows: list[tuple], *, limit: int = 12) -> dict:
    groups = group_site_rows(site, rows)
    findings = []
    for ip, events in groups.items():
        paths = {x[2] for x in events}
        suspicious = [x for x in events if x[4] & SUSPICIOUS_FEATURES]
        sus_paths = {x[2] for x in suspicious}
        distinct_signal_types = sorted(set().union(*(x[4] & SUSPICIOUS_FEATURES for x in suspicious))) if suspicious else []
        bad_status = sum(x[3] in (401, 403, 404, 405, 429) for x in suspicious)
        # Distinct fixed 10-minute windows provide a bounded persistence signal.
        # These windows are disjoint, unlike adjacent overlapping 60-minute reviews.
        timestamps=[]
        for item in suspicious:
            try:
                dt=datetime.fromisoformat(str(item[0]).replace('Z','+00:00'))
                if dt.tzinfo is not None:timestamps.append(dt.astimezone(timezone.utc))
            except (ValueError,TypeError):pass
        buckets={int(x.timestamp())//600 for x in timestamps}
        span_seconds=max(0,int((max(timestamps)-min(timestamps)).total_seconds())) if timestamps else 0
        # This is a preliminary REVIEW signal, not a validated malice score.
        if len(sus_paths) < ALERT_MIN_DISTINCT_PROBES or len(paths) < ALERT_MIN_DISTINCT_PATHS:
            continue
        if not (bad_status >= 2 or len(distinct_signal_types) >= 2):
            continue
        # No action is authorized even if confidence appears high.
        evidence_digest = hashlib.sha256(json.dumps(
            sorted((x[0], x[1], x[2], x[3]) for x in suspicious),
            ensure_ascii=True,
        ).encode()).hexdigest()[:20]
        findings.append({
            "scope_hostname": site,
            "src": ip,
            "total_events_on_assigned_site": len(events),
            "distinct_paths_on_assigned_site": len(paths),
            "suspicious_hits": len(suspicious),
            "distinct_suspicious_paths": len(sus_paths),
            "suspicious_feature_types": distinct_signal_types,
            "denied_or_missing_suspicious_events": bad_status,
            "suspicious_distinct_10min_windows":len(buckets),
            "suspicious_span_seconds":span_seconds,
            "first_suspicious_utc": min(timestamps).isoformat() if timestamps else None,
            "last_suspicious_utc": max(timestamps).isoformat() if timestamps else None,
            "evidence_digest": evidence_digest,
            "confidence_is_calibrated": False,
            "origin_ip_verified_at_enforcement_boundary": False,
            "verdict": "HUMAN_REVIEW_CANDIDATE_NOT_PROOF_OF_ATTACK",
            "action": "SHADOW_ONLY_NO_BAN",
            "no_automatic_ban": True,
        })
    findings.sort(key=lambda x:(-x["distinct_suspicious_paths"],-x["suspicious_hits"],x["src"]))
    return {
        "host":site,
        "site_source_count":len(groups),
        "proposals_total":len(findings),
        "findings":findings[:limit],
        "findings_truncated":len(findings)>limit,
    }

def sqlite_rows(agent_root: Path, cutoff: str) -> list[tuple]:
    db = agent_root / "state/sentinel.db"
    uri = "file:"+str(db)+"?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    try:
        # Read ALL recent host events for global context; only filter at decision time.
        cursor = conn.execute(
            "SELECT ts,src,host,method,path,status,features "
            "FROM observations WHERE ts>=? ORDER BY ts DESC LIMIT ?", (cutoff, MAX_ROWS+1))
        rows=cursor.fetchall()
    finally:
        conn.close()
    if len(rows)>MAX_ROWS:
        raise RuntimeError("Telemetry over cap. Fail closed; no complete window for analysis.")
    return rows

def evaluate(cfg: dict, agent_name: str, rows: list[tuple], *, cutoff: str) -> dict:
    assignment = cfg["agents"][agent_name]
    own = assignment["assigned_hostname"]
    summary = summarize_site(own,rows)
    all_hosts = collections.Counter(x[2] for x in rows)
    # Other hosts remain visible in all evidence and analytics, but their
    # paths/events NEVER add to own-site detection thresholds.
    for finding in summary["findings"]:
        ip=finding["src"]
        peers=sorted({row[2] for row in rows if canonical_ip(row[1])==ip and row[2]!=own})
        finding["cross_host_context_only"]={"other_host_count":len(peers)}
    # Second, lesson-backed shadow classifier: all-host input remains intact;
    # only site-local rows vote on a guardian proposal. No active bans.
    course=load_guardian_lesson(agent_name)
    site_by_ip=collections.defaultdict(list)
    for ts, src, host, method, path, status, features in rows:
        if host!=own:continue
        normalized=canonical_ip(src)
        if normalized is None:continue
        site_by_ip[normalized].append({'method':method,'path':path,'status':status})
    lesson_findings=[]
    for ip, requests in sorted(site_by_ip.items(),key=lambda x:-len(x[1]))[:50]:
        # Full source is accessible for campaigns. Limit repeated path examples
        # to avoid oversized or sensitive result files on busy API sites.
        unique=[];seen=set()
        for entry in requests:
            signature=(entry['method'],entry['path'],entry['status'])
            if signature in seen:continue
            seen.add(signature);unique.append(entry)
            if len(unique)>=200:break
        assessment=guardian_assess(agent_name,{
           'host':own,'ip':ip,'source_origin_verified':False,
           'requests':unique,'global_host_count':len(all_hosts)},course=course)
        if assessment['finding'] not in ('NO_ACTIONABLE_EVIDENCE',):
            lesson_findings.append(assessment)
    return {
        "agent":agent_name,
        "assigned_hostname":own,
        "mode":"SHADOW_ONLY",
        "input_visibility":"ALL_HOSTS",
        "total_global_window_events":len(rows),
        "global_hosts_seen":len(all_hosts),
        "cutoff_utc":cutoff,
        "site_summary":summary,
        "guardian_s1_training_shadow":{
            'knowledge_version':course['version'],
            'engine':'MAINTAINER_CURATED_DETERMINISTIC_REVIEW_NOT_LLM',
            'evaluated_source_count':min(50,len(site_by_ip)),
            'findings':lesson_findings[:16],
            'findings_total':len(lesson_findings),
            'site_action_enabled':False,
            'availability_detection_gap':'No independent p95/5xx/upstream-resource feed supplied; cannot call DDoS from access totals alone',
            'cve_detection_gap':'No verified installed-component SBOM or KEV-to-version matcher integrated',
        },
        "trust_blockers":[
            "source_ip_provenance_not_independently_verified",
            "hostname_safe_enforcement_not_integrated",
            "site_specific_false_positive_benchmark_not_accepted",
            "operator_live_release_not_granted",
        ],
        "effect":"NO_ACTION_PERFORMED",
    }

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--window-minutes",type=int,default=LOOKBACK_DEFAULT)
    p.add_argument("--out",type=Path,default=ROOT/"reports/latest.json")
    a=p.parse_args()
    if a.window_minutes<1 or a.window_minutes>240:
        raise SystemExit("window must be 1..240 minutes")
    cfg=load_policy()
    cutoff=(datetime.now(timezone.utc)-timedelta(minutes=a.window_minutes)).strftime("%Y-%m-%dT%H:%M:%S")
    result={
        "version":cfg["version"],
        "generated_at_utc":datetime.now(timezone.utc).isoformat(),
        "enforcement_enabled":False,
        "live_bans":0,
        "live_unbans":0,
        "agents":{},
    }
    # One shared, authoritative observation ledger; preserve independent site scope.
    # Cache the bounded read so the per-site guardian profiles do not duplicate IO.
    ledger_cache={}
    for name, policy in cfg["agents"].items():
        directory=str(Path(policy["agent_directory"]).resolve())
        if directory not in ledger_cache:
            ledger_cache[directory]=sqlite_rows(Path(directory),cutoff)
        result["agents"][name]=evaluate(cfg,name,ledger_cache[directory],cutoff=cutoff)
    a.out.parent.mkdir(parents=True,exist_ok=True)
    a.out.write_text(json.dumps(result,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    a.out.chmod(0o600)
    print(json.dumps({
        "report":str(a.out),
        "enforcement_enabled":False,
        "live_bans":0,
        "agents":{k:{
            "assigned_host":v["assigned_hostname"],
            "global_hosts_seen":v["global_hosts_seen"],
            "total_window_events":v["total_global_window_events"],
            "site_sources":v["site_summary"]["site_source_count"],
            "human_review_candidates":v["site_summary"]["proposals_total"]
        } for k,v in result["agents"].items()}
    },ensure_ascii=False,indent=2))

if __name__=="__main__":
    main()
