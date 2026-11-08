#!/usr/bin/env python3
"""Luna/Selene autonomous defensive *decisions*, never enforcement.

Judgements are site-scoped, evidence-bounded and reversible on new evidence.
No imports/calls to firewall, Fail2ban, CrowdSec, privileged IO or network.
"BAN_RECOMMENDED" is advice, not a deny rule or authority to execute.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path('/home/ubuntu/services')
BASE = ROOT / 'sentinel-site-guardian'
OUT = BASE / 'reports' / 'decisions_latest.json'
STATE = BASE / 'state' / 'decisions_state.json'
HISTORY = BASE / 'reports' / 'decision_history.jsonl'
SITES = {'Luna':'thaiduy.digital', 'Luna:LightRemote':'light-remote.thaiduy.digital'}
VALID = {'BAN_RECOMMENDED','WAIT_MORE_EVIDENCE','INCIDENT_REVIEW_RECOMMENDED',
         'NO_ACTION','INSUFFICIENT_TELEMETRY'}
MAX_HISTORY = 2_000_000

def utcnow():
    return datetime.now(timezone.utc)

def load(path):
    try:
        return json.loads(Path(path).read_text(encoding='utf-8'))
    except (FileNotFoundError, ValueError):
        return {}

def fresh(iso, minutes=20, now=None):
    try:
        dt=datetime.fromisoformat(str(iso).replace('Z','+00:00'))
        if dt.tzinfo is None:return False
        age=((now or utcnow())-dt.astimezone(timezone.utc)).total_seconds()
        return -60 <= age <= minutes*60
    except (TypeError, ValueError):return False

def save(path,obj):
    path=Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    tmp=path.with_suffix(path.suffix+'.new')
    tmp.write_text(json.dumps(obj,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    tmp.chmod(0o600);tmp.replace(path)

def fingerprint(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,ensure_ascii=True).encode()).hexdigest()[:20]

def decision(kind, why, evidence, missing, subject=None, next_minutes=15):
    assert kind in VALID
    return {
        'decision':kind,'subject':subject or 'SITE','rationale':why,
        'evidence':evidence[:12], 'needs_to_confirm_or_refute':missing[:12],
        'reassess_after_minutes':next_minutes,
        'origin_verified_for_enforcement':False,
        'executed':False,'enforcement_requested':False,
        'proposed_only':True,
    }

def for_agent(name, site, guardian, temporal, intel, metrics, *, now=None):
    now=now or utcnow()
    if site!=SITES[name]:
        raise ValueError('site ownership violation')
    if guardian.get('assigned_hostname')!=site or temporal.get('assigned_host')!=site:
        return decision('INSUFFICIENT_TELEMETRY','Site identity mismatch; refuse a site judgement',
           [],['Verify exact host-to-agent telemetry mapping'],next_minutes=2)
    sources=[('guardian', guardian.get('_report_timestamp')),('temporal', temporal.get('_report_timestamp')),
             ('proxy',metrics.get('_report_timestamp'))]
    stale=[k for k,v in sources if not fresh(v,minutes=90 if k=='guardian' else 20,now=now)]
    if stale:
        return decision('INSUFFICIENT_TELEMETRY','Evidence is stale/incomplete; cannot interpret silence as safety',
            [],['Refresh '+', '.join(stale),'Verify telemetry source before any response'],next_minutes=2)
    # A healthy global collector cannot substitute for proof that THIS site
    # was covered. Unknown is not the same as no suspicious activity.
    if metrics.get('_collection_state')!='PASS' or metrics.get('_window_complete') is not True or not isinstance(metrics.get('requests_70m'),int):
        return decision('INSUFFICIENT_TELEMETRY','Site telemetry or coverage is missing; no safe NO_ACTION conclusion',
            [],['Restore site-specific proxy coverage and verify complete window'],next_minutes=2)
    if guardian.get('site_summary',{}).get('findings_truncated') is True:
        return decision('INSUFFICIENT_TELEMETRY','Site findings were truncated; the decision input is not complete',
            [],['Raise bounded report evidence coverage without dropping candidates'],next_minutes=2)
    candidates=guardian.get('site_summary',{}).get('findings',[])
    urgent=[]
    observe=[]
    for row in candidates:
        if row.get('scope_hostname')!=site:continue
        ip=row.get('src','')
        try:
            if not ipaddress.ip_address(ip).is_global:continue
        except (ValueError,TypeError):continue
        hits=int(row.get('suspicious_hits') or 0)
        distinct=int(row.get('distinct_suspicious_paths') or 0)
        denied=int(row.get('denied_or_missing_suspicious_events') or 0)
        kinds=len(row.get('suspicious_feature_types') or [])
        windows=int(row.get('suspicious_distinct_10min_windows') or 0)
        span=int(row.get('suspicious_span_seconds') or 0)
        evidence=[f'{hits} suspicious requests, {distinct} distinct paths, {denied} denied/missing responses',
                  f'{kinds} heuristic feature families (not independent origin proof)',
                  f'{windows} disjoint 10-minute windows, {span}s observed span',
                  'EVIDENCE_HASH='+str(row.get('evidence_digest',''))]
        missing=['Independently validate original client IP at trusted ingress',
                 'Check approved scans, authorized integrations, allowlists and benign alternatives',
                 'Repeat signal over independent time windows']
        if hits>=8 and distinct>=6 and denied>=5 and kinds>=2 and windows>=2 and span>=600:
            urgent.append(decision('BAN_RECOMMENDED',
                'Persistent sensitive-path probing across disjoint windows; advisory SITE-only ban candidate, pending independent client origin and benign-intent verification',
                evidence,missing,subject=ip,next_minutes=5))
        else:
            observe.append(decision('WAIT_MORE_EVIDENCE',
                'Suspicious reconnaissance is plausible, but evidence is insufficient for a ban recommendation',
                evidence,missing,subject=ip,next_minutes=10))
    temporal_signal=temporal.get('finding','NO_TEMPORAL_ALERT')
    if temporal_signal=='SURGE_WITH_HTTP_ERROR_IMPACT_NEEDS_RESOURCE_CORRELATION':
        urgent.append(decision('INCIDENT_REVIEW_RECOMMENDED',
            'Site-scoped traffic increase and HTTP errors justify independent incident triage, not automatic DDoS attribution',
            [f'RPM={temporal.get("recent_rpm")}, baseline={temporal.get("baseline_rpm")}',
             f'HTTP 5xx fraction={temporal.get("recent_http_5xx_fraction")}'],
            ['Correlate upstream CPU/connections/route-specific p95',
             'Exclude legitimate bursts and retries; verify client identity'],next_minutes=2))
    elif temporal_signal!='NO_TEMPORAL_ALERT':
        observe.append(decision('WAIT_MORE_EVIDENCE',
            'Temporal deviation detected without adequate independent impact proof',
            ['temporal signal='+str(temporal_signal)],
            ['Correlate error, service saturation and expected legitimate traffic'],next_minutes=5))
    if urgent:
        priority={'INCIDENT_REVIEW_RECOMMENDED':0,'BAN_RECOMMENDED':1}
        urgent.sort(key=lambda a:(priority.get(a['decision'],9),a['subject']))
        best=urgent[0]
    elif observe:
        best=sorted(observe,key=lambda a:a['subject'])[0]
    else:
        best=decision('NO_ACTION',
            'No decision-grade harmful behavior within current telemetry coverage',
            ['No qualifying site-scoped signals in current review window'],
            ['Continue sampling; no observation proves absolute safety'],next_minutes=15)
    best['agent']=name
    best['site']=site
    # Never include the selected dict in its own children (JSON cycles).
    best['other_subject_decisions']=[dict(x) for x in (urgent+observe) if x is not best][:10] if best['decision'] not in ('NO_ACTION','INSUFFICIENT_TELEMETRY') else []
    # Public CVE headlines are awareness ONLY; never assert affected local service.
    best['cve_context']={
        'new_intelligence_available': bool(intel.get('sources',{}).get('nvd_recent',{}).get('fresh')),
        'verified_affected_installed_version':False,
        'local_exploitation_confirmed':False,
        'next_step':'Complete site-specific SBOM and vendor affected-version matching',
    }
    best['execution_gate']={'actual_ban_enabled':False, 'backend':None,
       'trusted_original_ip_verified':False,'site_scoped_enforcement_tested':False}
    return best

def build(guardian,temporal,intel,telemetry,*,now=None):
    now=now or utcnow()
    out={'schema':'SENTINEL_AUTONOMOUS_DECISION_V1',
         'generated_utc':now.isoformat(),
         'owner_policy':'AGENTS_DECIDE_AND_EXPLAIN_BUT_NEVER_ENFORCE',
         'actual_bans':0, 'agents':{}}
    for name, site in SITES.items():
        g=dict(guardian.get('agents',{}).get(name,{}))
        g['_report_timestamp']=guardian.get('generated_at_utc')
        t=dict(temporal.get('agents',{}).get(name,{}))
        t['_report_timestamp']=temporal.get('generated_utc')
        m=dict(telemetry.get('site_metrics',{}).get(site,{}))
        m['_report_timestamp']=telemetry.get('captured_utc')
        m['_collection_state']=telemetry.get('state')
        m['_window_complete']=telemetry.get('window_complete')
        judgement=for_agent(name,site,g,t,intel,m,now=now)
        # Even fail-closed/early-return decisions must preserve site ownership.
        judgement.setdefault('agent',name)
        judgement.setdefault('site',site)
        judgement.setdefault('cve_context',{'verified_affected_installed_version':False})
        judgement.setdefault('execution_gate',{'actual_ban_enabled':False,'backend':None})
        out['agents'][name]=judgement
    return out

def persist(report):
    assert report['actual_bans']==0
    old=load(STATE)
    previous=old.get('signatures',{})
    prior_kinds=old.get('decision_kinds',{})
    counters=dict(old.get('transition_counters',{}))
    last_tokens=dict(old.get('last_transition_tokens',{}))
    signatures={}
    kinds={}
    transitions=[]
    for name, item in report['agents'].items():
        # Change tracking uses judgement and evidence class, not volatile counters.
        marker={'decision':item['decision'],'subject':item['subject'],'site':item['site']}
        sig=fingerprint(marker)
        signatures[name]=sig
        kinds[name]=item['decision']
        item['decision_id']=sig
        item['changed_from_previous']=previous.get(name)!=sig
        item['previous_decision']=prior_kinds.get(name)
        if item['changed_from_previous']:
            sequence=min(int(counters.get(name,0))+1,1000000000)
            counters[name]=sequence
            last_tokens[name]=fingerprint({'agent':name,'sequence':sequence,'signature':sig})
            transitions.append({'agent':name,'site':item['site'],
                                'decision':item['decision'],'previous_decision':prior_kinds.get(name),
                                'subject':item['subject'],'decision_id':sig,
                                'transition_token':last_tokens[name],
                                'rationale':str(item.get('rationale',''))[:400],
                                'evidence':[str(s)[:190] for s in (item.get('evidence') or [])[:5]],
                                'needs_to_confirm_or_refute':[str(s)[:190] for s in (item.get('needs_to_confirm_or_refute') or [])[:4]],
                                'reassess_after_minutes':int(item.get('reassess_after_minutes') or 15),
                                'generated_utc':report['generated_utc']})
        item['transition_token']=last_tokens.get(name)
        item['transition_sequence']=int(counters.get(name,0))
    report['transitions']=transitions
    save(OUT,report)
    save(STATE,{'signatures':signatures,'decision_kinds':kinds,
                'transition_counters':counters,'last_transition_tokens':last_tokens,
                'last_generated_utc':report['generated_utc']})
    if transitions:
        HISTORY.parent.mkdir(parents=True,exist_ok=True)
        # Bounded history; only decision transitions, never raw request logs.
        lines=HISTORY.read_bytes()[-MAX_HISTORY:] if HISTORY.exists() else b''
        # Drop cut first incomplete line if truncated.
        if len(lines)>=MAX_HISTORY and b'\n' in lines:lines=lines.split(b'\n',1)[1]
        new=''.join(json.dumps(x,ensure_ascii=False)+'\n' for x in transitions).encode()
        tmp=HISTORY.with_suffix('.new')
        tmp.write_bytes((lines+new)[-MAX_HISTORY:])
        tmp.chmod(0o600);tmp.replace(HISTORY)
    return transitions

def main():
    g=load(BASE/'reports/latest.json')
    t=load(BASE/'reports/temporal_shadow_latest.json')
    i=load(ROOT/'sentinel-threat-intel/reports/intake_latest.json')
    m=load(ROOT/'sentinel-guardian-reports/state/telemetry_latest.json')
    r=build(g,t,i,m)
    changes=persist(r)
    print(json.dumps({'state':'DECISIONS_RECORDED','per_site':{
        n:{'decision':d['decision'],'subject':d['subject'],'executed':False}
        for n,d in r['agents'].items()},'transitions':len(changes),
        'live_bans':0},ensure_ascii=False))
if __name__=='__main__':main()
