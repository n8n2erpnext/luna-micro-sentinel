#!/usr/bin/env python3
"""Light Sentinel Web Guardian S1 scenario reasoning (offline/shadow only).

Reasoning over synthetic or safely normalized sanitized evidence. Neither
OWASP descriptions nor CVE path strings prove impact. No subprocess/network/
firewall writes. This module is MAINTAINER-authored deterministic curriculum,
not a learned neural net.
"""
from __future__ import annotations
import ipaddress,json,re
from pathlib import Path
from urllib.parse import unquote,urlsplit

ROOT=Path('/home/ubuntu/services')
ASSIGNMENTS=ROOT/'sentinel-site-guardian/owner_assignments.json'
EXPECTED_MODULES={'HTTP_APP_AUTH','REAL_CLIENT_IDENTITY','RECON_CVE',
 'DISTRIBUTED_SCAN','AVAILABILITY','DECISION_AND_RECOVERY'}
SEVERE_MARKERS=(
 '/.env','/.git/config','/.git/head','/.aws/credentials',
 '/.docker/config.json','/.kube/config','/etc/passwd','/etc/shadow',
 '/proc/self/environ','/vendor/phpunit','/wp-config.php',
)
TRAVERSAL_MARKERS=('../','..\\','/etc/passwd','/etc/shadow')
CVE_RE=re.compile(r'^CVE-20\d\d-\d{4,}$')

def lesson(agent: str) -> dict:
    cfg=json.loads(ASSIGNMENTS.read_text())
    assert not cfg['enforcement_enabled']
    d=cfg['agents'][agent]
    p=Path(d['agent_directory'])/'knowledge/lessons/guardian/web_guardian_s1_2026-10-08.json'
    o=json.loads(p.read_text())
    assert o['agent']==agent and o['assigned_site']==d['assigned_hostname']
    assert o['source_kind']=='MAINTAINER_CURATED_REFERENCE_NOT_GROUND_TRUTH'
    assert {x['id'] for x in o['modules']}==EXPECTED_MODULES
    assert not o['enforcement_enabled'] and o['shared_full_proxy_visibility']
    return o

def normalized_path(value):
    try:
        raw=urlsplit(str(value or '/')).path
        clean=unquote(raw).lower()
        return clean[:1024]
    except (TypeError,ValueError):
        return '/'

def severe_probe(path):
    s=normalized_path(path)
    return any(x in s for x in SEVERE_MARKERS) or any(x in s for x in TRAVERSAL_MARKERS)

def safe_div(a,b):
    return float(a)/float(b) if b else 0.0

def review(agent, scene, *, course=None):
    o=course if course is not None else lesson(agent)
    site=o['assigned_site']
    target=str(scene.get('host') or '')
    context=scene.get('global_host_count',1)
    observations={'shared_global_host_count':context,
                  'assessed_site':site,
                  'cross_host_context_does_not_raise_local_threshold':True}
    result={'agent':agent,'assigned_site':site,'requested_host':target,
            'authority':'SHADOW_ONLY',
            'action':'NO_BAN','real_enforcement':False,
            'finding':'NO_ACTIONABLE_EVIDENCE','evidence':[],
            'missing':[],'global_context':observations,
            'can_auto_ban':False,'exploit_confirmed':False}
    if target!=site:
        result['finding']='OUT_OF_SCOPE_FOR_ACTION'
        result['missing'].append('Only the assigned website can receive an action proposal')
        return result
    ip=scene.get('ip')
    try:
        addr=ipaddress.ip_address(ip)
        valid_ip=bool(addr.is_global)
    except (ValueError,TypeError):
        valid_ip=False
    if not valid_ip:
        result['missing'].append('Public client IP must be syntactically valid')
    if not scene.get('source_origin_verified',False):
        result['missing'].append('Trusted ingress source-IP provenance not yet verified')
    if scene.get('protected_actor',False):
        result['missing'].append('Protected actor: avoid denial / require owner review')
    rows=scene.get('requests') or []
    flagged=[]
    for row in rows:
        if not isinstance(row,dict):continue
        if severe_probe(row.get('path')):
            flagged.append((normalized_path(row.get('path')),int(row.get('status',0))))
    uniq={x[0] for x in flagged}
    denied=sum(x[1] in (401,403,404,405,429) for x in flagged)
    auth_failed=int(scene.get('app_verified_failed_auth',0) or 0)
    auth_attempts=int(scene.get('app_total_auth_attempts',0) or 0)
    auth_window=int(scene.get('auth_window_seconds',0) or 0)
    base=float(scene.get('baseline_rps',0) or 0)
    current=float(scene.get('current_rps',0) or 0)
    er=float(scene.get('error_fraction',0) or 0)
    base_error=float(scene.get('baseline_error_fraction',0) or 0)
    p95=float(scene.get('p95_latency_ms',0) or 0)
    base_p95=float(scene.get('baseline_p95_latency_ms',0) or 0)
    cpu=float(scene.get('upstream_cpu_pct',0) or 0)
    connection_pressure=bool(scene.get('upstream_connection_pressure',False))
    ratio=safe_div(current,base)
    traffic_surge=base>0 and current>=40 and ratio>=6
    impact=(er>=0.1 and er-base_error>=.08) or (base_p95>0 and p95/base_p95>=3) or cpu>=85 or connection_pressure
    known_id=str(scene.get('cve_id') or '')
    if CVE_RE.fullmatch(known_id) and scene.get('trusted_software_inventory') and scene.get('verified_affected_version'):
        result['finding']='CVE_EXPOSURE_CANDIDATE'
        result['evidence']=['Exact installed product/version inventory and affected range verified',known_id]
        if scene.get('cisa_kev_catalog_match_verified'):result['evidence'].append('Confirmed CISA KEV match from vetted cache')
        else: result['missing'].append('CISA KEV priority status unknown or not verified')
        result['action']='PRIORITY_PATCH_REVIEW_NO_BAN'
        result['missing'].append('Exploit success/compromise not established by inventory')
    elif known_id:
        result['finding']='CVE_INVESTIGATION_REQUIRED'
        result['evidence']=[known_id]
        result['missing'].append('Verified product/version and affected range required before exposure claim')
        result['action']='REQUEST_ASSET_INVENTORY'
    elif traffic_surge and impact:
        distributed=int(scene.get('observed_unique_sources',0) or 0)>=20
        result['finding']='DISTRIBUTED_AVAILABILITY_ABUSE_CANDIDATE' if distributed else 'APPLICATION_FLOOD_CANDIDATE'
        result['evidence']=['Current traffic surge >=6x comparable host baseline',
             'Independent service error/latency/resource pressure correlated']
        result['missing'].append('Benign flash crowd and retry storm remain alternatives until verified')
        result['action']='URGENT_HUMAN_MITIGATION_REVIEW'
    elif auth_failed>=12 and auth_attempts>=auth_failed and auth_window>0 and auth_window<=300 and safe_div(auth_failed,auth_attempts)>=.6:
        result['finding']='AUTH_BRUTE_FORCE_CANDIDATE'
        result['evidence']=['>=12 app-confirmed failed authentication attempts within 5m','failed fraction >=60%']
        result['action']='REVIEW_SITE_SCOPED_SHORT_BLOCK'
    elif len(uniq)>=3 and denied>=2:
        result['finding']='SENSITIVE_RECON_CANDIDATE'
        result['evidence']=['>=3 distinct sensitive paths within assigned site','>=2 denied/missing probe responses']
        result['action']='REVIEW_SITE_SCOPED_SHORT_BLOCK'
    elif (int(scene.get('campaign_host_count',0) or 0)>=3
          and bool(scene.get('campaign_probe_similarity_confirmed'))
          and bool(scene.get('own_site_probe_seen'))):
        result['finding']='CROSS_HOST_RECON_CAMPAIGN_CANDIDATE'
        result['evidence']=['Same probe family across >=3 hosts, including assigned site']
        result['action']='REPORT_AND_INVESTIGATE_ONLY'
    elif traffic_surge:
        result['finding']='UNVERIFIED_TRAFFIC_SURGE'
        result['evidence']=['Elevated requests on comparable host baseline']
        result['missing'].append('No independent availability impact or resource pressure')
        result['action']='MONITOR_ONLY'
    elif er>=.1 and er-base_error>=.08:
        result['finding']='APPLICATION_INCIDENT_NOT_ATTRIBUTED_TO_ATTACK'
        result['evidence']=['Error rate increased without correlated incoming traffic surge']
        result['action']='OPERATIONS_REVIEW'
    elif uniq:
        result['finding']='ISOLATED_SENSITIVE_PATH_PROBING'
        result['evidence']=['Sensitive path access, insufficient breadth/corroboration']
        result['action']='OBSERVE_AND_REPORT'
    if result['finding'].endswith('CANDIDATE') and not scene.get('source_origin_verified'):
        result['missing'].append('No site-level deny until source authenticity and enforcement scope proven')
    if scene.get('verified_independent_compromise_evidence'):
        # Even verified compromise evidence is not an IP ban authorization; owner IR escalation.
        result['evidence'].append('Independent compromise evidence reported; verify incident with owner')
        result['action']='URGENT_INCIDENT_RESPONSE_REVIEW'
        result['finding']='POSSIBLE_CONFIRMED_INCIDENT_REQUIRES_HUMAN'
        result['missing'].append('Owner confirmation and response workflow')
    # Invariant: case studies cannot grant execution rights. A site-specific
    # independent policy broker will need explicit release authorization.
    return result
