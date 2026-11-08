#!/usr/bin/env python3
"""Evidence-driven curriculum for Luna and its site profiles (no autonomous code mutation).

Each cycle identifies what evidence an agent must learn to discriminate a threat.
This is a bounded, site-specific *learning agenda*, NOT autonomous model training
and NOT proof of security decision accuracy. Progress requires independent data.
"""
from __future__ import annotations
from pathlib import Path
from datetime import datetime,timezone
import json,hashlib

ROOT=Path('/home/ubuntu/services')
BASE=ROOT/'sentinel-site-guardian'
OUT=BASE/'reports/learning_agenda_latest.json'
STATE=BASE/'state/learning_progress.json'
TOPICS={
 'ORIGINAL_SOURCE_IDENTITY':{
   'goal':'Distinguish real visitor IP from proxy/forwarding/NAT identity',
   'evidence_needed':'Trusted proxy chain and original IP verified at ingestion and enforcement boundary',
   'counterexample':'A shared proxy address must never be treated as one hostile user'},
 'APPLICATION_VULNERABILITY':{
   'goal':'Link new CVE to exact installed runtime and affected version range',
   'evidence_needed':'Per-site SBOM, service route provenance, vendor advisory and package backport status',
   'counterexample':'A new CVE in an unused product is not local exposure'},
 'INDEPENDENT_AVAILABILITY':{
   'goal':'Tell a real resource-exhaustion incident from long-poll/API normal traffic',
   'evidence_needed':'Upstream CPU, connections, route-specific p95 and 5xx correlated with traffic',
   'counterexample':'An 8s proxy response may be a healthy device long-poll'},
 'FALSE_POSITIVE_CALIBRATION':{
   'goal':'Learn when scanners, QA traffic or cloud endpoints are benign',
   'evidence_needed':'Owner-labelled replay set with per-site precision, recall, missed detections',
   'counterexample':'Multiple paths alone do not prove malicious intent'},
 'TEMPORAL_DISCRIMINATION':{
   'goal':'Wait for recurrence and independent corroboration before upgrading uncertainty',
   'evidence_needed':'Repeated windows, corroborating feature family and explicit falsification signals',
   'counterexample':'A burst in one window is not a sustained campaign'},
 'THREAT_FEED_RELIABILITY':{
   'goal':'Read public advisories without assuming freshness or trusting headlines as commands',
   'evidence_needed':'CISA Advisories fetch succeeds; NVD/KEV fresh; source-specific coverage indicated',
   'counterexample':'A cached advisory is not proof of a new publication'},
}
def load(p):
 try:return json.loads(Path(p).read_text(encoding='utf-8'))
 except (FileNotFoundError,ValueError):return {}
def save(p,v):
 p.parent.mkdir(parents=True,exist_ok=True)
 q=p.with_suffix(p.suffix+'.new')
 q.write_text(json.dumps(v,indent=2,ensure_ascii=False)+'\n')
 q.chmod(0o600);q.replace(p)
def evaluate(decisions,intel,asset,telemetry,now=None):
 now=now or datetime.now(timezone.utc)
 data={'schema':'SENTINEL_GUARDED_LEARNING_V1','generated_utc':now.isoformat(),
       'no_automatic_authority_promotion':True,'agents':{}}
 feeds=intel.get('sources',{})
 evidence=load(ROOT/'sentinel-guardian-reports/state/deployed_component_evidence_latest.json')
 try:
  recorded=datetime.fromisoformat(str(evidence.get('captured_utc','')).replace('Z','+00:00'))
  evidence_fresh=recorded.tzinfo is not None and 0 <= (now-recorded).total_seconds() <= 26*3600
 except (ValueError,TypeError):evidence_fresh=False
 nvd=load(ROOT/'sentinel-threat-intel/state/nvd_recent.json')
 total=int(nvd.get('total_published_window') or 0)
 captured=int(nvd.get('count') or 0)
 complete=bool(nvd.get('coverage_complete') is True and total>0 and captured>=total)
 feed_ok=bool(complete and feeds.get('cisa_advisories',{}).get('fresh') and feeds.get('nvd_recent',{}).get('fresh'))
 data['threat_intelligence_coverage']={'nvd_count':captured,'nvd_window_total':total,
   'nvd_window_complete':complete,'cisa_advisories_fresh':bool(feeds.get('cisa_advisories',{}).get('fresh')),
   'feed_research_ready':feed_ok,
   'local_component_vulnerability_confirmed':False}
 for name,d in decisions.get('agents',{}).items():
  site=d.get('site')
  if name not in ('Luna','Luna:LightRemote') or site not in ('thaiduy.digital','light-remote.thaiduy.digital'):continue
  top='TEMPORAL_DISCRIMINATION' if d['decision']=='WAIT_MORE_EVIDENCE' else (
      'ORIGINAL_SOURCE_IDENTITY' if d['decision']=='BAN_RECOMMENDED' else (
      'INDEPENDENT_AVAILABILITY' if d['decision']=='INCIDENT_REVIEW_RECOMMENDED' else (
      'THREAT_FEED_RELIABILITY' if d['decision']=='INSUFFICIENT_TELEMETRY' else 'APPLICATION_VULNERABILITY')))
  covered=asset.get('assigned_websites',{}).get(site,{})
  direct=(evidence.get('by_site',{}).get(site,{}) if evidence_fresh else {})
  os_packages=direct.get('os_installed_package_inventory',{})
  node_runtime=direct.get('runtime_versions',{})
  local_source=direct.get('source_status','OK' if direct else 'UNKNOWN')
  try:
   local_timestamp=direct.get('collected_utc') or evidence.get('captured_utc')
   local_dt=datetime.fromisoformat(str(local_timestamp).replace('Z','+00:00'))
   site_fresh=bool(evidence_fresh and local_source=='OK' and local_dt.tzinfo is not None and 0 <= (now-local_dt).total_seconds() <= 26*3600)
  except (ValueError,TypeError):site_fresh=False
  cached_count=int(os_packages.get('count') or 0) if os_packages.get('complete') is True else 0
  progress={'observed_site_route':bool(direct.get('route_proven') is True),
   'guest_package_count':cached_count if site_fresh else 0,
   'last_known_guest_package_count':cached_count,
   'node_version_observed':node_runtime.get('node') if site_fresh and node_runtime.get('status')=='OK' else None,
   'component_evidence_fresh':site_fresh,
   'component_source_status':local_source,
   'app_dependency_sbom_complete':bool(direct.get('full_app_sbom') is True),
   'vendor_affected_range_checked':bool(direct.get('vendor_affected_range_checked') is True),
   'vulnerability_exposure_status':'UNKNOWN'}
  entry={'site':site,'decision_now':d['decision'],'focus_now':top,
   'component_evidence_progress':progress,
   'decision_id':d.get('decision_id'),
   'threat_intelligence_coverage':data['threat_intelligence_coverage'],
   'lessons':{},
   'experience_only_no_self_granted_bans':True}
  for key,lesson in TOPICS.items():
   # Gate knowledge on independent evidence rather than accumulating lesson text.
   passed=False
   if key=='ORIGINAL_SOURCE_IDENTITY':passed=telemetry.get('origin_ip_verified') is True
   if key=='APPLICATION_VULNERABILITY':passed=(covered.get('service_route_proven')=='VERIFIED'
      and covered.get('package_scan_scope')=='COMPLETE_SBOM_WITH_VENDOR_MATCH')
   if key=='INDEPENDENT_AVAILABILITY':passed=telemetry.get('independent_upstream_resource_telemetry') is True
   if key=='FALSE_POSITIVE_CALIBRATION':passed=bool(asset.get('site_verified_false_positive_benchmark',{}).get(site))
   if key=='THREAT_FEED_RELIABILITY':passed=feed_ok
   # Multiple temporal windows alone aren't proof of campaign attribution.
   if key=='TEMPORAL_DISCRIMINATION':passed=False
   entry['lessons'][key]={**lesson,'status':'READY_FOR_INDEPENDENT_EVALUATION' if passed else 'EVIDENCE_GAP'}
  data['agents'][name]=entry
 return data
def persist(data):
 old=load(STATE)
 counts=dict(old.get('observed_decision_transitions',{}))
 latest=dict(old.get('last_decision_ids',{}))
 for name,row in data['agents'].items():
  sig=row.get('decision_id')
  if sig and latest.get(name)!=sig:
   counts[name]=min(int(counts.get(name,0))+1,100000000)
   latest[name]=sig
  row['observed_decision_transitions']=counts.get(name,0)
  row['mastery_claimed']=False
 data['promotion']='NONE'
 save(OUT,data)
 save(STATE,{'observed_decision_transitions':counts,'last_decision_ids':latest,
             'last_generated_utc':data['generated_utc']})
 return data
def main(decisions,intel,asset,telemetry):
 return persist(evaluate(decisions,intel,asset,telemetry))
