#!/usr/bin/env python3
"""Per-agent, read-only sanitized external intelligence bridge.

Never runs commands contained in feeds, changes detection/ban policy, sends
visitor IPs to third parties or writes into guarded cognition regions.
Both agents see the SAME global intelligence; only action scope differs.
"""
from datetime import datetime,timezone,timedelta
from pathlib import Path
import argparse,json,os,re

ROOT=Path('/home/ubuntu/services')
TI=ROOT/'sentinel-threat-intel'
GUARD=ROOT/'sentinel-site-guardian'
AGENTS={'Luna':'micro-sentinel','Selene':'micro-sentinel-b'}
CVE=re.compile(r'^CVE-20\d{2}-\d{4,9}$')
def load(p):
 try:return json.loads(p.read_text())
 except (ValueError,FileNotFoundError):return {}
def parse_dt(v):
 try:return datetime.fromisoformat(v.replace('Z','+00:00')).astimezone(timezone.utc)
 except (AttributeError,ValueError):return None
def brief(agent):
 assignments=load(GUARD/'owner_assignments.json')
 assert assignments['enforcement_enabled'] is False
 wanted=assignments['agents'][agent]['assigned_hostname']
 evidence=load(TI/'reports/intake_latest.json')
 merged=load(TI/'reports/correlations_latest.json')
 articles=load(TI/'reports/publisher_articles_latest.json')
 now=datetime.now(timezone.utc)
 received=parse_dt(evidence.get('generated_utc'))
 merged_at=parse_dt(merged.get('created_utc'))
 good=bool(received and merged_at and now-received < timedelta(hours=4) and now-merged_at < timedelta(hours=4))
 original=merged.get('agents',{}).get(agent,{})
 if good and original.get('assigned_site')!=wanted:good=False
 sources=evidence.get('sources',{})
 cves=[]
 if good:
  for row in merged.get('priority_cves',[])[:12]:
   cid=row.get('cve')
   if CVE.fullmatch(str(cid)):
    cves.append({'cve':cid,'vendor':str(row.get('vendor',''))[:65],
       'product':str(row.get('product',''))[:100],
       'known_exploited_in_wild':True,
       'local_asset_match':'UNKNOWN_NOT_VERIFIED',
       'local_compromise_proven':False})
 report={'version':'AGENT_INTEL_BRIDGE_S1',
   'agent':agent,'assigned_host':wanted,'global_log_visibility_unchanged':True,
   'intelligence_global_shared':True,
   'external_data_only_no_instructions':True,
   'source_age_checked':True,
   'intelligence_state':'FRESH' if good else 'STALE_OR_MISSING',
   'feed_sources_fresh':sum(v.get('fresh') is True for v in sources.values()) if good else 0,
   'feed_sources_available':len(sources) if good else 0,
   'publisher_article_count':min(6,int(articles.get('article_count',0))) if good else 0,
   'publisher_articles_untrusted_data_path':str(TI/'reports/publisher_articles_latest.json') if good else None,
   'external_articles_are_reference_only':True,
   'local_site_observed_sources':int(original.get('unique_sources_on_site',0)) if good else None,
   'local_external_reputation_overlap':int(original.get('reputation_overlap_count',0)) if good else None,
   'new_kevs_priority_list':cves,
   'zero_day_status':'MONITORING_PUBLIC_PUBLISHER_INTEL_NOT_PREDICTING_UNDISCLOSED_ZERO_DAYS',
   'missing':['verified_local_SBOM_and_advisory_affected_ranges',
      'trusted_proxy_origin_ip_at_enforcement_point','hostname_scoped_ban_backend',
      'independent_DDoS_resource_or_latency_telemetry'],
   'crowdsec_cti':'API_KEY_REQUIRED',
   'threatfox':'AUTH_KEY_REQUIRED',
   'website_authority':'OBSERVE_ONLY',
   'external_intelligence_may_ban':False,
   'ban_commands_run':0,
   'last_shared_refresh':evidence.get('generated_utc') if good else None}
 dest=ROOT/AGENTS[agent]/'reports/threat_intelligence/latest.json'
 dest.parent.mkdir(parents=True,exist_ok=True)
 temp=dest.with_suffix('.new');temp.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
 temp.replace(dest)
 return report
def main():
 p=argparse.ArgumentParser();p.add_argument('--agent',required=True,choices=list(AGENTS))
 args=p.parse_args()
 result=brief(args.agent)
 print(json.dumps({'agent':result['agent'],'status':result['intelligence_state'],
  'sources_fresh':result['feed_sources_fresh'],'own_site':result['assigned_host'],
  'kevs_to_review':len(result['new_kevs_priority_list']),
  'reputation_matches':result['local_external_reputation_overlap'],
  'authority':result['website_authority']},ensure_ascii=False))
if __name__=='__main__':main()
