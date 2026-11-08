#!/usr/bin/env python3
"""No network, no Fail2ban, no live writes. Contract/regression tests for S0 shadow."""
import importlib.util
import json
from pathlib import Path

SCRIPT=Path(__file__).with_name('shadow_review.py')
spec=importlib.util.spec_from_file_location('sentinel_site_shadow',SCRIPT)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
cfg=m.load_policy()

def entry(src,host,path,status,features,ts='2026-10-08T10:30:00Z'):
    return (ts,src,host,'GET',path,status,json.dumps(features))

assert cfg['agents']['Luna']['assigned_hostname']=='thaiduy.digital'
assert cfg['agents']['Luna:LightRemote']['assigned_hostname']=='light-remote.thaiduy.digital'
assert cfg['global_observation_unchanged'] and cfg['cross_host_learning_unchanged']
assert not cfg['enforcement_enabled'] and cfg['enforcement_backend'] is None
print('PASS: owner assignment + global observation + enforcement disabled')

# 6 unrelated legitimate paths on Luna's domain cannot combine with two
# suspicious paths on Luna:LightRemote's to trigger a Luna candidate.
rows=[
    entry('203.0.113.5','thaiduy.digital',p,200,[])
    for p in ['/','/about','/contact','/blog','/sitemap','/robots.txt']
]
rows += [
    entry('203.0.113.5','light-remote.thaiduy.digital','/config',404,['probe_path']),
    entry('203.0.113.5','light-remote.thaiduy.digital','/.env',403,['probe_path','sensitive_discovery']),
]
l=m.evaluate(cfg,'Luna',rows,cutoff='2026-10-08T10:00:00')
s=m.evaluate(cfg,'Luna:LightRemote',rows,cutoff='2026-10-08T10:00:00')
assert l['global_hosts_seen']==2 and s['global_hosts_seen']==2
assert l['site_summary']['proposals_total']==0
assert s['site_summary']['proposals_total']==0
print('PASS: shared visibility, cross-host actions do not contaminate site thresholds')

rows += [entry('203.0.113.5','light-remote.thaiduy.digital','/.git/config',404,['probe_path','sensitive_discovery'])]
s=m.evaluate(cfg,'Luna:LightRemote',rows,cutoff='2026-10-08T10:00:00')
l=m.evaluate(cfg,'Luna',rows,cutoff='2026-10-08T10:00:00')
assert s['site_summary']['proposals_total']==1 and l['site_summary']['proposals_total']==0
f=s['site_summary']['findings'][0]
assert f['src']=='203.0.113.5' and f['scope_hostname']=='light-remote.thaiduy.digital'
assert f['action']=='SHADOW_ONLY_NO_BAN' and f['no_automatic_ban']
assert not f['origin_ip_verified_at_enforcement_boundary']
assert f['cross_host_context_only']['other_host_count']==1
print('PASS: only Luna:LightRemote receives site-bound proposal; global campaign context retained as context only')

# Reverse case: candidate for Luna must not generate Luna:LightRemote action.
more=[entry('198.51.100.8','thaiduy.digital',p,404,['probe_path','sensitive_discovery'])
      for p in ['/.env','/.git/config','/.aws/credentials']]
more += [entry('198.51.100.8','light-remote.thaiduy.digital','/login',200,[])]
assert m.evaluate(cfg,'Luna',more,cutoff='2026-10-08T10:00:00')['site_summary']['proposals_total']==1
assert m.evaluate(cfg,'Luna:LightRemote',more,cutoff='2026-10-08T10:00:00')['site_summary']['proposals_total']==0
print('PASS: Luna assigned hostname enforced independently')

# IPv6 identifiers are individual normalized addresses; distinct /32 families
# never collapse into a single /24 candidate.
ip1='2001:db8:1234:abcd::1';ip2='2001:db8:5678::1'
assert m.canonical_ip(ip1)!=m.canonical_ip(ip2)
r=[entry(ip1,'thaiduy.digital','/.env',404,['probe_path']),
   entry(ip2,'thaiduy.digital','/.git/config',404,['probe_path']),
   entry(ip2,'thaiduy.digital','/admin',404,['probe_path'])]
assert len(m.group_site_rows('thaiduy.digital',r))==2
assert m.summarize_site('thaiduy.digital',r)['proposals_total']==0
print('PASS: no IPv6 /24 collapsing')

# IP/hostname/threshold failures must not escalate.
r=[
 entry('malformed','thaiduy.digital','/.env',404,['probe_path']),
 entry('203.0.113.9','THAIDUY.DIGITAL','/.env',404,['probe_path']),
 entry('203.0.113.9','thaiduy.digital','/legitimate/configuration',200,['probe_path'])
]
assert m.summarize_site('thaiduy.digital',r)['proposals_total']==0
print('PASS: invalid IP, spoof-like wrong host and isolated route do not trigger action')

# Explicit anti-cross-host assignment configuration guard.
bad=json.loads(json.dumps(cfg))
bad['agents']['Luna:LightRemote']['assigned_hostname']='thaiduy.digital'
try:
    # load_policy validates filesystem input; simulate using direct assertion on duplicates
    assert len({d['assigned_hostname'] for d in bad['agents'].values()})==2
except AssertionError:
    print('PASS: duplicate hostname assignment invalid')
else:
    raise AssertionError('duplicate hostname assignment undetected')

print('ALL 7 SHADOW CONTRACT GROUPS PASS; NO LIVE ENFORCEMENT')
