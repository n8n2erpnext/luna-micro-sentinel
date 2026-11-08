#!/usr/bin/env python3
"""Bounded, read-only measurements for Luna/Selene daily security reports.

Reads shared NetBird Proxy response log, never stores raw paths, headers, cookies,
request IDs or client IPs. Resource and installed version evidence are inventory,
not proof of a CVE or a traffic attack.
"""
from pathlib import Path
from datetime import datetime,timedelta,timezone
from collections import Counter,defaultdict
import json,re,subprocess,statistics,os

ROOT=Path('/home/ubuntu/services')
BASE=ROOT/'sentinel-guardian-reports'
OUT=BASE/'state/telemetry_latest.json'
LOG=Path('/home/ubuntu/proxy_logs/access.log')
ASSIGN=ROOT/'sentinel-site-guardian/owner_assignments.json'
FIELD_RE=re.compile(r'(?<!\S)(host|status|duration|source|method|path)=([^\s]+)')
STAMP_RE=re.compile(r'^([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z)')
DURATION_RE=re.compile(r'^([0-9]+(?:\.[0-9]+)?)(ns|µs|us|ms|s|m)$')
BYTES=65_000_000
MAX_RECORDS=250_000
def route_class(path):
 v=str(path or '').lower().split('?',1)[0]
 if v.startswith(('/device-channel/','/desktop/','/ws/','/socket/')):return 'long_running_device_channel'
 if any(x in v for x in ('/webhook','/paddle','/billing')):return 'server_to_server_or_billing'
 if any(x in v for x in ('/login','/auth','/oauth','/session','/approve')):return 'authentication_or_pairing'
 if v.startswith(('/api/','/mcp','/operator')):return 'api_or_control'
 return 'public_pages_or_other'
def utcnow():return datetime.now(timezone.utc)
def parse_date(line):
 m=STAMP_RE.match(line)
 if not m:return None
 try:return datetime.fromisoformat(m.group(1).replace('Z','+00:00'))
 except ValueError:return None
def parse_duration(v):
 # Go net/http duration may be 12ms, 200us or 1.2s; complex durations not guessed.
 m=DURATION_RE.fullmatch(v or '')
 if not m:return None
 n=float(m.group(1));u=m.group(2)
 return n*{'ns':0.000001,'µs':0.001,'us':0.001,'ms':1,'s':1000,'m':60000}[u]
def percentile(values,frac):
 if not values:return None
 arr=sorted(values)
 return round(arr[max(0,min(len(arr)-1,int((len(arr)-1)*frac)))],1)
def sanitized(log=LOG,now=None):
 now=now or utcnow()
 earliest=now-timedelta(minutes=70)
 targets={'thaiduy.digital','light-remote.thaiduy.digital'}
 result=defaultdict(lambda:{'count':0,'5xx':0,'4xx':0,'latencies':[], 'minutes':Counter(),'status_codes':Counter(),'samples':0,'by_route':defaultdict(list)})
 global_hosts=Counter();seen=0;bad=0
 if not log.exists():return {'state':'MISSING_LOG','site_metrics':{},'global_hosts':0,'window_complete':False}
 total_size=log.stat().st_size
 with log.open('rb') as f:
  if total_size>BYTES:
   f.seek(total_size-BYTES)
   f.readline()  # skip incomplete line
  raw=f.read(BYTES)
 lines=raw.decode('utf-8','replace').splitlines()
 min_dt=None;max_dt=None
 for line in lines:
  if 'response:' not in line:continue
  dt=parse_date(line)
  if not dt or dt<earliest or dt>now+timedelta(seconds=10):continue
  fields=dict(FIELD_RE.findall(line))
  host=fields.get('host','').lower().rstrip('.')
  if not host:continue
  global_hosts[host]+=1;seen+=1
  min_dt=dt if min_dt is None or dt<min_dt else min_dt
  max_dt=dt if max_dt is None or dt>max_dt else max_dt
  if host not in targets:continue
  try:status=int(fields.get('status','0'))
  except ValueError:bad+=1;continue
  x=result[host];x['count']+=1;x['5xx']+=int(status>=500);x['4xx']+=int(400<=status<500)
  x['status_codes'][str(status)]+=1
  x['minutes'][dt.strftime('%Y-%m-%dT%H:%M')]+=1
  d=parse_duration(fields.get('duration'))
  if d is not None and len(x['latencies'])<100000:x['latencies'].append(d)
  if d is not None and len(x['by_route'][route_class(fields.get('path'))])<30000:x['by_route'][route_class(fields.get('path'))].append(d)
  x['samples']+=int(d is not None)
 summary={}
 for host in sorted(targets):
  x=result[host]
  def group(start,end):
   minutes=[(start+timedelta(minutes=i)).strftime('%Y-%m-%dT%H:%M') for i in range(int((end-start).total_seconds()/60))]
   return sum(x['minutes'][m] for m in minutes)
  five_start=now.replace(second=0,microsecond=0)-timedelta(minutes=5)
  last5=group(five_start,now.replace(second=0,microsecond=0))
  prev60=group(five_start-timedelta(minutes=60),five_start)
  # Aggregate overall p95/p99 within available 70min. This is not interval-specific latency/impact corroboration.
  summary[host]={'requests_70m':x['count'],'errors_5xx_70m':x['5xx'],
   'http_5xx_fraction_70m':round(x['5xx']/x['count'],4) if x['count'] else None,
   'http_4xx_fraction_70m':round(x['4xx']/x['count'],4) if x['count'] else None,
   'duration_samples':x['samples'],
   'p50_duration_ms':percentile(x['latencies'],.50),
   'p95_duration_ms':percentile(x['latencies'],.95),
   'p99_duration_ms':percentile(x['latencies'],.99),
   'recent_5min_rpm':round(last5/5,2),'prior_60min_rpm':round(prev60/60,2),
   'recent_5min_events':last5,'prior_60min_events':prev60,
   'top_status_codes':x['status_codes'].most_common(5),
   'route_duration_ms':{k:{'samples':len(v),'p95':percentile(v,.95),'p99':percentile(v,.99)} for k,v in x['by_route'].items()},
   'latency_warning':'Long-lived device/control requests must be analyzed separately; global p95 is not upstream saturation evidence',
   'small_sample_warning':x['count']<100,
   'origin_ip_verified':False}
 enough=min_dt is not None and min_dt<now-timedelta(minutes=65)
 return {'version':'PROXY_METRICS_2026_10_08','captured_utc':now.isoformat(),
   'state':'PASS' if enough else 'PARTIAL_WINDOW',
   'source':'NetBird Proxy response access.log',
   'duration_layer':'proxy_response_middleware_total_duration_not_upstream_cpu',
   'log_total_size':total_size,'read_tail_max_bytes':BYTES,
   'window_complete':bool(enough),'oldest_sample':min_dt.isoformat() if min_dt else None,
   'newest_sample':max_dt.isoformat() if max_dt else None,
   'global_hosts':len(global_hosts),'global_observations_70min':seen,
   'malformed_status_rows':bad,'site_metrics':summary,
   'cannot_confirm_ddos_from_this_data_alone':True,
   'no_auto_bans':True}
def docker_inventory():
 cmd=['docker','ps','--format','{{.Names}}|{{.Image}}']
 try:
  r=subprocess.run(cmd,capture_output=True,text=True,timeout=9,check=True)
  rows=[]
  for line in r.stdout.splitlines():
   if '|' not in line:continue
   name,image=line.split('|',1)
   # Only image reference, no environment/inspect secrets
   rows.append({'name':name[:90],'image_ref':image[:200],
      'version_known_from_image_tag_only':':' in image and not image.endswith(':latest'),
      'installed_software_vulnerability_verified':False})
  return {'state':'OK','containers':rows[:100],'count':len(rows)}
 except Exception as exc:return {'state':'UNAVAILABLE','error_class':type(exc).__name__,'containers':[]}
def version_snapshot():
 d=docker_inventory()
 relevant=[x for x in d['containers'] if any(v in x['name'].lower() for v in ('netbird','thaiduy-digital','lightbi','n8n'))]
 return {'captured_utc':utcnow().isoformat(),
  'sources':['Docker running images','Ubuntu /etc/os-release','host uname'],
  'docker':{'state':d['state'],'running_count':d.get('count'),'relevant_image_refs':relevant},
  'site_component_mapping':{'thaiduy.digital':['thaiduy-digital (candidate; verify routing)'],
    'light-remote.thaiduy.digital':['light-remote-direct LXD (candidate; verify routing)']},
  'lxd':{'active_guest_names':['light-remote-direct','erpnext'],
    'guest_software_versions':'NOT_OBSERVED_YET'},
  'cve_status':'NEEDS_VERIFIED_PACKAGE_SBOM_AND_VENDOR_AFFECTED_RANGE',
  'automatic_patch':False,'automatic_ban':False}
def save(path,obj):
 path.parent.mkdir(parents=True,exist_ok=True)
 tmp=path.with_suffix('.new')
 tmp.write_text(json.dumps(obj,ensure_ascii=False,indent=2)+'\n')
 tmp.replace(path);path.chmod(0o600)
if __name__=='__main__':
 d=sanitized();save(OUT,d)
 i=version_snapshot();save(BASE/'state/asset_inventory_latest.json',i)
 print(json.dumps({'state':d['state'],'global_hosts':d['global_hosts'],
  'sites':{k:{'events':x['requests_70m'],'p95_ms':x['p95_duration_ms'],
    'rpm_5m':x['recent_5min_rpm']} for k,x in d['site_metrics'].items()},
  'inventory_containers':i['docker']['running_count'],
  'no_bans':d['no_auto_bans']},ensure_ascii=False))
