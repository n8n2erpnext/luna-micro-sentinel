#!/usr/bin/env python3
"""Threat Intelligence intake for Luna/Selene, public authoritative feeds only.

Network egress is allowlisted to literal publisher endpoints. Source data is
treated as UNTRUSTED DATA, not agent instructions. No arbitrary URL following,
no dynamic local-network fetch, no shell, no credential collection, no ban.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlencode, urlparse
from urllib.request import Request, build_opener, HTTPRedirectHandler, HTTPSHandler
import argparse, hashlib, ipaddress, json, re, ssl, time, xml.etree.ElementTree as ET

ROOT = Path('/home/ubuntu/services/sentinel-threat-intel')
CONFIG = ROOT / 'config.json'
DATA = ROOT / 'state'
STATUS = DATA / 'sources.json'
CVE = re.compile(r'CVE-20\d{2}-\d{4,7}', re.I)
HTML = re.compile(r'<[^>]{0,300}>')
MAX_BYTES = {'cisa_kev':8_000_000,'nvd_recent':9_000_000,'first_epss':250_000,
 'feodo_c2':600_000,'spamhaus_drop':1_500_000,'sans_diary':900_000,
 'cloudflare_security_blog':900_000,
 'sans_infocon':5000,'cisa_advisories':4_000_000,'ubuntu_security':900_000}
URLS = {
 'cisa_kev':'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
 'cisa_advisories':'https://www.cisa.gov/cybersecurity-advisories/all.xml',
 'nvd_recent':'https://services.nvd.nist.gov/rest/json/cves/2.0',
 'first_epss':'https://api.first.org/data/v1/epss',
 'feodo_c2':'https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json',
 'spamhaus_drop':'https://www.spamhaus.org/drop/drop_v4.json',
 'sans_diary':'https://isc.sans.edu/rssfeed.xml',
 'cloudflare_security_blog':'https://blog.cloudflare.com/rss/',
 'sans_infocon':'https://isc.sans.edu/infocon.txt',
 'ubuntu_security':'https://ubuntu.com/security/notices/rss.xml'}
HOSTS = {urlparse(x).hostname for x in URLS.values()}
SCHEMA = 'THREAT_INTEL_2026_10_08_1'
def utcnow():return datetime.now(timezone.utc)
def iso(v):return v.astimezone(timezone.utc).isoformat()
def parse_time(s):
 try:return datetime.fromisoformat(s.replace('Z','+00:00')).astimezone(timezone.utc)
 except (ValueError,AttributeError,TypeError):return None
def atomic(path, obj):
 path.parent.mkdir(parents=True,exist_ok=True)
 tmp=path.with_name(path.name+'.new')
 tmp.write_text(json.dumps(obj,ensure_ascii=False,separators=(',',':'))+'\n',encoding='utf-8')
 tmp.replace(path)
 path.chmod(0o600)
def clean(x,n=220):
 s=HTML.sub(' ',str(x or ''))
 s=re.sub(r'[\x00-\x1f\x7f]', ' ',s)
 s=re.sub(r'\s+',' ',s).strip()
 return s[:n]
def host_allowed_link(url):
 try:
  p=urlparse(url)
  return str(url)[:350] if p.scheme=='https' and p.hostname in HOSTS and not p.username else ''
 except (TypeError,ValueError):return ''
class NoRedirect(HTTPRedirectHandler):
 def redirect_request(self,request,fp,code,msg,headers,newurl):
  raise ValueError('Redirect prohibited (fixed publisher endpoints only)')
OPENER=build_opener(NoRedirect(),HTTPSHandler(context=ssl.create_default_context()))
def fetch(name,url):
 p=urlparse(url)
 if p.scheme!='https' or p.hostname not in HOSTS or p.username or p.port not in (443,None):
  raise ValueError('Untrusted feed URL')
 req=Request(url,headers={'User-Agent':'LightSentinel-Intelligence/1.0 (defensive, public feeds)',
    'Accept':'application/json,application/rss+xml,application/xml,text/xml,text/plain,*/*'})
 with OPENER.open(req,timeout=14) as r:
  if r.status!=200: raise ValueError(f'HTTP status {r.status}')
  cl=r.headers.get('Content-Length')
  if cl and int(cl)>MAX_BYTES[name]:raise ValueError('Size exceeds cap before reading')
  raw=r.read(MAX_BYTES[name]+1)
  if len(raw)>MAX_BYTES[name]:raise ValueError('Oversized feed')
 return raw
def extract_rss(name,raw):
 if b'<!DOCTYPE' in raw[:8000].upper() or b'<!ENTITY' in raw[:8000].upper():
  raise ValueError('DTD/entity refused')
 root=ET.fromstring(raw)
 entries=list(root.findall('.//item'))
 if not entries:entries=list(root.findall('{http://www.w3.org/2005/Atom}entry'))
 out=[]
 for entry in entries[:100]:
  def get(k):
   z=entry.find(k)
   if z is None:z=entry.find('{http://www.w3.org/2005/Atom}'+k)
   return (z.text or '') if z is not None else ''
  title=clean(get('title'),160)
  desc=clean(get('description') or get('summary'),170)
  date=clean(get('pubDate') or get('published') or get('updated'),65)
  link=get('link')
  if not link:
   node=entry.find('{http://www.w3.org/2005/Atom}link')
   if node is not None:link=node.attrib.get('href','')
  if not title:continue
  ids=sorted(set(x.upper() for x in CVE.findall(title+' '+desc)))[:8]
  # RSS headline/description are DATA. Never pass as prompt instructions.
  out.append({'title_untrusted':title,'description_untrusted':desc,'published_hint':date,
              'cves':ids,'publisher':name,'publisher_url':host_allowed_link(link)})
 if not out:raise ValueError('Empty/invalid RSS entries')
 return {'type':'publisher_headlines_untrusted','items':out,'count':len(out)}
def parse(name,raw):
 if name in ('cisa_advisories','sans_diary','ubuntu_security','cloudflare_security_blog'):
  return extract_rss(name,raw)
 if name=='sans_infocon':
  x=raw.decode('utf-8','replace').strip().lower()
  if x not in ('green','blue','yellow','orange','red'):raise ValueError('Unknown SANS Infocon')
  return {'type':'internet_global_indicator_not_site_impact','state':x,'count':1}
 if name=='cisa_kev':
  d=json.loads(raw)
  items=d['vulnerabilities']
  if not 500<=len(items)<=10000 or d.get('count')!=len(items):raise ValueError('KEV abnormal count')
  out=[]
  for x in items:
   cid=str(x.get('cveID','')).upper()
   if not CVE.fullmatch(cid):continue
   out.append({'cve':cid,'vendor':clean(x.get('vendorProject'),65),
     'product':clean(x.get('product'),100),'date_added':clean(x.get('dateAdded'),15),
     'required_action':clean(x.get('requiredAction'),140),
     'known_exploited_in_wild':True})
  return {'type':'verified_known_exploited_catalog_NOT_local_compromise',
     'catalog_version':clean(d.get('catalogVersion'),35),'items':out,'count':len(out)}
 if name=='nvd_recent':
  d=json.loads(raw);seen=[]
  for x in d.get('vulnerabilities',[]):
   obj=x.get('cve',{});cid=str(obj.get('id','')).upper()
   if not CVE.fullmatch(cid):continue
   eng=next((z.get('value','') for z in obj.get('descriptions',[]) if z.get('lang')=='en'),'')
   seen.append({'cve':cid,'published':clean(obj.get('published'),40),
      'last_modified':clean(obj.get('lastModified'),40),'description_untrusted':clean(eng,250),
      'local_affected_version_verified':False})
  return {'type':'recent_published_CVEs_not_installed_inventory',
    'items':seen,'count':len(seen),'total_published_window':int(d.get('totalResults',0)),
    'coverage_complete':len(seen)>=int(d.get('totalResults',0))}
 if name=='first_epss':
  d=json.loads(raw)
  if d.get('status')!='OK':raise ValueError('EPSS status not OK')
  out=[]
  for obj in d.get('data',[]):
   cve=str(obj.get('cve','')).upper()
   if not CVE.fullmatch(cve):continue
   val=float(obj['epss']);pct=float(obj['percentile'])
   if not (0<=val<=1 and 0<=pct<=1):raise ValueError('Bad EPSS')
   out.append({'cve':cve,'epss_probability_30d':val,
      'percentile':pct,'date':clean(obj.get('date'),30)})
  return {'type':'FIRST_prediction_not_local_exploitation','count':len(out),'items':out}
 if name=='feodo_c2':
  d=json.loads(raw)
  if not isinstance(d,list):raise ValueError('Feodo not list')
  valid=[]
  for item in d[:10000]:
   try:
    ip=str(ipaddress.ip_address(item['ip_address']))
    if not ipaddress.ip_address(ip).is_global:continue
   except (KeyError,TypeError,ValueError):continue
   seen=clean(item.get('last_online'),28)
   # Stale active C2 labels must not be treated as current.
   try:age=(utcnow().date()-datetime.fromisoformat(seen[:10]).date()).days
   except ValueError:age=9999
   valid.append({'ip':ip,'malware':clean(item.get('malware'),60),
      'last_online':seen,'age_days':age,'current_recent':0<=age<=14,
      'semantics':'known_botnet_COMMAND_CONTROL_not_inbound_attack_proof'})
  return {'type':'botnet_C2_reputation_not_site_scanner','items':valid,'count':len(valid),
    'recent_count':sum(x['current_recent'] for x in valid)}
 if name=='spamhaus_drop':
  out=[]
  for line in raw.decode('utf-8','replace').splitlines():
   try:
    obj=json.loads(line)
    net=ipaddress.ip_network(obj['cidr'],strict=True)
    if net.version!=4 or net.is_private or net.is_reserved:continue
    out.append({'cidr':str(net),'sblid':clean(obj.get('sblid'),35)})
   except (ValueError,KeyError,TypeError,json.JSONDecodeError):continue
  if len(out)<50:raise ValueError('Unexpectedly small Spamhaus DROP list')
  return {'type':'routing_prefix_THREAT_CONTEXT_NOT_global_firewall_ban','items':out,'count':len(out)}
 raise ValueError('Unexpected parser name')
def source_url(name,cache):
 if name=='nvd_recent':
  now=utcnow()
  qs=urlencode({'pubStartDate':(now-timedelta(hours=24)).strftime('%Y-%m-%dT%H:%M:%S.000'),
       'pubEndDate':now.strftime('%Y-%m-%dT%H:%M:%S.000'),'resultsPerPage':2000})
  return URLS[name]+'?'+qs
 if name=='first_epss':
  ids=[]
  for dep,sortkey in (('cisa_kev','date_added'),('nvd_recent','published')):
   candidates=sorted(cache.get(dep,{}).get('items',[]),
     key=lambda x:str(x.get(sortkey,'')),reverse=True)
   for item in candidates[:160]:
    cid=item.get('cve','')
    if CVE.fullmatch(cid) and cid not in ids:ids.append(cid)
    if len(ids)>=25:break
  if not ids:raise ValueError('No CVEs available for EPSS on-demand enrichment')
  return URLS[name]+'?'+urlencode({'cve':','.join(ids[:25])})
 return URLS[name]
def due(name,metadata,cfg,force):
 if force:return True
 entry=metadata.get(name,{})
 dt=parse_time(entry.get('last_success_utc',''))
 return not dt or (utcnow()-dt)>=timedelta(hours=float(cfg['freshness'][name+'_hours']))
def load(path):
 try:return json.loads(path.read_text())
 except (ValueError,FileNotFoundError):return {}
def main():
 p=argparse.ArgumentParser()
 p.add_argument('--force',action='store_true')
 p.add_argument('--test-source',choices=sorted(URLS),help='Fetch only selected source')
 args=p.parse_args()
 cfg=load(CONFIG)
 assert cfg['mode']=='SHADOW_INTEL_NO_ENFORCEMENT' and cfg['automatic_ban_allowed'] is False
 DATA.mkdir(parents=True,exist_ok=True)
 metadata=load(STATUS)
 cache={name:load(DATA/(name+'.json')) for name in URLS}
 names=[args.test_source] if args.test_source else [
  'cisa_kev','feodo_c2','spamhaus_drop','sans_infocon','sans_diary',
  'cisa_advisories','ubuntu_security','cloudflare_security_blog','nvd_recent','first_epss']
 selected=[n for n in names if due(n,metadata,cfg,args.force)]
 results={}
 # Fetch independent feeds in parallel; EPSS depends on the newest cached CVEs.
 tasks=[x for x in selected if x!='first_epss']
 def do(name):
  url=source_url(name,cache)
  raw=fetch(name,url)
  record=parse(name,raw)
  if len(raw)==0:raise ValueError('Empty body')
  return {'parsed':record,'sha256':hashlib.sha256(raw).hexdigest(),
     'request_host':urlparse(url).hostname,'response_bytes':len(raw)}
 with ThreadPoolExecutor(max_workers=4) as pool:
  futures={pool.submit(do,n):n for n in tasks}
  for fut in as_completed(futures):
   name=futures[fut]
   try:
    res=fut.result()
    cache[name]=res['parsed']
    atomic(DATA/(name+'.json'),res['parsed'])
    metadata[name]={'status':'OK','last_success_utc':iso(utcnow()),
      'sha256':res['sha256'],'count':res['parsed'].get('count'),
      'response_bytes':res['response_bytes'],'source_hostname':res['request_host']}
    results[name]='OK'
   except Exception as exc:
    x=metadata.get(name,{})
    x.update({'status':'STALE_OR_UNAVAILABLE','last_error_utc':iso(utcnow()),
      'error_class':type(exc).__name__,'error_note':clean(str(exc),140)})
    metadata[name]=x
    results[name]='FAILED:'+type(exc).__name__
 if 'first_epss' in selected:
  try:
   res=do('first_epss');cache['first_epss']=res['parsed']
   atomic(DATA/'first_epss.json',res['parsed'])
   metadata['first_epss']={'status':'OK','last_success_utc':iso(utcnow()),
     'sha256':res['sha256'],'count':res['parsed']['count'],
     'response_bytes':res['response_bytes'],'source_hostname':res['request_host']}
   results['first_epss']='OK'
  except Exception as exc:
   x=metadata.get('first_epss',{})
   x.update({'status':'STALE_OR_UNAVAILABLE','last_error_utc':iso(utcnow()),
     'error_class':type(exc).__name__,'error_note':clean(str(exc),140)})
   metadata['first_epss']=x
   results['first_epss']='FAILED:'+type(exc).__name__
 atomic(STATUS,metadata)
 report={'version':SCHEMA,'generated_utc':iso(utcnow()),'mode':'PUBLIC_THREAT_INTELLIGENCE_ONLY',
  'original_proxy_log_unchanged':True,'original_agent_memory_unchanged':True,
  'no_automatic_bans':True,'no_automatic_security_verdicts':True,
  'source_results':results,'sources':{},'credentials_required':['crowdsec_cti','threatfox'],
  'notes':['No direct IP bans from any threat-intelligence feed.',
   'KEV, NVD, EPSS, RSS and reputation are context until local evidence matches.',
   'Prompt injection in external descriptions is ignored as instructions.']}
 for name in URLS:
  entry=metadata.get(name,{})
  t=parse_time(entry.get('last_success_utc'))
  h=cfg['freshness'][name+'_hours']
  fresh=bool(t and (utcnow()-t).total_seconds() <= h*3600*2)
  report['sources'][name]={'status':entry.get('status','NEVER_FETCHED'),
    'fresh':fresh,'last_success_utc':entry.get('last_success_utc'),
    'count':entry.get('count'),'publisher':urlparse(URLS[name]).hostname,
    'stale_must_not_authorize_actions':True}
 dest=ROOT/'reports/intake_latest.json'
 atomic(dest,report)
 print(json.dumps({'results':results,
    'available_sources':sum(bool(s['last_success_utc']) for s in report['sources'].values()),
    'fresh_sources':sum(s['fresh'] for s in report['sources'].values()),
    'pending_keys':report['credentials_required'],
    'report':str(dest),'ban_commands':0},ensure_ascii=False))
if __name__=='__main__':main()
