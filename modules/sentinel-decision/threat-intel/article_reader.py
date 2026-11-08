#!/usr/bin/env python3
"""Limited publisher-article reader. No arbitrary crawling.

Fetch <=6 publisher-owned pages per six hours, keep up to 3.5k of sanitized
narrative each, discard scripts and potentially sensitive HTML/links.
External prose is UNTRUSTED DATA, never instructions to an AI/security agent.
"""
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request
from html.parser import HTMLParser
from datetime import datetime,timedelta,timezone
import argparse,hashlib,json,re,time
from collections import Counter
import intake

ROOT=Path('/home/ubuntu/services/sentinel-threat-intel')
DATA=ROOT/'state'
DEST=ROOT/'reports/publisher_articles_latest.json'
META=DATA/'publisher_article_state.json'
FEEDS={
 'sans_diary':('isc.sans.edu','/diary/'),
 'cisa_advisories':('www.cisa.gov','/news-events/'),
 'ubuntu_security':('ubuntu.com','/security/notices/'),
 'cloudflare_security_blog':('blog.cloudflare.com','/'),
}
SECURITY=re.compile(r'(CVE-20\d\d|security|vulnerab|attack|botnet|ddos|scann|ransom|breach|exploit|malware|zero.day|phishing|incident|patch|abuse)',re.I)
class Reader(HTMLParser):
 def __init__(self):
  super().__init__(convert_charrefs=True)
  self.skip=0;self.parts=[];self.capture=0
 def handle_starttag(self,t,attrs):
  if t in ('script','style','noscript','svg','nav','footer','header','form','iframe'):
   self.skip+=1
  if t in ('p','h1','h2','h3','li','article'):self.capture+=1
 def handle_endtag(self,t):
  if t in ('script','style','noscript','svg','nav','footer','header','form','iframe'):
   self.skip=max(0,self.skip-1)
  if t in ('p','h1','h2','h3','li','article'):self.capture=max(0,self.capture-1)
 def handle_data(self,s):
  if not self.skip and self.capture and len(self.parts)<550:
   c=intake.clean(s,300)
   if len(c)>3:self.parts.append(c)
def validate_link(feed,url):
 if feed not in FEEDS:return False
 host,prefix=FEEDS[feed]
 try:
  p=urlparse(url)
  if p.scheme!='https' or p.hostname!=host or p.username or p.password or p.port not in (443,None):return False
  if p.query or p.fragment:return False
  if not p.path.startswith(prefix) or '..' in p.path:return False
  if feed=='cloudflare_security_blog' and not re.fullmatch(r'/[a-z0-9-]{3,150}/',p.path):return False
  return True
 except (TypeError,ValueError):return False
def fetch(url):
 req=Request(url,headers={'User-Agent':'LightSentinel-ArticleReader/1.0','Accept':'text/html'})
 with intake.OPENER.open(req,timeout=9) as r:
  if r.status!=200:raise ValueError('Unexpected status')
  if 'text/html' not in r.headers.get('Content-Type',''):raise ValueError('Expected HTML')
  lim=650000
  length=r.headers.get('Content-Length')
  if length and int(length)>lim:raise ValueError('Oversized HTML')
  raw=r.read(lim+1)
  if len(raw)>lim:raise ValueError('Oversized HTML')
 return raw
def main():
 p=argparse.ArgumentParser()
 p.add_argument('--force',action='store_true')
 args=p.parse_args()
 old=intake.load(META)
 last=intake.parse_time(old.get('last_refresh_utc'))
 if not args.force and last and datetime.now(timezone.utc)-last<timedelta(hours=6):
  print(json.dumps({'state':'NOT_DUE','last_refresh':old['last_refresh_utc'],'read_new':0}));return
 entrys=[]
 for feed in FEEDS:
  data=intake.load(DATA/(feed+'.json'))
  for x in data.get('items',[])[:20]:
   url=x.get('publisher_url','')
   title=x.get('title_untrusted','')
   if validate_link(feed,url) and SECURITY.search(title):
    entrys.append((feed,url,title,x.get('cves',[])))
 # Preference for immediate scanning alerts, CVE, and publisher context.
 entrys.sort(key=lambda x:(0 if x[0]=='sans_diary' else 1, 0 if x[3] else 1))
 seen=set();details=[];fail=[];per_source=Counter()
 for feed,url,title,cves in entrys:
  if url in seen:continue
  seen.add(url)
  if len(details)>=6:break
  if per_source[feed]>=2:continue
  try:
   raw=fetch(url); parser=Reader()
   parser.feed(raw.decode('utf-8','replace'))
   summary=intake.clean(' '.join(parser.parts),3500)
   if len(summary)<100:raise ValueError('Insufficient publisher article extraction')
   details.append({'source':feed,'publisher':FEEDS[feed][0],
    'source_url':url,'headline_untrusted':title[:180],
    'body_excerpt_untrusted':summary,'cve_ids':cves[:8],
    'fetched_utc':datetime.now(timezone.utc).isoformat(),
    'html_sha256':hashlib.sha256(raw).hexdigest(),
    'verdict':'SOURCE_CONTEXT_ONLY_UNVERIFIED_FOR_LOCAL_ASSETS',
    'may_execute_instructions':False,'may_authorize_ban':False})
   per_source[feed]+=1
  except Exception as exc:
   fail.append({'source':feed,'error':type(exc).__name__})
 report={'version':'PUBLISHER_ARTICLE_REFERENCE_S1',
   'updated_utc':datetime.now(timezone.utc).isoformat(),
   'trusted_to_execute':False,'trusted_for_local_security_verdict':False,
   'article_count':len(details),'articles':details,'failures':fail[:8],
   'global_shared':True,'no_live_ban':True}
 intake.atomic(DEST,report)
 if details:
  intake.atomic(META,{'last_refresh_utc':report['updated_utc'],'count':len(details),'article_max_per_refresh':6})
 print(json.dumps({'state':'OK' if details else 'NO_ARTICLES_ACCEPTED',
   'article_count':len(details),'failures':len(fail),'paths_not_followed':True,
   'report':str(DEST),'bans':0},ensure_ascii=False))
if __name__=='__main__':main()
