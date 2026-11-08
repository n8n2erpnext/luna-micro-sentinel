#!/usr/bin/env python3
import re,json,sqlite3,ipaddress,hashlib,math,sys
from urllib.parse import urlsplit
from pathlib import Path
from datetime import datetime,timezone
from collections import Counter,defaultdict
ROOT=Path('/home/ubuntu/services/micro-sentinel'); DB=ROOT/'state/sentinel.db'
CURSOR=ROOT/'state/proxy_cursor.json'
PROXY=Path('/home/ubuntu/proxy_logs/access.log'); F2B=Path('/var/log/fail2ban.log')
KNOW=ROOT/'knowledge/foundation.json'
PROBE_WORDS=('env','git','wp-','phpmyadmin','cgi-bin','config','backup','shell','passwd','actuator','vendor','server-status')
AUTH_PATH_MARKERS=('/login','/signin','/sign-in','/wp-login','/oauth/token','/session/login','/auth/login')
TRAVERSAL_MARKERS=('../','..%2f','%2e%2e','%252e%252e','/etc/passwd','/etc/shadow','/proc/self/','win.ini','boot.ini')
ADMIN_MARKERS=('/admin','/administrator','/wp-admin','/phpmyadmin','/manager/html','/console','/actuator','/debug','/server-status')
FRAMEWORK_MARKERS=('/wp-login.php','/xmlrpc.php','/vendor/phpunit','/cgi-bin/','/jenkins/','/solr/')
BACKUP_SUFFIXES=('.bak','.backup','.old','.orig','.save','.sql','.dump','.swp','~')
ENUM_METHODS={'TRACE','PROPFIND','PROPPATCH','MKCOL','COPY','MOVE','LOCK','UNLOCK','SEARCH','CONNECT'}
SECRET_PATHS=('/.aws/credentials','/.docker/config.json','/.kube/config')
SAFE_METHODS={'GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS'}
def conn():
 c=sqlite3.connect(DB); c.executescript('''
 CREATE TABLE IF NOT EXISTS observations(id TEXT PRIMARY KEY,ts TEXT,src TEXT,subnet TEXT,host TEXT,method TEXT,path TEXT,status INT,features TEXT);
 CREATE TABLE IF NOT EXISTS learned_patterns(day TEXT,pattern TEXT,scope TEXT,count INT,confidence REAL,state TEXT,evidence TEXT,PRIMARY KEY(day,pattern,scope));
 CREATE TABLE IF NOT EXISTS daily_v2(day TEXT PRIMARY KEY,self_json TEXT,independent_json TEXT,knowledge_hash TEXT,created TEXT);
 '''); return c
def subnet(ip):
 try:return str(ipaddress.ip_network(ip+'/24',strict=False))
 except:return 'unknown'
def kid(): return hashlib.sha256(KNOW.read_bytes()).hexdigest()[:16]
def oid(*xs): return hashlib.sha256('|'.join(map(str,xs)).encode()).hexdigest()
def cursor_load(path):
 try:x=json.loads(CURSOR.read_text())
 except:x={}
 st=path.stat(); off=int(x.get('offset',0)) if x.get('inode')==st.st_ino else 0
 return {'offset':off if off<=st.st_size else 0,'inode':st.st_ino}
def cursor_save(path,offset):
 st=path.stat(); CURSOR.write_text(json.dumps({'inode':st.st_ino,'offset':offset}))
def clean_path(path):
 try:path=urlsplit(path or '/').path or '/'
 except:path=(path or '/').split('?',1)[0].split('#',1)[0]
 out=[]
 for seg in path.split('/'):
  if re.match(r'^[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,}$',seg): seg='{uuid}'
  elif re.match(r'^[0-9a-fA-F]{16,}$',seg): seg='{hexid}'
  elif re.match(r'^\d{5,}$',seg): seg='{numid}'
  elif re.match(r'^[A-Za-z0-9_-]{24,}$',seg): seg='{opaque}'
  out.append(seg)
 return '/'.join(out) or '/'
def features(method,path,status):
 path=clean_path(path); low=path.lower(); f=[]
 if low in SECRET_PATHS or any(w in low for w in PROBE_WORDS): f.append('probe_path')
 if any(x in low for x in TRAVERSAL_MARKERS): f.extend(['probe_path','path_traversal_indicator'])
 if any(x in low for x in ADMIN_MARKERS): f.append('admin_surface_discovery')
 if any(x in low for x in FRAMEWORK_MARKERS): f.append('framework_fingerprint_probe')
 if low.endswith(BACKUP_SUFFIXES): f.extend(['probe_path','backup_artifact_discovery'])
 if any(x in low for x in ('/.env','/.git','/.svn','/.hg','/.aws/','/.docker/','/.kube/')): f.extend(['probe_path','sensitive_discovery'])
 if method in ENUM_METHODS: f.extend(['unusual_method','method_capability_probe'])
 if status in (401,403): f.append('access_denied')
 if status==404: f.append('not_found')
 if status>=500: f.append('server_error_nonhostile_prior')
 return list(dict.fromkeys(f))
def ingest():
 c=conn(); n=0
 if PROXY.exists():
  cur=cursor_load(PROXY)
  with PROXY.open(errors='ignore') as f:
   f.seek(cur['offset'])
   for line in f:
    if 'response:' not in line: continue
    m=re.search(r'^(\S+).*?method=(\S+) host=(\S+) path=(\S+) status=(\d+).*?source=([0-9a-fA-F:.]+)',line)
    if not m: continue
    ts,method,host,path,status,src=m.groups(); status=int(status); path=clean_path(path); fs=features(method,path,status)
    c.execute('INSERT OR IGNORE INTO observations VALUES(?,?,?,?,?,?,?,?,?)',(oid(ts,src,host,method,path,status),ts,src,subnet(src),host,method,path,status,json.dumps(fs))); n+=c.execute('select changes()').fetchone()[0]
   cursor_save(PROXY,f.tell())
 c.commit(); c.close(); return n
def rows_for(c,day):
 return c.execute('select ts,src,subnet,host,method,path,status,features from observations where ts like ?',(day+'%',)).fetchall()
def derive(rows):
 bysrc=defaultdict(list); bysub=defaultdict(list); byhost=Counter(); statuses=Counter(); methods=Counter()
 for r in rows:
  bysrc[r[1]].append(r); bysub[r[2]].append(r); byhost[r[3]]+=1; statuses[str(r[6])]+=1; methods[r[4]]+=1
 patterns=[]
 for src,rs in bysrc.items():
  paths={r[5] for r in rs}; probes=sum('probe_path' in json.loads(r[7]) for r in rs)
  denied=sum(r[6] in (401,403,404) for r in rs)
  auth_denied=[r for r in rs if r[6] in (401,403) and any(m in (r[5] or '').lower() for m in AUTH_PATH_MARKERS)]
  auth_paths={r[5] for r in auth_denied}
  feat=[json.loads(r[7]) for r in rs]; fc=Counter(x for xs in feat for x in xs)
  recon_types={x for x in ('sensitive_discovery','admin_surface_discovery','backup_artifact_discovery','path_traversal_indicator','framework_fingerprint_probe') if fc[x]}
  recon_hits=sum(fc[x] for x in recon_types); traversal=fc['path_traversal_indicator']
  unusual=[r for r,xs in zip(rs,feat) if 'method_capability_probe' in xs]
  if traversal>=2:
   patterns.append(('traversal_probe_pattern',src,len(rs),min(.82,.44+.07*traversal),{'traversal_hits':traversal,'unique_paths':len(paths)}))
  if len(recon_types)>=3 and recon_hits>=6 and len(paths)>=6:
   conf=min(.90,.43+.07*len(recon_types)+.012*min(20,recon_hits)+.006*min(20,len(paths)))
   patterns.append(('recon_category_sweep',src,len(rs),conf,{'categories':sorted(recon_types),'category_count':len(recon_types),'recon_hits':recon_hits,'unique_paths':len(paths)}))
  if len(unusual)>=3 and len({r[5] for r in unusual})>=2:
   patterns.append(('method_enumeration_candidate',src,len(rs),min(.68,.42+.04*len(unusual)),{'methods':sorted({r[4] for r in unusual}),'paths':len({r[5] for r in unusual}),'alternative':'WebDAV or legitimate capability discovery remains possible'}))
  if len({r[3] for r in rs})>=3 and probes>=5 and len(recon_types)>=2:
   patterns.append(('cross_host_recon_candidate',src,len(rs),min(.78,.48+.04*len({r[3] for r in rs})+.02*len(recon_types)),{'hosts':len({r[3] for r in rs}),'probe_hits':probes,'categories':sorted(recon_types)}))
  if len(auth_denied)>=12 and len(auth_denied)/max(1,len(rs))>=.5:
   conf=min(.8,.48+.012*len(auth_denied)+.03*min(3,len(auth_paths)))
   patterns.append(('auth_retry_pattern',src,len(rs),conf,{'auth_denied':len(auth_denied),'auth_paths':len(auth_paths),'scope_rule':'source_level_denied_auth_routes'}))
  if len(paths)>=8 and probes>=2: patterns.append(('broad_probe',src,len(rs),min(.95,.45+.03*len(paths)+.04*probes),{'unique_paths':len(paths),'probe_hits':probes}))
  elif probes>=2: patterns.append(('targeted_probe',src,len(rs),min(.85,.4+.08*probes),{'probe_hits':probes,'denied':denied}))
 for sn,rs in bysub.items():
  ips={r[1] for r in rs}; probes=sum('probe_path' in json.loads(r[7]) for r in rs)
  if len(ips)>=3 and probes>=3: patterns.append(('distributed_subnet_probe',sn,len(rs),min(.98,.5+.025*len(ips)+.035*probes),{'sources':len(ips),'probe_hits':probes}))
 return patterns,bysrc,bysub,byhost,statuses,methods

def f2b_bans(day):
 if not F2B.exists(): return 0
 return sum(day in x and ' Ban ' in x for x in F2B.open(errors='ignore'))
def report(day=None):
 day=day or datetime.now().strftime('%Y-%m-%d'); c=conn(); rows=rows_for(c,day); pats,bysrc,bysub,hosts,statuses,methods=derive(rows)
 prev=c.execute('select day,self_json from daily_v2 where day<? order by day desc limit 1',(day,)).fetchone()
 c.execute('delete from learned_patterns where day=?',(day,))
 learned=[]
 for p,scope,count,conf,ev in pats:
  state='stable' if conf>=.8 else 'emerging'
  c.execute('insert or replace into learned_patterns values(?,?,?,?,?,?,?)',(day,p,scope,count,conf,state,json.dumps(ev,sort_keys=True)))
  learned.append({'pattern':p,'scope':scope,'observations':count,'confidence':round(conf,3),'state':state,'evidence':ev})
 normal=sum(not json.loads(r[7]) or json.loads(r[7])==['server_error_nonhostile_prior'] for r in rows)
 selfr={'day':day,'role':'SELF_INTERPRETATION','authority':'OBSERVE_ONLY','knowledge_version':kid(),'observations':len(rows),'normal_like':normal,'unique_sources':len(bysrc),'unique_subnets':len(bysub),'learned_patterns':learned,'baseline':{'methods':methods.most_common(8),'statuses':statuses.most_common(10),'hosts':hosts.most_common(10)},'previous_day':prev[0] if prev else None,'epistemic_rule':'patterns are hypotheses; evidence ledger is authority'}
 independent={'day':day,'role':'INDEPENDENT_DETERMINISTIC_AUDIT','observations':len(rows),'unique_sources':len(bysrc),'unique_subnets':len(bysub),'fail2ban_bans':f2b_bans(day),'probe_feature_hits':sum('probe_path' in json.loads(r[7]) for r in rows),'denied_or_missing':sum(r[6] in (401,403,404) for r in rows),'server_errors':sum(r[6]>=500 for r in rows),'derived_pattern_count':len(pats),'cross_check':'PASS' if len(learned)==len(pats) else 'FAIL'}
 c.execute('insert or replace into daily_v2 values(?,?,?,?,?)',(day,json.dumps(selfr),json.dumps(independent),kid(),datetime.now(timezone.utc).isoformat())); c.commit(); c.close()
 (ROOT/'reports/self'/f'{day}.json').write_text(json.dumps(selfr,indent=2)); (ROOT/'reports/independent'/f'{day}.json').write_text(json.dumps(independent,indent=2))
 import subprocess
 subprocess.run(['/usr/bin/python3',str(ROOT/'bin/sentinel_memory.py')],check=True,capture_output=True,text=True)
 subprocess.run(['/usr/bin/python3',str(ROOT/'bin/sentinel_reflect.py')],check=True,capture_output=True,text=True)
 guard=subprocess.run(['/usr/bin/python3',str(ROOT/'bin/sentinel_guard.py')],check=True,capture_output=True,text=True)
 guard_state=json.loads(guard.stdout).get('state','FAIL')
 if guard_state!='PASS': raise RuntimeError('independent guard failed after learning cycle')
 # Post-training operations: do not enqueue raw heuristic alerts.
 # Evidence remains in SQLite; vetted Guardian V2 handles Telegram notifications.
 return selfr,independent
def main():
 n=ingest(); s,i=report(); print(json.dumps({'new_observations':n,'self':s,'independent':i},indent=2))
if __name__=='__main__': main()
