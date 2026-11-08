#!/usr/bin/env python3
import re,json,sqlite3,ipaddress,hashlib,statistics
from pathlib import Path
from datetime import datetime,timezone,timedelta
ROOT=Path('/home/ubuntu/services/micro-sentinel'); DB=ROOT/'state/sentinel.db'
LOGS=[Path('/home/ubuntu/proxy_logs/access.log'),Path('/var/log/fail2ban.log')]
SUSPECT=('env','git','wp-','phpmyadmin','cgi-bin','admin','config','backup','shell')

def db():
 c=sqlite3.connect(DB); c.executescript('''CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY,ts TEXT,src TEXT,subnet TEXT,kind TEXT,host TEXT,path TEXT,status INT,score REAL,evidence TEXT); CREATE TABLE IF NOT EXISTS snapshots(day TEXT PRIMARY KEY,events INT,sources INT,subnets INT,suspicious INT,bans INT,patterns TEXT,created TEXT);'''); return c

def net(ip):
 try:return str(ipaddress.ip_network(ip+'/24',strict=False))
 except:return 'unknown'
def add(c,ts,src,kind,host='',path='',status=0,score=0,evidence=''):
 key=hashlib.sha256(f'{ts}|{src}|{kind}|{host}|{path}|{status}|{evidence}'.encode()).hexdigest(); c.execute('INSERT OR IGNORE INTO events VALUES(?,?,?,?,?,?,?,?,?,?)',(key,ts,src,net(src),kind,host,path,status,score,evidence))
def ingest():
 c=db()
 p=LOGS[0]
 if p.exists():
  for line in p.open(errors='ignore'):
   if 'response:' not in line: continue
   m=re.search(r'^(\S+).*?method=(\S+) host=(\S+) path=(\S+) status=(\d+).*?source=([0-9a-fA-F:.]+)',line)
   if not m: continue
   ts,method,host,path,status,src=m.groups(); status=int(status); low=path.lower(); score=0; ev=[]
   if any(x in low for x in SUSPECT): score+=0.55; ev.append('sensitive_or_admin_path')
   if status in (401,403,404): score+=0.12; ev.append('denied_or_missing')
   if method not in ('GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS'): score+=0.1; ev.append('unusual_method')
   add(c,ts,src,'http',host,path,status,min(score,1),','.join(ev))
 p=LOGS[1]
 if p.exists():
  for line in p.open(errors='ignore'):
   m=re.search(r'^(\S+ \S+).*?\[(.*?)\].*? (Ban|Found) ([0-9a-fA-F:.]+)',line)
   if m:
    ts,jail,act,src=m.groups(); add(c,ts,src,'f2b_'+act.lower(),evidence=jail,score=.8 if act=='Ban' else .35)
 c.commit(); c.close()
def summarize(day=None):
 c=db(); day=day or datetime.now().strftime('%Y-%m-%d'); rows=c.execute("select src,subnet,kind,host,path,status,score,evidence from events where ts like ?",(day+'%',)).fetchall()
 sources=len({r[0] for r in rows}); subs={}; suspicious=0; bans=0
 for r in rows:
  subs.setdefault(r[1],[]).append(r)
  suspicious+=r[6]>=.5; bans+=r[2]=='f2b_ban'
 campaigns=[]
 for sn,rs in subs.items():
  ips={r[0] for r in rs}; hi=sum(r[6]>=.35 for r in rs)
  if len(ips)>=3 and hi>=5: campaigns.append({'subnet':sn,'sources':len(ips),'signals':hi,'events':len(rs)})
 patterns={'campaign_candidates':sorted(campaigns,key=lambda x:x['signals'],reverse=True)[:20]}
 c.execute('INSERT OR REPLACE INTO snapshots VALUES(?,?,?,?,?,?,?,?)',(day,len(rows),sources,len(subs),suspicious,bans,json.dumps(patterns),datetime.now(timezone.utc).isoformat())); c.commit()
 prev=c.execute('select day,events,sources,subnets,suspicious,bans from snapshots where day<? order by day desc limit 1',(day,)).fetchone(); c.close()
 out={'day':day,'events':len(rows),'unique_sources':sources,'unique_subnets':len(subs),'suspicious_events':suspicious,'fail2ban_bans':bans,'campaign_candidates':campaigns,'previous':prev,'authority':'OBSERVE_ONLY'}
 (ROOT/'reports'/f'{day}.json').write_text(json.dumps(out,indent=2)); return out
if __name__=='__main__': ingest(); print(json.dumps(summarize(),indent=2))