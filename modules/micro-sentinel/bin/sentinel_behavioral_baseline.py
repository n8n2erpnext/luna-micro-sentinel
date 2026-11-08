#!/usr/bin/env python3
import json,sqlite3
from collections import Counter,defaultdict
from pathlib import Path
from datetime import datetime

ROOT=Path(__file__).resolve().parents[1]
DB=ROOT/'state/sentinel.db'
OUT=ROOT/'reports/behavioral'
OUT.mkdir(parents=True,exist_ok=True)

def dist(counter):
 total=sum(counter.values()) or 1
 return {str(k):v/total for k,v in counter.items()}

def tv(a,b):
 keys=set(a)|set(b)
 return 0.5*sum(abs(a.get(k,0.0)-b.get(k,0.0)) for k in keys)

def top_delta(cur,hist,limit=5):
 keys=set(cur)|set(hist)
 rows=[(k,cur.get(k,0.0),hist.get(k,0.0),cur.get(k,0.0)-hist.get(k,0.0)) for k in keys]
 rows.sort(key=lambda x:abs(x[3]),reverse=True)
 return [{'value':k,'current':round(c,3),'baseline':round(h,3),'delta':round(d,3)} for k,c,h,d in rows[:limit]]

def build(day=None):
 day=day or datetime.now().strftime('%Y-%m-%d')
 c=sqlite3.connect(DB)
 hist_days=[r[0] for r in c.execute("select distinct substr(ts,1,10) d from observations where substr(ts,1,10)<? order by d desc limit 7",(day,))]
 days=[day]+hist_days
 if not hist_days:
  out={'day':day,'state':'WAIT','reason':'no_history','authority':'OBSERVE_ONLY','shadow_only':True}
  (OUT/'latest.json').write_text(json.dumps(out,indent=2)); c.close(); return out
 q="select substr(ts,1,10),host,method,status from observations where substr(ts,1,10) in (%s)"%(','.join('?'*len(days)))
 cur=defaultdict(lambda:{'n':0,'methods':Counter(),'statuses':Counter()})
 hist=defaultdict(lambda:{'n':0,'methods':Counter(),'statuses':Counter(),'days':set()})
 for d,host,method,status in c.execute(q,days):
  target=cur if d==day else hist
  x=target[host]; x['n']+=1; x['methods'][method]+=1; x['statuses'][str(status)]+=1
  if d!=day:x['days'].add(d)
 c.close()
 deviations=[]; ready=0
 for host,x in cur.items():
  h=hist.get(host)
  if not h or x['n']<50 or h['n']<200 or len(h['days'])<3: continue
  ready+=1
  cm,hm=dist(x['methods']),dist(h['methods']); cs,hs=dist(x['statuses']),dist(h['statuses'])
  mt,st=tv(cm,hm),tv(cs,hs)
  novel_methods=[k for k,v in x['methods'].items() if h['methods'].get(k,0)==0 and v>=3]
  novel_statuses=[k for k,v in x['statuses'].items() if h['statuses'].get(k,0)==0 and v>=3]
  if mt>=0.25 or st>=0.30 or novel_methods or novel_statuses:
   score=max(mt/0.25,st/0.30,1.0 if novel_methods or novel_statuses else 0.0)
   deviations.append({
    'host':host,'state':'UNUSUAL_UNCERTAIN','current_observations':x['n'],
    'baseline_observations':h['n'],'baseline_days':len(h['days']),
    'method_tv':round(mt,3),'status_tv':round(st,3),
    'novel_methods':sorted(novel_methods),'novel_statuses':sorted(novel_statuses),
    'method_deltas':top_delta(cm,hm),'status_deltas':top_delta(cs,hs),
    'score':round(score,3),
    'not_justified':'Distribution shift alone does not establish hostility, compromise, outage, or actor identity.'
   })
 deviations.sort(key=lambda z:z['score'],reverse=True)
 out={'day':day,'state':'PASS','authority':'OBSERVE_ONLY','shadow_only':True,
      'history_days':hist_days,'hosts_ready':ready,'deviation_count':len(deviations),
      'deviations':deviations[:20],
      'contract':'Host-specific method/status distribution shifts are behavioral evidence only; partial-day, deployment, crawler, proxy and application changes remain alternatives.'}
 (OUT/f'{day}.json').write_text(json.dumps(out,ensure_ascii=False,indent=2))
 (OUT/'latest.json').write_text(json.dumps(out,ensure_ascii=False,indent=2))
 return out

if __name__=='__main__':
 print(json.dumps(build(),ensure_ascii=False,indent=2))
