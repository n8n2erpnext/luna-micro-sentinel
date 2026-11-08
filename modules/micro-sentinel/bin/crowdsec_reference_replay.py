#!/usr/bin/env python3
import json,sqlite3
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
DB=ROOT/'state/sentinel.db'
def latest():
 c=sqlite3.connect(DB)
 day=c.execute('select max(day) from learned_patterns').fetchone()[0]
 rows=c.execute('select pattern,scope,count,confidence,evidence from learned_patterns where day=? order by confidence desc,count desc limit 12',(day,)).fetchall()
 c.close(); return day,rows
def main():
 day,rows=latest(); out=[]
 for p,s,n,conf,evs in rows:
  ev=json.loads(evs)
  neighbors=[]
  missing=[]
  if p=='broad_probe':
   neighbors=['crowdsecurity/http-probing','crowdsecurity/http-crawl-non_statics','crowdsecurity/http-sensitive-files']
   missing=['exact HTTP status/method','static-resource flag','exact distinct target semantics','scenario timing bucket']
  elif p=='targeted_probe':
   neighbors=['crowdsecurity/http-probing','crowdsecurity/http-sensitive-files']
   missing=['exact request target classification','scenario timing bucket']
  elif p=='distributed_subnet_probe':
   neighbors=['CrowdSec single-source scenarios are comparison references only']
   missing=['same-source groupby equivalence; subnet coordination is a different hypothesis']
  else:
   continue
  out.append({'pattern':p,'scope':s,'observations':n,'confidence':conf,'mechanism_neighbors':neighbors,'state':'REFERENCE_CANDIDATE_ONLY','missing':missing,'actor_verdict':None})
 print(json.dumps({'day':day,'authority':'OBSERVE_ONLY','crowdsec_decisions_used_as_truth':False,'candidates':out},ensure_ascii=False,indent=2))
if __name__=='__main__': main()
