#!/usr/bin/env python3
import json,subprocess,time,sqlite3,math
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
DB=ROOT/'state/sentinel.db'
def load(p,d=None):
 try:return json.loads(p.read_text())
 except:return {} if d is None else d
def run_json(args):
 cp=subprocess.run(args,check=True,capture_output=True,text=True)
 try:return json.loads(cp.stdout)
 except:return {'state':'UNKNOWN','written':False,'raw':cp.stdout}
def structural_note():
 nr=load(ROOT/'reports/network_reasoning/latest.json',{})
 cs=nr.get('candidates',[])
 if not cs:return None
 i=int((nr.get('evidence_digest') or '0')[:8],16)%len(cs); x=cs[i]
 return f"Watch {x.get('concept','unknown')}: {x.get('strongest_conclusion','candidate retained')}. Need: {x.get('missing_evidence') or x.get('not_justified') or 'independent evidence'}."
def count_bucket(n):
 n=max(0,int(n or 0))
 for b in (1,5,10,25,50,100,250,500,1000,2500,5000,10000):
  if n<=b:return b
 return int(math.ceil(n/10000.0)*10000)
def experience_notes(day):
 if not DB.exists():return []
 c=sqlite3.connect(DB); c.row_factory=sqlite3.Row
 try: rows=c.execute("select pattern,scope,count,confidence,state,evidence from learned_patterns where day=? order by count desc, confidence desc, pattern, scope",(day,)).fetchall()
 finally:c.close()
 out=[]
 for r in rows:
  pattern=str(r['pattern'] or 'unknown').replace('|','/')
  scope=str(r['scope'] or 'unknown').replace('|','/')
  concept=f"experience|{pattern}|{scope}"
  try: conf=float(r['confidence'])
  except: conf=0.0
  state=str(r['state'] or 'unknown').replace(' ','_')
  bucket=count_bucket(r['count'])
  evtxt=''
  try:
   ev=json.loads(r['evidence'] or '{}')
   allowed={k:v for k,v in ev.items() if k in ('probe_hits','unique_paths','failures','successes','subnets','sources') and isinstance(v,(str,int,float,bool))}
   if allowed: evtxt=', evidence='+json.dumps(allowed,ensure_ascii=False,separators=(',',':'))
  except: pass
  out.append(f"Watch {concept}: observed pattern={pattern}, scope={scope}, observations_bucket={bucket}, confidence={conf:.2f}, state={state}{evtxt}.")
 return out
def attempt(note):
 decision=run_json(['/usr/bin/python3',str(ROOT/'bin/sentinel_notebook_deliberate.py'),'--consider-note',note])
 result={'state':'SKIPPED','written':False,'reason':decision.get('reason')}
 if decision.get('decision')=='WRITE':
  result=run_json(['/usr/bin/python3',str(ROOT/'bin/sentinel_notebook.py'),'add',note])
 return decision,result
def main():
 day=time.strftime('%Y-%m-%d'); lanes={}
 ds=load(ROOT/'state/notebook/deliberation_state.json',{})
 status=run_json(['/usr/bin/python3',str(ROOT/'bin/sentinel_notebook.py'),'status'])
 deliberation=None
 if status.get('bytes',0)>=status.get('max_bytes',65536) or ds.get('last_day')!=day:
  deliberation=run_json(['/usr/bin/python3',str(ROOT/'bin/sentinel_notebook_deliberate.py')])
 s=structural_note()
 if s:
  d,r=attempt(s); lanes['structural']={'attempted':True,'decision':d,'wrote':bool(r.get('written')),'result':r}
 else: lanes['structural']={'attempted':False,'wrote':False}
 checked=0; written=None; last=None
 for note in experience_notes(day):
  checked+=1; d,r=attempt(note); last={'decision':d,'result':r,'note':note}
  if r.get('written'):
   written=last; break
 lanes['experience']={'attempted':checked,'wrote':bool(written),'written':written,'last_checked':None if written else last}
 final=run_json(['/usr/bin/python3',str(ROOT/'bin/sentinel_notebook.py'),'status'])
 print(json.dumps({'state':'PASS','lanes':lanes,'deliberated':bool(deliberation),'notebook':final},ensure_ascii=False))
if __name__=='__main__':main()
