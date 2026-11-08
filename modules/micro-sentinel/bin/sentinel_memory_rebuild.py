#!/usr/bin/env python3
import sqlite3,json
from pathlib import Path
from datetime import date
ROOT=Path('/home/ubuntu/services/micro-sentinel'); DB=ROOT/'state/sentinel.db'
def transition(days,missing,conf):
 if missing>=30:return 'retired'
 if missing>=7:return 'decaying'
 if days>=3 and conf>=.72:return 'stable'
 return 'emerging'
def main():
 c=sqlite3.connect(DB); c.execute('delete from pattern_memory'); c.execute('delete from memory_history')
 days=[r[0] for r in c.execute('select distinct day from learned_patterns order by day')]
 mem={}
 for day in days:
  seen=set()
  for p,s,n,conf,_,ev in c.execute('select pattern,scope,count,confidence,state,evidence from learned_patterns where day=?',(day,)):
   k=(p,s); seen.add(k); old=mem.get(k)
   if old: first,last,ds,total,oldc,olds,miss,_=old; ds+=1; total+=n; newc=max(.05,min(.99,oldc*.65+conf*.35))
   else: first=day; ds=1; total=n; oldc=0.; olds='none'; newc=conf
   news=transition(ds,0,newc); mem[k]=(first,day,ds,total,newc,news,0,ev)
   c.execute('insert into memory_history values(?,?,?,?,?,?,?,?,?)',(day,p,s,'NEW' if not old else ('STATE_CHANGE' if olds!=news else 'UPDATED'),olds,news,oldc,newc,ev))
  for k,v in list(mem.items()):
   if k in seen:continue
   first,last,ds,total,oldc,olds,miss,ev=v; gap=(date.fromisoformat(day)-date.fromisoformat(last)).days
   newc=max(.05,oldc*(.94**max(1,gap))); news=transition(ds,gap,newc); mem[k]=(first,last,ds,total,newc,news,gap,ev)
 for (p,s),(first,last,ds,total,conf,state,miss,ev) in mem.items():
  c.execute('insert into pattern_memory values(?,?,?,?,?,?,?,?,?,?)',(p,s,first,last,ds,total,conf,state,miss,ev))
 c.commit(); print(json.dumps({'days':days,'patterns':len(mem),'history_rows':c.execute('select count(*) from memory_history').fetchone()[0]},indent=2)); c.close()
if __name__=='__main__':main()
