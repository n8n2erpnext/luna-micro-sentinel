#!/usr/bin/env python3
import json,sqlite3,sys
from pathlib import Path
from datetime import datetime,date
ROOT=Path('/home/ubuntu/services/micro-sentinel'); DB=ROOT/'state/sentinel.db'
def db():
 c=sqlite3.connect(DB); c.executescript('''
 CREATE TABLE IF NOT EXISTS pattern_memory(
 pattern TEXT,scope TEXT,first_seen TEXT,last_seen TEXT,days_seen INT,total_observations INT,
 confidence REAL,state TEXT,missing_days INT,evidence TEXT,PRIMARY KEY(pattern,scope));
 CREATE TABLE IF NOT EXISTS memory_history(
 day TEXT,pattern TEXT,scope TEXT,event TEXT,old_state TEXT,new_state TEXT,old_conf REAL,new_conf REAL,detail TEXT);
 '''); return c
def transition(days,missing,conf):
 if missing>=30:return 'retired'
 if missing>=7:return 'decaying'
 if days>=3 and conf>=.72:return 'stable'
 return 'emerging'
def update(day=None):
 day=day or datetime.now().strftime('%Y-%m-%d'); c=db()
 try:
  from sentinel_budget import metrics
  _,_,_,capacity_state=metrics()
 except Exception: capacity_state='UNKNOWN'
 promotion_frozen=capacity_state=='LIMIT_REACHED'
 todays=c.execute('select pattern,scope,count,confidence,state,evidence from learned_patterns where day=?',(day,)).fetchall(); seen=set()
 for p,s,n,conf,_,ev in todays:
  seen.add((p,s)); old=c.execute('select first_seen,last_seen,days_seen,total_observations,confidence,state,missing_days from pattern_memory where pattern=? and scope=?',(p,s)).fetchone()
  if old:
   first,last,days,total,oldc,olds,miss=old
   if last==day: continue
   days += 1; total+=n; newc=max(.05,min(.99,oldc*.65+conf*.35)); news=transition(days,0,newc)
   if promotion_frozen and olds != 'stable' and news == 'stable': news='emerging'
  else:first=day; days=1; total=n; oldc=0.; olds='none'; newc=conf; news=transition(days,0,newc)
  c.execute('insert or replace into pattern_memory values(?,?,?,?,?,?,?,?,?,?)',(p,s,first,day,days,total,newc,news,0,ev))
  event='NEW' if not old else ('STATE_CHANGE' if olds!=news else 'UPDATED')
  c.execute('insert into memory_history values(?,?,?,?,?,?,?,?,?)',(day,p,s,event,olds,news,oldc,newc,ev))
 for p,s,first,last,days,total,oldc,olds,miss,ev in c.execute('select * from pattern_memory').fetchall():
  if (p,s) in seen:continue
  gap=(date.fromisoformat(day)-date.fromisoformat(last)).days
  newc=max(.05,oldc*(.94**max(1,gap))); news=transition(days,gap,newc)
  if gap!=miss or news!=olds:
   c.execute('update pattern_memory set confidence=?,state=?,missing_days=? where pattern=? and scope=?',(newc,news,gap,p,s))
   c.execute('insert into memory_history values(?,?,?,?,?,?,?,?,?)',(day,p,s,'DECAY',olds,news,oldc,newc,json.dumps({'days_since_seen':gap})))
 c.commit(); counts=dict(c.execute('select state,count(*) from pattern_memory group by state').fetchall()); c.close(); return counts
def summary():
 c=db(); rows=c.execute('select pattern,scope,days_seen,total_observations,confidence,state,missing_days from pattern_memory order by case state when "stable" then 0 when "emerging" then 1 when "decaying" then 2 else 3 end,confidence desc limit 20').fetchall(); counts=dict(c.execute('select state,count(*) from pattern_memory group by state').fetchall()); c.close()
 return {'counts':counts,'patterns':[{'pattern':r[0],'scope':r[1],'days_seen':r[2],'observations':r[3],'confidence':round(r[4],3),'state':r[5],'missing_days':r[6]} for r in rows]}
def main():
 if len(sys.argv)>1 and sys.argv[1]=='show':print(json.dumps(summary(),indent=2));return
 print(json.dumps({'updated':update(),'memory':summary()},indent=2))
if __name__=='__main__':main()
