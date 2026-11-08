#!/usr/bin/env python3
import json,sqlite3,hashlib,sys
from pathlib import Path
from datetime import datetime,timedelta
ROOT=Path('/home/ubuntu/services/micro-sentinel'); DB=ROOT/'state/sentinel.db'
CFG=ROOT/'config/knowledge_ladder.json'; STATE=ROOT/'state/ladder/state.json'
def load(p,default=None):
 try:return json.loads(p.read_text())
 except:return default if default is not None else {}
def save(x):STATE.parent.mkdir(parents=True,exist_ok=True); STATE.write_text(json.dumps(x,indent=2))
def today():return datetime.now().date()
def init():
 s=load(STATE,{}); s.setdefault('started',str(today())); s.setdefault('unlocked',[]); s.setdefault('last_unlock',None); s.setdefault('locked_until',None); s.setdefault('violations',[]); save(s); return s
def guard():return load(ROOT/'reports/guard/latest.json',{})
def observations():
 c=sqlite3.connect(DB); n=c.execute('select count(*) from observations').fetchone()[0]; c.close(); return n
def reflection_ok():
 p=ROOT/'reports/reflection'/f'{today()}.json'
 if p.exists():return True
 try:
  import sentinel_reflect; sentinel_reflect.build(str(today()))
 except Exception:return False
 return p.exists()
def status():
 cfg=load(CFG); s=init(); unlocked=s['unlocked']; nxt=len(unlocked)+1
 locked=s.get('locked_until'); lock=bool(locked and today()<datetime.fromisoformat(locked).date())
 return {'name':cfg['name'],'current_level':len(unlocked),'next_level':nxt if nxt<=14 else None,'unlocked':unlocked,'locked':lock,'locked_until':locked,'guard':guard().get('state'),'observations':observations(),'reflection_today':reflection_ok()}
def evaluate():
 cfg=load(CFG); s=init(); st=status(); nxt=st['next_level']
 if not nxt:return {'state':'COMPLETE','status':st}
 if st['locked']:return {'state':'REWARD_LOCKED','status':st}
 lv=cfg['levels'][nxt-1]; start=datetime.fromisoformat(s['started']).date(); age=(today()-start).days+1
 reasons=[]
 if guard().get('state')!='PASS':reasons.append('guard_not_pass')
 if observations()<cfg['pass']['minimum_observations']:reasons.append('insufficient_observations')
 if not reflection_ok():reasons.append('reflection_missing')
 if age<lv['requires_days']:reasons.append('minimum_day_not_reached')
 if s.get('last_unlock')==str(today()):reasons.append('one_reward_per_day')
 return {'state':'READY_FOR_REVIEW' if not reasons else 'WAIT','level':lv['level'],'title':lv['title'],'reasons':reasons,'status':st}
def unlock():
 cfg=load(CFG); s=init(); ev=evaluate()
 if ev['state']!='READY_FOR_REVIEW':return ev
 lv=cfg['levels'][ev['level']-1]; src=ROOT/'knowledge'/lv['file']; reward=load(src)
 digest=hashlib.sha256(src.read_bytes()).hexdigest(); s['unlocked'].append({'level':lv['level'],'title':lv['title'],'day':str(today()),'sha256':digest}); s['last_unlock']=str(today()); save(s)
 out={'state':'REWARD_UNLOCKED','level':lv['level'],'title':lv['title'],'knowledge':reward,'sha256':digest}; (ROOT/'reports/ladder'/f"level-{lv['level']:02d}-{today()}.json").write_text(json.dumps(out,indent=2)); return out
def violate(reason):
 s=init(); until=today()+timedelta(days=1); s['locked_until']=str(until); s['violations'].append({'day':str(today()),'reason':reason,'reward_locked_until':str(until)}); save(s)
 return {'state':'REWARD_LOCKED_24H','reason':reason,'until':str(until),'observation_continues':True,'authority':'OBSERVE_ONLY'}
def main():
 q=sys.argv[1] if len(sys.argv)>1 else 'status'
 out=unlock() if q=='unlock' else evaluate() if q=='evaluate' else violate(' '.join(sys.argv[2:]) or 'rule_violation') if q=='violate' else status()
 print(json.dumps(out,indent=2))
if __name__=='__main__':main()
