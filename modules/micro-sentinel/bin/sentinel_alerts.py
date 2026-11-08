#!/usr/bin/env python3
import html,json,sqlite3,sys,hashlib
from collections import Counter
from pathlib import Path
from datetime import datetime,timezone,timedelta
ROOT=Path('/home/ubuntu/services/micro-sentinel'); DB=ROOT/'state/sentinel.db'
POL=json.loads((ROOT/'config/alert_policy.json').read_text())
def db():
 c=sqlite3.connect(DB); c.execute('''CREATE TABLE IF NOT EXISTS alert_outbox(id INTEGER PRIMARY KEY AUTOINCREMENT,event_key TEXT UNIQUE,kind TEXT,severity TEXT,created_at TEXT,payload TEXT,delivered_at TEXT)'''); return c
def key(*x):return hashlib.sha256('|'.join(map(str,x)).encode()).hexdigest()
def enqueue(day=None):
 day=day or datetime.now().strftime('%Y-%m-%d'); c=db(); n=0
 for p,scope,count,conf,state,ev in c.execute('select pattern,scope,count,confidence,state,evidence from learned_patterns where day=?',(day,)):
  if p not in ('broad_probe','targeted_probe','distributed_subnet_probe'):continue
  kind='SUBNET_SCAN' if p=='distributed_subnet_probe' else 'SOURCE_ANOMALY'; severity='high' if kind=='SUBNET_SCAN' or conf>=.8 else 'medium'
  payload={'day':day,'pattern':p,'scope':scope,'count':count,'confidence':conf,'state':state,'evidence':json.loads(ev)}
  k=key(day,p,scope,json.dumps(payload['evidence'],sort_keys=True))
  c.execute('insert or ignore into alert_outbox(event_key,kind,severity,created_at,payload) values(?,?,?,?,?)',(k,kind,severity,datetime.now(timezone.utc).isoformat(),json.dumps(payload))); n+=c.execute('select changes()').fetchone()[0]
 c.commit(); c.close(); return n
def request_note(c,x,limit=96):
 day=x.get('day',''); scope=x.get('scope','')
 rows=c.execute('select method,host,path,status,features from observations where ts like ? and src=?',(day+'%',scope)).fetchall()
 if not rows:return 'insufficient request evidence'
 methods=Counter(r[0] for r in rows); hosts=Counter(r[1] for r in rows); paths=Counter(r[2] for r in rows); statuses=Counter(str(r[3]) for r in rows)
 probes=sum('probe_path' in json.loads(r[4]) for r in rows)
 top_path,n=paths.most_common(1)[0]; meth=methods.most_common(1)[0][0]; host=hosts.most_common(1)[0][0]; status=statuses.most_common(1)[0][0]
 note=f'{meth} {host}{top_path} (top {n}/{len(rows)}, status {status}, probe {probes})'
 return note[:limit-1]+'…' if len(note)>limit else note
def poll():
 c=db(); now=datetime.now(timezone.utc); since=(now-timedelta(seconds=60)).isoformat(); limit=int(POL['max_messages_per_minute'])
 sent=c.execute('select count(*) from alert_outbox where delivered_at>=?',(since,)).fetchone()[0]
 if sent>=limit:c.close(); return ''
 row=c.execute('select id,kind,severity,payload from alert_outbox where delivered_at is null order by case kind when "SUBNET_SCAN" then 0 else 1 end,id limit 1').fetchone()
 if not row:c.close(); return ''
 i,kind,sev,raw=row; x=json.loads(raw); ev=x['evidence']; conf=x['confidence']
 if kind=='SUBNET_SCAN':
  title='🚨 <b>SUBNET SCAN CORRELATION</b>'; detail=f"• Correlated sources: <b>{ev.get('sources','?')}</b>\n• Probe hits: <b>{ev.get('probe_hits','?')}</b>"
 else:
  title='⚠️ <b>BEHAVIORAL ANOMALY</b>'; detail=f"• Pattern: <b>{html.escape(x['pattern'])}</b>\n• Evidence: <code>{html.escape(json.dumps(ev,sort_keys=True))}</code>"
 note=request_note(c,x)
 text=f"<b>🅰️ Sentinel-A</b>\n{title}\n\n• Scope: <code>{html.escape(x['scope'])}</code>\n• Request view: <code>{html.escape(note)}</code>\n• Observations: <b>{x['count']}</b>\n• Confidence: <b>{conf:.2f}</b>\n{detail}\n\n<i>Hypothesis only · OBSERVE_ONLY · no automatic ban.</i>"
 c.execute('update alert_outbox set delivered_at=? where id=?',(now.isoformat(),i)); c.commit(); c.close(); return text
def stats():
 c=db(); x={'queued':c.execute('select count(*) from alert_outbox where delivered_at is null').fetchone()[0],'delivered':c.execute('select count(*) from alert_outbox where delivered_at is not null').fetchone()[0],'limit_per_minute':POL['max_messages_per_minute']}; c.close(); return json.dumps(x)
def main():
 cmd=sys.argv[1] if len(sys.argv)>1 else 'enqueue'
 if cmd=='enqueue':print(enqueue())
 elif cmd=='poll':print(poll())
 elif cmd=='stats':print(stats())
if __name__=='__main__':main()
