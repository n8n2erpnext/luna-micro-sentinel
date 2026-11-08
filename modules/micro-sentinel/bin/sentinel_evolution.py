#!/usr/bin/env python3
import html,json,secrets,sqlite3,sys
from pathlib import Path
from datetime import datetime,timezone
ROOT=Path('/home/ubuntu/services/micro-sentinel'); DB=ROOT/'state/sentinel.db'
def db():
 c=sqlite3.connect(DB); c.execute('''CREATE TABLE IF NOT EXISTS sentinel_events(id INTEGER PRIMARY KEY AUTOINCREMENT,generation INT,event_type TEXT,state TEXT,created_at TEXT,payload TEXT,delivered_at TEXT,UNIQUE(generation,event_type,state))''')
 c.execute('''CREATE TABLE IF NOT EXISTS evolution_approvals(generation INT PRIMARY KEY,challenge TEXT,status TEXT,requested_at TEXT,approved_at TEXT,route TEXT)'''); return c
def budget():
 sys.path.insert(0,str(ROOT/'bin')); from sentinel_budget import snapshot; return snapshot()
def emit_capacity():
 b=budget(); state=b['state']; gen=b['generation']; c=db()
 if state in ('WARNING','LIMIT_REACHED'):
  challenge=secrets.token_hex(4).upper() if state=='LIMIT_REACHED' else None
  payload={'generation':gen,'state':state,'ratios':b['ratios'],'challenge':challenge}
  c.execute('insert or ignore into sentinel_events(generation,event_type,state,created_at,payload) values(?,?,?,?,?)',(gen,'CAPACITY',state,datetime.now(timezone.utc).isoformat(),json.dumps(payload)))
  if state=='LIMIT_REACHED':c.execute('insert or ignore into evolution_approvals values(?,?,?,?,?,?)',(gen,challenge,'AWAITING_APPROVAL',datetime.now(timezone.utc).isoformat(),None,None))
 c.commit(); c.close(); return b
def capacity_text():
 b=emit_capacity(); peak=max(b['ratios'].items(),key=lambda x:x[1]); pct=peak[1]*100
 lines=['<b>🧬 Sentinel — learning capacity</b>','',f"• Generation: <b>{b['generation']}</b>",f"• State: <b>{html.escape(b['state'])}</b>",f"• Peak: <b>{pct:.1f}%</b> · {html.escape(peak[0])}"]
 c=db(); a=c.execute('select challenge,status from evolution_approvals where generation=?',(b['generation'],)).fetchone(); c.close()
 if a:lines += ['',f"• Evolution: <b>{html.escape(a[1])}</b>",f"• Challenge: <code>{html.escape(a[0])}</code>",f"Approve: <code>/sentinel_approve {b['generation']} {html.escape(a[0])}</code>"]
 lines += ['','<i>Sentinel không thể tự tăng budget hoặc tự train.</i>']; return '\n'.join(lines)
def approve(gen,challenge):
 c=db(); row=c.execute('select challenge,status from evolution_approvals where generation=?',(gen,)).fetchone()
 if not row:c.close(); return '❌ Không có evolution request đang chờ cho generation này.'
 if row[1]!='AWAITING_APPROVAL':c.close(); return f'ℹ️ Generation {gen}: {html.escape(row[1])}.'
 if not secrets.compare_digest(row[0],challenge.upper()):c.close(); return '❌ Challenge không đúng.'
 now=datetime.now(timezone.utc).isoformat(); c.execute("update evolution_approvals set status='APPROVED_FOR_MAINTAINER_REVIEW',approved_at=?,route='AUTHORIZED_TELEGRAM_COMMAND' where generation=?",(now,gen)); c.commit(); c.close()
 return f'✅ Generation {gen}: <b>APPROVED_FOR_MAINTAINER_REVIEW</b>.\n\n<i>Approval chỉ mở maintainer review/tune offline; Sentinel vẫn không tự train, không tự sửa code và không có quyền enforcement.</i>'
def poll():
 emit_capacity(); c=db(); row=c.execute("select id,payload from sentinel_events where delivered_at is null order by id limit 1").fetchone()
 if not row:c.close(); return ''
 i,p=row; x=json.loads(p); state=x['state']; gen=x['generation']; peak=max(x['ratios'].items(),key=lambda z:z[1])
 title='⚠️ MICRO SENTINEL — LEARNING BUDGET WARNING' if state=='WARNING' else '🧬 MICRO SENTINEL — EVOLUTION REQUIRED'
 lines=[f'<b>{title}</b>','',f'Generation <b>{gen}</b> · capacity <b>{peak[1]*100:.1f}%</b> ({html.escape(peak[0])})']
 if state=='LIMIT_REACHED':lines += ['Learning promotion/expansion is gated pending approval.',f"Challenge: <code>{html.escape(x['challenge'])}</code>",f"<code>/sentinel_approve {gen} {html.escape(x['challenge'])}</code>"]
 c.execute('update sentinel_events set delivered_at=? where id=?',(datetime.now(timezone.utc).isoformat(),i)); c.commit(); c.close(); return '\n'.join(lines)
def main():
 cmd=sys.argv[1] if len(sys.argv)>1 else 'capacity'
 if cmd=='capacity':print(capacity_text())
 elif cmd=='poll':print(poll())
 elif cmd=='approve' and len(sys.argv)==4:
  try:gen=int(sys.argv[2])
  except ValueError:print('❌ Generation không hợp lệ.'); return
  print(approve(gen,sys.argv[3]))
 else:print('usage: sentinel_evolution.py capacity|poll|approve GEN CHALLENGE')
if __name__=='__main__':main()
