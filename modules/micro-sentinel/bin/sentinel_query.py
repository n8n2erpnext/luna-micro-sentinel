#!/usr/bin/env python3
import html,json,sqlite3,sys
from pathlib import Path
from datetime import datetime
ROOT=Path('/home/ubuntu/services/micro-sentinel'); DB=ROOT/'state/sentinel.db'
def load(p):
 try:return json.loads(p.read_text())
 except:return {}
def today(): return datetime.now().strftime('%Y-%m-%d')
def learned():
 day=today(); c=sqlite3.connect(DB)
 rows=c.execute('select pattern,scope,count,confidence,state,evidence from learned_patterns where day=? order by confidence desc,count desc',(day,)).fetchall(); c.close()
 lines=['<b>🧠 Tôi đang học được gì?</b>',f'<code>{day}</code>','']
 if not rows:return '\n'.join(lines+['Chưa có learned pattern cho hôm nay.'])
 for p,scope,n,conf,state,ev in rows[:12]:
  lines.append(f"• <b>{html.escape(p)}</b> · {html.escape(state)} · {conf:.2f}")
  lines.append(f"  <code>{html.escape(scope)}</code> · {n} observations")
 lines += ['','<i>Đây là hypothesis đã học, không phải verdict.</i>']; return '\n'.join(lines)
def identity():
 x=load(ROOT/'knowledge/identity.json'); a=x.get('authority',{})
 return '\n'.join(['<b>🧭 Micro Sentinel</b>','',html.escape(x.get('mission','')),'',f"Mode: <b>{html.escape(a.get('mode','?'))}</b>",f"Continuity: {html.escape(x.get('continuity',''))}"])
def changes():
 day=today(); c=sqlite3.connect(DB)
 ds=[r[0] for r in c.execute('select distinct day from learned_patterns where day<=? order by day desc limit 2',(day,))];
 if len(ds)<2:c.close(); return '<b>📈 Learning changes</b>\n\nChưa đủ hai ngày evidence để so sánh.'
 cur={(r[0],r[1]):r for r in c.execute('select pattern,scope,count,confidence,state from learned_patterns where day=?',(ds[0],))}; prev={(r[0],r[1]):r for r in c.execute('select pattern,scope,count,confidence,state from learned_patterns where day=?',(ds[1],))}; c.close()
 new=set(cur)-set(prev); gone=set(prev)-set(cur); common=set(cur)&set(prev)
 moved=[k for k in common if abs(cur[k][3]-prev[k][3])>=.05 or cur[k][4]!=prev[k][4]]
 lines=['<b>📈 Sentinel — learning changes</b>',f'<code>{ds[1]} → {ds[0]}</code>','',f'• New: <b>{len(new)}</b>',f'• Updated: <b>{len(moved)}</b>',f'• Not observed today: <b>{len(gone)}</b>']
 for k in list(new)[:5]:lines.append(f"+ {html.escape(k[0])} · <code>{html.escape(k[1])}</code>")
 for k in moved[:5]:lines.append(f"~ {html.escape(k[0])}: {prev[k][3]:.2f} → {cur[k][3]:.2f}")
 lines += ['','<i>Not observed today ≠ disproven; decay needs history.</i>']; return '\n'.join(lines)
def memory():
 c=sqlite3.connect(DB); counts=dict(c.execute('select state,count(*) from pattern_memory group by state').fetchall())
 rows=c.execute('select pattern,scope,days_seen,total_observations,confidence,state,missing_days from pattern_memory order by confidence desc limit 12').fetchall(); c.close()
 lines=['<b>🧬 Sentinel — durable memory</b>','',f"• Emerging: <b>{counts.get('emerging',0)}</b> · Stable: <b>{counts.get('stable',0)}</b>",f"• Decaying: <b>{counts.get('decaying',0)}</b> · Retired: <b>{counts.get('retired',0)}</b>",'']
 for p,s,d,n,conf,state,miss in rows: lines.append(f"• <b>{html.escape(p)}</b> · {html.escape(state)} · {conf:.2f} · {d}d seen · {n} obs")
 lines += ['','<i>Frequency changes memory strength, never enforcement authority.</i>']; return '\n'.join(lines)
def reflect():
 r=load(ROOT/'reports/reflection'/f'{today()}.json'); g=load(ROOT/'reports/guard/latest.json')
 if not r:return '<b>🪞 Nhật ký học tập</b>\n\nChưa có reflection cho hôm nay.'
 lines=['<b>🪞 Hôm nay tôi học được gì?</b>',f"<code>{r.get('day')}</code>",'']
 for x in r.get('today_i_learned',[])[:6]:lines.append(f"• Tôi ghi nhận <b>{html.escape(x['pattern'])}</b> ({x['confidence']:.2f}) từ {x['observations']} observations.")
 if r.get('previous_day'):
  lines += ['', '<b>So với hôm qua</b>']
  for x in r.get('progress_since_yesterday',[])[:5]:lines.append(f"• {html.escape(x['pattern'])}: {x['from']:.2f} → {x['to']:.2f}")
  if not r.get('progress_since_yesterday'):lines.append('• Chưa có thay đổi confidence đủ lớn để gọi là tiến bộ.')
 else:lines += ['', 'Tôi chưa có đủ lịch sử ngày trước để tự nhận mình tiến bộ.']
 lines += ['',f"Double-check độc lập: <b>{html.escape(g.get('state','UNKNOWN'))}</b>",f"Evidence digest: <code>{html.escape(r.get('evidence_digest','?'))}</code>"]
 return '\n'.join(lines)
def main():
 q=(sys.argv[1] if len(sys.argv)>1 else 'learn').lower()
 print(identity() if q in ('brain','identity','mission') else changes() if q in ('changes','change','delta') else memory() if q in ('memory','mem') else reflect() if q in ('reflect','daily','journal') else learned())
if __name__=='__main__':main()
