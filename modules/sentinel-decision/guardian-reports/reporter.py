#!/usr/bin/env python3
"""Sentinel Guardian owner reports, safe-alert proposals and reliable outbox.

Reports are evidence-bounded. No vulnerability or DDoS claims without independent
proof. New outbox is independent of Sentinel's legacy Telegram outbox.
claim() leases one item; ack() is called ONLY after Telegram node success.
"""
from pathlib import Path
from datetime import datetime,timedelta,timezone
from zoneinfo import ZoneInfo
import argparse,html,hashlib,json,sqlite3,re
ROOT=Path('/home/ubuntu/services')
BASE=ROOT/'sentinel-guardian-reports'
DB=BASE/'state/telegram_outbox.sqlite3'
TZ=ZoneInfo('Asia/Ho_Chi_Minh')
HOSTS={'Luna':'thaiduy.digital','Selene':'light-remote.thaiduy.digital'}
MAX_MSG=3400
def load(p):
 try:return json.loads(Path(p).read_text())
 except (FileNotFoundError,ValueError):return {}
def esc(x):return html.escape(str(x),quote=False)
def now():return datetime.now(timezone.utc)
def local_date():return now().astimezone(TZ).date()
def status():
 return {
  'metrics':load(BASE/'state/telemetry_latest.json'),
  'inventory':load(BASE/'state/asset_inventory_latest.json'),
  'inventory_versions':load(BASE/'state/software_inventory_latest.json'),
  'shadow':load(ROOT/'sentinel-site-guardian/reports/cycle_status.json'),
  'temporal':load(ROOT/'sentinel-site-guardian/reports/temporal_shadow_latest.json'),
  'intel':load(ROOT/'sentinel-threat-intel/reports/intake_latest.json'),
  'correlations':load(ROOT/'sentinel-threat-intel/reports/correlations_latest.json'),
  'decisions':load(ROOT/'sentinel-site-guardian/reports/decisions_latest.json'),
  'self':{a:load(ROOT/f'micro-sentinel{"" if a=="Luna" else "-b"}/reports/reflection/{local_date().isoformat()}.json') for a in HOSTS},
  'guards':{a:load(ROOT/f'micro-sentinel{"" if a=="Luna" else "-b"}/reports/guard/latest.json') for a in HOSTS}
 }
def freshness(stamp,hours):
 try:return 0<=(now()-datetime.fromisoformat(stamp.replace('Z','+00:00'))).total_seconds()<=hours*3600
 except (ValueError,AttributeError):return False
def init():
 DB.parent.mkdir(parents=True,exist_ok=True)
 db=sqlite3.connect(DB,timeout=6)
 db.execute('PRAGMA busy_timeout=5000')
 db.execute('''CREATE TABLE IF NOT EXISTS outbox(
  id INTEGER PRIMARY KEY, event_key TEXT UNIQUE NOT NULL, kind TEXT NOT NULL,
  created_utc TEXT NOT NULL, html TEXT NOT NULL, priority INTEGER NOT NULL,
  claimed_until TEXT, attempts INTEGER NOT NULL DEFAULT 0, delivered_utc TEXT,
  telegram_message_id TEXT)''')
 db.execute('CREATE INDEX IF NOT EXISTS outbox_pending ON outbox(delivered_utc,priority,id)')
 db.commit()
 return db
def enqueue(key,kind,text,priority=5):
 assert kind in ('URGENT','DAILY','WEEKLY','SYSTEM_TEST')
 assert len(text)<=MAX_MSG,('Telegram text oversized',len(text))
 db=init()
 cur=db.execute('INSERT OR IGNORE INTO outbox(event_key,kind,created_utc,html,priority) VALUES(?,?,?,?,?)',
    (key,kind,now().isoformat(),text,priority))
 db.commit();result=cur.rowcount==1;db.close();return result
def claim():
 db=init()
 db.execute('BEGIN IMMEDIATE')
 stamp=now().isoformat()
 row=db.execute('''SELECT id,html,kind,attempts FROM outbox
     WHERE delivered_utc IS NULL AND (claimed_until IS NULL OR claimed_until<?)
       AND attempts<9 ORDER BY priority ASC,id ASC LIMIT 1''',(stamp,)).fetchone()
 if not row:db.commit();db.close();return {}
 i,body,kind,attempts=row
 expires=(now()+timedelta(minutes=4)).isoformat()
 db.execute('UPDATE outbox SET claimed_until=?,attempts=attempts+1 WHERE id=?',(expires,i))
 db.commit();db.close()
 return {'id':i,'text':body,'kind':kind,'attempt':attempts+1}
def ack(i,message_id):
 assert int(i)>0
 mid=str(message_id)
 assert re.fullmatch(r'[0-9]{1,20}',mid)
 db=init()
 cur=db.execute('UPDATE outbox SET delivered_utc=?,telegram_message_id=?,claimed_until=NULL WHERE id=? AND delivered_utc IS NULL',
     (now().isoformat(),mid,int(i)))
 db.commit();matched=cur.rowcount;db.close()
 return {'acknowledged':bool(matched),'id':int(i)}
def backlog():
 db=init()
 stats=dict(db.execute('SELECT kind,count(*) FROM outbox WHERE delivered_utc IS NULL GROUP BY kind').fetchall())
 delivered=db.execute('SELECT count(*) FROM outbox WHERE delivered_utc IS NOT NULL').fetchone()[0]
 expired=db.execute('SELECT count(*) FROM outbox WHERE delivered_utc IS NULL AND attempts>=9').fetchone()[0]
 db.close();return {'pending':stats,'delivered':delivered,'retry_exhausted':expired}
def event_age(source):
 return freshness(source.get('generated_utc',''),4)
def site_summary(name,s):
 metrics=s['metrics'].get('site_metrics',{}).get(HOSTS[name],{})
 temporal=s['temporal'].get('agents',{}).get(name,{})
 shadow=s['shadow'].get('site_guardians',{}).get(name,{})
 guard=s['guards'].get(name,{}).get('state','UNKNOWN')
 self_ref=s['self'].get(name,{})
 if not freshness(s['metrics'].get('captured_utc'),3):
  return f'• <b>{name}</b> — {esc(HOSTS[name])}: thiếu telemetry mới; guard={esc(guard)}'
 count=metrics.get('requests_70m',0)
 p95=metrics.get('p95_duration_ms')
 route=metrics.get('route_duration_ms',{})
 public=route.get('public_pages_or_other',{})
 api=route.get('api_or_control',{})
 cve='Chưa đối chiếu SBOM'
 d=s['decisions'].get('agents',{}).get(name,{})
 judgement=d.get('decision','UNAVAILABLE') if freshness(s['decisions'].get('generated_utc'),1/6) else 'STALE_DECISION'
 why=esc(str(d.get('rationale','No fresh decision'))[:200])
 subject=esc(d.get('subject','SITE'))
 finding=temporal.get('finding','UNKNOWN')
 caveat='mẫu nhỏ' if metrics.get('small_sample_warning') else 'tham khảo'
 evidence=esc('; '.join(map(str,(d.get('evidence') or [])[:2]))[:230])
 missing=esc('; '.join(map(str,(d.get('needs_to_confirm_or_refute') or [])[:2]))[:220])
 return (f'• <b>{name}</b> · <code>{esc(HOSTS[name])}</code>\n'
  f'  <b>QUYẾT ĐỊNH: {esc(judgement)}</b> · {subject}\n'
  f'  Vì sao: {why}\n'
  f'  Dẫn chứng: {evidence}; cần thêm: {missing}\n'
  f'  Mốc đề xuất đánh giá lại: {int(d.get("reassess_after_minutes") or 15)} phút\n'
  f'  <i>Đối chiếu: {count} HTTP/70p, 5xx={metrics.get("errors_5xx_70m")}, '
  f'p95 public={esc(public.get("p95","n/a"))}ms; KHÔNG BAN THẬT.</i>')
def daily():
 s=status(); today=local_date().isoformat()
 feeds=s['intel'].get('sources',{})
 valid=event_age(s['intel'])
 fresh_count=sum(v.get('fresh') is True for v in feeds.values()) if valid else 0
 candidate=sum(s['correlations'].get('agents',{}).get(n,{}).get('reputation_overlap_count',0) for n in HOSTS)
 caveat=('Lưu ý: dữ liệu feed đã cũ/thiếu.' if not valid else 'CVE/blacklist chỉ là dữ liệu tham khảo, không khẳng định máy bị khai thác.')
 lines=[f'<b>🛡️ LUNA + SELENE · TỔNG HỢP 09:30 · {esc(today)}</b>',
  '<i>Hai tác tử tự quyết định theo website; chỉ gửi quyết định, chưa có quyền ban thật.</i>',
  '',f'• Threat Intelligence: <b>{fresh_count}/{len(feeds)}</b> nguồn mới; '
      f'IP reputation trùng nguồn quan sát (2h): {candidate}.',
  f'• Mức tin cậy: {esc(caveat)}','',
  '<b>Hai website được bảo vệ</b>',
  site_summary('Luna',s),'',site_summary('Selene',s),'',
  '<b>Rủi ro/việc cần Owner</b>',
  '• Chưa xác nhận IP gốc tại điểm chặn; Fail2ban chung chưa đủ để ban theo hostname.',
  '• Kiểm kê nền: '+str(len(s['inventory_versions'].get('host',{}).get('selected_package_versions',{})))+' gói host, '+str(len(s['inventory_versions'].get('assigned_websites',{}).get('light-remote.thaiduy.digital',{}).get('selected_package_versions',{})))+' gói LXD; còn thiếu SBOM ứng dụng và dải phiên bản CVE.',
  '• Quan sát p95 của Light Remote có thể gồm long-poll; không suy ra DDoS từ p95 chung.',
  '• Các quyết định đề xuất không thực thi firewall/Fail2Ban; cần đo FP/FN theo bằng chứng.',
  f'\n<i>Telegram report · {esc(today)} · OBSERVE_ONLY</i>']
 text='\n'.join(lines)
 return text[:MAX_MSG]
def weekly():
 s=status(); today=local_date()
 p=ROOT/'sentinel-site-guardian/reports/training_progress.jsonl'
 rows=[]
 if p.exists():
  for line in p.read_text(errors='replace').splitlines()[-20000:]:
   try:
    d=json.loads(line);dt=datetime.fromisoformat(d.get('time_utc','').replace('Z','+00:00'))
    if now()-dt<=timedelta(days=7):rows.append(d)
   except (ValueError,TypeError):pass
 num=len(rows)
 agentlines=[]
 for name in HOSTS:
  count=sum(bool(r.get('site_guardians',{}).get(name,{}).get('guardian_lesson_findings')) for r in rows)
  concerns=sum(str(r.get('site_guardians',{}).get(name,{}).get('temporal_finding')) not in ('NO_TEMPORAL_ALERT','None') for r in rows)
  agentlines.append(f'• {name}: {num} shadow snapshots; {count} lần có đề xuất nghiên cứu; {concerns} lần tín hiệu thời gian khác bình thường.')
 st=backlog()
 lines=[f'<b>📘 ĐÁNH GIÁ TUẦN · LUNA / SELENE · {today.isoformat()}</b>',
 'Giai đoạn: Web Guardian S1 · quan sát + học, không auto-ban.',
 '',*agentlines,'',
 '<b>Nghiệm thu năng lực</b>',
 '• 45 kiểm tra mô phỏng S1 PASS; không phải accuracy ngoài thực tế.',
 '• Precision / Recall: CHƯA ĐO ĐƯỢC vì thiếu nhãn đúng/sai do người kiểm chứng.',
 '• Tốc độ phát hiện: CHƯA ĐO chính xác, cần ground-truth và timestamp chuẩn.',
 '• Cô lập website: shadow PASS, live ban/unban test CHƯA ĐẠT.',
 '• DDoS: có RPS, HTTP status và proxy duration; thiếu upstream CPU/connections/p95 riêng theo backend.',
 '• CVE: đã có tin tình báo; thiếu SBOM/version để xác nhận tác động.',
 f'• Outbox mới: {sum(st["pending"].values())} tin chờ, {st["retry_exhausted"]} hết retry.',
 '', '<b>Điều kiện giao quyền thật</b>',
 'Xác thực IP nguồn → phân quyền hostname tại edge → thử ban/unban trên staging → đo FP/FN đã gắn nhãn → Owner duyệt.',
 '\n<i>Không thay đổi quyền OBSERVE_ONLY.</i>']
 return '\n'.join(lines)[:MAX_MSG]
def propose():
 # Journal-backed delivery: each classification transition is an autonomous
 # judgement with evidence, not a raw network metric or a firewall command.
 # Journal allows catch-up if the 2-minute report poll misses a brief verdict.
 p=ROOT/'sentinel-site-guardian/reports/decision_history.jsonl'
 if not p.is_file():return []
 try: lines=p.read_text(encoding='utf-8',errors='replace').splitlines()[-300:]
 except OSError:return []
 alerts=[]
 for line in lines:
  try: d=json.loads(line)
  except ValueError:continue
  agent=d.get('agent'); host=HOSTS.get(agent)
  if host is None or d.get('site')!=host:continue
  if not freshness(d.get('generated_utc'),24):continue
  verdict=d.get('decision')
  previous=d.get('previous_decision')
  label={'BAN_RECOMMENDED':'ĐỀ XUẤT BAN, CHƯA THỰC THI',
         'WAIT_MORE_EVIDENCE':'CHỜ TÍN HIỆU / BẰNG CHỨNG BỔ SUNG',
         'INCIDENT_REVIEW_RECOMMENDED':'NGHI SỰ CỐ CẦN ƯU TIÊN',
         'INSUFFICIENT_TELEMETRY':'MẤT KHẢ NĂNG XÁC MINH DỮ LIỆU',
         'NO_ACTION':'TÍN HIỆU CŨ ĐÃ GIẢM — TIẾP TỤC GIÁM SÁT'}.get(verdict)
  if label is None:continue
  # A routine NO_ACTION is silent. Only a transition from a threat
  # hypothesis gets a bounded resolution notice; not a safety certificate.
  if verdict=='NO_ACTION' and previous not in ('BAN_RECOMMENDED',
      'WAIT_MORE_EVIDENCE','INCIDENT_REVIEW_RECOMMENDED'):continue
  token=str(d.get('transition_token',''))
  if not re.fullmatch(r'[0-9a-f]{20}',token):continue
  key='agent_decision:'+agent+':'+token
  subject=esc(str(d.get('subject','SITE'))[:90])
  reason=esc(str(d.get('rationale',''))[:420])
  evidence=esc('; '.join(map(str,(d.get('evidence') or [])[:4]))[:420])
  missing=esc('; '.join(map(str,(d.get('needs_to_confirm_or_refute') or [])[:3]))[:330])
  review=int(d.get('reassess_after_minutes') or 15)
  review=max(1,min(review,180))
  prior=esc(str(previous or 'UNKNOWN'))
  msg=(f'<b>🛡️ {esc(agent)} · {esc(label)}</b>\n'
       f'<code>{esc(host)}</code> · đối tượng <code>{subject}</code>\n'
       f'<b>Thay đổi:</b> {prior} → {esc(verdict)}\n'
       f'<b>Lý do:</b> {reason}\n'
       f'<b>Bằng chứng:</b> {evidence}\n'
       f'<b>Cần kiểm chứng:</b> {missing}\n'
       f'<b>Đánh giá lại:</b> đề xuất {review} phút\n'
       '<i>Phán quyết shadow · KHÔNG BAN THẬT · không kết luận hệ thống an toàn tuyệt đối.</i>')
  priority=1 if verdict in ('BAN_RECOMMENDED','INCIDENT_REVIEW_RECOMMENDED') else 2 if verdict!='NO_ACTION' else 3
  alerts.append((key,msg,priority))
 return alerts

def cmd():
 parser=argparse.ArgumentParser()
 parser.add_argument('command',choices=['daily','weekly','propose','claim','ack','stats','preview-daily','preview-weekly'])
 parser.add_argument('--id',type=int)
 parser.add_argument('--telegram-message-id')
 args=parser.parse_args()
 if args.command=='daily':
  date=local_date().isoformat();res=enqueue('daily:'+date,'DAILY',daily(),priority=3)
  print(json.dumps({'queued':res,'date':date,'kind':'DAILY'}))
 elif args.command=='weekly':
  date=local_date().isoformat();res=enqueue('weekly:'+date,'WEEKLY',weekly(),priority=4)
  print(json.dumps({'queued':res,'date':date,'kind':'WEEKLY'}))
 elif args.command=='propose':
  items=propose();n=0
  for key,message,priority in items:n+=int(enqueue(key,'URGENT',message,priority))
  print(json.dumps({'new_alerts':n,'candidates':len(items),'automatic_bans':0}))
 elif args.command=='claim':print(json.dumps(claim(),ensure_ascii=False))
 elif args.command=='ack':print(json.dumps(ack(args.id,args.telegram_message_id)))
 elif args.command=='stats':print(json.dumps(backlog(),ensure_ascii=False))
 elif args.command=='preview-daily':print(daily())
 elif args.command=='preview-weekly':print(weekly())
if __name__=='__main__':cmd()
