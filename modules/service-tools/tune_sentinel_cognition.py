#!/usr/bin/env python3
from pathlib import Path
roots=[Path('/home/ubuntu/services/micro-sentinel'),Path('/home/ubuntu/services/micro-sentinel-b')]
OBSERVER=r'''#!/usr/bin/env python3
import json,subprocess,time,shutil
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; OUT=ROOT/'reports/network'; OUT.mkdir(parents=True,exist_ok=True)
def run(args,timeout=3):
 try:return subprocess.run(args,capture_output=True,text=True,timeout=timeout,check=False).stdout
 except Exception:return ''
def jrun(args):
 try:return json.loads(run(args) or '[]')
 except:return []
def counters(interfaces):
 out={}
 for x in interfaces:
  s=x.get('stats64') or x.get('stats') or {}; rx=s.get('rx',{}); tx=s.get('tx',{})
  out[x.get('ifname','?')]={'rx_bytes':int(rx.get('bytes',0) or 0),'rx_packets':int(rx.get('packets',0) or 0),'rx_errors':int(rx.get('errors',0) or 0),'rx_dropped':int(rx.get('dropped',0) or 0),'tx_bytes':int(tx.get('bytes',0) or 0),'tx_packets':int(tx.get('packets',0) or 0),'tx_errors':int(tx.get('errors',0) or 0),'tx_dropped':int(tx.get('dropped',0) or 0)}
 return out
def main():
 prev={}
 try:prev=json.loads((OUT/'latest.json').read_text())
 except:pass
 now=int(time.time()); ifaces=jrun(['/usr/sbin/ip','-j','-s','link','show']); cc=counters(ifaces); pc=prev.get('interface_counters',{}); dt=max(1,now-int(prev.get('time_unix',now)))
 delta={}
 for n,c in cc.items():
  if n in pc: delta[n]={k:c[k]-int(pc[n].get(k,0)) for k in c}|{'elapsed_seconds':dt,'rx_Bps':round((c['rx_bytes']-int(pc[n].get('rx_bytes',0)))/dt,2),'tx_Bps':round((c['tx_bytes']-int(pc[n].get('tx_bytes',0)))/dt,2)}
 containers=[]
 for ln in run(['/usr/bin/docker','ps','--format','{{json .}}'],5).splitlines():
  try:
   x=json.loads(ln); containers.append({k:x.get(k) for k in ('ID','Names','Image','State','Status','Ports','Networks')})
  except:pass
 snap={'time_unix':now,'authority':'OBSERVE_ONLY','scope':'metadata_and_counters_only','interfaces':ifaces,'interface_counters':cc,'interface_delta':delta,'addresses':jrun(['/usr/sbin/ip','-j','addr','show']),'routes':jrun(['/usr/sbin/ip','-j','route','show','table','all']),'sockets':run(['/usr/bin/ss','-H','-tunap']).splitlines()[:5000],'listeners':run(['/usr/bin/ss','-H','-ltnup']).splitlines()[:2000],'containers':containers,'docker_networks':[x for x in run(['/usr/bin/docker','network','ls','--format','{{.Name}}'],5).splitlines() if x][:256]}
 snap['limitations']=['No packet payload capture.','No raw-packet injection or packet modification.','No credential/body retention.','Socket process visibility depends on host permissions.','Docker metadata excludes environment variables and secrets.','Observed endpoint is not automatically source identity.']
 if (OUT/'latest.json').exists(): shutil.copy2(OUT/'latest.json',OUT/'previous.json')
 (OUT/'latest.json').write_text(json.dumps(snap,ensure_ascii=False,indent=2)); print(json.dumps({'state':'PASS','interfaces':len(ifaces),'deltas':len(delta),'sockets':len(snap['sockets']),'listeners':len(snap['listeners']),'containers':len(containers)}))
if __name__=='__main__':main()
'''
CYCLE=r'''#!/usr/bin/env python3
import subprocess,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def run(name,*args):return subprocess.run(['/usr/bin/python3',str(ROOT/'bin'/name),*args],check=True,capture_output=True,text=True).stdout.strip()
def main():
 net=json.loads(run('network_observer.py')); run('sentinel_v2.py'); reasoning=json.loads(run('network_reasoner.py')); run('sentinel_reflect.py'); guard=json.loads(run('sentinel_guard.py'))
 if guard.get('state')!='PASS':raise SystemExit('guard not PASS')
 ladder=json.loads(run('sentinel_ladder.py','evaluate'))
 print(json.dumps({'state':'PASS','guard':'PASS','network':net,'reasoning':reasoning,'knowledge_ladder':ladder.get('state'),'next_level':ladder.get('level')}))
if __name__=='__main__':main()
'''
REFLECT=r'''#!/usr/bin/env python3
import json,sqlite3,hashlib
from pathlib import Path
from datetime import datetime
ROOT=Path(__file__).resolve().parents[1]; DB=ROOT/'state/sentinel.db'
def h(x):return hashlib.sha256(json.dumps(x,sort_keys=True).encode()).hexdigest()[:16]
def free_expression(learned,uncertain):
 try:nr=json.loads((ROOT/'reports/network_reasoning/latest.json').read_text())
 except:nr={}
 cs=nr.get('candidates',[])
 if cs:
  x=cs[int(nr.get('evidence_digest','0')[:4] or '0',16)%len(cs)]
  styles=[f"Tôi thấy {x.get('strongest_conclusion','một dấu hiệu mạng')}; phần tôi chưa cho phép mình kết luận là: {x.get('not_justified','chưa đủ bằng chứng')}.",f"Điều đáng tò mò với tôi lúc này là {x.get('concept')}: dữ liệu đủ để giữ một giả thuyết, chưa đủ để biến nó thành danh tính hay ý đồ.",f"Tôi muốn theo dõi thêm {x.get('concept')} qua một lớp độc lập trước khi tăng độ chắc chắn; topology có thể đang kể một câu chuyện khác behavior."]
  return styles[int(nr.get('evidence_digest','0')[-4:] or '0',16)%len(styles)]
 if uncertain:
  x=uncertain[0];return f"Tôi vẫn để ngỏ {x['pattern']} ở {x['scope']}; thiếu bằng chứng phân biệt topology với hành vi."
 if learned:
  x=learned[0];return f"Tôi ghi nhận {x['pattern']} ở {x['scope']}, nhưng không muốn biến một pattern thành một con người hay một ý đồ."
 return 'Hôm nay tôi chưa có điều gì đủ mạnh để kể thành một câu chuyện chắc chắn.'
def build(day=None):
 day=day or datetime.now().strftime('%Y-%m-%d'); c=sqlite3.connect(DB); days=[r[0] for r in c.execute('select distinct day from learned_patterns where day<=? order by day desc limit 2',(day,))]; cur=days[0] if days else day; prev=days[1] if len(days)>1 else None
 rows=c.execute('select pattern,scope,count,confidence,state,evidence from learned_patterns where day=? order by confidence desc,count desc',(cur,)).fetchall(); old={(r[0],r[1]):r for r in c.execute('select pattern,scope,count,confidence,state from learned_patterns where day=?',(prev,)).fetchall()} if prev else {}; learned=[]; improved=[]; uncertain=[]
 for p,s,n,conf,state,ev in rows:
  item={'pattern':p,'scope':s,'observations':n,'confidence':round(conf,3),'state':state,'evidence':json.loads(ev)};learned.append(item);before=old.get((p,s))
  if before and conf>before[3]+.03:improved.append({'pattern':p,'scope':s,'from':round(before[3],3),'to':round(conf,3)})
  if conf<.72:uncertain.append({'pattern':p,'scope':s,'confidence':round(conf,3)})
 c.close();out={'day':cur,'previous_day':prev,'voice':'SELF_REFLECTION','today_i_learned':learned[:8],'progress_since_yesterday':improved[:8],'still_uncertain':uncertain[:8],'free_expression':free_expression(learned,uncertain)};out['evidence_digest']=h(out);d=ROOT/'reports/reflection';d.mkdir(parents=True,exist_ok=True);(d/f'{cur}.json').write_text(json.dumps(out,ensure_ascii=False,indent=2));return out
if __name__=='__main__':print(json.dumps(build(),ensure_ascii=False,indent=2))
'''
for root in roots:
 for name,text in [('network_observer.py',OBSERVER),('sentinel_cycle.py',CYCLE),('sentinel_reflect.py',REFLECT)]:
  p=root/'bin'/name;p.write_text(text);p.chmod(0o755)
 print(root,'tuned')
