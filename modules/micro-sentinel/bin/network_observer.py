#!/usr/bin/env python3
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
