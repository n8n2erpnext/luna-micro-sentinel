#!/usr/bin/env python3
import json,re,sqlite3,hashlib,time,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT/'bin'))
import cognitive_bridge
NET=ROOT/'reports/network/latest.json'; OUT=ROOT/'reports/network_reasoning'; DB=ROOT/'state/cognition_links.sqlite'
def load():
 try:return json.loads(NET.read_text())
 except:return {}
def digest(x):return hashlib.sha256(json.dumps(x,sort_keys=True).encode()).hexdigest()[:16]
def iface_kind(n):
 if n=='lo':return 'loopback'
 if n.startswith('veth'):return 'veth'
 if n.startswith(('br-','docker')):return 'bridge'
 if n.startswith(('wt','wg','tun','tap','nb')):return 'overlay_or_tunnel'
 return 'host_or_other'
def support(tag):
 b=cognitive_bridge.bundle(tag)
 return {'tag':tag,'knowledge_id':(b.get('knowledge')or{}).get('id'),'reasoning_id':(b.get('reasoning')or{}).get('id'),'context_id':(b.get('context')or{}).get('id'),'knowledge_prior':(b.get('knowledge')or{}).get('fact'),'reasoning_rule':(b.get('reasoning')or{}).get('anti_shortcut'),'context_invariants':(b.get('context')or{}).get('invariants',[])[:3]}
def record(cands,evdig):
 c=sqlite3.connect(DB); c.execute('create table if not exists associations(concept text,relation text,first_seen int,last_seen int,seen_count int,conflicts int,evidence_digest text,primary key(concept,relation))')
 now=int(time.time())
 for x in cands:
  concept=x['concept']; rel=x['relation']; old=c.execute('select seen_count,conflicts from associations where concept=? and relation=?',(concept,rel)).fetchone()
  if old:c.execute('update associations set last_seen=?,seen_count=?,evidence_digest=? where concept=? and relation=?',(now,old[0]+1,evdig,concept,rel))
  else:c.execute('insert into associations values(?,?,?,?,?,?,?)',(concept,rel,now,now,1,0,evdig))
 c.commit(); c.close()
def main():
 n=load(); ifaces=n.get('interfaces',[]); sockets=n.get('sockets',[]); listeners=n.get('listeners',[]); docker=n.get('containers',[])
 kinds={}
 for i in ifaces:k=iface_kind(i.get('ifname','')); kinds[k]=kinds.get(k,0)+1
 broad=sum(('0.0.0.0:' in s or '[::]:' in s or ' *:' in s) for s in listeners)
 established=sum(('ESTAB' in s or 'ESTABLISHED' in s) for s in sockets)
 cands=[]
 if kinds.get('veth',0) or kinds.get('bridge',0):
  cands.append({'concept':'topology','relation':'container_or_bridge_boundaries_present','state':'SUPPORTED_OBSERVATION','evidence':{'interface_kinds':kinds},'strongest_conclusion':'Network identity must be interpreted through namespace/bridge boundaries before actor attribution.','not_justified':'Any bridge/veth address is an Internet actor identity.','support':support('topology')})
 if broad:
  cands.append({'concept':'listener','relation':'broad_bind_scope_present','state':'SUPPORTED_OBSERVATION','evidence':{'broad_bind_listeners':broad,'listeners_total':len(listeners)},'strongest_conclusion':'Some sockets bind broadly on the host observation surface.','not_justified':'Those services are necessarily reachable from the public Internet.','support':support('listener')})
 if docker:
  cands.append({'concept':'container','relation':'container_network_context_present','state':'SUPPORTED_OBSERVATION','evidence':{'containers':len(docker)},'strongest_conclusion':'Container topology is part of the request path for some services.','not_justified':'Container peer/source metadata equals original client identity.','support':support('container')})
 if len(sockets)>0:
  cands.append({'concept':'connection','relation':'transport_activity_observed','state':'SUPPORTED_OBSERVATION','evidence':{'socket_records':len(sockets),'established_like':established},'strongest_conclusion':'Transport activity is observable and can be correlated with application evidence.','not_justified':'Socket count alone implies bots, scan or DDoS.','support':support('connection')})
 ev={'network_digest':digest(n),'authority':'OBSERVE_ONLY','interface_kinds':kinds,'socket_records':len(sockets),'listeners':len(listeners),'broad_bind_listeners':broad,'containers':len(docker)}
 out={'time_unix':int(time.time()),'state':'PASS','authority':'OBSERVE_ONLY','architecture':'TRI_REGION_COGNITION','evidence':ev,'candidates':cands,'epistemic':'Each candidate combines live evidence with all three cognition regions; none is an enforcement verdict.'}
 out['evidence_digest']=digest(out); OUT.mkdir(parents=True,exist_ok=True); (OUT/'latest.json').write_text(json.dumps(out,ensure_ascii=False,indent=2)); record(cands,out['evidence_digest']); print(json.dumps({'state':'PASS','candidates':len(cands),'digest':out['evidence_digest']}))
if __name__=='__main__':main()
