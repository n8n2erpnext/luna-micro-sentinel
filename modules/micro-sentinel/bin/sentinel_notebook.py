#!/usr/bin/env python3
import json,sys,time,hashlib,re
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; NB=ROOT/'state/notebook'; FILE=NB/'notes.jsonl'; MAX=65536
NB.mkdir(parents=True,exist_ok=True); FILE.touch(exist_ok=True)
def load():
 out=[]
 for line in FILE.read_text(errors='ignore').splitlines():
  try: out.append(json.loads(line))
  except: pass
 return out
def save(rows):
 data=''.join(json.dumps(x,ensure_ascii=False,separators=(',',':'))+'\n' for x in rows).encode()
 if len(data)>MAX: raise SystemExit('notebook_quota_exceeded')
 FILE.write_bytes(data)
def infer_concept(text):
 for pat in (r'Watch\s+([^:]+):',r'Retained\s+([^ ]+)\s+after reviewing'):
  m=re.match(pat,text or '')
  if m:return m.group(1).strip()
 return None
def status(): return {'bytes':FILE.stat().st_size,'max_bytes':MAX,'entries':len(load())}
def add(text,topic='free'):
 rows=load(); concept=infer_concept(text)
 if topic=='free' and concept: topic='attention'
 item={'id':hashlib.sha256(f"{time.time_ns()}|{text}".encode()).hexdigest()[:12],'time':int(time.time()),'topic':topic,'text':text}
 if concept:item['concept']=concept
 candidate=rows+[item]
 data=''.join(json.dumps(x,ensure_ascii=False,separators=(',',':'))+'\n' for x in candidate).encode()
 if len(data)>MAX:
  return {'state':'FULL','written':False,'bytes':FILE.stat().st_size,'max_bytes':MAX,'message':'Notebook full. Read it, choose what you no longer need, delete or rewrite that material yourself, then retry.'}
 save(candidate); return {'state':'WRITTEN','written':True,'note':item}
def delete(q):
 rows=load(); before=len(rows); rows=[x for x in rows if x.get('id')!=q and q.lower() not in x.get('text','').lower() and q.lower() not in x.get('topic','').lower()]; save(rows); return before-len(rows)
def main():
 op=sys.argv[1] if len(sys.argv)>1 else 'status'
 if op=='read': print(json.dumps(load(),ensure_ascii=False,indent=2))
 elif op=='add': print(json.dumps(add(' '.join(sys.argv[2:]) or 'blank note'),ensure_ascii=False))
 elif op=='delete': print(json.dumps({'deleted':delete(' '.join(sys.argv[2:]))}))
 elif op=='clear': save([]); print('{"cleared":true}')
 else: print(json.dumps(status()))
if __name__=='__main__': main()
