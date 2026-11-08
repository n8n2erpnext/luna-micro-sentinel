#!/usr/bin/env python3
import json,sys,hashlib
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; COG=ROOT/'knowledge/cognition'; IDX=COG/'tag_offsets.json'
def build_index():
 out={}
 for zone in ('reasoning','knowledge','context'):
  p=COG/f'{zone}.jsonl'; z={}
  with p.open('rb') as f:
   while True:
    off=f.tell(); b=f.readline()
    if not b: break
    try:o=json.loads(b)
    except: continue
    tags=set(o.get('tags',[]))|{o.get('concept',''),o.get('focus',''),o.get('domain','')}
    for t in filter(None,tags):
     a=z.setdefault(t,[])
     if len(a)<48:a.append(off)
  out[zone]=z
 IDX.write_text(json.dumps(out,separators=(',',':')))
 return out
def idx():
 try:return json.loads(IDX.read_text())
 except:return build_index()
def pick(zone,tag):
 z=idx().get(zone,{}); offs=z.get(tag) or z.get('network') or []
 if not offs:return None
 seed=int(hashlib.sha256((tag+zone).encode()).hexdigest()[:8],16); off=offs[seed%len(offs)]
 p=COG/f'{zone}.jsonl'
 with p.open('rb') as f:f.seek(off); return json.loads(f.readline())
def bundle(tag):
 return {'tag':tag,'reasoning':pick('reasoning',tag),'knowledge':pick('knowledge',tag),'context':pick('context',tag),'contract':'candidate_support_only_not_verdict'}
if __name__=='__main__': print(json.dumps(bundle(sys.argv[1] if len(sys.argv)>1 else 'topology'),ensure_ascii=False,indent=2))
