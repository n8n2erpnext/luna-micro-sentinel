#!/usr/bin/env python3
import json,sys,time,hashlib,re
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
NB=ROOT/'state/notebook'; FILE=NB/'notes.jsonl'; MAX=65536
AUDIT=NB/'deliberation_audit.jsonl'; STATE=NB/'deliberation_state.json'
NB.mkdir(parents=True,exist_ok=True)

def load_json(p,d=None):
    try:return json.loads(p.read_text())
    except:return {} if d is None else d

def load_notes():
    out=[]
    if not FILE.exists(): return out
    for line in FILE.read_text(errors='ignore').splitlines():
        try: out.append(json.loads(line))
        except: pass
    return out

def enc(rows):
    return ''.join(json.dumps(x,ensure_ascii=False,separators=(',',':'))+'\n' for x in rows).encode()

def text_concept(text):
    for pat in (r'Watch\s+([^:]+):',r'Retained\s+([^ ]+)\s+after reviewing'):
        m=re.match(pat,text or '')
        if m:return m.group(1).strip()
    return None

def concept_of(note):
    return note.get('concept') or text_concept(note.get('text',''))

def now_note(text,topic='attention',**meta):
    x={'id':hashlib.sha256(f"{time.time_ns()}|{text}".encode()).hexdigest()[:12],
       'time':int(time.time()),'topic':topic,'text':text}
    x.update(meta); return x

def current_context():
    nr=load_json(ROOT/'reports/network_reasoning/latest.json',{})
    day=time.strftime('%Y-%m-%d')
    rf=load_json(ROOT/'reports/reflection'/f'{day}.json',{})
    candidates={x.get('concept'):x for x in nr.get('candidates',[]) if x.get('concept')}
    return nr,rf,candidates,rf.get('still_uncertain',[])

def stable_rank(identity,key):
    return int(hashlib.sha256((identity+'|'+key).encode()).hexdigest()[:12],16)

def consider_pending(text):
    rows=load_notes(); nr,rf,cands,uncertain=current_context()
    concept=text_concept(text)
    if any(x.get('text')==text for x in rows):
        return {'decision':'SKIP','reason':'exact attention already retained','concept':concept}
    if concept:
        c=cands.get(concept,{})
        strongest=c.get('strongest_conclusion','')
        for x in rows:
            if concept_of(x)==concept and strongest and strongest in x.get('text',''):
                return {'decision':'SKIP','reason':'current concept and conclusion already represented; repetition adds no independent evidence','concept':concept}
    return {'decision':'WRITE','reason':'new or materially changed attention is not represented in notebook','concept':concept}

def plan():
    rows=load_notes(); before=len(enc(rows))
    ident=load_json(ROOT/'knowledge/identity.json',{}).get('name','sentinel')
    nr,rf,cands,uncertain=current_context()
    groups={}
    for x in rows: groups.setdefault(x.get('text',''),[]).append(x)
    actions=[]; kept=[]
    for text,items in groups.items():
        concept=next((concept_of(x) for x in items if concept_of(x)),None)
        active=concept in cands
        unresolved=('Need:' in text or 'Still unresolved:' in text or 'Revisit ' in text)
        if len(items)>1:
            if active or unresolved:
                c=cands.get(concept,{})
                strongest=c.get('strongest_conclusion') or text
                missing=c.get('not_justified') or 'independent discriminating evidence remains missing'
                summary=(f"Retained {concept or 'attention'} after reviewing {len(items)} repeated notes. "
                         f"Current observation: {strongest} "
                         f"Still unresolved: {missing} "
                         f"Repeated same-layer notes add no independent evidence.")
                kept.append(now_note(summary,'attention-merged',concept=concept,merged_count=len(items),reviewed=time.strftime('%Y-%m-%d')))
                actions.append({'action':'MERGE','count':len(items),'concept':concept,'reason':'same attention repeated; active/unresolved question retained as one current summary'})
            else:
                if stable_rank(ident,text)%3:
                    kept.append(max(items,key=lambda x:x.get('time',0)))
                    actions.append({'action':'DELETE','count':len(items)-1,'concept':concept,'reason':'repeated stale attention; one exemplar retained'})
                else:
                    actions.append({'action':'DELETE','count':len(items),'concept':concept,'reason':'repeated stale attention with no current activation or unresolved evidence'})
        else:
            x=items[0]; age=max(0,int(time.time())-int(x.get('time',0)))
            if active or unresolved or age < 7*86400:
                if active and concept:
                    c=cands[concept]; current=c.get('strongest_conclusion','')
                    if current and current not in text:
                        new=(f"Watch {concept}: {current} Still unresolved: "
                             f"{c.get('not_justified','independent evidence')}.")
                        kept.append(now_note(new,'attention-rewrite',concept=concept,reviewed=time.strftime('%Y-%m-%d')))
                        actions.append({'action':'REWRITE','count':1,'concept':concept,'reason':'current evidence changed the retained wording'})
                    else:
                        kept.append(x); actions.append({'action':'KEEP','count':1,'concept':concept,'reason':'still active or unresolved'})
                else:
                    kept.append(x); actions.append({'action':'KEEP','count':1,'concept':concept,'reason':'still active, unresolved, or recent'})
            else:
                actions.append({'action':'DELETE','count':1,'concept':concept,'reason':'stale note with no current activation or unresolved evidence'})
    if rows and not kept and not cands and not uncertain:
        actions.append({'action':'CLEAR','count':len(rows),'reason':'no retained question remains active or unresolved'})
    exp=[x for x in kept if (concept_of(x) or '').startswith('experience|')]
    if before>=int(MAX*.80) and exp:
        active=set()
        for z in (rf.get('today_i_learned',[])+rf.get('still_uncertain',[])):
            active.add(f"experience|{z.get('pattern')}|{z.get('scope')}")
        removable=sorted([x for x in exp if concept_of(x) not in active],key=lambda x:x.get('time',0))
        dropped=[]
        target=int(MAX*.70)
        while len(enc(kept))>target and removable:
            victim=removable.pop(0); vid=victim.get('id')
            kept=[x for x in kept if x.get('id')!=vid]; dropped.append(victim)
        if dropped:
            actions.append({'action':'PRUNE','count':len(dropped),'concept':'experience',
                            'reason':'notebook quota pressure; inactive experience pruned after deliberation while current learned/uncertain experience is retained; durable pattern_memory remains authoritative'})
    kept.sort(key=lambda x:(0 if concept_of(x) in cands else 1,stable_rank(ident,x.get('text',''))))
    after=len(enc(kept))
    return {'identity':ident,'time':int(time.time()),'before_bytes':before,'after_bytes':after,
            'before_entries':len(rows),'after_entries':len(kept),'actions':actions,
            'evidence_digest':nr.get('evidence_digest'),'authority':'NOTEBOOK_ONLY_NO_EVIDENCE_OR_ENFORCEMENT'},kept

def apply(dry=False):
    report,rows=plan(); report['dry_run']=dry
    if not dry:
        data=enc(rows)
        if len(data)>MAX: raise SystemExit('deliberation_result_exceeds_notebook_quota')
        tmp=FILE.with_suffix('.jsonl.tmp'); tmp.write_bytes(data); tmp.replace(FILE)
        with AUDIT.open('a') as f:f.write(json.dumps(report,ensure_ascii=False,separators=(',',':'))+'\n')
        STATE.write_text(json.dumps({'last_time':report['time'],'last_day':time.strftime('%Y-%m-%d'),
                                     'evidence_digest':report.get('evidence_digest'),
                                     'before_bytes':report['before_bytes'],'after_bytes':report['after_bytes']},
                                    ensure_ascii=False,indent=2))
    print(json.dumps(report,ensure_ascii=False,indent=2))

if __name__=='__main__':
    if '--consider-note' in sys.argv:
        i=sys.argv.index('--consider-note')
        print(json.dumps(consider_pending(' '.join(sys.argv[i+1:])),ensure_ascii=False))
    else: apply('--dry-run' in sys.argv)
