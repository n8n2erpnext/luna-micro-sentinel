#!/usr/bin/env python3
import json,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]

def load(p,d=None):
    try:return json.loads(p.read_text())
    except:return {} if d is None else d

def notebook():
    p=ROOT/'state/notebook/notes.jsonl'
    rows=[]
    if p.exists():
        for line in p.read_text(errors='ignore').splitlines():
            try:rows.append(json.loads(line))
            except:pass
    return {'bytes':p.stat().st_size if p.exists() else 0,'max_bytes':65536,'entries':len(rows),'notes':rows}

def build(ref):
    learned=ref.get('today_i_learned',[])
    prog=ref.get('progress_since_yesterday',[])
    uncertain=ref.get('still_uncertain',[])
    ctx=ref.get('comparison_context',{})
    req=ref.get('requested_learning')
    memory_progress=ref.get('memory_progress',{})
    behavioral=ref.get('behavioral_baseline',{})
    nb=notebook()
    comps=ctx.get('comparisons',[])
    changed=[x for x in comps if x.get('interpretation')=='changed_across_days']
    unchanged=[x for x in comps if x.get('interpretation')=='no_demonstrated_confidence_change']
    candidates=ctx.get('independent_context',{}).get('candidates',[])
    topics=[]
    retained=[]
    for n in nb['notes']:
        concept=n.get('concept')
        if concept and concept not in topics:
            topics.append(concept)
        retained.append({
          'id':n.get('id'),'concept':concept,'topic':n.get('topic'),
          'merged_count':n.get('merged_count'),'reviewed':n.get('reviewed')
        })
    limits=[{
      'concept':x.get('concept'),'relation':x.get('relation'),'state':x.get('state'),
      'not_justified':x.get('not_justified')
    } for x in candidates if x.get('not_justified')]
    return {
      'version':'SELF_REVIEW_RAW_V2',
      'today':learned,
      'change':{
        'progress_since_yesterday':prog,
        'historical_changed':changed,
        'historical_unchanged':unchanged
      },
      'uncertainty':{
        'patterns':uncertain,
        'independent_limits':limits
      },
      'learning':{
        'formal_request_present':bool(req),
        'requested_learning':req,
        'attention_topics':topics,
        'memory_progress':memory_progress
      },
      'behavioral_baseline':behavioral,
      'notebook':{
        'bytes':nb['bytes'],'max_bytes':nb['max_bytes'],
        'entries':nb['entries'],'retained':retained
      },
      'self_assessment':{
        'tracked_patterns':len(learned),
        'progress_count':len(prog),
        'historical_changed_count':len(changed),
        'historical_unchanged_count':len(unchanged),
        'uncertain_count':len(uncertain),
        'formal_learning_request':bool(req),
        'authority':ctx.get('independent_context',{}).get('authority','OBSERVE_ONLY'),
        'external_review_required':True
      },
      'free':ref.get('raw_self_note'),
      'source_reflection_digest':ref.get('evidence_digest')
    }

if __name__=='__main__':
    day=time.strftime('%Y-%m-%d')
    ref=load(ROOT/'reports/reflection'/f'{day}.json',{})
    print(json.dumps(build(ref),ensure_ascii=False,indent=2))
