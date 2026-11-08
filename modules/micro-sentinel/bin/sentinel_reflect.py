#!/usr/bin/env python3
import json,sqlite3,hashlib
from pathlib import Path
from datetime import datetime
ROOT=Path(__file__).resolve().parents[1]
DB=ROOT/'state/sentinel.db'

def h(x):
    return hashlib.sha256(json.dumps(x,sort_keys=True).encode()).hexdigest()[:16]

def load(p,d=None):
    try:return json.loads(p.read_text())
    except:return {} if d is None else d

def comparison_context(c,day,rows):
    days=[x[0] for x in c.execute('select distinct day from learned_patterns where day<=? order by day desc limit 7',(day,))]
    comps=[]
    for p,s,n,conf,state,ev in rows[:8]:
        hist=c.execute('select day,count,confidence,state from learned_patterns where pattern=? and scope=? and day<=? order by day desc limit 7',(p,s,day)).fetchall()[::-1]
        if not hist: continue
        confs=[float(x[2]) for x in hist]
        delta=round(confs[-1]-confs[0],3)
        comps.append({'pattern':p,'scope':s,'days_seen':len(hist),'days':[x[0] for x in hist],
          'confidence_first':round(confs[0],3),'confidence_latest':round(confs[-1],3),
          'confidence_delta':delta,'latest_observations':int(hist[-1][1]),
          'interpretation':'changed_across_days' if abs(delta)>.03 else 'no_demonstrated_confidence_change'})
    nr=load(ROOT/'reports/network_reasoning/latest.json',{})
    independent={'source':'network_reasoning','authority':nr.get('authority','OBSERVE_ONLY'),
      'evidence_digest':nr.get('evidence_digest'),
      'candidates':[{'concept':x.get('concept'),'relation':x.get('relation'),'state':x.get('state'),
        'evidence':x.get('evidence'),'strongest_conclusion':x.get('strongest_conclusion'),
        'not_justified':x.get('not_justified')} for x in nr.get('candidates',[])[:6]],
      'contract':'different-layer context may constrain interpretation but never auto-raises behavioral confidence'}
    return {'window_days':days[::-1],'comparisons':comps,'independent_context':independent,'auto_confidence_increase':False}
def learning_request(uncertain,ctx):
    promoted=set()
    base=ROOT/'state/requested_learning'
    if base.exists():
        for q in base.glob('*-promotion.json'):
            r=load(q,{})
            if r.get('state')=='PROMOTED':
                rec=r.get('request') or r.get('record') or {}
                rid=r.get('request_id') or rec.get('request_id')
                if rid: promoted.add(rid)
    behavior=load(ROOT/'reports/behavioral/latest.json',{})
    concepts=[x.get('concept') for x in ctx.get('independent_context',{}).get('candidates',[]) if x.get('concept')]
    devs=behavior.get('deviations',[])
    if devs:
        x=devs[0]; host=x.get('host','unknown')
        rid='behavioral-baseline-'+hashlib.sha256(host.encode()).hexdigest()[:12]
        if rid in promoted:return None
        return {'request_id':rid,'topic':'Host-scoped Behavioral Baseline Calibration',
          'origin':'SELF_REFLECTION_EVIDENCE_GAP',
          'reason':f"Host {host} changed method/status distribution versus recent history; distinguish deployment, client mix, crawler, proxy, outage and abuse without treating the shift as a verdict.",
          'desired_evidence':['same host across additional time windows','deployment/change context if available','route-family or application context','independent resource/upstream evidence'],
          'current_context_concepts':concepts[:4],'authority':'REQUEST_NOT_VERDICT'}
    if uncertain:
        x=uncertain[0]; pattern=x.get('pattern','unknown'); scope=x.get('scope','unknown')
        rid='uncertainty-discrimination-'+hashlib.sha256((pattern+'|'+scope).encode()).hexdigest()[:12]
        if rid in promoted:return None
        return {'request_id':rid,'topic':'Uncertainty Discrimination',
          'origin':'SELF_REFLECTION_EVIDENCE_GAP',
          'reason':f"Repeated uncertainty remains for {pattern} at {scope}; identify evidence that would distinguish benign recurrence, intermediary/proxy effects and hostile-looking behavior.",
          'desired_evidence':['cross-day recurrence','independent observation layer','conflicting/benign alternative evidence','falsification condition'],
          'current_context_concepts':concepts[:4],'authority':'REQUEST_NOT_VERDICT'}
    return None

def raw_self_note(uncertain):
    nr=load(ROOT/'reports/network_reasoning/latest.json',{})
    cs=nr.get('candidates',[])
    if cs:
        digest=nr.get('evidence_digest') or '0'
        idx=int(digest[:8],16)%len(cs)
        x=cs[idx]
        support=x.get('support') or {}
        return {'source':'network_reasoning','selection_rule':'evidence_digest_index','selection_index':idx,
          'concept':x.get('concept'),'relation':x.get('relation'),'state':x.get('state'),
          'evidence':x.get('evidence'),'supported':x.get('strongest_conclusion'),
          'not_justified':x.get('not_justified'),
          'support':{'knowledge_id':support.get('knowledge_id'),'reasoning_id':support.get('reasoning_id'),
            'context_id':support.get('context_id'),'reasoning_rule':support.get('reasoning_rule')},
          'evidence_digest':nr.get('evidence_digest'),'provenance':'reports/network_reasoning/latest.json'}
    if uncertain:
        x=uncertain[0]
        return {'source':'reflection_uncertainty','selection_rule':'first_uncertain',
          'pattern':x.get('pattern'),'scope':x.get('scope'),'confidence':x.get('confidence'),
          'provenance':'current reflection'}
    return None
def build(day=None):
    day=day or datetime.now().strftime('%Y-%m-%d')
    c=sqlite3.connect(DB)
    days=[r[0] for r in c.execute('select distinct day from learned_patterns where day<=? order by day desc limit 2',(day,))]
    cur=days[0] if days else day
    prev=days[1] if len(days)>1 else None
    rows=c.execute('select pattern,scope,count,confidence,state,evidence from learned_patterns where day=? order by confidence desc,count desc',(cur,)).fetchall()
    old={(r[0],r[1]):r for r in c.execute('select pattern,scope,count,confidence,state from learned_patterns where day=?',(prev,)).fetchall()} if prev else {}
    learned=[]; improved=[]; uncertain=[]
    for p,s,n,conf,state,ev in rows:
        item={'pattern':p,'scope':s,'observations':n,'confidence':round(conf,3),'state':state,'evidence':json.loads(ev)}
        learned.append(item)
        before=old.get((p,s))
        if before and conf>before[3]+.03:
            improved.append({'pattern':p,'scope':s,'from':round(before[3],3),'to':round(conf,3)})
        if conf<.72:
            uncertain.append({'pattern':p,'scope':s,'confidence':round(conf,3)})
    ctx=comparison_context(c,cur,rows)
    try:
        changes=[{'day':r[0],'pattern':r[1],'scope':r[2],'event':r[3],'from_state':r[4],'to_state':r[5],
                  'from_confidence':round(float(r[6]),3),'to_confidence':round(float(r[7]),3)}
                 for r in c.execute("select day,pattern,scope,event,old_state,new_state,old_conf,new_conf from memory_history where day=? and event='STATE_CHANGE' order by rowid desc limit 8",(cur,))]
        recurring=[{'pattern':r[0],'scope':r[1],'days_seen':int(r[2]),'observations':int(r[3]),'confidence':round(float(r[4]),3),'state':r[5]}
                   for r in c.execute("select pattern,scope,days_seen,total_observations,confidence,state from pattern_memory where last_seen=? and days_seen>=2 order by days_seen desc,total_observations desc limit 8",(cur,))]
    except Exception:
        changes=[]; recurring=[]
    c.close()
    behavior=load(ROOT/'reports/behavioral/latest.json',{})
    memory_progress={'state_changes':changes,'recurring_patterns':recurring,
                     'summary':{'state_changes_today':len(changes),'recurring_seen_today':len(recurring)}}
    behavior_summary={'state':behavior.get('state'),'shadow_only':behavior.get('shadow_only',True),
                      'hosts_ready':behavior.get('hosts_ready',0),'deviation_count':behavior.get('deviation_count',0),
                      'deviations':behavior.get('deviations',[])[:5]}
    req=learning_request(uncertain,ctx)
    out={'day':cur,'previous_day':prev,'voice':'SELF_REFLECTION_RAW_V2',
      'today_i_learned':learned[:8],'progress_since_yesterday':improved[:8],
      'still_uncertain':uncertain[:8],'comparison_context':ctx,
      'memory_progress':memory_progress,'behavioral_baseline':behavior_summary,
      'raw_self_note':raw_self_note(uncertain)}
    if req: out['requested_learning']=req
    out['evidence_digest']=h(out)
    d=ROOT/'reports/reflection'; d.mkdir(parents=True,exist_ok=True)
    (d/f'{cur}.json').write_text(json.dumps(out,ensure_ascii=False,indent=2))
    return out

if __name__=='__main__':
    print(json.dumps(build(),ensure_ascii=False,indent=2))
