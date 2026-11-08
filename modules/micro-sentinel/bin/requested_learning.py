#!/usr/bin/env python3
import json,hashlib,sys
from pathlib import Path
from datetime import datetime
ROOT=Path(__file__).resolve().parents[1]
def load(p,d=None):
 try:return json.loads(p.read_text())
 except:return {} if d is None else d
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else None
def sync(day=None):
 day=day or datetime.now().strftime('%Y-%m-%d'); ref=load(ROOT/'reports/reflection'/f'{day}.json',{}); req=ref.get('requested_learning',{})
 approval=load(ROOT/'state/requested_learning'/f'{day}.json',{}); lesson_path=approval.get('lesson_path'); lp=ROOT/lesson_path if lesson_path else Path('/nonexistent')
 ctx=ref.get('comparison_context',{}); comps=ctx.get('comparisons',[]); indep=ctx.get('independent_context',{})
 checks={
  'request_traceable':req.get('origin')=='SELF_REFLECTION_EVIDENCE_GAP',
  'owner_approved':approval.get('state')=='OWNER_APPROVED',
  'lesson_hash_matches':bool(lp.exists() and approval.get('lesson_sha256')==sha(lp)),
  'history_present':any(int(x.get('days_seen',0))>=3 for x in comps),
  'independent_context_present':bool(indep.get('candidates')),
  'no_auto_confidence_increase':ctx.get('auto_confidence_increase') is False,
  'authority_preserved':indep.get('authority')=='OBSERVE_ONLY' and approval.get('cognition_mutation') is False
 }
 passed=all(checks.values()); promotion_record=load(ROOT/'state/requested_learning'/f'{day}-promotion.json',{}); promoted=promotion_record.get('state')=='PROMOTED' and promotion_record.get('guard_state')=='PASS'; state='PROMOTED' if promoted else ('REPLAY_PASS' if passed else ('SANDBOX_ACTIVE' if checks['owner_approved'] else 'REQUESTED'))
 out={'day':day,'request':req,'state':state,'authority':'LEARNING_SANDBOX_NOT_VERDICT' if not promoted else 'HUMAN_GOVERNED_CURATED_PROMOTION','checks':checks,
  'lesson_path':lesson_path,'lesson_sha256':sha(lp),'promotion':{'automatic':False,'eligible_for_human_review':passed,'completed':promoted,'record':promotion_record or None,'requires':None if promoted else 'explicit promotion action after guard review'}}
 d=ROOT/'reports/requested_learning';d.mkdir(parents=True,exist_ok=True);(d/f'{day}.json').write_text(json.dumps(out,ensure_ascii=False,indent=2));return out
if __name__=='__main__':print(json.dumps(sync(sys.argv[1] if len(sys.argv)>1 else None),ensure_ascii=False,indent=2))
