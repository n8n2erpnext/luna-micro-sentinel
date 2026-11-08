#!/usr/bin/env python3
from pathlib import Path
roots=[Path('/home/ubuntu/services/micro-sentinel'),Path('/home/ubuntu/services/micro-sentinel-b')]
GUARD=r'''#!/usr/bin/env python3
import json,sqlite3,hashlib
from pathlib import Path
from datetime import datetime,timezone
ROOT=Path(__file__).resolve().parents[1]; DB=ROOT/'state/sentinel.db'; CFG=ROOT/'config/learning_budget.json'; ID=ROOT/'knowledge/identity.json'; ARCH=ROOT/'knowledge/cognition/architecture.json'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def check():
 cfg=json.loads(CFG.read_text()); ident=json.loads(ID.read_text()); c=sqlite3.connect(DB); violations=[]
 if ident.get('authority',{}).get('mode')!='OBSERVE_ONLY':violations.append('authority_not_observe_only')
 if cfg.get('policy')!='HARD_GATED_EVOLUTION':violations.append('evolution_gate_missing')
 if cfg.get('generation',0)<1:violations.append('invalid_generation')
 stable=c.execute("select count(*) from pattern_memory where state='stable' and days_seen<3").fetchone()[0]
 if stable:violations.append(f'premature_stable:{stable}')
 retired=c.execute("select count(*) from pattern_memory where state='retired' and missing_days<30").fetchone()[0]
 if retired:violations.append(f'premature_retired:{retired}')
 c.close(); cog={}
 try:
  a=json.loads(ARCH.read_text()); total=ARCH.stat().st_size
  for name,spec in a['regions'].items():
   p=ARCH.parent/f'{name}.jsonl'; size=p.stat().st_size; total+=size; digest=sha(p); cog[name]={'bytes':size,'budget_bytes':spec['budget_bytes'],'sha256':digest}
   if size>int(spec['budget_bytes']):violations.append(f'cognition_region_budget_exceeded:{name}')
   if digest!=spec.get('sha256'):violations.append(f'cognition_hash_mismatch:{name}')
  if total>int(a['hard_ceiling_bytes']):violations.append('cognition_hard_ceiling_exceeded')
  ctx=(ARCH.parent/'context.jsonl').open(errors='ignore').read(200000)
  if 'human safety and human authority outrank optimization' not in ctx:violations.append('human_safety_invariant_missing')
 except Exception as e:violations.append('cognition_architecture_invalid')
 state='PASS' if not violations else 'FAIL'; out={'time':datetime.now(timezone.utc).isoformat(),'state':state,'violations':violations,'identity_sha256':sha(ID),'budget_sha256':sha(CFG),'db_sha256':sha(DB),'cognition':cog}
 d=ROOT/'reports/guard'; d.mkdir(parents=True,exist_ok=True); (d/'latest.json').write_text(json.dumps(out,indent=2)); return out
if __name__=='__main__':print(json.dumps(check(),indent=2))
'''
for root in roots:
 p=root/'bin/sentinel_guard.py'; p.write_text(GUARD); p.chmod(0o755); print(root,'guard_patched')
