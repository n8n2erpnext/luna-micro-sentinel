#!/usr/bin/env python3
import json,sqlite3,hashlib
from pathlib import Path
from datetime import datetime,timezone
ROOT=Path('/home/ubuntu/services/micro-sentinel'); DB=ROOT/'state/sentinel.db'; CFG=ROOT/'config/learning_budget.json'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else None
def metrics():
 cfg=json.loads(CFG.read_text()); c=sqlite3.connect(DB)
 q=lambda s:c.execute(s).fetchone()[0]
 m={'active_pattern_memory':q("select count(*) from pattern_memory where state!='retired'"),'memory_database_bytes':DB.stat().st_size,'observations_retained':q('select count(*) from observations'),'knowledge_files_bytes':sum(p.stat().st_size for p in (ROOT/'knowledge').glob('*') if p.is_file()),'history_rows':q('select count(*) from memory_history')}; c.close()
 ratios={k:m[k]/cfg['limits'][k] for k in m}; peak=max(ratios.values(),default=0)
 state='LIMIT_REACHED' if peak>=cfg['hard_stop_ratio'] else 'WARNING' if peak>=cfg['warning_ratio'] else 'HEALTHY'
 return cfg,m,ratios,state
def snapshot():
 cfg,m,r,state=metrics(); now=datetime.now(timezone.utc).isoformat(); out={'time':now,'generation':cfg['generation'],'state':state,'metrics':m,'limits':cfg['limits'],'ratios':{k:round(v,4) for k,v in r.items()},'db_sha256':sha(DB),'knowledge':{p.name:sha(p) for p in sorted((ROOT/'knowledge').glob('*')) if p.is_file()}}
 d=ROOT/'reports/capacity'; d.mkdir(parents=True,exist_ok=True); (d/'latest.json').write_text(json.dumps(out,indent=2)); return out
if __name__=='__main__':print(json.dumps(snapshot(),indent=2))
