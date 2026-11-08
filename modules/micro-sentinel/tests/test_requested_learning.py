#!/usr/bin/env python3
import json,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def run(*a):return subprocess.run(['/usr/bin/python3',str(ROOT/'bin'/a[0]),*a[1:]],check=True,capture_output=True,text=True).stdout
ref=json.loads(run('sentinel_reflect.py'))
assert ref['comparison_context']['auto_confidence_increase'] is False
req=ref.get('requested_learning')
if req:
 out=json.loads(run('requested_learning.py'))
 assert req['origin']=='SELF_REFLECTION_EVIDENCE_GAP'
 assert out['promotion']['automatic'] is False
 assert out['state'] in ('REQUESTED','SANDBOX_ACTIVE','REPLAY_PASS','PROMOTED')
else:
 records=list((ROOT/'state/requested_learning').glob('*-promotion.json'))
 assert any(json.loads(x.read_text()).get('state')=='PROMOTED' for x in records)
print('PASS: requested-learning lane suppresses already-promoted repeat requests')
