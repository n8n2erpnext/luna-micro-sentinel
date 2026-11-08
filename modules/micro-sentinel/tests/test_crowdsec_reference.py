#!/usr/bin/env python3
import json,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
cfg=json.loads((ROOT/'knowledge/crowdsec_curriculum.json').read_text())
assert cfg['activation']=='governed_reference_active'
assert cfg['authority']=='REFERENCE_CORPUS_NOT_GROUND_TRUTH'
assert 'crowdsecurity/http-generic-bf' in cfg['reviewed_inventory']['tainted_scenarios']
lesson=json.loads((ROOT/'knowledge/lessons/crowdsec/2026-09-19_local_scenario_mechanisms.json').read_text())
assert lesson['authority']=='CURATED_REFERENCE_NOT_VERDICT'
out=json.loads(subprocess.check_output(['/usr/bin/python3',str(ROOT/'bin/crowdsec_reference_replay.py')],text=True))
assert out['authority']=='OBSERVE_ONLY'
assert out['crowdsec_decisions_used_as_truth'] is False
assert all(x['state']=='REFERENCE_CANDIDATE_ONLY' and x['actor_verdict'] is None for x in out['candidates'])
print('PASS: CrowdSec reference curriculum, taint provenance, offline replay, no verdict/authority promotion')
