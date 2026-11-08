#!/usr/bin/env python3
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
SHARED=Path('/home/ubuntu/services/sentinel-dialogue')
proto=json.loads((SHARED/'protocol.json').read_text())
assert proto['version']=='SENTINEL_DIALOGUE_V2'
assert proto['runtime']['min_interval_seconds']>=1800
assert proto['runtime']['max_messages_per_agent_per_day']<=48
rows=[]
for line in (SHARED/'history.jsonl').read_text(errors='ignore').splitlines():
    try: rows.append(json.loads(line))
    except: pass
v2=[x for x in rows if x.get('protocol')=='SENTINEL_DIALOGUE_V2']
assert v2
for x in v2:
    assert 'text' not in x
    assert x['authority']=='PEER_DIALOGUE_ONLY'
    assert x['evidence_status']=='NOT_EVIDENCE'
    assert isinstance(x.get('content'),dict)
    assert 'own_position' in x['content']
    assert 'comparison' in x['content']
    assert x['from']!=x['to']
    if x.get('interaction')=='reply':
        assert x.get('reply_to')
        assert x['content'].get('peer_position') is not None
engine=(SHARED/'sentinel_dialogue.py').read_text()
assert "authored_text_not_allowed_v2" in engine
cycle=(ROOT/'bin/sentinel_cycle.py').read_text()
assert cycle.index("guard=json.loads") < cycle.index("dialogue=peer_dialogue()")
print('PASS: V2 raw peer state transport, no authored dialogue text, NOT_EVIDENCE boundary, post-guard cycle wiring')
