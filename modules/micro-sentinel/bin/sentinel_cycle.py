#!/usr/bin/env python3
import subprocess,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]

def run(name,*args):
    return subprocess.run(['/usr/bin/python3',str(ROOT/'bin'/name),*args],check=True,capture_output=True,text=True).stdout.strip()

def main():
    net=json.loads(run('network_observer.py'))
    run('sentinel_v2.py')
    behavior=json.loads(run('sentinel_behavioral_baseline.py'))
    reasoning=json.loads(run('network_reasoner.py'))
    run('sentinel_reflect.py')
    run('requested_learning.py')
    run('sentinel_notebook_attention.py')
    guard=json.loads(run('sentinel_guard.py'))
    if guard.get('state')!='PASS': raise SystemExit('guard not PASS')
    try: intel=json.loads(run('sentinel_intelligence.py'))
    except Exception: intel={'state':'DEGRADED','reason':'brief_unavailable','enforcement':'DISABLED'}
    # 2026-10-30: one collector only; do not queue artificial peer conversations.
    dialogue={'state':'DISABLED','reason':'single_collector_mode','identity':'Luna'}
    ladder=json.loads(run('sentinel_ladder.py','evaluate'))
    print(json.dumps({'state':'PASS','guard':'PASS','network':net,'reasoning':reasoning,
                      'behavioral_baseline':{'state':behavior.get('state'),'hosts_ready':behavior.get('hosts_ready'),'deviation_count':behavior.get('deviation_count'),'shadow_only':behavior.get('shadow_only')},
                      'threat_intelligence':intel,
                      'peer_dialogue':dialogue.get('state'),'peer_dialogue_detail':dialogue,
                      'knowledge_ladder':ladder.get('state'),'next_level':ladder.get('level')}))
if __name__=='__main__':main()
