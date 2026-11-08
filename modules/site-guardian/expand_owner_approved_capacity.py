#!/usr/bin/env python3
"""Owner-authorized capacity expansion: immutable snapshots, no data deletion."""
from pathlib import Path
import json,hashlib,os,datetime,subprocess
ROOT=Path('/home/ubuntu/services')
STAMP='2026-10-08'
OUT=ROOT/'sentinel-site-guardian/governance'/f'owner-approved-capacity-{STAMP}'
OUT.mkdir(parents=True,exist_ok=True)
LIMITS={'active_pattern_memory':2000,
        'memory_database_bytes':1073741824,
        'observations_retained':3500000,
        'knowledge_files_bytes':67108864,
        'history_rows':250000}
COG_BYTES={'reasoning':52428800,'knowledge':52428800,'context':31457280}
logs=[]
def atomic_json(path,obj):
    tmp=path.with_name(path.name+'.guardian-new.tmp')
    tmp.write_text(json.dumps(obj,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    tmp.replace(path)
def backup(path,destination):
    b=path.read_bytes()
    if destination.exists():
        assert destination.read_bytes()==b,'checkpoint conflict: '+str(path)
    else:
        destination.write_bytes(b)
    return hashlib.sha256(b).hexdigest()
for label,dir_name in [('Luna','micro-sentinel')]:
    root=ROOT/dir_name
    cfg_path=root/'config/learning_budget.json'
    cog_path=root/'knowledge/cognition/architecture.json'
    cfg=json.loads(cfg_path.read_text())
    cog=json.loads(cog_path.read_text())
    if cfg.get('budget_version')=='2026-10-08.owner-approved.guardian-v2':
        print(label,'already migrated; skipping')
        continue
    assert cfg['generation']==1 and cfg['policy']=='HARD_GATED_EVOLUTION'
    assert cfg['limits']['memory_database_bytes']==52428800
    assert cog['hard_ceiling_bytes']==52428800
    assert len(cog['regions'])==3
    for region in COG_BYTES: assert region in cog['regions']
    record={'agent':label,'owner_request':'50MB was original pilot; hundreds MB per agent allowed with ceiling well below multi-GB',
       'timestamp':datetime.datetime.now(datetime.timezone.utc).isoformat(),
       'checkpoint_paths':{},
       'old_limits':cfg['limits'],'new_limits':LIMITS,
       'old_cognition_ceiling':cog['hard_ceiling_bytes'],'new_cognition_ceiling':134217728,
       'evidence_policy':'no delete/truncate/alter SQLite evidence or cognition region contents; preserve hashes',
       'operational_status':'CAPACITY_ONLY;OBSERVE_ONLY;NO_ENFORCEMENT'}
    for path,tag in [(cfg_path,'budget'),(cog_path,'architecture')]:
        dst=OUT/(dir_name+'-'+tag+'.before.json')
        record['checkpoint_paths'][tag]={'path':str(dst),'sha256':backup(path,dst)}
    cfg['generation']=2
    cfg['budget_version']='2026-10-08.owner-approved.guardian-v2'
    cfg['limits']=LIMITS
    cfg['warning_ratio']=0.85
    cfg['evolution_owner_approval']={'date':STAMP,
        'approval':'owner explicitly permitted increasing 50MB pilot budget',
        'event':'guardian capacity review','auto_enforcement':False}
    cog['version']='2026-10-08.owner-approved.guardian-v2'
    cog['hard_ceiling_bytes']=134217728
    for region,size in COG_BYTES.items():
        cog['regions'][region]['budget_bytes']=size
    # Do not alter cognition file contents or their existing hashes.
    atomic_json(cfg_path,cfg)
    atomic_json(cog_path,cog)
    record['new_policy_sha256']=hashlib.sha256(cfg_path.read_bytes()).hexdigest()
    record['new_cognition_config_sha256']=hashlib.sha256(cog_path.read_bytes()).hexdigest()
    guard=subprocess.run(['/usr/bin/python3',str(root/'bin/sentinel_guard.py')],
        capture_output=True,text=True,check=True)
    g=json.loads(guard.stdout)
    assert g['state']=='PASS', f'{label} guard FAIL {g}'
    budget=subprocess.run(['/usr/bin/python3',str(root/'bin/sentinel_budget.py')],
        capture_output=True,text=True,check=True)
    b=json.loads(budget.stdout)
    assert b['state']=='HEALTHY',(label,b['state'],b['ratios'])
    assert b['generation']==2
    record['post_validation']={
        'guard':g['state'],'capacity':b['state'],
        'db_bytes':b['metrics']['memory_database_bytes'],
        'obs_count':b['metrics']['observations_retained'],
        'ratios':b['ratios']}
    out=OUT/(dir_name+'-owner-approval.json')
    atomic_json(out,record)
    logs.append(record)
    print(json.dumps({'agent':label,'guard':g['state'],'capacity':b['state'],
                       'db_bytes':record['post_validation']['db_bytes'],
                       'new_db_ceiling':LIMITS['memory_database_bytes'],
                       'cognition_ceiling':cog['hard_ceiling_bytes']},ensure_ascii=False))
print('APPROVED_POLICY_MIGRATION_COMPLETE',len(logs),'agents')
