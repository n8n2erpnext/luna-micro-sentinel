#!/usr/bin/env python3
"""Unprivileged periodic learner: snapshots only, no active enforcement.

Writes rotating *latest* reports and a small append-only per-cycle summary.
It never refreshes KEV without explicit operator action, never changes
Sentinel agent databases/cognition, never imports Fail2ban or nftables.
"""
from pathlib import Path
import subprocess,sys,json,datetime,os
ROOT=Path('/home/ubuntu/services/sentinel-site-guardian')
OUT=ROOT/'reports'
OUT.mkdir(parents=True,exist_ok=True)
def run(script,opts,timeout=30):
    cmd=[sys.executable,str(ROOT/script)]+opts
    p=subprocess.run(cmd,cwd=ROOT,capture_output=True,text=True,timeout=timeout)
    if p.returncode:
        raise RuntimeError(f'{script} failed rc={p.returncode} stderr={p.stderr[-1800:]}')
    return p.stdout
def main():
    cfg=json.loads((ROOT/'owner_assignments.json').read_text())
    if cfg['enforcement_enabled'] or cfg['enforcement_backend'] is not None:
        raise SystemExit('NO SHADOW RUNNING WHEN ENFORCEMENT STATE CHANGED')
    now=datetime.datetime.now(datetime.timezone.utc).isoformat()
    run('shadow_review.py',['--window-minutes','60','--out',str(OUT/'latest.json')])
    run('guardian_temporal_shadow.py',['--out',str(OUT/'temporal_shadow_latest.json')])
    s=json.loads((OUT/'latest.json').read_text())
    t=json.loads((OUT/'temporal_shadow_latest.json').read_text())
    assert not s['enforcement_enabled'] and t['governance']['enforcement_enabled'] is False
    # Agents now publish actual *judgements* (recommend / wait / no-action),
    # not just suspicious log summaries. This module has zero ban authority.
    from decision_engine import build as decide, persist as save_decisions, load as read_decision_input
    metrics=read_decision_input(Path('/home/ubuntu/services/sentinel-guardian-reports/state/telemetry_latest.json'))
    intel=read_decision_input(Path('/home/ubuntu/services/sentinel-threat-intel/reports/intake_latest.json'))
    decisions=decide(s,t,intel,metrics)
    transitions=save_decisions(decisions)
    # Autonomous curriculum queue: only independent evidence can close a gap.
    from learning_loop import main as record_learning
    assets=read_decision_input(Path('/home/ubuntu/services/sentinel-guardian-reports/state/software_inventory_latest.json'))
    try:
        learning=record_learning(decisions,intel,assets,metrics)
        learning_status='REFRESHED'
    except (OSError,ValueError,KeyError,TypeError):
        learning_status='DEGRADED'
    assert decisions['actual_bans']==0 and all(not x['executed'] for x in decisions['agents'].values())
    agents={}
    for name in ('Luna','Selene'):
        sd=s['agents'][name]; td=t['agents'][name]
        assert sd['assigned_hostname']==td['assigned_host']
        assert sd['effect']=='NO_ACTION_PERFORMED' and td['live_bans']==0
        agents[name]={
            'host':sd['assigned_hostname'],
            'global_hosts_visible':sd['global_hosts_seen'],
            'guardian_lesson_findings':sd['guardian_s1_training_shadow']['findings_total'],
            'temporal_finding':td['finding'],
            'subnet_campaigns_touching_site':len(td['assigned_host_campaign_candidates']),
            'recent_rpm':td['recent_rpm'],
            'decision':decisions['agents'][name]['decision'],
            'decision_subject':decisions['agents'][name]['subject'],
            'decision_reason':decisions['agents'][name]['rationale'],
            'decision_executed':False}
    result={'time_utc':now,'mode':'AUTONOMOUS_DECISIONS_SHADOW_EXECUTION','fail2ban_actions':0,
            'site_guardians':agents,'decision_transitions':len(transitions),
            'learning_state':learning_status,
            'decisions_path':str(OUT/'decisions_latest.json'),
            'learning_agenda_path':str(OUT/'learning_agenda_latest.json')}
    (OUT/'cycle_status.json').write_text(json.dumps(result,indent=2,ensure_ascii=False)+'\n')
    with (OUT/'training_progress.jsonl').open('a',encoding='utf-8') as f:
        f.write(json.dumps(result,ensure_ascii=False,separators=(',',':'))+'\n')
    print(json.dumps(result,ensure_ascii=False))
if __name__=='__main__':
    # Serialize the decision writer if another owner-approved scheduler overlaps.
    import fcntl
    lock=ROOT/'state/guardian_cycle.lock'
    lock.parent.mkdir(parents=True,exist_ok=True)
    with lock.open('a') as fd:
        fcntl.flock(fd.fileno(),fcntl.LOCK_EX)
        main()
