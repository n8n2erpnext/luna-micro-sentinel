#!/usr/bin/env python3
"""Offline Luna V2 alert acceptance. No Telegram, no bans, no live queue writes."""
from pathlib import Path
from datetime import datetime,timezone,timedelta
from tempfile import TemporaryDirectory
import json,sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import luna_firewall_v2 as luna
import reporter
old_read=luna.read
old_guard=luna.GUARD
now=datetime.now(timezone.utc).isoformat()
def make_row(ip='9.9.9.9',hits=6,paths=5,denied=3,windows=2,site='thaiduy.digital'):
    return {'src':ip,'scope_hostname':site,'suspicious_hits':hits,
            'distinct_suspicious_paths':paths,'denied_or_missing_suspicious_events':denied,
            'suspicious_distinct_10min_windows':windows,
            'suspicious_span_seconds':1,
            'first_suspicious_utc':now,'last_suspicious_utc':now,
            'evidence_digest':'abc123abc123abc123ab',
            'suspicious_feature_types':['probe_path','sensitive_discovery']}
def policy(rows):
    return {'generated_at_utc':now,'enforcement_enabled':False,
            'agents':{'Luna':{'assigned_hostname':'thaiduy.digital',
                              'site_summary':{'findings':rows}}}}
def set_scene(snapshot):
    luna.read=lambda path:snapshot if Path(path).name=='latest.json' else {}
with TemporaryDirectory() as d:
    luna.GUARD=Path(d)
    set_scene(policy([])); assert luna.proposals()==[],'Normal traffic should be silent'
    set_scene(policy([make_row(hits=2,paths=2,denied=0,windows=1)]))
    assert not luna.proposals(),'Weak single-route requests should be silent'
    set_scene(policy([make_row(ip='127.0.0.1')]))
    assert not luna.proposals(),'Loopback must never be reported as Internet attacker'
    set_scene(policy([make_row()]))
    events=luna.proposals()
    assert len(events)==1 and '9.9.9.9' in events[0][1]
    assert 'không tự ban IP' in events[0][1] and 'CrowdSec/Fail2Ban' in events[0][1]
    assert 'thaiduy.digital' in events[0][1]
    assert events[0][2] in (1,2)
    assert events[0][0].startswith('luna:v3:probe:')
    # Regression: the same evidence must retain its event key across midnight.
    real_now=luna.now
    incident_time='2026-10-30T16:59:30+00:00'  # 23:59:30 Vietnam
    cross=make_row()
    cross['last_suspicious_utc']=incident_time
    cross['first_suspicious_utc']=incident_time
    snapshot=policy([cross])
    snapshot['generated_at_utc']=incident_time
    luna.now=lambda:datetime.fromisoformat('2026-10-30T16:59:50+00:00')
    set_scene(snapshot)
    before=luna.proposals()
    luna.now=lambda:datetime.fromisoformat('2026-10-30T17:00:40+00:00')
    after=luna.proposals()
    assert len(before)==len(after)==1 and before[0][0]==after[0][0], 'Midnight must not reset deduplication'
    luna.now=lambda:datetime.fromisoformat('2026-10-30T17:35:40+00:00')
    snapshot['generated_at_utc']=luna.now().isoformat()
    assert luna.proposals()==[], 'Previously banned/stale evidence must not be recycled'
    luna.now=real_now
    bad=policy([make_row()])
    bad['generated_at_utc']=(datetime.now(timezone.utc)-timedelta(hours=2)).isoformat()
    set_scene(bad); assert not luna.proposals(),'Stale evidence must fail closed'
    no=policy([make_row()]);no['enforcement_enabled']=True
    set_scene(no);assert not luna.proposals(),'Unexpected enforcement mode must fail closed'
    rejected=False
    try:
        luna.block_receipt_message({'mode':'VERIFIED_LIVE_RECEIPT','action':'BLOCK'})
    except AssertionError:
        rejected=True
    assert rejected,'Unsigned/unapproved receipt was accepted'
    assert 'MÔ PHỎNG' in luna.preview_block()
    reporter.DB=Path(d)/'queue.sqlite3'
    assert reporter.enqueue('offline-test','URGENT','<b>test only</b>',1) is True
    assert reporter.enqueue('offline-test','URGENT','<b>duplicate</b>',1) is False
    row=reporter.claim()
    assert row['id']>0 and row['kind']=='URGENT'
    assert reporter.backlog()['pending']['URGENT']==1
    assert reporter.ack(row['id'],'777000')['acknowledged'] is True
    assert reporter.backlog()['delivered']==1
    assert reporter.backlog()['pending']=={}
luna.read=old_read;luna.GUARD=old_guard
print('PASS: quiet normal, weak evidence, nonpublic IP, actionable alert, site scope, stale/unsafe fail-closed, ban receipt gate, duplicate queue, claim/ack; zero real Telegram and bans')
