#!/usr/bin/env python3
"""Offline regression fixtures for autonomous site decisions (no network/ban)."""
import sys, unittest, json, tempfile
from unittest.mock import patch
from datetime import datetime, timezone
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import decision_engine as d

NOW=datetime(2026,10,13,4,0,tzinfo=timezone.utc)
STAMP=NOW.isoformat()
def fixture(luna_rows=None, selene_rows=None):
    g={'generated_at_utc':STAMP,'agents':{}}
    t={'generated_utc':STAMP,'agents':{}}
    m={'captured_utc':STAMP,'state':'PASS','window_complete':True,'site_metrics':{}}
    for name,host in d.SITES.items():
        rows=luna_rows if name=='Luna' else selene_rows
        g['agents'][name]={'assigned_hostname':host,
                 'site_summary':{'findings':rows or []}}
        t['agents'][name]={'assigned_host':host,'finding':'NO_TEMPORAL_ALERT'}
        m['site_metrics'][host]={'requests_70m':100,'errors_5xx_70m':0}
    i={'sources':{'nvd_recent':{'fresh':True}}}
    return g,t,i,m
def candidate(site, ip='93.184.216.34', paths=4,hits=4,denied=4,kinds=2,windows=1,span=60):
    return {'scope_hostname':site,'src':ip,'distinct_suspicious_paths':paths,
      'suspicious_hits':hits,'denied_or_missing_suspicious_events':denied,
      'suspicious_distinct_10min_windows':windows,'suspicious_span_seconds':span,
      'suspicious_feature_types':['probe_path','sensitive_discovery'][:kinds],
      'evidence_digest':'0123456789abcdef'}
class TestDecisions(unittest.TestCase):
    def test_no_action_without_site_signal(self):
        r=d.build(*fixture(),now=NOW)
        self.assertEqual([x['decision'] for x in r['agents'].values()],['NO_ACTION','NO_ACTION'])
        self.assertEqual(r['actual_bans'],0)
    def test_wait_for_more_evidence(self):
        r=d.build(*fixture(luna_rows=[candidate('thaiduy.digital')]),now=NOW)
        self.assertEqual(r['agents']['Luna']['decision'],'WAIT_MORE_EVIDENCE')
        self.assertEqual(r['agents']['Selene']['decision'],'NO_ACTION')
        self.assertFalse(r['agents']['Luna']['executed'])
    def test_decision_report_is_json_serializable(self):
        r=d.build(*fixture(luna_rows=[candidate('thaiduy.digital')]),now=NOW)
        self.assertIn('WAIT_MORE_EVIDENCE',json.dumps(r))
    def test_strong_recon_recommends_ban_never_executes(self):
        r=d.build(*fixture(luna_rows=[candidate('thaiduy.digital',paths=8,hits=15,denied=9,windows=3,span=1250)]),now=NOW)
        x=r['agents']['Luna']
        self.assertEqual(x['decision'],'BAN_RECOMMENDED')
        self.assertFalse(x['execution_gate']['actual_ban_enabled'])
        self.assertFalse(x['executed'])
    def test_one_short_burst_never_recommends_ban(self):
        g,t,i,m=fixture(luna_rows=[candidate('thaiduy.digital',paths=8,hits=15,denied=9,windows=1,span=50)])
        r=d.build(g,t,i,m,now=NOW)
        self.assertEqual(r['agents']['Luna']['decision'],'WAIT_MORE_EVIDENCE')
        self.assertFalse(r['agents']['Luna']['executed'])
    def test_two_buckets_without_duration_are_not_persistence(self):
        g,t,i,m=fixture(luna_rows=[candidate('thaiduy.digital',paths=8,hits=15,denied=9,windows=2,span=40)])
        r=d.build(g,t,i,m,now=NOW)
        self.assertEqual(r['agents']['Luna']['decision'],'WAIT_MORE_EVIDENCE')
    def test_cross_site_evidence_does_not_authorize(self):
        bad=candidate('light-remote.thaiduy.digital',paths=15,hits=40,denied=32)
        r=d.build(*fixture(luna_rows=[bad]),now=NOW)
        self.assertEqual(r['agents']['Luna']['decision'],'NO_ACTION')
    def test_missing_site_telemetry_fails_closed(self):
        g,t,i,m=fixture()
        m['site_metrics'].pop('thaiduy.digital')
        r=d.build(g,t,i,m,now=NOW)
        self.assertEqual(r['agents']['Luna']['decision'],'INSUFFICIENT_TELEMETRY')
        self.assertEqual(r['agents']['Selene']['decision'],'NO_ACTION')
    def test_truncated_heuristic_evidence_fails_closed(self):
        g,t,i,m=fixture()
        g['agents']['Luna']['site_summary']['findings_truncated']=True
        r=d.build(g,t,i,m,now=NOW)
        self.assertEqual(r['agents']['Luna']['decision'],'INSUFFICIENT_TELEMETRY')
    def test_stale_telemetry_is_not_safe(self):
        g,t,i,m=fixture()
        t['generated_utc']='2026-10-12T01:00:00+00:00'
        r=d.build(g,t,i,m,now=NOW)
        self.assertEqual(r['agents']['Luna']['decision'],'INSUFFICIENT_TELEMETRY')
    def test_temporal_pressure_not_called_ddos(self):
        g,t,i,m=fixture()
        t['agents']['Selene'].update({'finding':'SURGE_WITH_HTTP_ERROR_IMPACT_NEEDS_RESOURCE_CORRELATION',
             'recent_rpm':900,'baseline_rpm':10,'recent_http_5xx_fraction':.4})
        r=d.build(g,t,i,m,now=NOW)
        self.assertEqual(r['agents']['Selene']['decision'],'INCIDENT_REVIEW_RECOMMENDED')
        self.assertEqual(r['actual_bans'],0)
    def test_transition_journal_dedupes_and_reopens_same_hypothesis(self):
        with tempfile.TemporaryDirectory() as td:
            base=Path(td)
            with patch.object(d,'STATE',base/'state.json'), patch.object(d,'OUT',base/'decisions.json'), patch.object(d,'HISTORY',base/'events.jsonl'):
                wa=d.build(*fixture(luna_rows=[candidate('thaiduy.digital')]),now=NOW)
                self.assertEqual(len(d.persist(wa)),2)
                first=wa['agents']['Luna']['transition_token']
                wb=d.build(*fixture(luna_rows=[candidate('thaiduy.digital')]),now=NOW)
                self.assertEqual(len(d.persist(wb)),0)
                self.assertEqual(first,wb['agents']['Luna']['transition_token'])
                clear=d.build(*fixture(),now=NOW)
                transitions=d.persist(clear)
                self.assertEqual(clear['agents']['Luna']['previous_decision'],'WAIT_MORE_EVIDENCE')
                self.assertEqual(clear['agents']['Luna']['decision'],'NO_ACTION')
                again=d.build(*fixture(luna_rows=[candidate('thaiduy.digital')]),now=NOW)
                d.persist(again)
                self.assertNotEqual(first,again['agents']['Luna']['transition_token'])
                self.assertEqual(again['agents']['Luna']['previous_decision'],'NO_ACTION')
                rows=[json.loads(x) for x in (base/'events.jsonl').read_text().splitlines()]
                self.assertEqual(len(rows),4)
                self.assertEqual(rows[2]['previous_decision'],'WAIT_MORE_EVIDENCE')
    def test_unknown_cve_does_not_prove_affected(self):
        r=d.build(*fixture(),now=NOW)
        self.assertFalse(r['agents']['Luna']['cve_context']['verified_affected_installed_version'])
if __name__=='__main__':unittest.main()
