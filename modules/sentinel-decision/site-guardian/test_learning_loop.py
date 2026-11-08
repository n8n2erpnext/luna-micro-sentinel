#!/usr/bin/env python3
"""Evidence-gated curriculum tests. Mock public feed coverage, never fetch URLs."""
import json,tempfile,unittest
from pathlib import Path
from datetime import datetime,timezone
from unittest.mock import patch
import learning_loop as l

def decision_fixture():
 return {'agents':{
  'Luna':{'site':'thaiduy.digital','decision':'WAIT_MORE_EVIDENCE','decision_id':'a'*20},
  'Selene':{'site':'light-remote.thaiduy.digital','decision':'NO_ACTION','decision_id':'b'*20}}}
def feeds(cisa=True,nvd=True):
 return {'sources':{'cisa_advisories':{'fresh':cisa},
                    'nvd_recent':{'fresh':nvd}}}
class TestLearning(unittest.TestCase):
 def evaluate(self,count=5,total=5,complete=True,cisa=True,nvd=True):
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);f=root/'sentinel-threat-intel/state/nvd_recent.json'
   f.parent.mkdir(parents=True)
   f.write_text(json.dumps({'count':count,'total_published_window':total,'coverage_complete':complete}))
   with patch.object(l,'ROOT',root):
    return l.evaluate(decision_fixture(),feeds(cisa,nvd),{}, {},now=datetime(2026,10,13,tzinfo=timezone.utc))
 def test_full_nvd_and_fresh_cisa_ready_for_independent_evaluation(self):
  d=self.evaluate()
  self.assertTrue(d['threat_intelligence_coverage']['nvd_window_complete'])
  self.assertEqual(d['agents']['Luna']['lessons']['THREAT_FEED_RELIABILITY']['status'],'READY_FOR_INDEPENDENT_EVALUATION')
  self.assertFalse(d['agents']['Luna']['mastery_claimed'] if 'mastery_claimed' in d['agents']['Luna'] else False)
 def test_partial_nvd_never_counts_as_ready(self):
  d=self.evaluate(count=4,total=5,complete=False)
  self.assertFalse(d['threat_intelligence_coverage']['feed_research_ready'])
  self.assertEqual(d['agents']['Selene']['lessons']['THREAT_FEED_RELIABILITY']['status'],'EVIDENCE_GAP')
 def test_component_evidence_does_not_mean_cve_exposure_proven(self):
  with tempfile.TemporaryDirectory() as td:
   root=Path(td)
   nvd_file=root/'sentinel-threat-intel/state/nvd_recent.json'
   nvd_file.parent.mkdir(parents=True)
   nvd_file.write_text(json.dumps({'count':5,'total_published_window':5,'coverage_complete':True}))
   ev=root/'sentinel-guardian-reports/state/deployed_component_evidence_latest.json'
   ev.parent.mkdir(parents=True)
   ev.write_text(json.dumps({'captured_utc':'2026-10-13T00:00:00+00:00',
     'by_site':{'thaiduy.digital':{'route_proven':False,'runtime_versions':{'status':'OK','node':'v22.23.3'},'full_app_sbom':False},
     'light-remote.thaiduy.digital':{'route_proven':False,'os_installed_package_inventory':{'count':595,'complete':True},'full_app_sbom':False}}}))
   with patch.object(l,'ROOT',root):
    d=l.evaluate(decision_fixture(),feeds(),{}, {},now=datetime(2026,10,13,tzinfo=timezone.utc))
   a=d['agents']['Luna']['component_evidence_progress']
   b=d['agents']['Selene']['component_evidence_progress']
   self.assertEqual(a['node_version_observed'],'v22.23.3')
   self.assertEqual(b['guest_package_count'],595)
   self.assertEqual(a['vulnerability_exposure_status'],'UNKNOWN')
   self.assertEqual(b['vulnerability_exposure_status'],'UNKNOWN')
   self.assertFalse(a['observed_site_route'])
   self.assertEqual(d['agents']['Luna']['lessons']['APPLICATION_VULNERABILITY']['status'],'EVIDENCE_GAP')
 def test_cached_guest_data_never_passes_as_fresh(self):
  with tempfile.TemporaryDirectory() as td:
   root=Path(td)
   nvd=root/'sentinel-threat-intel/state/nvd_recent.json'
   nvd.parent.mkdir(parents=True)
   nvd.write_text(json.dumps({'count':5,'total_published_window':5,'coverage_complete':True}))
   ev=root/'sentinel-guardian-reports/state/deployed_component_evidence_latest.json'
   ev.parent.mkdir(parents=True)
   ev.write_text(json.dumps({'captured_utc':'2026-10-13T00:00:00+00:00',
    'by_site':{'light-remote.thaiduy.digital':{'collected_utc':'2026-10-13T00:00:00+00:00',
     'source_status':'CACHED_UNVERIFIED_NOW',
     'os_installed_package_inventory':{'complete':True,'count':595},'route_proven':False}}}))
   with patch.object(l,'ROOT',root):
    d=l.evaluate(decision_fixture(),feeds(),{}, {},now=datetime(2026,10,13,tzinfo=timezone.utc))
   x=d['agents']['Selene']['component_evidence_progress']
   self.assertFalse(x['component_evidence_fresh'])
   self.assertEqual(x['guest_package_count'],0)
   self.assertEqual(x['last_known_guest_package_count'],595)
   self.assertEqual(x['vulnerability_exposure_status'],'UNKNOWN')
 def test_stale_component_evidence_is_not_usable(self):
  with tempfile.TemporaryDirectory() as td:
   root=Path(td)
   nvd_file=root/'sentinel-threat-intel/state/nvd_recent.json'
   nvd_file.parent.mkdir(parents=True)
   nvd_file.write_text(json.dumps({'count':5,'total_published_window':5,'coverage_complete':True}))
   ev=root/'sentinel-guardian-reports/state/deployed_component_evidence_latest.json'
   ev.parent.mkdir(parents=True)
   ev.write_text(json.dumps({'captured_utc':'2026-10-11T00:00:00+00:00',
      'by_site':{'thaiduy.digital':{'runtime_versions':{'status':'OK','node':'v22.23.3'}}}}))
   with patch.object(l,'ROOT',root):
    d=l.evaluate(decision_fixture(),feeds(),{}, {},now=datetime(2026,10,13,tzinfo=timezone.utc))
   self.assertFalse(d['agents']['Luna']['component_evidence_progress']['component_evidence_fresh'])
   self.assertIsNone(d['agents']['Luna']['component_evidence_progress']['node_version_observed'])
 def test_stale_cisa_is_not_ready(self):
  d=self.evaluate(cisa=False)
  self.assertFalse(d['threat_intelligence_coverage']['feed_research_ready'])
 def test_learning_does_not_claim_installed_software_vulnerability(self):
  d=self.evaluate()
  self.assertFalse(d['threat_intelligence_coverage']['local_component_vulnerability_confirmed'])
  self.assertTrue(d['no_automatic_authority_promotion'])
if __name__=='__main__': unittest.main()
