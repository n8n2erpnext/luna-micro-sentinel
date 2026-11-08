#!/usr/bin/env python3
"""Offline tests for decision-transition notifications. Never enqueue or deliver."""
import unittest,tempfile,json
from pathlib import Path
from datetime import datetime,timezone
from unittest.mock import patch
import reporter as r

def event(token,decision,previous=None,agent='Luna',site='thaiduy.digital'):
 return {'transition_token':token*20,'decision':decision,
   'previous_decision':previous,'agent':agent,'site':site,
   'subject':'93.184.216.34','rationale':'Independent evidence test',
   'evidence':['3 paths with 404','repeated activity'],
   'needs_to_confirm_or_refute':['Original client attribution'],
   'reassess_after_minutes':10,
   'generated_utc':datetime.now(timezone.utc).isoformat()}
class TestNotifications(unittest.TestCase):
 def run_with_events(self,events):
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);p=root/'sentinel-site-guardian/reports/decision_history.jsonl'
   p.parent.mkdir(parents=True)
   p.write_text(''.join(json.dumps(x)+'\n' for x in events),encoding='utf-8')
   with patch.object(r,'ROOT',root):
    return r.propose()
 def test_active_suspicion_is_emitted(self):
  items=self.run_with_events([event('a','WAIT_MORE_EVIDENCE')])
  self.assertEqual(len(items),1)
  self.assertIn('CHỜ TÍN HIỆU',items[0][1])
  self.assertIn('agent_decision:Luna:',items[0][0])
 def test_resolution_after_wait_is_not_safety_certificate(self):
  items=self.run_with_events([event('b','NO_ACTION','WAIT_MORE_EVIDENCE')])
  self.assertEqual(len(items),1)
  self.assertIn('TIẾP TỤC GIÁM SÁT',items[0][1])
  self.assertIn('không kết luận hệ thống an toàn tuyệt đối',items[0][1])
 def test_routine_no_action_is_silent(self):
  self.assertEqual(self.run_with_events([event('c','NO_ACTION')]),[])
 def test_wrong_site_is_ignored(self):
  self.assertEqual(self.run_with_events([event('d','BAN_RECOMMENDED',site='light-remote.thaiduy.digital')]),[])
 def test_reappearing_threat_has_new_dedup_key(self):
  a,b=self.run_with_events([event('e','WAIT_MORE_EVIDENCE'),event('f','NO_ACTION','WAIT_MORE_EVIDENCE'),event('4','WAIT_MORE_EVIDENCE','NO_ACTION')])[0::2]
  self.assertNotEqual(a[0],b[0])
 def test_journal_has_no_firewall_action(self):
  items=self.run_with_events([event('5','BAN_RECOMMENDED')])
  self.assertEqual(len(items),1)
  self.assertIn('KHÔNG BAN THẬT',items[0][1])
if __name__=='__main__':unittest.main()
