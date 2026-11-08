#!/usr/bin/env python3
"""Offline-only reliability and report checks; no Telegram sends."""
import tempfile,sys
from pathlib import Path
import reporter
with tempfile.TemporaryDirectory() as tmp:
 reporter.DB=Path(tmp)/'outbox.sqlite3'
 assert reporter.enqueue('test-campaign','URGENT','<b>Test</b>',priority=1)
 assert not reporter.enqueue('test-campaign','URGENT','<b>Test</b>',priority=1)
 one=reporter.claim()
 assert one['id']>0 and one['kind']=='URGENT' and one['text']=='<b>Test</b>'
 assert reporter.claim()=={},'duplicate claim on leased row'
 assert reporter.backlog()['pending']=={'URGENT':1}
 ack=reporter.ack(one['id'],'423131')
 assert ack['acknowledged']
 assert reporter.backlog()['delivered']==1
 assert reporter.claim()=={}
 print('PASS: queue dedupe, lease, Telegram-after-send acknowledgment')
 text=reporter.daily()
 assert len(text)<3400 and '<b>' in text and 'KHÔNG auto-ban' in text
 assert 'Luna' in text and 'Selene' in text
 print('PASS: 09:30 daily report both agents and clear non-enforcement scope')
 text=reporter.weekly()
 assert len(text)<3400 and 'Precision / Recall: CHƯA ĐO' in text
 assert 'CVE' in text
 print('PASS: weekly proficiency abstains from invented accuracy statistics')
 assert reporter.propose() == [], 'No current security incident should be invented'
 print('PASS: no unsolicited incident from current real source feeds')
print('GUARDIAN_OWNER_REPORTS_4_GROUPS_PASS')
