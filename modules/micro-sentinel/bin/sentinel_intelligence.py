#!/usr/bin/env python3
"""Nonblocking, read-only external intelligence overlay for observer cycle."""
from pathlib import Path
import json,subprocess,sys
ROOT=Path(__file__).resolve().parents[1]
NAME={'micro-sentinel':'Luna','micro-sentinel-b':'Selene'}.get(ROOT.name)
BRIDGE=Path('/home/ubuntu/services/sentinel-threat-intel/bridge.py')
def main():
 if NAME is None or not BRIDGE.is_file():
  print(json.dumps({'state':'WAIT','reason':'missing known agent or bridge','enforcement':'DISABLED'}));return
 try:
  r=subprocess.run(['/usr/bin/python3',str(BRIDGE),'--agent',NAME],
      timeout=9,text=True,capture_output=True,check=False)
  if r.returncode:
   print(json.dumps({'state':'DEGRADED','reason':'intelligence bridge nonzero','enforcement':'DISABLED'}));return
  d=json.loads(r.stdout)
  print(json.dumps({'state':'PASS' if d.get('status')=='FRESH' else 'STALE',
      'publisher_feed_count_fresh':d.get('sources_fresh',0),
      'reputation_overlap':d.get('reputation_matches'),
      'site':d.get('own_site'),'high_priority_global_kevs':d.get('kevs_to_review',0),
      'authority':'OBSERVE_ONLY','enforcement':'DISABLED'}))
 except Exception as exc:
  print(json.dumps({'state':'DEGRADED','reason':type(exc).__name__,
      'enforcement':'DISABLED'}))
if __name__=='__main__':main()
