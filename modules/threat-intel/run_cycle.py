#!/usr/bin/env python3
"""One bounded, observable threat-intelligence refresh + correlation cycle."""
from pathlib import Path
import subprocess,sys,json,datetime
ROOT=Path('/home/ubuntu/services/sentinel-threat-intel')
def run(name,timeout):
 r=subprocess.run(['/usr/bin/python3',str(ROOT/name)],cwd=ROOT,
     capture_output=True,text=True,timeout=timeout)
 if r.returncode:raise RuntimeError(name+' exit '+str(r.returncode)+' '+r.stderr[-400:])
 return json.loads(r.stdout)
def main():
 intake=run('intake.py',85)
 try:articles=run('article_reader.py',65)
 except Exception:articles={'state':'DEGRADED','read_new':0}
 corr=run('correlate.py',20)
 # Stale feeds don't cause illegal actions; they are flagged for maintainer.
 report={'time_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
  'mode':'READ_PUBLIC_INTEL_AND_CORRELATE_SHADOW',
  'refresh':intake,'articles':articles,'correlation':corr,'live_ban_actions':0,
  'owner_authorization':'NO_AUTOMATED_ENFORCEMENT'}
 dest=ROOT/'reports/cycle_status.json'
 temp=dest.with_suffix('.new')
 temp.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
 temp.replace(dest);dest.chmod(0o600)
 print(json.dumps({'status':'PASS','fresh_source_count':intake['fresh_sources'],
  'agents':corr['agents'],'live_bans':0},ensure_ascii=False))
if __name__=='__main__':main()
