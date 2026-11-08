#!/usr/bin/env python3
"""2-minute bounded guardian evidence collector and safe incident queue scan."""
import json,subprocess,datetime
from pathlib import Path
ROOT=Path('/home/ubuntu/services/sentinel-guardian-reports')
def run(name,args,seconds):
 p=subprocess.run(['/usr/bin/python3',str(ROOT/name)]+args,
   cwd=ROOT,capture_output=True,text=True,timeout=seconds)
 if p.returncode:raise RuntimeError(f'{name} failed: {p.stderr[-600:]}')
 return json.loads(p.stdout)
def main():
 t=run('collect_evidence.py',[],45)
 a=run('reporter.py',['propose'],15)
 record={'at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
   'collection':t,'proposals':a,'automated_bans':0,
   'outbox_delivery':'n8n only; must acknowledge telegram success'}
 p=ROOT/'state/monitor_latest.json'
 tmp=p.with_suffix('.tmp')
 tmp.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n')
 tmp.replace(p)
 print(json.dumps(record,ensure_ascii=False))
if __name__=='__main__':main()
