#!/usr/bin/env python3
"""Safely back up and add a time index to existing Sentinel observations.

Backup and apply must be separate explicit phases. No deletion, vacuum, or
policy changes. Never reads or writes firewall, CrowdSec, or Fail2Ban.
"""
import argparse,hashlib,json,sqlite3,datetime,time
from pathlib import Path

ROOT=Path('/home/ubuntu/services')
BACKUP=Path('/home/ubuntu/backups/sentinel-index-pre-2026-10-13')
AGENTS={'Luna':ROOT/'micro-sentinel/state/sentinel.db',
        'Selene':ROOT/'micro-sentinel-b/state/sentinel.db'}
INDEX='idx_observations_ts_desc'

def sha(path):
 h=hashlib.sha256()
 with open(path,'rb') as f:
  while True:
   c=f.read(2**20)
   if not c:break
   h.update(c)
 return h.hexdigest()

def snapshot(agent):
 src=AGENTS[agent]
 BACKUP.mkdir(mode=0o700,parents=True,exist_ok=True)
 BACKUP.chmod(0o700)
 dst_path=BACKUP/(agent.lower()+'-preindex.sqlite3')
 if dst_path.exists():raise RuntimeError('Snapshot already exists; refuse overwrite')
 src_db=sqlite3.connect('file:'+str(src)+'?mode=ro',uri=True,timeout=20)
 dst_db=sqlite3.connect(str(dst_path),timeout=20)
 try:
  src_db.backup(dst_db,pages=1024,sleep=0.1)
  status=dst_db.execute('PRAGMA quick_check').fetchone()[0]
  if status!='ok':raise RuntimeError('Snapshot integrity failed')
  dst_db.close(); dst_db=None
  dst_path.chmod(0o600)
  item={'source':str(src),'backup':str(dst_path),'size':dst_path.stat().st_size,
        'sha256':sha(dst_path),'quick_check':status,
        'captured_utc':datetime.datetime.now(datetime.timezone.utc).isoformat()}
  manifest=BACKUP/(agent.lower()+'-manifest.json')
  manifest.write_text(json.dumps(item,indent=2)+'\n')
  manifest.chmod(0o600)
  return item
 finally:
  if dst_db is not None:dst_db.close()
  src_db.close()

def apply(agent):
 manifest=BACKUP/(agent.lower()+'-manifest.json')
 if not manifest.is_file():raise RuntimeError('No validated backup manifest')
 item=json.loads(manifest.read_text())
 backup=Path(item['backup'])
 if not backup.is_file() or backup.stat().st_size!=item['size'] or sha(backup)!=item['sha256']:
  raise RuntimeError('Backup invalid or changed; refusing index')
 src=AGENTS[agent]
 con=sqlite3.connect(str(src),timeout=25)
 try:
  con.execute('PRAGMA busy_timeout=25000')
  before=con.execute('EXPLAIN QUERY PLAN SELECT ts FROM observations WHERE ts>=? ORDER BY ts DESC LIMIT 100',('2026-10-13',)).fetchall()
  con.execute('BEGIN IMMEDIATE')
  con.execute('CREATE INDEX IF NOT EXISTS '+INDEX+' ON observations(ts DESC)')
  con.commit()
  after=con.execute('EXPLAIN QUERY PLAN SELECT ts FROM observations WHERE ts>=? ORDER BY ts DESC LIMIT 100',('2026-10-13',)).fetchall()
  verified=any('USING COVERING INDEX '+INDEX in str(x) for x in after)
  if not verified:raise RuntimeError('Index exists but query plan not verified')
  return {'agent':agent,'before':before,'after':after,'query_uses_index':verified,
          'live_bans':0,'snapshot':str(backup)}
 except BaseException:
  con.rollback()
  raise
 finally:con.close()

if __name__=='__main__':
 p=argparse.ArgumentParser()
 p.add_argument('--agent',choices=tuple(AGENTS),required=True)
 grp=p.add_mutually_exclusive_group(required=True)
 grp.add_argument('--backup',action='store_true')
 grp.add_argument('--apply',action='store_true')
 args=p.parse_args()
 print(json.dumps(snapshot(args.agent) if args.backup else apply(args.agent),
       ensure_ascii=False,default=str))
