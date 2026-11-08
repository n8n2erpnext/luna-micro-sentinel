#!/usr/bin/env python3
import json,os
from pathlib import Path
ROOT=Path('/home/ubuntu/services/micro-sentinel'); STATE=ROOT/'state/proxy_cursor.json'
def load(log):
 st=log.stat(); cur={'inode':st.st_ino,'offset':0}
 if STATE.exists():
  try:cur.update(json.loads(STATE.read_text()))
  except:pass
 if cur.get('inode')!=st.st_ino or cur.get('offset',0)>st.st_size: cur={'inode':st.st_ino,'offset':0}
 return cur
def save(log,offset):
 st=log.stat(); tmp=STATE.with_suffix('.tmp')
 tmp.write_text(json.dumps({'inode':st.st_ino,'offset':offset,'size':st.st_size}))
 os.replace(tmp,STATE)
def initialize_eof(log):
 if not STATE.exists(): save(log,log.stat().st_size)
