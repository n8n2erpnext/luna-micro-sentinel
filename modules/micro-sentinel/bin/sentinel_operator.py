#!/usr/bin/env python3
import json,html,sys
from pathlib import Path
ROOT=Path('/home/ubuntu/services/micro-sentinel')
def profile(): return json.loads((ROOT/'knowledge/operator.json').read_text())
def whoami():
 p=profile()['operator']
 return '\n'.join(['<b>👤 Operator relationship</b>','',f"Bạn là <b>{html.escape(p['display_name'])}</b>.",'Role: <b>Owner / primary human reviewer</b> của Micro Sentinel.','Bạn cùng maintainer review tiến bộ và knowledge rewards.','','<i>Boundary: operator identity không phải security evidence; tôi không suy ra IP/traffic nào thuộc Owner chỉ từ quan hệ này.</i>'])
def main(): print(whoami())
if __name__=='__main__': main()
