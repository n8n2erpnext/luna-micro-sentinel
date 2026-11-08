#!/usr/bin/env python3
import html,json,sqlite3
from pathlib import Path
from datetime import datetime
ROOT=Path('/home/ubuntu/services/micro-sentinel')
DB=ROOT/'state/sentinel.db'
def load(path):
 try:return json.loads(path.read_text())
 except:return {}
def status():
 day=datetime.now().strftime('%Y-%m-%d')
 ident=load(ROOT/'knowledge/identity.json')
 selfr=load(ROOT/'reports/self'/f'{day}.json')
 audit=load(ROOT/'reports/independent'/f'{day}.json')
 lines=['<b>🧠 Micro Sentinel — tình hình hiện tại</b>','',f"• Vai trò: <b>{html.escape(ident.get('authority',{}).get('mode','OBSERVE_ONLY'))}</b>",f"• Ngày: <code>{day}</code>"]
 if selfr:
  lines += [f"• Observations: <b>{selfr.get('observations',0)}</b>",f"• Sources / subnets: <b>{selfr.get('unique_sources',0)}</b> / <b>{selfr.get('unique_subnets',0)}</b>",f"• Learned patterns: <b>{len(selfr.get('learned_patterns',[]))}</b>",f"• Knowledge: <code>{html.escape(str(selfr.get('knowledge_version','?')))}</code>"]
 if audit:
  lines += ['', '<b>🔎 Independent audit</b>',f"• Fail2ban bans: <b>{audit.get('fail2ban_bans',0)}</b>",f"• Probe hits: <b>{audit.get('probe_feature_hits',0)}</b>",f"• Derived patterns: <b>{audit.get('derived_pattern_count',0)}</b>",f"• Cross-check: <b>{html.escape(str(audit.get('cross_check','?')))}</b>"]
 lines += ['', '<i>Sentinel chỉ quan sát/học/báo cáo; không có quyền ban hoặc sửa firewall.</i>']
 return '\n'.join(lines)
if __name__=='__main__': print(status())
