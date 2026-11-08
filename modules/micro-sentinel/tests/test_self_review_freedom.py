#!/usr/bin/env python3
import json,subprocess,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
tmpl=json.loads((ROOT/'knowledge/self_review_template.json').read_text())
assert [x['id'] for x in tmpl['sections']]==['today','change','uncertainty','learning','notebook','self_assessment','free']
day=time.strftime('%Y-%m-%d')
ref=json.loads((ROOT/'reports/reflection'/f'{day}.json').read_text())
assert ref.get('voice')=='SELF_REFLECTION_RAW_V2'
assert 'free_expression' not in ref
assert 'raw_self_note' in ref
out=json.loads(subprocess.check_output(['/usr/bin/python3',str(ROOT/'bin/sentinel_self_assessment.py')],text=True))
assert out.get('version')=='SELF_REVIEW_RAW_V2'
assert isinstance(out.get('self_assessment'),dict)
assert isinstance(out.get('learning'),dict)
assert 'formal_request_present' in out['learning']
src=(ROOT/'bin/sentinel_self_report.py').read_text()
for bad in ['CHƯA ĐẠT','TẠM ĐẠT','Tôi chưa hình thành','Tôi muốn theo dõi thêm','Điều đáng tò mò với tôi']:
    assert bad not in src
html=subprocess.check_output(['/usr/bin/python3',str(ROOT/'bin/sentinel_self_report.py')],text=True)
assert 'SELF-REVIEW RAW V2' in html
assert 'no authored self-review prose' in html
print('PASS: RAW V2 self-review, no authored self-evaluation prose, structured request/attention/uncertainty state')
print('current_report_bytes',len(html.encode()))
