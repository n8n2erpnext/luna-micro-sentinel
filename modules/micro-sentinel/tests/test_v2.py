#!/usr/bin/env python3
import importlib.util,json,tempfile,sqlite3
from pathlib import Path
P='/home/ubuntu/services/micro-sentinel/bin/sentinel_v2.py'
s=importlib.util.spec_from_file_location('sentinel',P); m=importlib.util.module_from_spec(s); s.loader.exec_module(m)
assert m.features('GET','/',200)==[]
assert 'server_error_nonhostile_prior' in m.features('GET','/',502)
assert 'probe_path' in m.features('GET','/.env',404)
assert 'access_denied' in m.features('POST','/login',403)
assert m.subnet('173.252.70.14')=='173.252.70.0/24'
rows=[]
for i in range(1,5):
 for j in range(2): rows.append(('2026-09-05T00:00:00Z',f'10.0.0.{i}','10.0.0.0/24','x','GET',f'/.env{j}',404,json.dumps(['probe_path','not_found'])))
pats,*_=m.derive(rows)
assert any(x[0]=='distributed_subnet_probe' for x in pats)
print('PASS: knowledge-safe features, subnet correlation, distributed campaign candidate')
