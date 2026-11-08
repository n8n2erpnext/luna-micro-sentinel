#!/usr/bin/env python3
import importlib.util,json
from pathlib import Path
P=Path(__file__).resolve().parents[1]/'bin/sentinel_v2.py'
sp=importlib.util.spec_from_file_location('sentinel_recon',P); m=importlib.util.module_from_spec(sp); sp.loader.exec_module(m)
checks=[('GET','/../../etc/passwd',404,'path_traversal_indicator'),('GET','/config.php.bak',404,'backup_artifact_discovery'),('GET','/admin',401,'admin_surface_discovery'),('GET','/vendor/phpunit/x',404,'framework_fingerprint_probe'),('PROPFIND','/webdav/a',401,'method_capability_probe')]
for method,path,status,want in checks: assert want in m.features(method,path,status)
assert 'probe_path' not in m.features('GET','/admin',200)
rows=[]
for i,p in enumerate(['/../../etc/passwd','/%2e%2e/etc/shadow','/.env','/.git/config','/admin','/config.php.bak','/vendor/phpunit/x','/wp-login.php']):
 rows.append((f'2026-09-30T00:00:{i:02d}Z','203.0.113.10','203.0.113.0/24','x','GET',p,404,json.dumps(m.features('GET',p,404))))
names={x[0] for x in m.derive(rows)[0]}; assert {'traversal_probe_pattern','recon_category_sweep'}<=names
rows=[]
for i,(method,path) in enumerate([('PROPFIND','/a'),('COPY','/b'),('MOVE','/c')]):
 rows.append((f'2026-09-30T01:00:{i:02d}Z','203.0.113.11','203.0.113.0/24','x',method,path,405,json.dumps(m.features(method,path,405))))
assert any(x[0]=='method_enumeration_candidate' for x in m.derive(rows)[0])
print('PASS: recon taxonomy/traversal/sweep/method-enumeration/FP-boundary')
