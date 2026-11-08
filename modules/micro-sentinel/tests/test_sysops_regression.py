#!/usr/bin/env python3
import importlib.util,sys
from pathlib import Path
ROOT=Path('/home/ubuntu/services/micro-sentinel'); sys.path.insert(0,str(ROOT/'bin'))
def load(name,file):
 s=importlib.util.spec_from_file_location(name,ROOT/'bin'/file); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); return m
v2=load('v2','sentinel_v2.py'); ru=load('ru','request_understanding.py')
# Application API route named credentials is not a filesystem secret probe.
for p in ['/rest/credentials','/rest/credentials/for-workflow','/projects/abc/credentials/xyz']:
 assert 'probe_path' not in v2.features('GET',p,200), p
 assert ru.classify('GET',p,200,baseline_count=10)['class']=='normal_like', p
# Actual secret/config probes remain evidence.
for p in ['/.env','/.git/config','/.docker/config.json','/.aws/credentials']:
 assert 'probe_path' in v2.features('GET',p,404), p
# Service failures and request volume alone are not hostility verdicts.
x=ru.classify('GET','/health',502,baseline_count=10,source_events=500)
assert x['class']=='normal_like' and 'server_error_not_hostility' in x['reasons']
print('PASS: app-route context, secret probes, 5xx negative knowledge')
