#!/usr/bin/env python3
from urllib.parse import urlsplit
PROBE=('env','git','wp-','phpmyadmin','cgi-bin','config','backup','shell','passwd','actuator','vendor','server-status')
SECRET_PATHS=('/.aws/credentials','/.docker/config.json','/.kube/config')
SAFE={'GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS'}
def clean_path(raw):
 try:return urlsplit(raw).path or '/'
 except:return (raw or '/').split('?',1)[0]
def classify(method,path,status,baseline_count=0,source_events=1,unique_paths=1,probe_hits=0,correlated_sources=1):
 method=(method or '').upper(); path=clean_path(path); low=path.lower(); reasons=[]; score=0
 probe=low in SECRET_PATHS or any(x in low for x in PROBE)
 if method not in SAFE: score+=2; reasons.append('unusual_method')
 if probe: score+=3; reasons.append('sensitive_probe_path')
 if unique_paths>=8 and probe_hits>=2: score+=3; reasons.append('broad_path_recon')
 if source_events>=20 and probe_hits>=3: score+=2; reasons.append('repeated_probe_behavior')
 if correlated_sources>=3 and probe_hits>=3: score+=2; reasons.append('correlated_multi_source_behavior')
 if baseline_count>=5 and not probe and method in SAFE: score-=2; reasons.append('established_scoped_baseline')
 if status>=500: reasons.append('server_error_not_hostility')
 if status in (401,403,404): reasons.append('denied_or_missing_not_verdict')
 label='suspicious_pattern' if score>=5 else 'unusual_uncertain' if score>=2 else 'normal_like'
 return {'class':label,'score':score,'reasons':reasons or ['no_material_anomaly_evidence'],'path':path}
