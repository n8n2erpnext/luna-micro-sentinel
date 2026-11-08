#!/usr/bin/env python3
"""Bounded, read-only installed software evidence (no vulnerability claims).

The data is evidence for LUNA/SELENE CVE reasoning. It is neither a validated
site routing attestation nor full application dependency SBOM. No package
install, network request, remediation or ban executor.
"""
from __future__ import annotations
import hashlib
import json
import os
import re
import subprocess
from datetime import datetime,timezone
from pathlib import Path

ROOT=Path('/home/ubuntu/services/sentinel-guardian-reports')
OUT=ROOT/'state/deployed_component_evidence_latest.json'
MAX_STDOUT=3_000_000
def run(argv,timeout=22):
    try:
        p=subprocess.run(argv,capture_output=True,timeout=timeout)
        if p.returncode:return None,'EXIT_'+str(p.returncode)
        if len(p.stdout)>MAX_STDOUT:return None,'OVERSIZE_OUTPUT'
        return p.stdout.decode('utf-8','replace'),'OK'
    except (OSError,subprocess.TimeoutExpired) as e:
        return None,type(e).__name__
def installed_packages():
    cmd=['lxc','exec','light-remote-direct','--','dpkg-query','-W',
         '-f=${binary:Package}\\t${Version}\\n']
    text,status=run(cmd,27)
    if text is None:return {'status':status,'count':0,'packages':{},'complete':False}
    parsed={}
    for line in text.splitlines():
        if '\t' not in line:continue
        n,v=line.split('\t',1)
        if re.fullmatch(r'[A-Za-z0-9.+:_-]{1,140}',n) and re.fullmatch(r'[A-Za-z0-9.+:~_-]{1,160}',v):
            parsed[n]=v
    if len(parsed)<50 or len(parsed)>10000:return {'status':'INCOMPLETE_OR_INVALID','count':len(parsed),'packages':{},'complete':False}
    checksum=hashlib.sha256(json.dumps(parsed,sort_keys=True).encode()).hexdigest()
    return {'status':'OK','count':len(parsed),'packages':parsed,'sha256':checksum,'complete':True,
            'collection_method':'lxc exec dpkg-query -W (read-only installed OS packages)',
            'not_an_application_sbom':True}
def node_runtime():
    node,status=run(['docker','exec','thaiduy-digital','node','--version'],12)
    npm,status_npm=run(['docker','exec','thaiduy-digital','npm','--version'],12)
    ver=(node or '').strip()
    nver=(npm or '').strip()
    good=bool(re.fullmatch(r'v\d+\.\d+\.\d+',ver)) and status=='OK'
    return {'status':'OK' if good else 'INCOMPLETE',
            'node':ver if good else None,
            'npm':nver if status_npm=='OK' and re.fullmatch(r'\d+\.\d+\.\d+',nver) else None,
            'method':'docker exec version read-only',
            'application_dependencies':'NOT_COLLECTED',
            'complete_sbom':False}
def main():
    components=installed_packages()
    node=node_runtime()
    now=datetime.now(timezone.utc).isoformat()
    try:previous=json.loads(OUT.read_text(encoding='utf-8'))
    except (OSError,ValueError):previous={}
    # Never pretend that a cached LXD package list was refreshed.
    guest_captured=now if components.get('complete') else None
    if not components.get('complete'):
        prior=previous.get('by_site',{}).get('light-remote.thaiduy.digital',{})
        saved=prior.get('os_installed_package_inventory',{})
        guest_captured=prior.get('collected_utc') or previous.get('captured_utc')
        if saved.get('complete') is True and guest_captured:
            components=dict(saved)
            components['status']='CACHED_UNVERIFIED_NOW'
            components['cached_not_refreshed']=True
    # If even the Docker runtime failed, keep the previous entire snapshot
    # and let evidence age naturally rather than replacing it with a false OK.
    if node.get('status')!='OK':
        print(json.dumps({'result':'COLLECTION_DEGRADED',
          'guest_status':components.get('status'),'node_status':node.get('status'),
          'previous_snapshot_preserved':True,'executed_bans':0}))
        raise SystemExit(2)
    out={
        'schema':'SENTINEL_DEPLOYED_COMPONENT_EVIDENCE_V1',
        'captured_utc':now,
        'collection_authority':'READ_ONLY_COMPONENT_VERSIONS_NOT_EXPLOITATION',
        'by_site':{
            'thaiduy.digital':{
                'candidate_runtime':'Docker thaiduy-digital',
                'runtime_versions':node,
                'collected_utc':now,
                'source_status':'OK',
                'route_proven':False,
                'full_app_sbom':False,
                'vendor_affected_range_checked':False,
                'exposure_status':'UNKNOWN'},
            'light-remote.thaiduy.digital':{
                'candidate_runtime':'LXD light-remote-direct',
                'os_installed_package_inventory':components,
                'collected_utc':guest_captured,
                'source_status':components.get('status'),
                'route_proven':False,
                'full_app_sbom':False,
                'vendor_affected_range_checked':False,
                'exposure_status':'UNKNOWN'}
        },
        'known_limitations':[
            'The candidate runtime-to-domain mapping has not been independently verified',
            'Node.js runtime version is not complete npm/production app dependency graph',
            'dpkg versions require Ubuntu USN/backport-aware CVE checks',
            'OS inventory is not proof of exposed vulnerable application code',
            'LXD package inventory represents one guest, not all containers and libraries'],
        'automatic_patch':False,'automatic_ban':False}
    OUT.parent.mkdir(parents=True,exist_ok=True)
    tmp=OUT.with_suffix('.new')
    tmp.write_text(json.dumps(out,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    tmp.chmod(0o600)
    os.replace(tmp,OUT)
    print(json.dumps({'result':'RECORDED' if components.get('status')=='OK' else 'PARTIAL_WITH_LXD_CACHED_OR_MISSING',
        'guest_dpkg_count':components.get('count',0),
        'guest_inventory_fresh':components.get('status')=='OK',
        'node_runtime_found':node.get('node'),
        'cve_exposure_verified':False,
        'site_route_verified':False,
        'executed_bans':0},ensure_ascii=False))
if __name__=='__main__':main()
