#!/usr/bin/env python3
"""Bounded read-only component inventory for Luna/Selene CVE correlation.

Never guesses installed vulnerability. No authenticated scanning, no network
calls, and no environment variables/passwords from containers are collected.
"""
from pathlib import Path
from datetime import datetime,timezone
import json,subprocess,re,hashlib
ROOT=Path('/home/ubuntu/services/sentinel-guardian-reports')
OUT=ROOT/'state/software_inventory_latest.json'
PROTECTED=['/home/ubuntu/services/micro-sentinel']
def run(cmd,timeout=12):
 try:
  x=subprocess.run(cmd,text=True,capture_output=True,timeout=timeout)
  if x.returncode:return {'status':'UNAVAILABLE','reason':'returncode_'+str(x.returncode)+':'+re.sub(r'[^A-Za-z0-9 ._:/-]','',x.stderr[:140]),'lines':[]}
  return {'status':'OK','lines':x.stdout.splitlines()[:5000]}
 except Exception as e:return {'status':'UNAVAILABLE','reason':type(e).__name__,'lines':[]}
def strip_v(v):
 s=str(v)
 return re.sub(r'[^A-Za-z0-9._+~:-]','',s)[:110]
def packages(lines):
 out={}
 for s in lines:
  p=s.strip().split()
  if len(p)>=2:
   name=strip_v(p[0]);version=strip_v(p[1])
   if name in ('openssl','curl','libssl3','libssl3t64','linux-image-generic','docker.io','nginx','nodejs','python3','libc6','openssh-server') and version:out[name]=version
 return out
def main():
 try:previous=json.loads(OUT.read_text())
 except (ValueError,FileNotFoundError):previous={}
 host=run(['dpkg-query','-W'],10)
 hostpk=packages(host['lines'])
 guest=run(['lxc','exec','light-remote-direct','--','dpkg-query','-W'],18)
 guestpk=packages(guest['lines'])
 if guest['status']!='OK':
  prev=previous.get('assigned_websites',{}).get('light-remote.thaiduy.digital',{}).get('selected_package_versions',{})
  if prev and previous.get('source_status',{}).get('lxd') in ('OK','STALE_CACHED'):
   guestpk=prev
   guest['status']='STALE_CACHED'
   guest['reason']='LXD inaccessible to hardened user service; retained last read-only version evidence'
 docker=run(['docker','inspect','-f','{{.Name}}|{{.Config.Image}}|{{.Image}}',
    'thaiduy-digital','netbird-proxy','netbird-traefik'],9)
 images=[]
 for row in docker['lines']:
  p=row.split('|')
  if len(p)==3:
   images.append({'container_name':p[0].lstrip('/'),'image_reference':p[1],
    'immutable_image_id':p[2],'image_ref_not_proof_of_package_versions':True})
 data={'version':'GUARDIAN_ASSET_EVIDENCE_S1','captured_utc':datetime.now(timezone.utc).isoformat(),
  'data_authority':'READ_ONLY_VERSION_INVENTORY_NOT_CVE_MATCH',
  'host':{'os':'Ubuntu 24.04.4 LTS','kernel':'7.0.0-1012-oracle',
   'selected_package_versions':hostpk,'query_status':host['status']},
  'assigned_websites':{
    'thaiduy.digital':{
      'candidate_runtime':'Docker thaiduy-digital',
      'container_image':next((r for r in images if r['container_name']=='thaiduy-digital'),None),
      'service_route_proven':'NOT_AUDITED'},
    'light-remote.thaiduy.digital':{
      'candidate_runtime':'LXD light-remote-direct',
      'guest_os':'Ubuntu 24.04.5 LTS',
      'selected_package_versions':guestpk,
      'package_scan_scope':'SELECTED_OS_PACKAGES_ONLY',
      'service_route_proven':'NOT_AUDITED'}
   },
   'proxy_image_references':[r for r in images if r['container_name'] in ('netbird-proxy','netbird-traefik')],
   'source_status':{'host':host['status'],'lxd':guest['status'],'docker':docker['status']},
   'missing_for_cve_confirmation':[
     'Verified per-website route-to-runtime mapping',
     'Complete application dependencies SBOM with lockfiles',
     'Vendor affected version ranges or distro security advisory match',
     'Runtime fixes/backports and deployment confirmation'],
   'known_exploited_in_wild_does_not_equal_local_vulnerability':True,
   'zero_day_behavior_inference_requires_application_evidence':True,
   'automatic_patch':False,'automatic_ban':False}
 OUT.parent.mkdir(parents=True,exist_ok=True)
 tmp=OUT.with_suffix('.new');tmp.write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n')
 tmp.replace(OUT);OUT.chmod(0o600)
 print(json.dumps({'state':'PARTIAL_REAL_VERSIONS','host_pkg_count':len(hostpk),
   'lxd_pkg_count':len(guestpk),'docker_images':len(images),
   'software_status':data['source_status'],'cve_verified_matches':0,
   'no_ban':True},ensure_ascii=False))
if __name__=='__main__':main()
