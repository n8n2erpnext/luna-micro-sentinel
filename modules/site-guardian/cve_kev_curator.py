#!/usr/bin/env python3
"""CISA KEV catalog cache for Web Guardian, advisory only.

CISA KEV answers "has this CVE been exploited in the wild?". It does not
say whether THIS website or installed version is affected. The latter needs
verified local SBOM/advisory evidence. No scanner, exploit, firewall actions.
"""
from pathlib import Path
import argparse,datetime,hashlib,json,re,urllib.request

ROOT=Path('/home/ubuntu/services/sentinel-site-guardian')
CACHE=ROOT/'state/cisa_kev_catalog.json'
MANIFEST=ROOT/'state/cisa_kev_metadata.json'
SOURCE='https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
ID=re.compile(r'^CVE-20\d\d-\d{4,}$')
MAX_BYTES=12*1024*1024

def validate(obj,*,min_records=1):
    assert isinstance(obj,dict) and isinstance(obj.get('vulnerabilities'),list)
    assert isinstance(obj.get('catalogVersion'),str) and obj['catalogVersion']
    records=obj['vulnerabilities']
    assert len(records)>=min_records
    assert len(records)==obj.get('count'), 'CISA count mismatch'
    ids=set()
    for v in records:
        assert isinstance(v,dict)
        assert ID.fullmatch(str(v.get('cveID','')))
        assert str(v.get('vendorProject','')).strip()
        assert str(v.get('product','')).strip()
        assert isinstance(v.get('dateAdded'),str)
        assert v['cveID'] not in ids
        ids.add(v['cveID'])
    return {v['cveID']:v for v in records}

def refresh():
    assert SOURCE.startswith('https://www.cisa.gov/')
    req=urllib.request.Request(SOURCE,headers={'User-Agent':'LightSentinel-KEV-ReferenceCache/1.0','Accept':'application/json'})
    with urllib.request.urlopen(req,timeout=18) as resp:
        if resp.status!=200: raise ValueError('HTTP '+str(resp.status))
        raw=resp.read(MAX_BYTES+1)
    if len(raw)>MAX_BYTES: raise ValueError('Oversized catalog')
    obj=json.loads(raw)
    indexes=validate(obj,min_records=300)
    CACHE.parent.mkdir(parents=True,exist_ok=True)
    tmp=CACHE.with_suffix('.tmp')
    tmp.write_bytes(raw)
    tmp.replace(CACHE)
    manifest={
        'origin':SOURCE,'retrieved_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'sha256':hashlib.sha256(raw).hexdigest(),
        'count':len(indexes),'catalogVersion':obj['catalogVersion'],
        'identity':'PUBLIC_CURATED_KEV_CATALOG_NOT_LOCAL_VULNERABILITY_PROOF',
        'site_enforcement':'NONE',
    }
    MANIFEST.write_text(json.dumps(manifest,indent=2)+'\n')
    return manifest

def review(assets,catalog):
    index=validate(catalog)
    out=[]
    for asset in assets:
        cve=str(asset.get('cve_id') or '').upper()
        p=index.get(cve)
        exact_match=bool(p and str(asset.get('vendor','')).lower().strip()==p.get('vendorProject','').lower().strip()
                         and str(asset.get('product','')).lower().strip()==p.get('product','').lower().strip())
        ver=bool(asset.get('installed_version_verified'))
        affected=bool(asset.get('affected_range_verified_from_vendor_advisory'))
        result='NEED_SOFTWARE_INVENTORY'
        if exact_match and ver and affected:
            result='PRIORITY_HUMAN_PATCH_REVIEW_KEV_MAPPED'
        elif exact_match:
            result='KEV_PRODUCT_MATCH_VERSION_UNKNOWN'
        elif cve in index:
            result='KEV_LISTED_BUT_PRODUCT_NOT_MATCHED'
        elif cve:
            result='CVE_NOT_IN_CURRENT_KEV_NOT_PROOF_SAFE'
        out.append({
            'site':asset.get('site'),'cve_id':cve,'inventory_component':asset.get('product'),
            'installed_version':asset.get('version') if ver else None,
            'status':result,'known_exploited_feed_entry':bool(p),
            'locally_exploited':None,'automatic_ban':False,'automatic_patch':False,
            'notes':'CISA KEV + verified affected version means urgent patch assessment, not local exploit detection',
        })
    return out

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--refresh',action='store_true')
    p.add_argument('--inventory',type=Path,help='Owner-reviewed JSON list of installed component+CVE advisory matches')
    p.add_argument('--out',type=Path,default=ROOT/'reports/cve_kev_review.json')
    args=p.parse_args()
    if args.refresh:
        print(json.dumps({'cache_refreshed':refresh()},ensure_ascii=False))
    if args.inventory:
        if not CACHE.exists():raise SystemExit('No KEV cache: refresh first')
        catalog=json.loads(CACHE.read_text())
        assets=json.loads(args.inventory.read_text())
        assert isinstance(assets,list)
        results=review(assets,catalog)
        args.out.parent.mkdir(parents=True,exist_ok=True)
        args.out.write_text(json.dumps({
            'status':'ADVISORY_ONLY','cache':str(CACHE),'count':len(results),
            'results':results,'live_bans':0},indent=2,ensure_ascii=False)+'\n')
        args.out.chmod(0o600)
        print(json.dumps({'items':len(results),'requires_patch_review':
            sum(x['status']=='PRIORITY_HUMAN_PATCH_REVIEW_KEV_MAPPED' for x in results),
            'live_bans':0,'report':str(args.out)},ensure_ascii=False))
    elif not args.refresh:
        print(json.dumps({'status':'WAIT_FOR_VERIFIED_ASSET_INVENTORY',
            'cache_available':CACHE.exists(),'live_bans':0},ensure_ascii=False))
if __name__=='__main__':main()
