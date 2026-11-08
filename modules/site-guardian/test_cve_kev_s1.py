#!/usr/bin/env python3
"""Offline known-exploited catalog regression with fixture inventory only."""
import json,hashlib
from cve_kev_curator import CACHE,MANIFEST,review,validate
catalog=json.loads(CACHE.read_text())
idx=validate(catalog,min_records=300)
manifest=json.loads(MANIFEST.read_text())
assert manifest['sha256']==hashlib.sha256(CACHE.read_bytes()).hexdigest()
assert manifest['count']==len(idx) and manifest['origin'].startswith('https://www.cisa.gov/')
v=next(iter(idx.values()))
cve=v['cveID']
common={'site':'test.invalid','cve_id':cve,'vendor':v['vendorProject'],'product':v['product'],
        'version':'demo-version-not-installed'}
cases=[
 (dict(common,installed_version_verified=False,affected_range_verified_from_vendor_advisory=False),
  'KEV_PRODUCT_MATCH_VERSION_UNKNOWN'),
 (dict(common,installed_version_verified=True,affected_range_verified_from_vendor_advisory=True),
  'PRIORITY_HUMAN_PATCH_REVIEW_KEV_MAPPED'),
 (dict(common,vendor='unrelated-vendor',product='unrelated-product',installed_version_verified=True,
       affected_range_verified_from_vendor_advisory=True),
  'KEV_LISTED_BUT_PRODUCT_NOT_MATCHED'),
 ({'site':'test.invalid','cve_id':'CVE-2099-9999999','vendor':'n/a','product':'n/a'},
  'CVE_NOT_IN_CURRENT_KEV_NOT_PROOF_SAFE')
]
for asset,want in cases:
    got=review([asset],catalog)[0]
    assert got['status']==want,(want,got)
    assert got['locally_exploited'] is None
    assert got['automatic_ban'] is False and got['automatic_patch'] is False
print('CVE_KEV_S1_ALL_4_PASS count',len(idx),'feed_version',manifest['catalogVersion'],
      'real_websites_scanned',0,'actual_installed_products_claimed',0)
