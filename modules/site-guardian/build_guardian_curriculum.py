#!/usr/bin/env python3
"""Web Guardian S1 curriculum — curated from verified defensive references.
Writes only governed lesson files; never touches guarded cognition triplets or
agent authority, and never promotes owner-requested lessons automatically.
"""
from pathlib import Path
import json,hashlib,datetime
ROOT=Path('/home/ubuntu/services')
SOURCES={
 'owasp2025':'https://top10.owasp.org/',
 'owasp_api2023':'https://api-security.owasp.org/editions/2023/en/0x11-t10/',
 'cisa_kev':'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
 'cisa_kev_feed':'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
 'cloudflare_sourceip':'https://developers.cloudflare.com/support/troubleshooting/restoring-visitor-ips/restoring-original-visitor-ips/',
}
module_defs=[
 {'id':'HTTP_APP_AUTH','goal':'Separate application auth/session workflows from brute-force and broken object-level/function-level authorization.',
  'positive':['correlated server-side failed-auth results on a verified auth route with a bounded time window',
              'independent authorization evidence or explicit app security event'],
  'negative':['a single 401/403/404','browser retries after session expiry','unverified BOLA guess from ID-like URLs','status code 200 alone cannot prove authorization failure'],
  'missing':['sanitized application authentication-result event','authorized route inventory','identity/session boundary']},
 {'id':'REAL_CLIENT_IDENTITY','goal':'Understand trusted source IP, NetBird Proxy, CDN, NAT, IPv4 and IPv6.',
  'positive':['verified ingress hop chain','source address anchored at the enforcement point'],
  'negative':['trust arbitrary X-Forwarded-For or CF-Connecting-IP from the Internet',
              'ban a proxy/CDN address as if it were a unique client','group unrelated IPv6 families using a /24'],
  'missing':['trusted proxy CIDR config','actual matching client address as seen by firewall/edge','header sanitization proof']},
 {'id':'RECON_CVE','goal':'Distinguish suspicious reconnaissance, exploit attempt, confirmed vulnerable installation, and confirmed compromise.',
  'positive':['multiple independent sensitive-path probes with context and rate',
              'signed inventory evidence of affected product and version',
              'validated CISA KEV entry as urgency signal, not proof of local impact'],
  'negative':['assume website vulnerable because one URL resembles CVE exploitation',
              'a 200 response means leaked a secret','a published CVE applies without product/version inventory'],
  'missing':['software BOM/version data','fix or vendor advisory','authorized low-impact verification','backend impact evidence']},
 {'id':'DISTRIBUTED_SCAN','goal':'Detect distributed cross-host sweep based on common probe family, time and path-order signatures.',
  'positive':['correlated paths and timing across distinct verified origin clients',
              'repeated independently observed target similarity'],
  'negative':['same /24 or cloud ASN alone','legitimate uptime monitors or CDN checks',
              'conclude DDoS from number of sources without availability impact'],
  'missing':['campaign time window','differentiating benign scanner/crawler evidence','network provenance']},
 {'id':'AVAILABILITY','goal':'Early suspected DDoS/app flood from traffic-baseline deviation AND independent impact/pressure.',
  'positive':['rate/burst increase over time-of-day baseline',
              'p95 latency/error/timeout increase or upstream queue/CPU/socket pressure independently',
              'repeated persistence and source/route dispersion'],
  'negative':['large request count only','daily totals compared with partial day','public launch flash crowd with healthy latency','5xx spike without incoming rate shift'],
  'missing':['host-normalized RPS baseline','p95 latency baseline','5xx and timeout rates','upstream resource/connection health']},
 {'id':'DECISION_AND_RECOVERY','goal':'Understand bounded and independently approved actions plus recovery.',
  'positive':['verified IP and host binding','rule ID+TTL+owner allowlist exclusion','execution receipt and rollback receipt','Telegram ack/retry'],
  'negative':['agent directly gets sudo/iptables/fail2ban-client banip on global jail',
              'auto-infinite recidive','expand to subnet bans without separate approval','auto ban on confidence alone'],
  'missing':['site-scoped enforcement backend','policy broker','manual kill switch','verified unban']},
]
COMMON={
 'version':'WEB_GUARDIAN_S1_2026_10_08',
 'source_kind':'MAINTAINER_CURATED_REFERENCE_NOT_GROUND_TRUTH',
 'curriculum_provenance':'GPT-6-guided curriculum with public primary security reference sources and independent owner-visible acceptance tests',
 'source_links':SOURCES,
 'scope':'offline/advisory/shadow; no authorizing live bans, pentest requests or exploit generation',
 'learning_mode':'versioned_corpus_plus_scenario_reasoning_not_weight_finetune',
 'shared_full_proxy_visibility':True,
 'cross_host_correlation_enabled':True,
 'enforcement_enabled':False,
 'modules':module_defs,
 'graduation_conditions':[
    'read and explain evidence vs hypothesis vs action',
    'correctly classify benign operational changes and attack-looking traffic',
    'correctly abstain for missing source-IP or impact evidence',
    'use host-specific actions while retaining global campaign context',
    'pass unseen scenario regression; no model-owned authority promotion',
 ],
 'hard_invariants':[
    'Logs from all sites remain visible to Luna.',
    'Only assigned site may be targeted by a proposal.',
    'Fail2ban current DOCKER-USER and recidive jails are global; do not use for per-host autonomous ban.',
    'Observed public IP in a proxy log is not independently verified client identity.',
    'Never claim vulnerability or exploit success from URL/status alone.',
    'No automatic learning-promotion or real enforcement; human release + independent broker required.',
 ]}
ROLES={
 'Luna':{'root':'micro-sentinel','site':'thaiduy.digital',
         'specialization':'PUBLIC_SITE_LOW_VOLUME_RECON',
         'site_lessons':[
            'Low-traffic public website: do not infer normal/abnormal from tiny sample counts alone.',
            'Distinguish real sitemap/robots/crawler/API routes from secret/config-file hunting.',
            'Bursts of new visitors from content publication may be benign even with greater geographic diversity.',
            'Treat suspected CMS or dependency CVE as a versioned inventory question; do not assume a particular CMS is deployed.']},
 'Luna:LightRemote':{'root':'micro-sentinel','site':'light-remote.thaiduy.digital',
           'specialization':'AUTH_DEVICE_CONTROL_API_AND_AVAILABILITY',
           'site_lessons':[
              'High-frequency authenticated device-channel activity/polling and realtime sessions are common legitimate workloads; benchmark by route.',
              'Account login retries, OAuth redirects, pairing approval and desktop-session reconnects require application-side success/failure semantics, not just 401/403.',
              'Subscription/billing/webhook endpoints can have trusted server-to-server clients and retries; never auto-ban because of unfamiliar user agents or burst.',
              'Object/function authorization weaknesses (BOLA/BFLA) require sanitized resource ownership/permission evidence; varied IDs in URL are not proof.',
              'Guard against unusual floods independently of legitimate background poll volume by observing latency, errors and upstream pressure.']}}
for name,role in ROLES.items():
    base=ROOT/role['root']/'knowledge/lessons/guardian'
    base.mkdir(parents=True,exist_ok=True)
    obj=dict(COMMON)
    obj.update({
        'agent':'Luna','assigned_site':role['site'],
        'specialization':role['specialization'],'site_lessons':role['site_lessons'],
        'created_utc':datetime.datetime(2026,10,8,11,0,0,tzinfo=datetime.timezone.utc).isoformat(),
    })
    out=base/('web_guardian_light_remote_s1_2026-10-08.json' if role['site']=='light-remote.thaiduy.digital' else 'web_guardian_s1_2026-10-08.json')
    b=(json.dumps(obj,ensure_ascii=False,indent=2)+'\n').encode()
    if out.exists():
        assert out.read_bytes()==b,'Existing lesson differs, require explicit version bump'
    else:out.write_bytes(b)
    print(json.dumps({'agent':name,'lesson':str(out),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),
       'modules':len(module_defs)},ensure_ascii=False))
