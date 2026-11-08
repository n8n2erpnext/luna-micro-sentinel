#!/usr/bin/env python3
"""Offline-only enforce-readiness XFAIL probes for Luna/Selene, 2026-10-08.
NO live input writes, NO fail2ban mutation, NO traffic generation, NO network.
Reports blockers from read-only code, evidence models, policies and synthetic rows.
"""
import sys,json,hashlib,importlib.util
from pathlib import Path
ROOT=Path('/home/ubuntu/services')
cases=[]
def flag(name,blocker,evidence):
    cases.append({'check':name,'ready_for_real_bans':not blocker,'evidence':evidence})
for display,dir_name in [('Luna','micro-sentinel'),('Selene','micro-sentinel-b')]:
    root=ROOT/dir_name
    agent_spec=importlib.util.spec_from_file_location('guardian_readonly_'+dir_name.replace('-','_'),root/'bin/sentinel_v2.py')
    agent=importlib.util.module_from_spec(agent_spec)
    agent_spec.loader.exec_module(agent)
    origin='203.0.113.5' # reserved documentation source
    rows=[]
    for host,paths in [('a.example',['/public','/home','/about','/docs','/assets','/contact']),
                       ('b.example',['/config','/backup'])]:
        for path in paths:
            ts='2026-10-08T12:00:%02dZ'%len(rows)
            rows.append((ts,origin,agent.subnet(origin),host,'GET',path,200,
                         json.dumps(agent.features('GET',path,200))))
    global_patterns=[x[0] for x in agent.derive(rows)[0]]
    per_host=[x[0] for host in ('a.example','b.example') for x in agent.derive([r for r in rows if r[3]==host])[0]]
    flag(f'{display}: host-isolation',('broad_probe' in global_patterns and 'broad_probe' not in per_host),
         {'combined':global_patterns,'scoped':per_host,'test':'synthetic, no real traffic'})
    a6=agent.subnet('2001:db8:1234:abcd::1')
    b6=agent.subnet('2001:db8:5678::1')
    flag(f'{display}: IPv6-prefix-safety',a6==b6,
         {'first_prefix':a6,'second_prefix':b6,'danger':'distinct /32 families collapsed'})
    ident=json.loads((root/'knowledge/identity.json').read_text())
    flag(f'{display}: enforce-authority-contract',ident.get('authority',{}).get('mode')!='SCOPED_ENFORCEMENT',
        {'current':ident.get('authority',{}).get('mode')})
    cycle=(root/'bin/sentinel_cycle.py').read_text()
    enforcer=any(word in cycle for word in ('site_enforcer.py','ban_executor.py','enforcement_gateway.py'))
    flag(f'{display}: end-to-end-controlled-enforcer',not enforcer,
        {'present_in_cycle':enforcer})
    code=(root/'bin/sentinel_v2.py').read_text()
    flag(f'{display}: independently-verified-positive',"'PASS' if len(learned)==len(pats)" in code,
        {'problem':'count-only self-check is not an independent detector validator'})
    alerts=(root/'bin/sentinel_alerts.py').read_text()
    flag(f'{display}: telegram-delivery-ack', 'update alert_outbox set delivered_at=? where id=?' in alerts,
        {'problem':'poll marks delivered before separate transport sends, potential missed alert'})
# Firewall scoping audit: parse text only. Do not call iptables or fail2ban-client.
import configparser
conf=configparser.ConfigParser(interpolation=None)
conf.read('/etc/fail2ban/jail.local')
for section in ('traefik-bot','netbird-env-probe','recidive'):
    action=conf.get(section,'action',fallback='').replace('\n',' ')
    global_scope=('DOCKER-USER' in action or 'chain=INPUT' in action)
    flag('firewall: '+section+' host-isolation',global_scope,
         {'global_chains':global_scope,'ports':conf.get(section,'port',fallback=''),
          'scope_note':'firewall chain is source IP/port rather than HTTP Host'})
report={
    'id':'SENTINEL_ENFORCE_READINESS_2026_10_08',
    'scope':'read-only offline evaluation of current implementation; readiness blockers are expected',
    'auto_ban_authorized':False,'live_bans_performed':0,
    'checks':cases,'readiness_blockers':sum(not x['ready_for_real_bans'] for x in cases),
    'pass':'NO — absent site-safe enforcement layer'
}
path=ROOT/'sentinel-competition-reviews/2026-10-08-enforce-readiness.json'
path.write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n')
print(json.dumps({'total':len(cases),'readiness_blockers':report['readiness_blockers'],
                  'checks':[{x['check']:x['ready_for_real_bans']} for x in cases],
                  'report':str(path)},ensure_ascii=False,indent=2))
