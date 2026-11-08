#!/usr/bin/env python3
"""Temporal defensive shadow: 1/5 minute rates, independent error checks, cross-host sweep.
Input = agent's existing global observation ledger, read-only. NEVER bans.
Raw status and timestamps are NOT enough to prove DDoS, CVE or exploitation.
"""
from collections import Counter,defaultdict
from datetime import datetime,timedelta,timezone
import argparse,ipaddress,json,sqlite3,math
from pathlib import Path
from guardian_reasoner import severe_probe

ROOT=Path('/home/ubuntu/services')
CFG=ROOT/'sentinel-site-guardian/owner_assignments.json'
REPORT=ROOT/'sentinel-site-guardian/reports/temporal_shadow_latest.json'

def utc_ts(x):
    try:return datetime.fromisoformat(x.replace('Z','+00:00')).astimezone(timezone.utc)
    except (AttributeError,ValueError):return None

def safe_net(ip):
    try:
        a=ipaddress.ip_address(ip)
        if not a.is_global:return None
        return str(ipaddress.ip_network(f'{a}/{24 if a.version==4 else 64}',strict=False))
    except (ValueError,TypeError):return None

def evaluate(rows, assignments, now):
    pre=now-timedelta(minutes=65)
    oldend=now-timedelta(minutes=5)
    recent=now-timedelta(minutes=5)
    scan_start=now-timedelta(minutes=30)
    host_minutes=defaultdict(Counter)
    host_fives=defaultdict(Counter)
    source_hosts=defaultdict(set)
    subnet_hunt=defaultdict(list)
    for ts,src,host,method,path,status,features in rows:
        at=utc_ts(ts)
        if not at or at>now+timedelta(seconds=10) or at<pre:continue
        minute=at.strftime('%Y-%m-%dT%H:%M')
        host_minutes[host][minute]+=1
        group='recent' if at>=recent else 'baseline'
        host_fives[host][f'{group}_count']+=1
        if status>=500:host_fives[host][f'{group}_5xx']+=1
        if at>=scan_start and severe_probe(path):
            network=safe_net(src)
            if network:
                subnet_hunt[network].append((str(src),str(host),str(path).split('?',1)[0].lower()))
                source_hosts[src].add(host)
    assessments={}
    global_campaigns=[]
    for net,entries in subnet_hunt.items():
        ips={e[0] for e in entries}
        hosts={e[1] for e in entries}
        probes=defaultdict(set)
        for ip,host,path in entries:probes[path].add(ip)
        correlated=[path for path,sources in probes.items() if len(sources)>=2]
        if len(ips)>=3 and len(hosts)>=2 and len(entries)>=6 and correlated:
            global_campaigns.append({
                'type':'COORDINATED_SUBNET_RECON_CANDIDATE_NOT_ATTRIBUTION',
                'subnet_for_analytics_only':net,'source_count':len(ips),'target_hosts':len(hosts),
                'probe_event_count':len(entries),
                'correlated_probe_signature_count':len(correlated),
                'ban_subnet':False,'ban_any_ip':False,
                'need':'validate original client IP, benign scanners and independent campaign evidence'})
    for name,assignment in assignments.items():
        site=assignment['assigned_hostname'];data=host_fives.get(site,Counter())
        recentcount=int(data['recent_count']);basecount=int(data['baseline_count'])
        baseline_rpm=basecount/60.0 # last 60 minutes excluding latest 5m
        recent_rpm=recentcount/5.0
        baseline_error=(data['baseline_5xx']/basecount) if basecount else 0
        recent_error=(data['recent_5xx']/recentcount) if recentcount else 0
        ratio=recent_rpm/max(baseline_rpm,0.01)
        surge=recent_rpm>=50 and baseline_rpm>=1 and ratio>=6
        error_impact=recent_error>=.10 and recent_error-baseline_error>=.08
        finding=('SURGE_WITH_HTTP_ERROR_IMPACT_NEEDS_RESOURCE_CORRELATION' if surge and error_impact
           else 'RATE_SURGE_NO_INDEPENDENT_IMPACT' if surge
           else 'SERVICE_ERRORS_WITHOUT_SURGE' if recent_error>=.10 and recent_error-baseline_error>=.08
           else 'NO_TEMPORAL_ALERT')
        networks={safe_net(src) for ts,src,host,method,path,status,features in rows
                  if host==site and severe_probe(path)}
        host_campaigns=[{'type':c['type'],'source_count':c['source_count'],
            'target_hosts':c['target_hosts'],'probe_event_count':c['probe_event_count'],
            'ban_subnet':False}
            for c in global_campaigns if c['subnet_for_analytics_only'] in networks]
        assessments[name]={
            'assigned_host':site,'global_hosts_visible':len(host_minutes),
            'recent_5m_requests':recentcount,'baseline_60m_requests':basecount,
            'recent_rpm':round(recent_rpm,3),'baseline_rpm':round(baseline_rpm,3),
            'rate_ratio':round(ratio,2) if baseline_rpm>=1 else None,
            'recent_http_5xx_fraction':round(recent_error,4),
            'baseline_http_5xx_fraction':round(baseline_error,4),
            'finding':finding,
            'assigned_host_campaign_candidates':host_campaigns[:10],
            'interpretation':'Observed HTTP response distribution and volume are not independently measured service saturation; DDoS remains unconfirmed',
            'independent_latency_metrics_available':False,
            'upstream_resource_telemetry_available':False,
            'enforcement':'DISABLED',
            'live_bans':0,
        }
    return {'version':'TEMPORAL_SHADOW_S1_2026_10_08',
            'generated_utc':now.isoformat(),
            'global_campaign_hypotheses':global_campaigns[:20],
            'global_traffic_coverage_hosts':len(host_minutes),
            'agents':assessments,
            'governance':{'only_owner_assigned_site_may_propose':True,'shared_log_unchanged':True,
               'enforcement_enabled':False,'no_subnet_bans':True}}

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--out',type=Path,default=REPORT)
    parser.add_argument('--now',help='fixed UTC ISO8601 timestamp for reproducible offline replays')
    args=parser.parse_args()
    now=datetime.fromisoformat(args.now).astimezone(timezone.utc) if args.now else datetime.now(timezone.utc)
    cfg=json.loads(CFG.read_text())
    assert not cfg['enforcement_enabled']
    db=ROOT/'micro-sentinel/state/sentinel.db'
    con=sqlite3.connect('file:'+str(db)+'?mode=ro',uri=True)
    try:
        cutoff=(now-timedelta(minutes=65)).strftime('%Y-%m-%dT%H:%M:%S')
        rows=con.execute('SELECT ts,src,host,method,path,status,features FROM observations WHERE ts>=? ORDER BY ts DESC LIMIT 120001',(cutoff,)).fetchall()
    finally:con.close()
    if len(rows)>120000:raise RuntimeError('Incomplete telemetry: 120000 window limit. Shadow fail-closed.')
    report=evaluate(rows,cfg['agents'],now)
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n')
    args.out.chmod(0o600)
    print(json.dumps({'global_hosts':report['global_traffic_coverage_hosts'],
       'global_campaigns':len(report['global_campaign_hypotheses']),
       'agents':{n:{'host':x['assigned_host'],'rps_last_5m':x['recent_rpm']/60,
            'finding':x['finding'],'site_campaigns':len(x['assigned_host_campaign_candidates'])}
            for n,x in report['agents'].items()},
       'enforcement_enabled':False,'report':str(args.out)},ensure_ascii=False))
if __name__=='__main__':main()
