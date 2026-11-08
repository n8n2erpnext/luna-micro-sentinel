#!/usr/bin/env python3
"""Independent synthetic temporal replay; never touches network/firewall."""
from datetime import datetime,timedelta,timezone
from guardian_temporal_shadow import evaluate,safe_net
from guardian_reasoner import severe_probe
NOW=datetime(2026,10,8,11,0,0,tzinfo=timezone.utc)
ASSIGN={
 'Luna':{'assigned_hostname':'thaiduy.digital'},
 'Luna:LightRemote':{'assigned_hostname':'light-remote.thaiduy.digital'}}
def ev(minutes_ago,ip,host,path='/',status=200):
    ts=(NOW-timedelta(minutes=minutes_ago)).isoformat().replace('+00:00','Z')
    return (ts,ip,host,'GET',path,status,'[]')
def chk(rows,name,expected):
    r=evaluate(rows,ASSIGN,NOW)
    got=r['agents'][name]['finding']
    assert got==expected,(name,expected,got)
    assert not r['governance']['enforcement_enabled']
    assert all(x['live_bans']==0 and x['enforcement']=='DISABLED' for x in r['agents'].values())
    return r
# Time-scoped benign session traffic on Light Remote, without resource pressure.
rows=[ev(10,'8.8.8.8','light-remote.thaiduy.digital','/device-channel/activity') for _ in range(12)]
chk(rows,'Luna:LightRemote','NO_TEMPORAL_ALERT')
print('PASS: healthy Light Remote background traffic')

# Legitimate publicity burst with healthy HTTP responses -> no DDoS verdict.
flash=[ev(30,'8.8.8.8','thaiduy.digital') for _ in range(60)]
flash += [ev(1,'8.8.8.8','thaiduy.digital') for _ in range(500)]
chk(flash,'Luna','RATE_SURGE_NO_INDEPENDENT_IMPACT')
print('PASS: flash crowd is only an unverified traffic surge')

# Strong rate + HTTP error impact -> pressure candidate NOT DDoS confirmation.
flood=flash[:-500]+[ev(1,'8.8.8.8','thaiduy.digital',status=502 if i%3==0 else 200) for i in range(500)]
r=chk(flood,'Luna','SURGE_WITH_HTTP_ERROR_IMPACT_NEEDS_RESOURCE_CORRELATION')
assert not r['agents']['Luna']['independent_latency_metrics_available']
print('PASS: early pressure hypothesis with missing latency/CPU caveat')

# Application outage with flat rate -> operational incident, not network attack.
error=[ev(30,'8.8.8.8','thaiduy.digital') for _ in range(60)]
error += [ev(1,'8.8.8.8','thaiduy.digital',status=502 if i%2==0 else 200) for i in range(5)]
chk(error,'Luna','SERVICE_ERRORS_WITHOUT_SURGE')
print('PASS: application errors without rate surge')

# Three sources within analytics-only IPv4 /24, same probing signatures,
# both websites. Campaign context is global; neither agent can ban a subnet.
scans=[]
for ip in ['8.8.8.1','8.8.8.2','8.8.8.3']:
    for h in ('thaiduy.digital','light-remote.thaiduy.digital'):
        for p in ('/.env','/.git/config'):
            scans.append(ev(2,ip,h,p,404))
r=evaluate(scans,ASSIGN,NOW)
assert len(r['global_campaign_hypotheses'])==1,r['global_campaign_hypotheses']
for name in ('Luna','Luna:LightRemote'):
    assert len(r['agents'][name]['assigned_host_campaign_candidates'])==1
assert not r['global_campaign_hypotheses'][0]['ban_subnet']
print('PASS: correlated global subnet scan, own-site context, no CIDR ban')

# IPv6 grouping must be <= /64 not /24; unrelated /32 cannot merge.
assert safe_net('2001:4860:1000::1')!=safe_net('2001:4860:2000::1')
assert severe_probe('/.git/config') and not severe_probe('/rest/credentials')
print('PASS: IPv6 grouping and benign app config route')

print('TEMPORAL_SHADOW_S1_ALL_6_PASS_REAL_BANS_ZERO')
