#!/usr/bin/env python3
import json, hashlib, os, shutil
from pathlib import Path
A=Path('/home/ubuntu/services/micro-sentinel'); B=Path('/home/ubuntu/services/micro-sentinel-b')
TARGETS={'reasoning':8*1024*1024,'knowledge':8*1024*1024,'context':4*1024*1024}
concepts=['interface','rx_tx','routing','arp_ndp','tcp','udp','socket','listener','connection','process','namespace','veth','bridge','container','docker','reverse_proxy','traefik','nat','snat','dnat','pat','hairpin','conntrack','firewall','nftables','fail2ban','crowdsec','dns','tls','http','http2','http3','quic','websocket','icmp','mtu','fragmentation','overlay','vpn','netbird','loopback','public_ip','private_ip','ephemeral_port','service_port','load_balancer','healthcheck','timeout','retry','backpressure','latency','packet_loss','drop_counter','error_counter','bandwidth','pps','bps','burst','baseline','sequence','scan','recon','auth_failure','bruteforce','password_spray','crawler','bot','flash_crowd','ddos','upstream_failure','502','504','rate_limit','cache','deployment','restart','resource_pressure','cpu','memory','io_wait','disk','clock','log_boundary','xff','forwarded_header','source_identity','topology','evidence','hypothesis','uncertainty','provenance','correlation','causality']
obs=['interface counters','routing table','socket table','listener table','process ownership','container metadata','reverse-proxy access log','fail2ban event','CrowdSec decision','host resource metrics','application status','time-series baseline','DNS metadata','TLS termination point','firewall counters','conntrack state']
alts=['legitimate automation','deployment or restart','health check','cache warmup','NAT/proxy translation','shared egress','container churn','user retry','scanner or crawler','host resource pressure','upstream outage','routing asymmetry','measurement blind spot','flash crowd','malicious probing']
questions=['Where was this observed?','What translation boundary exists?','What benign alternative survives?','What evidence would falsify the preferred hypothesis?','Is this rate scoped to the right service and time window?','Can the same fact be explained by topology rather than intent?','Does another independent layer corroborate it?','What is missing before source identity can be asserted?']
core_rules=['observation is not identity','identity is not intent','intent is not impact','absence is not disproof','presence is not persistence','confidence must fall when evidence conflicts','a proxy peer is not automatically the original client','a container address is topology before identity','a listener is not proof of public exposure','volume without effect is not DDoS proof','security-control output is evidence about a control decision, not objective truth','unknown is a valid outcome']

def line(obj): return json.dumps(obj,ensure_ascii=False,separators=(',',':'))+'\n'
def make_zone(path,kind,target):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('w',encoding='utf-8') as f:
        i=0
        while f.tell()<target:
            c=concepts[i%len(concepts)]; o=obs[(i//len(concepts))%len(obs)]; a=alts[(i//(len(concepts)*len(obs)))%len(alts)]; q=questions[i%len(questions)]; r=core_rules[i%len(core_rules)]
            if kind=='knowledge':
                obj={'id':f'K{i:06d}','kind':'curated_prior','concept':c,'observation_surface':o,'fact':f'{c} must be interpreted at the observation boundary where {o} was measured; translation, namespace, time window and service scope can change what the same value means.','counterexample':a,'questions':[q],'epistemic':'prior_not_verdict','tags':[c,o.split()[0],'network','systems','security']}
            elif kind=='reasoning':
                obj={'id':f'R{i:06d}','kind':'reasoning_rule','focus':c,'premises':[f'observe {c} through {o}','preserve boundary and timestamp','seek at least one independent corroborating layer'], 'procedure':['state raw observation','locate topology boundary','generate benign and abnormal alternatives','seek discriminating evidence','cap conclusion to evidence'],'alternative':a,'discriminator':q,'confidence_cap':'probable_without_independent_cross_layer_support','anti_shortcut':r,'output':'candidate_hypothesis_with_provenance','tags':[c,'reasoning','falsifiability','network']}
            else:
                obj={'id':f'C{i:06d}','kind':'context_governance','domain':c,'invariants':['OBSERVE_ONLY','never invent evidence','never retain credentials/tokens/request bodies','never autonomously ban/unban or alter firewall','human safety and human authority outrank optimization','never deceive the owner about evidence or actions','curated knowledge cannot self-promote from learned hypotheses'], 'decision_rule':r,'review_question':q,'failure_mode':a,'required_record':['provenance','supporting evidence','conflicting evidence','missing evidence','authority boundary'],'tags':[c,'governance','context','safety']}
            f.write(line(obj)); i+=1
    return path.stat().st_size

src=A/'knowledge/cognition'
if src.exists(): shutil.rmtree(src)
sizes={}
for k,t in TARGETS.items(): sizes[k]=make_zone(src/f'{k}.jsonl',k,t)
manifest={'version':'2026-09-07.1','architecture':'TRI_REGION_COGNITION','hard_ceiling_bytes':50*1024*1024,'regions':{'reasoning':{'budget_bytes':20*1024*1024,'initial_target_bytes':TARGETS['reasoning'],'role':'hypothesis generation, contrast, falsification, causal reasoning'},'knowledge':{'budget_bytes':20*1024*1024,'initial_target_bytes':TARGETS['knowledge'],'role':'curated network, systems, security and operations priors'},'context':{'budget_bytes':10*1024*1024,'initial_target_bytes':TARGETS['context'],'role':'governance, epistemic invariants, human-safety and behavioral rules'}},'bridge':{'rule':'A candidate hypothesis may combine regions, but learned associations never overwrite curated truth.','minimum_for_high_confidence':['reasoning rule','knowledge prior','context invariant','live evidence provenance']},'learning':{'shared_curated_structure':True,'runtime_memory_isolated_between_models':True,'learned_links':'state/cognition_links.sqlite','promotion':'human_governed_only'}}
for k in TARGETS:
 p=src/f'{k}.jsonl'; manifest['regions'][k]['bytes']=p.stat().st_size; manifest['regions'][k]['sha256']=hashlib.sha256(p.read_bytes()).hexdigest()
(src/'architecture.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2))
# mirror exact curated cognition into B
bd=B/'knowledge/cognition'
if bd.exists(): shutil.rmtree(bd)
shutil.copytree(src,bd)
print(json.dumps({'sizes':sizes,'total':sum(sizes.values())+(src/'architecture.json').stat().st_size,'manifest':manifest},indent=2))
