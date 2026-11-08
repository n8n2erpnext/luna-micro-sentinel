#!/usr/bin/env python3
"""Luna v2 Telegram presentation and defensive assessment.
One collector, multiple hostname-scoped profiles, never any enforcement.
Uses Guardian's already-acknowledged Telegram outbox; does not send Telegram itself.
"""
from __future__ import annotations
from datetime import datetime,timezone,timedelta
from zoneinfo import ZoneInfo
from pathlib import Path
from collections import Counter
import html, ipaddress, json, os, sqlite3

ROOT=Path('/home/ubuntu/services')
GUARD=ROOT/'sentinel-site-guardian'
LUNA=ROOT/'micro-sentinel'
REPORT=ROOT/'sentinel-guardian-reports'
TZ=ZoneInfo('Asia/Ho_Chi_Minh')
SITES={'Luna':'thaiduy.digital','Luna:LightRemote':'light-remote.thaiduy.digital'}
MAX=3400
def esc(value):
    return html.escape(str(value),quote=False)
def read(path):
    try:return json.loads(Path(path).read_text(encoding='utf-8'))
    except (OSError,ValueError,TypeError):return {}
def now():
    return datetime.now(timezone.utc)
def age_minutes(timestamp):
    try:
        t=datetime.fromisoformat(str(timestamp).replace('Z','+00:00'))
        if t.tzinfo is None:return 10**9
        return (now()-t.astimezone(timezone.utc)).total_seconds()/60
    except (ValueError,TypeError):return 10**9
def valid_public_ip(value):
    try:return ipaddress.ip_address(value).is_global
    except (TypeError,ValueError):return False
def bytes_human(value):
    v=float(value or 0)
    for unit in ('B','KiB','MiB','GiB','TiB'):
        if v<1024 or unit=='TiB':return f'{v:.1f} {unit}'
        v/=1024
def size_tree(path):
    total=0
    stack=[Path(path)]
    while stack:
        current=stack.pop()
        try:
            with os.scandir(current) as directory:
                for entry in directory:
                    try:
                        if entry.is_symlink():continue
                        if entry.is_dir(follow_symlinks=False):stack.append(Path(entry.path))
                        elif entry.is_file(follow_symlinks=False):total+=entry.stat(follow_symlinks=False).st_size
                    except OSError:pass
        except OSError:pass
    return total
def storage():
    fs=os.statvfs('/home')
    free=fs.f_bavail*fs.f_frsize
    capacity=fs.f_blocks*fs.f_frsize
    db=LUNA/'state/sentinel.db'
    return {'agent_bytes':size_tree(LUNA),'db_bytes':db.stat().st_size if db.exists() else 0,
            'disk_free_bytes':free,'disk_used_pct':100*(1-free/capacity) if capacity else None}
def day_stats(day):
    db=LUNA/'state/sentinel.db'
    try:
        con=sqlite3.connect('file:'+str(db)+'?mode=ro',uri=True,timeout=5)
        con.execute('PRAGMA query_only=1')
        row=con.execute('SELECT self_json,independent_json FROM daily_v2 WHERE day=?',(day,)).fetchone()
        con.close()
        if not row:return {}
        return {'self':json.loads(row[0]),'audit':json.loads(row[1])}
    except (OSError,ValueError,sqlite3.Error):return {}
def health():
    cycle=read(GUARD/'reports/cycle_status.json')
    decisions=read(GUARD/'reports/decisions_latest.json')
    guard=read(LUNA/'reports/guard/latest.json')
    monitor=read(GUARD/'reports/cutover/latest.json')
    return {'cycle':cycle,'decisions':decisions,'guard':guard,'monitor':monitor}
def daily():
    # Always report last fully completed local calendar day, never a partial day
    local=now().astimezone(TZ)
    day=(local.date()-timedelta(days=1)).isoformat()
    stats=day_stats(day)
    self=stats.get('self',{})
    audit=stats.get('audit',{})
    counts={str(h):int(n) for h,n in self.get('baseline',{}).get('hosts',[]) if isinstance(n,int)}
    s=storage()
    h=health()
    decision=h['decisions']
    ok=h['guard'].get('state')=='PASS' and h['guard'].get('violations')==[] and age_minutes(h['guard'].get('time'))<60
    # Guard has a time field with timezone; if missing report unknown rather than healthy.
    state='PASS' if ok else 'CHƯA XÁC MINH'
    verdicts='; '.join(f'{site}: {decision.get("agents",{}).get(profile,{}).get("decision","UNKNOWN")}'
                      for profile,site in SITES.items())
    prior=day_stats((local.date()-timedelta(days=2)).isoformat()).get('self',{})
    prev=int(prior.get('observations',0)) if prior else None
    current=int(self.get('observations',0))
    trend=f'{(current-prev)/prev*100:+.1f}%' if prev and current else 'Chưa đủ dữ liệu'
    patterns=Counter(x.get('pattern','') for x in self.get('learned_patterns',[]) if isinstance(x,dict))
    kinds=', '.join(f'{key}: {value}' for key,value in patterns.most_common(3)) or 'Không có mẫu nổi bật'
    lines=[
        f'<b>🛡️ LUNA | BÁO CÁO AN NINH NGÀY {esc(day)}</b>',
        '<i>Defensive Agent · Quan sát toàn hệ thống · Không chặn IP tự động</i>',
        '',
        '<b>📊 Tổng quan lưu lượng</b>',
        f'• Tổng yêu cầu: <b>{current:,}</b> | so với ngày trước: {esc(trend)}',
        f'• thaiduy.digital: {counts.get("thaiduy.digital",0):,}',
        f'• light-remote.thaiduy.digital: {counts.get("light-remote.thaiduy.digital",0):,}',
        f'• Dấu hiệu probe: {int(audit.get("probe_feature_hits",0))}; từ chối/404: {int(audit.get("denied_or_missing",0))}; lỗi 5xx: {int(audit.get("server_errors",0))}',
        f'• Các nhóm phán đoán: {esc(kinds)}',
        '',
        '<b>🧠 Đánh giá</b>',
        f'• Guardian: {esc(state)}; quyết định gần nhất: {esc(verdicts)}',
        '• Dấu hiệu nghi vấn không đồng nghĩa đã xâm nhập. Các sự kiện đủ chứng cứ được gửi riêng khi phát sinh.',
        f'• Chặn do Luna: <b>0</b> | chế độ: <b>SHADOW / OBSERVE ONLY</b>',
        '',
        '<b>💾 Dung lượng bản thân</b>',
        f'• Luna (toàn bộ): <b>{bytes_human(s["agent_bytes"])}</b>',
        f'• Database quan sát: {bytes_human(s["db_bytes"])}',
        f'• Ổ /home: {s["disk_used_pct"]:.1f}% đã sử dụng; còn {bytes_human(s["disk_free_bytes"])}',
        '',
        '<i>Nguồn: Luna DB + Guardian + filesystem; thống kê ngày đã kết thúc. Không thay đổi quyền firewall.</i>',
    ]
    if not stats:lines.insert(4,'⚠️ Chưa có dữ liệu hoàn chỉnh của ngày được báo cáo.')
    return '\n'.join(lines)[:MAX]
def weekly():
    local=now().astimezone(TZ)
    days=[(local.date()-timedelta(days=d)).isoformat() for d in range(1,8)]
    summaries=[day_stats(d) for d in days]
    valid=[x for x in summaries if x]
    total=sum(int(x['self'].get('observations',0)) for x in valid)
    probe=sum(int(x['audit'].get('probe_feature_hits',0)) for x in valid)
    h=health();s=storage()
    lines=[
        f'<b>📘 LUNA | TỔNG KẾT TUẦN {local.date().isoformat()}</b>',
        f'• Số ngày có dữ liệu: {len(valid)}/7',
        f'• Tổng yêu cầu đã phân tích: {total:,}',
        f'• Dấu hiệu probe trong log: {probe:,} (không phải số vụ xâm nhập)',
        f'• Guardian: {esc(h["guard"].get("state","UNKNOWN"))}',
        f'• Luna: {bytes_human(s["agent_bytes"])} (DB {bytes_human(s["db_bytes"])})',
        '• Chưa xác minh IP gốc và bộ chặn theo hostname; chưa cấp quyền chặn.',
        '• Đánh giá năng lực cần đối chiếu false-positive với dữ liệu đã gắn nhãn; không tự tuyên bố độ chính xác.',
        '<i>DEFENSIVE OBSERVE ONLY · Không có lệnh firewall.</i>'
    ]
    return '\n'.join(lines)[:MAX]
def format_alert(profile,site,ip,kind,details,*,recommendation='Theo dõi tiếp và đối chiếu log ứng dụng.'):
    # Explicitly distinguish inference from independent proof of intrusion.
    title={'suspect':'⚠️ NGHI VẤN DÒ QUÉT','urgent':'🚨 ĐỀ NGHỊ ĐIỀU TRA SỰ CỐ',
           'ban_candidate':'🟠 ĐỀ XUẤT CHẶN — CHƯA THỰC THI'}.get(kind,'⚠️ CẦN XÁC MINH')
    count=int(details.get('hits',0))
    distinct=int(details.get('distinct',0))
    denied=int(details.get('denied',0))
    windows=int(details.get('windows',0))
    confidence=details.get('confidence','chưa hiệu chuẩn')
    proof=details.get('evidence') or []
    evidence_summary=('; '.join(str(x) for x in proof[:3]) if isinstance(proof,list) and proof
                      else f'{count} dấu hiệu, {distinct} đường dẫn đáng ngờ, {denied} phản hồi từ chối/không tìm thấy, {windows} cửa sổ thời gian')
    observed_at=details.get('observed_at')
    observed_line=''
    if observed_at:
        try:
            dt=datetime.fromisoformat(str(observed_at).replace('Z','+00:00'))
            if dt.tzinfo is not None:
                observed_line=f'🕒 Log ghi nhận lúc: {dt.astimezone(TZ).strftime("%d/%m %H:%M:%S")} (VN)'
        except (ValueError,TypeError):pass
    msg=[
        f'<b>🛡️ LUNA | {title}</b>',
        f'🌐 Website: <code>{esc(site)}</code>',
        f'🔎 Nguồn quan sát: <code>{esc(ip)}</code>',
        *([observed_line] if observed_line else []),
        f'📌 Bằng chứng: {esc(evidence_summary)}.',
        f'🧠 Nhận định: {esc(details.get("judgement","Có dấu hiệu thăm dò; chưa có bằng chứng xâm nhập thành công."))}',
        '⚖️ Khả năng khác: scanner hợp lệ, kiểm thử được phép, crawler hoặc nhận diện sai IP qua proxy.',
        f'🧭 Đề xuất: {esc(recommendation)}',
        f'📊 Độ tin cậy heuristic: {esc(confidence)} (không phải xác suất khai thác thành công)',
        '🔒 Luna chỉ đánh giá (SHADOW), không tự ban IP. CrowdSec/Fail2Ban có thể đã chặn độc lập.',
    ]
    return '\n'.join(msg)[:MAX]
def proposals():
    """Only confirmed site-scoped observations or significant decisions; no daily learning spam."""
    p=read(GUARD/'reports/latest.json')
    d=read(GUARD/'reports/decisions_latest.json')
    items=[]
    if age_minutes(p.get('generated_at_utc'))>20 or p.get('enforcement_enabled') is not False:
        return items
    # Stable evidence-based key: midnight cannot restart the same incident.
    # A separate campaign with distinct evidence can receive a new alert.
    day=now().astimezone(TZ).date().isoformat()
    for profile,site in SITES.items():
        report=p.get('agents',{}).get(profile,{})
        if report.get('assigned_hostname')!=site:continue
        findings=report.get('site_summary',{}).get('findings',[])
        if not isinstance(findings,list):continue
        for row in findings[:3]:
            ip=row.get('src')
            if not valid_public_ip(ip) or row.get('scope_hostname')!=site:continue
            hits=int(row.get('suspicious_hits') or 0)
            distinct=int(row.get('distinct_suspicious_paths') or 0)
            denied=int(row.get('denied_or_missing_suspicious_events') or 0)
            windows=int(row.get('suspicious_distinct_10min_windows') or 0)
            feature_families=len(row.get('suspicious_feature_types') or [])
            digest=str(row.get('evidence_digest') or '')
            if len(digest)!=20 or any(ch not in '0123456789abcdef' for ch in digest):continue
            # A fresh Guardian snapshot may still contain stale source events.
            # Never send the same old probe again after midnight or next scan.
            last_seen_age=age_minutes(row.get('last_suspicious_utc'))
            if not (-2 <= last_seen_age <= 7):continue
            # Dedup benign single-window guesses: require repeated strong corroboration.
            if not ((hits>=5 and distinct>=4 and denied>=2 and feature_families>=2)
                    or (hits>=8 and distinct>=6 and windows>=2)):continue
            kind='ban_candidate' if hits>=8 and denied>=5 and distinct>=6 and windows>=2 else 'suspect'
            span=int(row.get('suspicious_span_seconds') or 0)
            shape=('Chùm request dò quét nhanh' if span<10 else 'Chuỗi request dò quét theo thời gian')
            evidence={'hits':hits,'distinct':distinct,'denied':denied,'windows':windows,
                      'observed_at':row.get('last_suspicious_utc'),
                      'confidence':'chưa hiệu chuẩn','judgement':
                      f'{shape} trên nhiều đường dẫn ({span} giây); chưa chứng minh xâm nhập thành công. Cần đối chiếu log ứng dụng và danh tính IP gốc.'}
            msg=format_alert(profile,site,ip,kind,evidence)
            items.append((f'luna:v3:probe:{site}:{ip}:{digest}',msg,1 if kind=='ban_candidate' else 2))
    # Only action-grade decision transitions, never routine NO_ACTION/WAIT or missing telemetry.
    journal=GUARD/'reports/decision_history.jsonl'
    if journal.exists():
        for line in journal.read_text(encoding='utf-8',errors='replace').splitlines()[-150:]:
            try: row=json.loads(line)
            except ValueError:continue
            profile=row.get('agent');site=SITES.get(profile)
            if not site or site!=row.get('site'):continue
            if age_minutes(row.get('generated_utc'))>20:continue
            if row.get('decision') not in ('BAN_RECOMMENDED','INCIDENT_REVIEW_RECOMMENDED'):continue
            token=str(row.get('transition_token') or '')
            if len(token)!=20:continue
            ip=row.get('subject','SITE')
            evidence=row.get('evidence') or []
            # Never mistake SITE scope for malicious IP.
            if ip=='SITE' and row.get('decision')=='BAN_RECOMMENDED':continue
            category='ban_candidate' if row['decision']=='BAN_RECOMMENDED' else 'urgent'
            msg=format_alert(profile,site,ip,category,{
                'judgement':row.get('rationale','Cần điều tra thêm.'),
                'evidence':evidence,
                'confidence':'chưa hiệu chuẩn'},
                recommendation='Ưu tiên xem telemetry độc lập, xác minh IP tại edge và kiểm tra sức khỏe ứng dụng.')
            if not any(k.startswith(f'luna:v3:probe:{site}:{ip}:') for k,*_ in items):
                items.append((f'luna:v2:decision:{profile}:{token}',msg,1))
    # Self-storage alert only when a capacity threshold is crossed.
    fs=os.statvfs('/home')
    used=100*(1-fs.f_bavail/fs.f_blocks) if fs.f_blocks else 0
    db=LUNA/'state/sentinel.db'
    db_bytes=db.stat().st_size if db.exists() else 0
    if used>=90 or db_bytes>=6*1024**3:
        key=f'luna:v2:capacity:{day}:{"critical" if used>=95 else "warning"}'
        message=(
            '<b>💾 LUNA | CẢNH BÁO DUNG LƯỢNG</b>\n'
            f'• /home: {used:.1f}% đã dùng\n'
            f'• Luna database: {bytes_human(db_bytes)}\n'
            '• Đề xuất: kiểm tra retention, kiểm kê trước khi xóa; không tự xóa dữ liệu hoặc thay firewall.')
        items.append((key,message,1 if used>=95 else 2))
    return items[:12]
def block_receipt_message(receipt):
    """Format a future independently executed and verified edge receipt; does NOT execute."""
    assert isinstance(receipt,dict)
    mode=str(receipt.get('mode',''))
    assert mode in ('SIMULATION','VERIFIED_LIVE_RECEIPT')
    if mode=='VERIFIED_LIVE_RECEIPT':
        assert receipt.get('verified_edge_receipt') is True
        assert receipt.get('scope_verified') is True
        assert receipt.get('owner_authorized') is True
    action=str(receipt.get('action','BLOCK')).upper()
    assert action in ('BLOCK','UNBLOCK','EXPIRED')
    label='MÔ PHỎNG — KHÔNG CHẶN' if mode=='SIMULATION' else ('ĐÃ CHẶN' if action=='BLOCK' else 'ĐÃ GỠ CHẶN')
    return ('<b>🛡️ LUNA | '+label+'</b>\n'
       f'• Website: <code>{esc(receipt.get("site",""))}</code>\n'
       f'• IP xác minh: <code>{esc(receipt.get("ip",""))}</code>\n'
       f'• Quyết định: {esc(action)} · TTL: {esc(receipt.get("ttl_minutes","-"))} phút\n'
       f'• Lý do: {esc(receipt.get("reason","Chờ chứng cứ"))}\n'
       f'• Rule ID: <code>{esc(receipt.get("rule_id","-"))}</code>\n'
       '• Audit: '+esc(receipt.get('audit','Not available'))+'\n'
       '• Rollback / unban: '+esc(receipt.get('rollback','Not available')))
def preview_block():
    return block_receipt_message({
       'mode':'SIMULATION','action':'BLOCK','site':'example.invalid','ip':'192.0.2.100',
       'ttl_minutes':15,'reason':'Mô phỏng định dạng, không phải sự kiện thật',
       'rule_id':'DRY-RUN-ONLY','audit':'NO LIVE ACTION','rollback':'NO ACTION REQUIRED'})
