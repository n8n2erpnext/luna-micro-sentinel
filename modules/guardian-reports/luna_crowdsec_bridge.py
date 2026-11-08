#!/usr/bin/env python3
"""Read-only CrowdSec -> Luna Guardian digest.

Reads local CrowdSec alert decisions via a bounded docker exec cscli query.
Writes only a deduplicated message to Luna's existing SQLite Telegram outbox.
No bans, no changes to CrowdSec / Traefik / Fail2Ban / firewall.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo
import html
import ipaddress
import json
import sqlite3
import subprocess

ROOT = Path("/home/ubuntu/services")
DB_DEFAULT = ROOT / "sentinel-guardian-reports/state/telegram_outbox.sqlite3"
LUNA_DB = ROOT / "micro-sentinel/state/sentinel.db"
TZ = ZoneInfo("Asia/Ho_Chi_Minh")
MAX_ALERTS = 150
MAX_MESSAGE = 3400

def utc_now():
    return datetime.now(timezone.utc)

def iso_datetime(value):
    try:
        value = datetime.fromisoformat(str(value).replace("Z","+00:00"))
        return value.astimezone(timezone.utc) if value.tzinfo else None
    except (TypeError, ValueError):
        return None

def esc(text):
    return html.escape(str(text), quote=False)

def hhmm(when):
    return when.astimezone(TZ).strftime("%H:%M:%S")

def safe_ip(value):
    try:
        address = ipaddress.ip_address(str(value))
        return str(address) if address.is_global else None
    except ValueError:
        return None

def read_alerts():
    cmd = ["docker","exec","netbird-crowdsec","cscli","alerts","list",
           "--since","6h","--limit",str(MAX_ALERTS),"-o","json"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
    if result.returncode:
        raise RuntimeError("CrowdSec alert query failed (no policy changes made)")
    parsed = json.loads(result.stdout)
    if not isinstance(parsed, list):
        raise ValueError("CrowdSec response is not an alert list")
    # Fail closed on partial datasets; cannot guarantee no older unseen events.
    if len(parsed) >= MAX_ALERTS:
        raise RuntimeError("CrowdSec alert list has reached the bounded limit")
    return parsed

def event_metadata(alert):
    hostnames = Counter()
    statuses = Counter()
    for event in (alert.get("events") or [])[:200]:
        meta = {m.get("key"):m.get("value") for m in event.get("meta",[]) if isinstance(m,dict)}
        hostname=str(meta.get("target_fqdn") or "")
        if hostname and len(hostname)<=255:
            hostnames[hostname]+=1
        status=str(meta.get("http_status") or "")
        if status.isdigit() and 100<=int(status)<=599:
            statuses[status]+=1
    return hostnames,statuses

def extract(alert, now):
    if not isinstance(alert,dict): return None
    created=iso_datetime(alert.get("created_at"))
    if created is None or not now-timedelta(hours=6)<=created<=now+timedelta(minutes=2):return None
    identifier=alert.get("id")
    if not isinstance(identifier,int) or identifier<1:return None
    ip=safe_ip((alert.get("source") or {}).get("ip"))
    if ip is None:return None
    if alert.get("simulated") is True:return None
    accepted=[]
    for decision in alert.get("decisions") or []:
        if not isinstance(decision,dict):continue
        if (decision.get("type")=="ban" and decision.get("simulated") is False
            and decision.get("origin") in ("crowdsec","cscli")
            and decision.get("value")==ip and decision.get("scope")=="Ip"):
            accepted.append(decision)
    if not accepted:return None
    hostnames,statuses=event_metadata(alert)
    return {"key":f"crowdsec:verified-ban:{identifier}",
            "id":identifier, "ip":ip, "created":created,
            "host":hostnames.most_common(1)[0][0] if hostnames else "không xác định",
            "scenario":str(accepted[0].get("scenario") or alert.get("scenario") or "unknown")[:100],
            "events_count":int(alert.get("events_count") or len(alert.get("events") or [])),
            "statuses":statuses,
            "sensitive_200":("sensitive-files" in str(alert.get("scenario") or accepted[0].get("scenario"))
                             and statuses.get("200",0)>0)}

def verify_sensitive_paths(item, db_path=LUNA_DB):
    """Independent access log read-back. Treat HTTP 200 as suspicious, NOT leaked content."""
    if not item["sensitive_200"]:return []
    created=item["created"]
    lower=(created-timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%S")
    upper=(created+timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%S")
    try:
        c=sqlite3.connect("file:"+str(db_path)+"?mode=ro", uri=True,timeout=1.8)
        c.execute("PRAGMA query_only=ON")
        rows=c.execute("""SELECT path,status FROM observations
            WHERE src=? AND host=? AND ts>=? AND ts<=? AND status=200
            ORDER BY ts DESC LIMIT 55""",(item["ip"],item["host"],lower,upper)).fetchall()
        c.close()
        paths=[]
        for path,status in rows:
            if not isinstance(path,str):continue
            clean=path.split("?",1)[0].split("#",1)[0]
            if len(clean)>100:continue
            if any(s in clean.lower() for s in ("/.env","/.git","/debug/vars","/config")):
                if clean not in paths:paths.append(clean)
            if len(paths)>=2:break
        return paths
    except (sqlite3.Error,OSError):
        return []

def message(items, total):
    event_sum=sum(x["events_count"] for x in items)
    high=sum(x["sensitive_200"] for x in items)
    lines=["<b>🛡️ LUNA | TƯƠNG QUAN CROWDSEC</b>",
           f"🚫 CrowdSec đã ra <b>{total} quyết định ban</b> mới trên proxy.",
           f"🔎 Chứng cứ: {event_sum} sự kiện từ CrowdSec; website được ghi theo access log.",
           ""]
    for item in items[:8]:
        scenario=item["scenario"]
        if "sensitive-files" in scenario:
            reason="Dò đường dẫn/tệp nhạy cảm"
        elif "403-bf" in scenario:
            reason="Lặp truy cập bị từ chối HTTP 403"
        elif "401-bf" in scenario:
            reason="Lặp truy cập bị từ chối HTTP 401"
        else:
            reason="Khớp quy tắc "+scenario
        status=", ".join(f"{k}×{v}" for k,v in sorted(item["statuses"].items()))
        lines.append(f"• <b>{esc(item['ip'])}</b> · <code>{esc(item['host'])}</code>")
        lines.append(f"  {hhmm(item['created'])} VN · {esc(reason)} · {item['events_count']} events · HTTP {esc(status or 'n/a')}")
        if item["sensitive_200"]:
            paths=verify_sensitive_paths(item)
            suffix=f" (ví dụ {', '.join(paths)})" if paths else ""
            lines.append("  ⚠️ Đường dẫn nhạy cảm trả 200"+esc(suffix)+". Cần xác minh response body; chưa kết luận lộ dữ liệu.")
    if total>len(items):lines.append(f"… và {total-len(items)} quyết định khác trong cùng nhóm.")
    lines.extend(["",
        "<b>🧠 Đánh giá Luna</b>",
        ("• Có dấu hiệu rà quét/brute-force trên nhiều hostname; chưa có căn cứ kết luận một chiến dịch phối hợp."
         if total>=2 else "• Một nguồn đã khớp kịch bản CrowdSec; chưa có căn cứ khẳng định xâm nhập thành công."),
        ("• Ưu tiên xác minh các HTTP 200 tại đường dẫn nhạy cảm (SPA fallback hoặc nội dung thật)."
         if high else "• Các HTTP 401/403 không chứng minh đã xâm nhập thành công."),
        "🔐 CrowdSec đã tạo quyết định ban; tình trạng áp dụng tại bouncer chưa được kiểm chứng độc lập.",
        "🧭 Luna chỉ phân tích/giám sát, không phát hành lệnh ban.",
    ])
    return "\n".join(lines)[:MAX_MESSAGE]

def collect(db_path=DB_DEFAULT, *, fetcher=read_alerts, at=None):
    """Single atomic batch insert + seen checkpoint, safe under concurrent 2-minute polls."""
    at=at or utc_now()
    records=fetcher()
    valid=[]
    for raw in records:
        row=extract(raw,at)
        if row is not None:valid.append(row)
    valid.sort(key=lambda item:(item["created"],item["id"]))
    db=sqlite3.connect(db_path,timeout=6)
    db.execute("PRAGMA busy_timeout=5000")
    # reporter.init() has already created 'outbox' before this function is called.
    db.execute("""CREATE TABLE IF NOT EXISTS crowdsec_seen (
        alert_key TEXT PRIMARY KEY, created_utc TEXT NOT NULL,
        processed_utc TEXT NOT NULL, notified INTEGER NOT NULL)""")
    db.execute("""CREATE TABLE IF NOT EXISTS crowdsec_bridge_meta (
        name TEXT PRIMARY KEY, value TEXT NOT NULL)""")
    db.commit()
    db.execute("BEGIN IMMEDIATE")
    bootstrap=db.execute("SELECT value FROM crowdsec_bridge_meta WHERE name='initialized'").fetchone() is None
    known={row[0] for row in db.execute("SELECT alert_key FROM crowdsec_seen")}
    unseen=[r for r in valid if r["key"] not in known]
    # On first startup notify only the last 120min; mark earlier history as seen.
    recent=[r for r in unseen if not bootstrap or r["created"]>=at-timedelta(minutes=120)]
    total=len(recent)
    if recent:
        digest=message(recent[:8],total)
        batch_key="luna:crowdsec:batch:"+str(recent[0]["id"])+":"+str(recent[-1]["id"])
        db.execute("""INSERT OR IGNORE INTO outbox
          (event_key,kind,created_utc,html,priority) VALUES(?,?,?,?,?)""",
          (batch_key,"URGENT",at.isoformat(),digest,1 if any(r["sensitive_200"] for r in recent) else 2))
    for item in unseen:
        db.execute("""INSERT OR IGNORE INTO crowdsec_seen
          (alert_key,created_utc,processed_utc,notified) VALUES(?,?,?,?)""",
          (item["key"],item["created"].isoformat(),at.isoformat(),int(item in recent)))
    if bootstrap:
        db.execute("INSERT OR REPLACE INTO crowdsec_bridge_meta(name,value) VALUES('initialized',?)",(at.isoformat(),))
    db.commit()
    db.close()
    return {"state":"PASS","crowdsec_alerts_checked":len(records),
            "new_decisions":total,"digest_queued":bool(recent),
            "bootstrapped":bootstrap,"automatic_bans":0}
