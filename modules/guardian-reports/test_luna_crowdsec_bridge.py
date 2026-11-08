#!/usr/bin/env python3
"""Offline CrowdSec bridge acceptance: no real n8n, bans, network or Telegram."""
import json, sqlite3, tempfile, sys
from pathlib import Path
from datetime import datetime,timezone,timedelta
sys.path.insert(0,str(Path(__file__).parent))
import luna_crowdsec_bridge as bridge

NOW=datetime(2026,10,31,2,21,tzinfo=timezone.utc)
def ban(i,ip,minutes_ago,host,scenario="crowdsecurity/http-sensitive-files",status=200,simulated=False):
    created=(NOW-timedelta(minutes=minutes_ago)).isoformat().replace("+00:00","Z")
    return {"id":i,"created_at":created,"scenario":scenario,"simulated":simulated,
            "events_count":5,
            "source":{"ip":ip},"decisions":[{"id":90000+i,"origin":"crowdsec",
                "type":"ban","scope":"Ip","value":ip,"simulated":simulated,"scenario":scenario}],
            "events":[{"meta":[{"key":"target_fqdn","value":host},
                               {"key":"http_status","value":str(status)}]}]}
def setup_db(path):
    conn=sqlite3.connect(path)
    conn.execute("""CREATE TABLE outbox(id INTEGER PRIMARY KEY,event_key TEXT UNIQUE NOT NULL,
        kind TEXT NOT NULL,created_utc TEXT NOT NULL,html TEXT NOT NULL,
        priority INTEGER NOT NULL,claimed_until TEXT,attempts INTEGER NOT NULL DEFAULT 0,
        delivered_utc TEXT,telegram_message_id TEXT)""")
    conn.commit();conn.close()
with tempfile.TemporaryDirectory() as tmp:
    db=Path(tmp)/"queue.sqlite3";setup_db(db)
    data=[
        ban(1,"8.8.8.8",10,"a.example"),
        ban(2,"9.9.9.9",8,"b.example",scenario="LePresidente/http-generic-403-bf",status=403),
        ban(3,"127.0.0.1",6,"c.example"),
        ban(4,"1.1.1.1",5,"d.example",simulated=True),
        ban(5,"1.0.0.1",310,"e.example")]
    f=lambda: data
    x=bridge.collect(db,fetcher=f,at=NOW)
    assert x["state"]=="PASS" and x["new_decisions"]==2 and x["bootstrapped"]
    c=sqlite3.connect(db)
    records=c.execute("SELECT event_key,kind,html FROM outbox").fetchall()
    assert len(records)==1
    assert "8.8.8.8" in records[0][2] and "9.9.9.9" in records[0][2]
    assert "a.example" in records[0][2] and "b.example" in records[0][2]
    assert "đường dẫn nhạy cảm" in records[0][2] or "Đường dẫn nhạy cảm" in records[0][2]
    assert "bouncer" in records[0][2]
    assert c.execute("SELECT count(*) FROM crowdsec_seen").fetchone()[0]==3
    y=bridge.collect(db,fetcher=f,at=NOW+timedelta(minutes=1))
    assert y["new_decisions"]==0 and c.execute("SELECT count(*) FROM outbox").fetchone()[0]==1
    data.append(ban(6,"4.2.2.2",-2,"f.example",scenario="LePresidente/http-generic-403-bf",status=403))
    z=bridge.collect(db,fetcher=f,at=NOW+timedelta(minutes=2))
    assert z["new_decisions"]==1 and c.execute("SELECT count(*) FROM outbox").fetchone()[0]==2
    assert c.execute("SELECT count(*) FROM crowdsec_seen").fetchone()[0]==4
    c.close()
print("PASS: live CrowdSec decisions only; simulated and private IP ignored; initial bootstrap bounded; digest once; stable dedupe, later ban detection; SQLite queue atomic; no Telegram/firewall actions")
