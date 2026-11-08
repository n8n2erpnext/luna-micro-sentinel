#!/usr/bin/env python3
"""Luna Guardian Telegram V2: reliable queue, evidence-based reports, NO enforcement.
Legacy training notification workflow intentionally retired.
The Telegram transport/credentials remain in the existing n8n workflow.
"""
from __future__ import annotations
from pathlib import Path
from datetime import datetime,timedelta,timezone
import argparse,json,re,sqlite3
from luna_firewall_v2 import daily,weekly,proposals,preview_block
from luna_crowdsec_bridge import collect as collect_crowdsec

BASE=Path('/home/ubuntu/services/sentinel-guardian-reports')
DB=BASE/'state/telegram_outbox.sqlite3'
MAX_MSG=3400

def now():
    return datetime.now(timezone.utc)

def init():
    DB.parent.mkdir(parents=True,exist_ok=True)
    db=sqlite3.connect(DB,timeout=6)
    db.execute('PRAGMA busy_timeout=5000')
    db.execute('''CREATE TABLE IF NOT EXISTS outbox(
      id INTEGER PRIMARY KEY, event_key TEXT UNIQUE NOT NULL, kind TEXT NOT NULL,
      created_utc TEXT NOT NULL, html TEXT NOT NULL, priority INTEGER NOT NULL,
      claimed_until TEXT, attempts INTEGER NOT NULL DEFAULT 0, delivered_utc TEXT,
      telegram_message_id TEXT)''')
    db.execute('CREATE INDEX IF NOT EXISTS outbox_pending ON outbox(delivered_utc,priority,id)')
    db.commit()
    return db

def enqueue(key,kind,content,priority=5):
    assert kind in ('URGENT','DAILY','WEEKLY','SYSTEM_TEST')
    assert isinstance(content,str) and 0<len(content)<=MAX_MSG
    db=init()
    cursor=db.execute(
        'INSERT OR IGNORE INTO outbox(event_key,kind,created_utc,html,priority) VALUES(?,?,?,?,?)',
        (key,kind,now().isoformat(),content,int(priority)))
    db.commit()
    queued=cursor.rowcount==1
    db.close()
    return queued

def claim():
    db=init()
    db.execute('BEGIN IMMEDIATE')
    row=db.execute('''SELECT id,html,kind,attempts FROM outbox
        WHERE delivered_utc IS NULL AND (claimed_until IS NULL OR claimed_until<?)
          AND attempts<9 ORDER BY priority ASC,id ASC LIMIT 1''',
        (now().isoformat(),)).fetchone()
    if not row:
        db.commit();db.close();return {}
    ident,content,kind,attempts=row
    expire=(now()+timedelta(minutes=4)).isoformat()
    db.execute('UPDATE outbox SET claimed_until=?,attempts=attempts+1 WHERE id=?',(expire,ident))
    db.commit();db.close()
    return {'id':ident,'text':content,'kind':kind,'attempt':attempts+1}

def ack(ident,telegram_id):
    assert isinstance(ident,int) and ident>0
    mid=str(telegram_id)
    assert re.fullmatch(r'[0-9]{1,20}',mid)
    db=init()
    row=db.execute('''UPDATE outbox
        SET delivered_utc=?,telegram_message_id=?,claimed_until=NULL
        WHERE id=? AND delivered_utc IS NULL''',(now().isoformat(),mid,ident))
    db.commit()
    changed=row.rowcount
    db.close()
    return {'acknowledged':changed==1,'id':ident}

def backlog():
    db=init()
    pending=dict(db.execute('SELECT kind,count(*) FROM outbox WHERE delivered_utc IS NULL GROUP BY kind'))
    sent=db.execute('SELECT count(*) FROM outbox WHERE delivered_utc IS NOT NULL').fetchone()[0]
    expired=db.execute('SELECT count(*) FROM outbox WHERE delivered_utc IS NULL AND attempts>=9').fetchone()[0]
    db.close()
    return {'pending':pending,'delivered':sent,'retry_exhausted':expired}

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('command',choices=[
        'daily','weekly','propose','claim','ack','stats',
        'preview-daily','preview-weekly','preview-block'])
    parser.add_argument('--id',type=int)
    parser.add_argument('--telegram-message-id')
    args=parser.parse_args()
    cmd=args.command
    if cmd=='daily':
        date=(now()+timedelta(hours=7)).date().isoformat()
        queued=enqueue('daily:'+date,'DAILY',daily(),priority=3)
        print(json.dumps({'queued':queued,'date':date,'kind':'DAILY'}))
    elif cmd=='weekly':
        date=(now()+timedelta(hours=7)).date().isoformat()
        queued=enqueue('weekly:'+date,'WEEKLY',weekly(),priority=4)
        print(json.dumps({'queued':queued,'date':date,'kind':'WEEKLY'}))
    elif cmd=='propose':
        alerts=proposals()
        added=0
        for key,text,priority in alerts:
            added+=int(enqueue(key,'URGENT',text,priority))
        # Independent CrowdSec decisions across all proxy websites.
        # Read-only query; stable dedup; shares the existing Telegram claim/ack queue.
        db=init();db.close()
        try:
            crowdsec=collect_crowdsec(DB)
        except Exception as exc:
            crowdsec={'state':'ERROR','type':type(exc).__name__,
                      'new_decisions':0,'digest_queued':False,'automatic_bans':0}
        print(json.dumps({'new_alerts':added+int(crowdsec.get('digest_queued',False)),
                          'candidates':len(alerts),'crowdsec':crowdsec,
                          'automatic_bans':0}))
    elif cmd=='claim':
        print(json.dumps(claim(),ensure_ascii=False))
    elif cmd=='ack':
        print(json.dumps(ack(args.id,args.telegram_message_id)))
    elif cmd=='stats':
        print(json.dumps(backlog(),ensure_ascii=False))
    elif cmd=='preview-daily':
        print(daily())
    elif cmd=='preview-weekly':
        print(weekly())
    elif cmd=='preview-block':
        print(preview_block())

if __name__=='__main__':
    main()
