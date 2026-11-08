#!/usr/bin/env python3
import json,html,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def load(p,d=None):
    try:return json.loads(p.read_text())
    except:return {} if d is None else d
def esc(x):return html.escape(str(x),quote=False)
def js(x):return esc(json.dumps(x,ensure_ascii=False,separators=(',',':')))
def build():
    day=time.strftime('%Y-%m-%d')
    ref=load(ROOT/'reports/reflection'/f'{day}.json')
    if not ref:
        import sentinel_reflect
        ref=sentinel_reflect.build(day)
    import sentinel_self_assessment
    a=sentinel_self_assessment.build(ref)
    tmpl=load(ROOT/'knowledge/self_review_template.json',{})
    titles={x['id']:x['title'] for x in tmpl.get('sections',[])}
    ident=load(ROOT/'knowledge/identity.json',{}).get('name','Sentinel')
    label=('🌙 ' if ident=='Luna' else '🌘 ' if ident=='Selene' else '')+ident
    parts=[f"<b>{esc(label)} · SELF-REVIEW RAW V2 · {esc(ref.get('day',day))}</b>"]
    today=[]
    for x in a.get('today',[]):
        today.append(f"• <code>{esc(x.get('pattern'))}</code> @ <code>{esc(x.get('scope'))}</code> · conf={esc(x.get('confidence'))} · state={esc(x.get('state'))} · obs={esc(x.get('observations'))} · evidence=<code>{js(x.get('evidence'))}</code>")
    parts.append(f"\n<b>{esc(titles.get('today','Hôm nay tôi thấy gì'))}</b>\n"+("\n".join(today) if today else "• []"))
    ch=a.get('change',{})
    change=[]
    for x in ch.get('progress_since_yesterday',[]):
        change.append(f"• progress · <code>{esc(x.get('pattern'))}</code> @ <code>{esc(x.get('scope'))}</code> · {esc(x.get('from'))}→{esc(x.get('to'))}")
    for x in ch.get('historical_changed',[]):
        change.append(f"• history · <code>{esc(x.get('pattern'))}</code> @ <code>{esc(x.get('scope'))}</code> · {esc(x.get('confidence_first'))}→{esc(x.get('confidence_latest'))} · days={esc(x.get('days_seen'))}")
    if not change:change=["• progress=[] · historical_changed=[]"]
    parts.append(f"\n<b>{esc(titles.get('change','Điều gì thật sự thay đổi'))}</b>\n"+"\n".join(change))
    un=a.get('uncertainty',{})
    lines=[]
    for x in un.get('patterns',[]):
        lines.append(f"• pattern · <code>{esc(x.get('pattern'))}</code> @ <code>{esc(x.get('scope'))}</code> · conf={esc(x.get('confidence'))}")
    for x in un.get('independent_limits',[]):
        lines.append(f"• limit · <code>{esc(x.get('concept'))}</code> · {esc(x.get('not_justified'))}")
    parts.append(f"\n<b>{esc(titles.get('uncertainty','Điều tôi vẫn chưa chắc'))}</b>\n"+("\n".join(lines) if lines else "• []"))
    le=a.get('learning',{})
    parts.append(f"\n<b>{esc(titles.get('learning','Tôi muốn học hoặc kiểm chứng gì tiếp'))}</b>\n"
      f"• formal_request_present=<code>{str(bool(le.get('formal_request_present'))).lower()}</code>\n"
      f"• requested_learning=<code>{js(le.get('requested_learning'))}</code>\n"
      f"• attention_topics=<code>{js(le.get('attention_topics'))}</code>")
    nb=a.get('notebook',{})
    nl=[f"• entries={esc(nb.get('entries'))} · bytes={esc(nb.get('bytes'))}/{esc(nb.get('max_bytes'))}"]
    for x in nb.get('retained',[]):
        nl.append(f"• <code>{esc(x.get('concept'))}</code> · merged={esc(x.get('merged_count'))} · reviewed={esc(x.get('reviewed'))}")
    parts.append(f"\n<b>{esc(titles.get('notebook','Notebook của tôi đang giữ gì'))}</b>\n"+"\n".join(nl))
    sa=a.get('self_assessment',{})
    parts.append(f"\n<b>{esc(titles.get('self_assessment','Tôi tự đánh giá hôm nay thế nào'))}</b>\n<code>{js(sa)}</code>")
    raw=a.get('free')
    if raw:
        raw_lines=[f"• source=<code>{esc(raw.get('source'))}</code> · selection=<code>{esc(raw.get('selection_rule'))}</code>"]
        for k in ('concept','relation','state','pattern','scope','confidence','supported','not_justified'):
            if raw.get(k) is not None:raw_lines.append(f"• {esc(k)}={esc(raw.get(k))}")
        if raw.get('evidence') is not None:raw_lines.append(f"• evidence=<code>{js(raw.get('evidence'))}</code>")
    else:
        raw_lines=["• null"]
    parts.append(f"\n<b>{esc(titles.get('free','Dòng tự do'))}</b>\n"+"\n".join(raw_lines))
    parts.append("\n<i>RAW V2 renderer · no authored self-review prose · authority OBSERVE_ONLY.</i>")
    text="\n".join(parts)
    d=ROOT/'reports/self_review_rendered'
    d.mkdir(parents=True,exist_ok=True)
    (d/f'{day}.html').write_text(text)
    (d/f'{day}.json').write_text(json.dumps(a,ensure_ascii=False,indent=2))
    return text
if __name__=='__main__':
    print(build())
