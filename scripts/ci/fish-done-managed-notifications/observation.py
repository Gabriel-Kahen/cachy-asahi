# SPDX-License-Identifier: MIT
"""Strict joins of real busctl-monitor calls/replies and Mako's live listing."""
import json,re

CASES={'minimal':('foreground-success',0),'overlay':('foreground-failure',7),'background':('watched-background-success',0)}


def body(stage):return 'Watched job completed.' if stage=='background' else 'Foreground command completed.'


def need(ok,why):
    if not ok:raise ValueError(why)


def messages(raw):
    need(len(raw)<=262144,'D-Bus monitor byte cap')
    result=[]
    for line in raw.splitlines():
        if not line.strip():continue
        value=json.loads(line);need(type(value) is dict,'D-Bus JSON message required');result.append(value)
        need(len(result)<=512,'D-Bus message count cap')
    return result


def summary(value,outcome):
    prefix='Done in ' if outcome==0 else 'Failed (7) after '
    need(type(value) is str and value.startswith(prefix) and
         re.fullmatch(r'[0-9hms ]{1,40}',value[len(prefix):]) is not None and
         any(c.isdigit() for c in value[len(prefix):]),'actual Done summary differs')


def notify(rows,owner,outcome,kind='Foreground command'):
    need(kind in ('Foreground command','Watched job'),'fixed notification kind required')
    calls=[r for r in rows if r.get('type')=='method_call' and r.get('interface')=='org.freedesktop.Notifications' and r.get('member')=='Notify']
    need(len(calls)<=1,'duplicate notification call')
    if not calls:return None
    call=calls[0];need(call.get('path')=='/org/freedesktop/Notifications' and
         call.get('destination') in ('org.freedesktop.Notifications',owner) and
         re.fullmatch(r':[0-9]+\.[0-9]+',call.get('sender','')) and
         call['sender']!=owner and type(call.get('cookie')) is int,'notification sender/recipient/cookie differs')
    payload=call.get('payload');need(type(payload) is dict and payload.get('type')=='susssasa{sv}i','Notify signature differs')
    data=payload.get('data');need(type(data) is list and len(data)==8 and data[0]=='fish' and data[1]==0 and
         data[2]=='' and data[4]==kind+' completed.' and data[5]==[] and data[7]==3000,
         'unmodified Done Notify data/expiry differs')
    summary(data[3],outcome)
    hints=data[6];need(type(hints) is dict and hints.get('urgency')==dict(type='y',data=1 if outcome==0 else 2) and
         hints.get('transient')==dict(type='i',data=1) and
         hints.get('image-path')==dict(type='s',data='utilities-terminal'),'Done urgency/transient hints differ')
    replies=[]
    for row in rows:
        if row.get('type')!='method_return':continue
        cookie=row.get('reply_cookie',row.get('reply-cookie'))
        if cookie==call['cookie'] and row.get('destination')==call['sender']:
            need(row.get('sender')==owner,'Notify reply from foreign recipient');replies.append(row)
    need(len(replies)<=1,'duplicate Notify reply')
    if not replies:return None
    reply=replies[0];p=reply.get('payload');need(type(p) is dict and p.get('type')=='u' and
         type(p.get('data')) is list and len(p['data'])==1 and type(p['data'][0]) is int and 0<p['data'][0]<2**32,
         'actual Notify returned ID absent')
    return dict(id=p['data'][0],sender=call['sender'],recipient=owner,call=call,reply=reply,
                summary=data[3],body=data[4],app_name='fish',expire_time_ms=3000,outcome=outcome)


def listing(value,wire):
    need(type(value) is list and all(type(r) is dict for r in value),'actual Mako list required')
    found=[r for r in value if r.get('id')==wire['id']]
    need(len(found)<=1,'duplicate Mako notification ID')
    if not found:return None
    row=found[0]
    need(all(row.get(k)==wire[k] for k in ('app_name','summary','body')),'Mako listing/wire payload differs')
    return row
