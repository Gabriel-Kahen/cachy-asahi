# SPDX-License-Identifier: MIT
"""Strict joins of real busctl-monitor calls/replies and Mako's live listing."""
import json,re
from pathlib import Path

CASES={'minimal':('foreground-success',0),'overlay':('foreground-failure',7),'background':('watched-background-success',0)}


def diagnostic_policy():
    path=Path(__file__).with_name('diagnostic-policy.json')
    need(not path.is_symlink() and path.is_file() and path.stat().st_size<=4096,'bounded source-pinned diagnostic policy required')
    raw=path.read_bytes()
    def pairs(rows):
        value={}
        for key,item in rows:need(key not in value,'duplicate diagnostic policy key');value[key]=item
        return value
    value=json.loads(raw,object_pairs_hook=pairs)
    need(set(value)=={'schema_version','mako_wayland_protocol_probe','scope'} and type(value['schema_version']) is int and value['schema_version']==1 and
         type(value['mako_wayland_protocol_probe']) is bool and value['scope']=='ONE_EXPLICIT_SOURCE_PINNED_DIAGNOSTIC_NOT_NORMAL_ACCEPTANCE',
         'explicit source-pinned diagnostic boolean required')
    return value


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


def capture_timing_facts(wire,request_realtime_us,request_monotonic_ns):
    """One guest clock domain: busctl message time -> immediately before emit."""
    call=wire['call'].get('timestamp-realtime');reply=wire['reply'].get('timestamp-realtime')
    need(all(type(v) is int and v>0 for v in (call,reply,request_realtime_us,request_monotonic_ns)) and
         call<=reply<=request_realtime_us,'actual guest Notify/reply/request timestamps required')
    age=request_realtime_us-call
    return dict(basis='GUEST_REALTIME_NOTIFY_TO_PRE_EMISSION',notify_realtime_us=call,reply_realtime_us=reply,
                request_realtime_us=request_realtime_us,request_monotonic_ns=request_monotonic_ns,
                age_us=age,age_ms=(age+999)//1000,original_expiry_ms=3000,reserve_us=3_000_000-age)


def capture_timing(wire,request_realtime_us,request_monotonic_ns):
    facts=capture_timing_facts(wire,request_realtime_us,request_monotonic_ns)
    need(facts['age_us']<=2_000_000,'first capture request has less than one second of original TTL reserved')
    return facts


def closure_facts(raw,wire):
    """Raw matching close-signal facts only; no inferred expiry/presentation pass."""
    rows=messages(raw)
    closed=[r for r in rows if r.get('type')=='signal' and r.get('path')=='/org/freedesktop/Notifications' and
            r.get('interface')=='org.freedesktop.Notifications' and r.get('member')=='NotificationClosed']
    matching=[]
    for row in closed:
        payload=row.get('payload',{});data=payload.get('data')
        if row.get('sender')==wire['recipient'] and payload.get('type')=='uu' and type(data) is list and len(data)==2 and data[0]==wire['id']:
            timestamp=row.get('timestamp-realtime')
            delta=timestamp-wire['call']['timestamp-realtime'] if type(timestamp) is int else None
            matching.append(dict(signal=row,notify_to_closed_realtime_us=delta))
    return dict(scope='DIAGNOSTIC_ONLY_NO_EXPIRY_OR_PRESENTATION_ACCEPTANCE',
                matching_closed_signals=matching,other_closed_signals=len(closed)-len(matching),
                status='MATCHING_CLOSED_SIGNAL_OBSERVED' if matching else 'NO_MATCHING_CLOSED_SIGNAL_OBSERVED')
