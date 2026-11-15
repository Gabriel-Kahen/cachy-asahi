#!/usr/bin/env python3
"""Finite public-certificate expiry DATA; no key import or trust decision."""
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
SOURCES = {'scripts/repository/revoke.py':'8804cf14527341c23bd7ba540c23a08185a10c92f6d405a65f52f277ff6bc44b',
           'scripts/repository/enroll.py':'38db2d45955b569a4c74c3f31d6b6c79611126238e1bbe1e5cf819f81d0fb54f'}


def require(ok, reason):
    if not ok: raise ValueError(reason)


def inspect(raw, packets, expected, now):
    require(0<len(raw)<=65536,'public certificate byte cap')
    framed=packets(raw)
    require(len(framed)<=16,'finite project certificate shape')
    key=next(body for tag,body,_ in framed if tag==6)
    require(key[0]==4 and len(key)<65536,'v4 public primary')
    fingerprint=hashlib.sha1(b'\x99'+len(key).to_bytes(2,'big')+key).hexdigest().upper()
    require(fingerprint==expected,'exact project primary')
    created=int.from_bytes(key[1:5],'big'); expiries=[]
    for tag,body,_ in framed:
        if tag!=2: continue
        require(len(body)>=6 and body[0]==4 and body[1]==0x13,'single user certification DATA required')
        length=int.from_bytes(body[4:6],'big'); sub=body[6:6+length]
        require(len(sub)==length,'hashed subpacket area')
        fields={};at=0
        while at<len(sub):
            size=sub[at];at+=1
            if 192<=size<255:
                require(at<len(sub),'two-byte subpacket length');size=((size-192)<<8)+sub[at]+192;at+=1
            elif size==255:
                require(at+4<=len(sub),'five-byte subpacket length');size=int.from_bytes(sub[at:at+4],'big');at+=4
            require(0<size and at+size<=len(sub),'bounded complete subpacket')
            kind=sub[at]&127;fields.setdefault(kind,[]).append(sub[at+1:at+size]);at+=size
        require(fields.get(33)==[b'\x04'+bytes.fromhex(expected)],'declared certification issuer fingerprint')
        require(len(fields.get(9,[]))==1 and len(fields[9][0])==4,'one declared key expiry interval')
        require(fields.get(2)==[created.to_bytes(4,'big')],'certification/primary creation agreement')
        expiries.append(created+int.from_bytes(fields[9][0],'big'))
    require(len(expiries)==1 and expiries[0]>created,'one finite declared expiry')
    iso=lambda n:datetime.datetime.fromtimestamp(n,datetime.timezone.utc).isoformat()
    return {'fingerprint':fingerprint,'key_created_utc_epoch':created,'declared_key_expires_utc_epoch':expiries[0],
        'declared_key_expires_UTC':iso(expiries[0]),'observed_utc_epoch':now,'observed_UTC':iso(now),
        'declaration_expired_at_observation':now>=expiries[0],
        'scope':'Pinned public packet declaration only; self-certification mathematical validation/current trust horizon remain external. Fresh package gpgv evidence is separate.',
        'Root_trust_approval':False}


if __name__=='__main__':
    for name,digest in SOURCES.items():
        body=(ROOT/name).read_bytes();require(len(body)<=1024**2 and hashlib.sha256(body).hexdigest()==digest,'packet reader source pin')
    spec=importlib.util.spec_from_file_location('ui172_public_packets',ROOT/'scripts/repository/revoke.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    config=json.loads((HERE/'inputs.json').read_text());ref=config['project_binary_keyring'];raw=Path(ref['path']).read_bytes()
    require(len(raw)==ref['bytes'] and hashlib.sha256(raw).hexdigest()==ref['sha256'],'project public keyring pin')
    result=inspect(raw,module.packets,config['project_primary'],time.time())
    result.update(public_keyring=ref,packet_reader_sources=SOURCES)
    print(json.dumps(result,indent=2,sort_keys=True))
