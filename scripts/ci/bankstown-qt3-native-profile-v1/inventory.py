# SPDX-License-Identifier: MIT
"""Finite passive477/349/333 name-version joins; no actors or trust issuance."""
import hashlib
import json
import math
import re

PROTECTED_BYTES=6800
PROTECTED_SHA='579981195b654d8cdf142e4101dfc2bfffbc3576eed50f23796a06e90cf57453'
INVENTORY_CAP=2*1024**2
CATALOG_CAP=64*1024**2
NAME=re.compile(r'[a-z0-9][a-z0-9@._+-]{0,254}')
VERSION=re.compile(r'[A-Za-z0-9][A-Za-z0-9.+:~_-]{0,254}')

def need(value,message):
    if not value:raise ValueError(message)

def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())

def bounded(raw,cap):
    need(type(raw)is bytes and 0<len(raw)<=cap,'bounded nonempty raw bytes');return raw

def inventory(raw,count):
    text=bounded(raw,INVENTORY_CAP).decode('ascii','strict');rows={}
    need(text.endswith('\n'),'canonical inventory trailing newline')
    for line in text[:-1].split('\n'):
        words=line.split(' ')
        need(len(words)==2 and NAME.fullmatch(words[0])and VERSION.fullmatch(words[1]),'canonical package name/version row')
        name,version=words;need(name not in rows,'duplicate inventory package');rows[name]=version
    need(len(rows)==count and raw==''.join(n+' '+v+'\n'for n,v in sorted(rows.items())).encode(),'exact sorted inventory count')
    return rows

def catalog(raw):
    def pairs(rows):
        value={}
        for key,item in rows:need(key not in value,'duplicate catalog JSON key');value[key]=item
        return value
    def finite(value):
        value=float(value);need(math.isfinite(value),'nonfinite catalog JSON number');return value
    value=json.loads(bounded(raw,CATALOG_CAP),object_pairs_hook=pairs,parse_float=finite,
        parse_constant=lambda _:need(False,'nonfinite catalog JSON constant'))
    need(type(value)is dict and type(value.get('packages'))is dict and len(value['packages'])==333,'exact333 catalog packages')
    versions={}
    for name,row in value['packages'].items():
        need(NAME.fullmatch(name)and type(row)is dict and type(row.get('metadata'))is dict,'typed catalog package metadata')
        info=row['metadata'].get('/.PKGINFO');need(type(info)is dict and info.get('pkgname')==[name],'catalog package identity')
        version=info.get('pkgver');need(type(version)is list and len(version)==1 and type(version[0])is str and VERSION.fullmatch(version[0]),'one canonical catalog version')
        versions[name]=version[0]
    need(versions.get('qt6-base')=='6.12.0-3'and versions.get('rust')=='1:1.99.0-1','exact Qt3 and Rust199 catalog versions')
    return versions

def check(inventory_raw,protected_raw,catalog_raw):
    """Caller authenticates raw operands; this function proves only finite joins."""
    bounded(protected_raw,INVENTORY_CAP)
    need(pin(protected_raw)==dict(bytes=PROTECTED_BYTES,sha256=PROTECTED_SHA),'whole held protected349 inventory pin')
    protected=inventory(protected_raw,349);observed=inventory(inventory_raw,477);selected=catalog(catalog_raw)
    need(all(observed.get(n)==v for n,v in protected.items()),'protected349 names/versions unchanged')
    need(all(observed.get(n)==v for n,v in selected.items()),'all333 catalog names/versions observed')
    expected=dict(protected)
    for name,version in selected.items():
        need(name not in expected or expected[name]==version,'catalog cannot replace a protected version');expected[name]=version
    additions=set(observed)-set(protected)
    need(observed==expected and len(additions)==128 and set(selected)-set(protected)==additions,'exact477 protected349 plus128 catalog additions')
    return dict(schema=1,kind='BANKSTOWN_QT3_INVENTORY_JOINS_DATA_V1',
        inventory=pin(inventory_raw),protected=pin(protected_raw),catalog=pin(catalog_raw),
        inventory_count=477,protected_count=349,catalog_count=333,addition_count=128,
        Root_acceptance=None,native_acceptance=False)
