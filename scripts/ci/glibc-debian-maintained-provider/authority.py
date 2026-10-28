#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Separate explicit Root source selection; never borrow caa2 admission."""
import json
from pathlib import Path
import materialize as M
EXPECTED=dict(name='cachy-asahi-glibc-gnu-provider',version='2.43.caa3-1',archive_sha256=M.ORIG_SHA,patch_tar_sha256=M.ARCHIVE_SHA,quilt_tree='aa963b6ef1d55056efbab622411d2530a636422d',prepared_tree='08ea2aef96bd3144cf02cbc68cbbb003dc25ed9f')
KEYS={'B8B80B5B623EAB6AD8775C45B7C5D7D6350947F8':'4CB50190207B4758A3F73A796ED0E7B82643E131','04B54C3CDCA79751B16BC6B5225629DF75B188BD':'B8E5F13176D2A7A75220028078DBA3BC47EF2265'}
def check(policy,inputs,auth_helper=None):
 # Refuse the shipped UNBOUND policy before helper imports, crypto or output.
 path=Path(policy).absolute();M.need(not any(p.is_symlink() for p in (path,*path.parents)) and M.stat.S_ISREG(path.stat().st_mode) and path.stat().st_nlink==1 and path.stat().st_size<=65536,'ordinary bounded authority policy required')
 def pairs(rows):
  out={}
  for k,v in rows:M.need(k not in out,'duplicate authority field');out[k]=v
  return out
 value=json.loads(path.read_bytes(),object_pairs_hook=pairs,parse_constant=lambda _:M.need(False,'finite policy required'))
 M.need(type(value) is dict,'authority object required')
 M.need(value.get('schema_version')==1 and value.get('status')=='ROOT_BOUND_DEBIAN_MAINTAINED_SOURCE_AUTHORITY','UNBOUND maintained caa3 source authority; no bundle/build/native actors')
 M.need(value.get('candidate')==EXPECTED and value.get('key_pairs')==KEYS,'distinct exact maintained candidate/key selection required')
 row=value.get('decision');M.need(type(row) is dict and set(row)=={'path','bytes','sha256'} and type(row['path']) is str and Path(row['path']).name==row['path'] and row['path'] not in ('.','..'),'Root maintained candidate decision reference required')
 a=M.helper('maintained_authority_auth',M.helper_path('auth.py',auth_helper),M.AUTH_SHA);raw=a.read(Path(inputs)/row['path'],65536);M.need(a.pin(raw)=={k:row[k] for k in ('bytes','sha256')},'Root maintained decision bytes differ');decision=a.decode(raw)
 M.need(decision.get('status')=='ROOT_ACCEPTED_DEBIAN_MAINTAINED_SOURCE_AUTHORITY' and decision.get('candidate')==EXPECTED and decision.get('key_pairs')==KEYS and decision.get('independent_evidence') and decision.get('not_just_publisher_https') is True,'independent authority and explicit new full-quilt/manual/source selection required')
 return dict(status='PASS_ROOT_BOUND_MAINTAINED_SOURCE_AUTHORITY_ONLY',decision_sha256=a.pin(raw)['sha256'],candidate=EXPECTED,native='NOT_RUN',security='NO_CREDIT',release='NOT_ADMITTED')
