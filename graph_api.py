# SPDX-License-Identifier: MIT
"""Per-observation fresh descriptor queries; original full graph bodies stay held."""
import hashlib,os,types
from pathlib import Path
PINS={'roots': {'bytes': 35970, 'sha256': 'cece1c597b2e2eb98b0e3087cc7e7c148b54332f8a1c4f18e04e4552a71fb51d'}, 'installer': {'bytes': 93752, 'sha256': '14381d049506b52770059bf7af415f7a079f69872543e74417aca11ce24ac3c5'}, 'query': {'bytes': 2784, 'sha256': 'c3d804e7f2927c7889835ad187a39a3d7c618a4651700f57b0c5413c46612607'}, 'caps': {'bytes': 13562, 'sha256': '498a3beec0327b9335dcd6d80ed5919fa2edebebd3284e9ee8b97770328e26a2'}}

def need(ok,why):
 if not ok:raise ValueError(why)

def exact(module,key):
 raw=Path(module.__file__).read_bytes();need(dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())==PINS[key],'whole original graph API source: '+key)

def relative(original):
 def validate(value):
  if os.name=='posix'and type(value)is str and value and '\0'not in value and all(p not in('','.','..')for p in value.split('/')):return value
  return original(value)
 return validate

def roots(original,query):
 exact(original,'roots');exact(original.installer,'installer');exact(query,'query')
 api=types.SimpleNamespace(**vars(original));installer=types.SimpleNamespace(**vars(original.installer));installer.relative=relative(original.installer.relative);api.installer=installer;api._mount_id=query._mount600(original._mount_id);return api

def capabilities(observer,query,raw,root,nodes,label):
 exact(query,'query');need(dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())==PINS['caps'],'whole original capability observer source')
 need(observer.__name__=='_apps6_persistent_caps'and observer._scan.__globals__ is vars(observer),'fresh whole source-derived capability namespace')
 observer._mount=query._mount600(observer._mount);__import__('acl_policy').install(observer,raw,root,nodes,label);return observer
