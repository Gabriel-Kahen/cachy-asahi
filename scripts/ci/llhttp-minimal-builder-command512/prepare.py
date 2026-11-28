#!/usr/bin/python3 -I -B
# SPDX-License-Identifier: MIT
"""New minimal206512/cadence successor, complete6651 inverse, no new Source leaf."""
import argparse,ast,base64,hashlib,importlib.util,json,math,stat,types,zlib
from pathlib import Path
HERE=Path(__file__).resolve().parent
ORIGINAL=dict(bytes=20399,sha256='a7915d97b9e8fc9a5e152d803dbd5e453a6a99e59ae62704712b5e73015f1d7f')
CONSTRUCTOR=dict(bytes=21041, sha256='588565d2340c77e2c6469100d1c54ac432bc62dd1b4e43eca69f932e8db4668f')
p=HERE.parent/'llhttp-minimal-builder-source/prepare.py';raw=p.read_bytes()
if dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())!=CONSTRUCTOR:raise ValueError('whole maintained constructor')
spec=importlib.util.spec_from_file_location('minimal206_original6651',p);P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)
NB=P.NB;NO=P.NO;MARKER=P.MARKER
MAP=dict(bytes=20332,sha256='a5661571f8698b41233d4a0cb5cdbe39b27ecbcc5c59c266e9555a003efc0ec5')
TREE='06061af2729a5806556cc76f84eba36aafb9a0e3'
EXT='command512_successor'
CHANGED=(NB+'entry.py',NO+'hosted_owner.py',NO+'public_evidence.py',NO+'policy.json',NB+'source-map.json',NO+'base-binding.json',NO+'owner-program.json',MARKER,'source-map.json')
need=P.need;pin=P.pin;encode=P.encoded;decode=P.decode;read=P.read;tree=P.tree

def original_call(fn,*args,marker,**kwargs):
 # DEFLATE is not byte-canonical across zlib versions. Reuse ONLY the pinned
 # historical compressed preimages, checking complete decompression first.
 need(type(marker['changed'])is dict and 2<=len(marker['changed'])<=95,'finite historical compression table')
 table={}
 for row in marker['changed'].values():
  need(set(row)=={'pin','mode','zlib_base64'}and type(row['pin']['bytes'])is int and 0<row['pin']['bytes']<=1318237 and row['mode']==0o644,'typed bounded historical preimage')
  packed=base64.b64decode(row['zlib_base64'],validate=True);need(len(packed)<=2*1024**2,'bounded historical compressed bytes');stream=zlib.decompressobj();raw=stream.decompress(packed,1318238)
  need(stream.eof and not stream.unused_data and not stream.unconsumed_tail and pin(raw)==row['pin'],'whole historical compression input')
  need(raw not in table or table[raw]==packed,'unambiguous exact historical compression');table[raw]=packed
 def compress(raw,level):
  need(level==9 and raw in table,'only exact recorded historical compression');return table[raw]
 previous=P.zlib;P.zlib=types.SimpleNamespace(compress=compress,decompressobj=zlib.decompressobj)
 try:return fn(*args,**kwargs)
 finally:P.zlib=previous

def predecessor95(b):return original_call(P.inverse,b,marker=decode(b[MARKER]))

def validate_parent(b):
 need(len(b)==96 and sum(map(len,b.values()))==1592222 and pin(b['source-map.json'])==MAP and tree(b)==TREE,'whole immutable6651 Source96')
 d=decode(b['source-map.json']);need(set(b)==set(d['files'])|{'source-map.json'}and all(v is None for v in d['actual'].values()),'whole unissued96 namespace')
 for n,r in d['files'].items():need(dict(pin(b[n]),mode=0o644)==r,'whole6651 body/mode '+n)
 predecessor95(b)

def parent_bodies(root):
 root=P.ordinary(root);names=P.census(root,96);b={n:read(root/n)for n in names};need(all(stat.S_IMODE((root/n).stat().st_mode)==0o644 for n in names),'whole96 physical modes');validate_parent(b);return b

def owner_projection(raw):
 text=raw.decode();seams=[]
 node=next(n for n in ast.walk(ast.parse(text))if isinstance(n,ast.FunctionDef)and n.name=='start');old=ast.get_source_segment(text,node);need(old.count('time.sleep(.1)')==1,'one exact30s startup query cadence')
 for before,after in((old,old.replace('time.sleep(.1)','time.sleep(min(1,max(0,until-time.monotonic())))')),('            time.sleep(.2)','            time.sleep(min(10,max(0,owner.end-time.monotonic())))')):
  need(text.count(before)==1,'one exact bounded outer cadence seam');text=text.replace(before,after);seams.append(dict(before=before,after=after))
 restored=text
 for r in reversed(seams):restored=restored.replace(r['after'],r['before'])
 need(restored.encode()==raw,'whole original6651 controller inverse');return text.encode(),seams

def section(seams):return dict(kind='MINIMAL206_INNER512_OUTER_CADENCE_V1',parent_revision='6651ad8c6f02a1a5c6c5683b40571af7512aedf1',parent_map=MAP,parent_tree=TREE,parent_files=96,parent_bytes=1592222,original_constructor=ORIGINAL,seams=seams,inner_limit=512,outer_limit=512,inner_normal_upper=228,inner_failure_cleanup_upper=240,outer_lifetime_upper=253,startup_seconds=1,running_seconds=10,status_query_existing_seconds=30,observation_seconds_before_natural_retirement=40,cleanup_whole_seconds=90,actual=None,Root_selection=None,native=None)

def assemble(old):
 validate_parent(old);b=dict(old);entry=old[NB+'entry.py'].decode();need(entry.count('len(self.rows)<160')==1,'one existing inner160 guard');b[NB+'entry.py']=entry.replace('len(self.rows)<160','len(self.rows)<512').encode();b[NO+'hosted_owner.py'],seams=owner_projection(old[NO+'hosted_owner.py'])
 public=old[NO+'public_evidence.py'].decode();need(public.count('range(160)')==1,'one exact command receipt catalog');b[NO+'public_evidence.py']=public.replace('range(160)','range(512)').encode()
 scope={};exec(compile(b[NO+'public_evidence.py'],'<minimal206 finite public exporter>','exec'),scope);need(len(scope['PUBLIC_LEAVES'])==1582 and scope['MAX_BYTES']==16*1024**2,'strict finite1582 leaf/same16MiB exporter')
 policy=decode(old[NO+'policy.json']);policy['inner_public_retention']=scope['DECLARATION'];policy['command_ledger']=section([]);b[NO+'policy.json']=encode(policy)
 base={n[len('held-source/'):]:raw for n,raw in b.items()if n.startswith('held-source/')and n!=NB+'source-map.json'};d=decode(old[NB+'source-map.json']);b[NB+'source-map.json']=encode(dict(d,files={n:dict(pin(raw),mode=0o644)for n,raw in sorted(base.items())}));base[P.NEW+'base/source-map.json']=b[NB+'source-map.json'];b[NO+'base-binding.json']=encode(dict(map=pin(b[NB+'source-map.json']),files=len(base),bytes=sum(map(len,base.values()))))
 marker=decode(old[MARKER]);need(EXT not in marker,'new versioned compact ledger only');marker[EXT]=section(seams);b[MARKER]=encode(marker)
 b.pop(NO+'owner-program.json');b.pop('source-map.json');b[NO+'owner-program.json']=encode(dict(schema=1,base_source_map_sha256=pin(b[NB+'source-map.json'])['sha256'],files={n:dict(pin(raw),mode=0o644)for n,raw in sorted(b.items())if not n.startswith('held-source/')}));b['source-map.json']=encode(dict(decode(old['source-map.json']),files={n:dict(pin(raw),mode=0o644)for n,raw in sorted(b.items())}));need(len(b)==96 and sum(map(len,b.values()))<2*1024**2,'unchanged96-leaf/2MiB Source cap');return b

def recover_parent(b):
 need(type(b)is dict and len(b)==96 and sum(map(len,b.values()))<2*1024**2,'bounded complete new96 input');marker=decode(b[MARKER]);current=marker.pop(EXT);need(current['parent_map']==MAP and current['parent_tree']==TREE and current['original_constructor']==ORIGINAL,'whole6651 inverse binding')
 # Reuse the old compact95 preimages already present. Canonical6651 regeneration
 # reconstructs EVERY previous96 byte/map/mode without copying another old map.
 need(len(marker['renames'])<=95 and len(marker['changed'])<=95 and sum(r['pin']['bytes']for r in marker['changed'].values())<=1318237,'finite original compact inverse')
 renames={v:k for k,v in marker['renames'].items()};old95={renames.get(n,n):raw for n,raw in b.items()if n!=MARKER}
 for n,r in marker['changed'].items():
  compressed=base64.b64decode(r['zlib_base64'],validate=True);need(0<r['pin']['bytes']<=1318237 and len(compressed)<=2*1024**2,'finite exact old preimage');stream=zlib.decompressobj();raw=stream.decompress(compressed,1318238);need(stream.eof and not stream.unused_data and not stream.unconsumed_tail and pin(raw)==r['pin']and r['mode']==0o644,'whole original95 preimage');old95[n]=raw
 P.validate_parent(old95);parent=original_call(P.assemble,old95,b[NB+'runtime/scripts/ci/inputs.lock.json'],b[NB+'expected206.lock'],decode(b[NB+'profile.json'])['minimal_public_signatures'],marker=marker,historical=True);need(parent[MARKER]==encode(marker),'old compact marker exact regeneration');validate_parent(parent);return parent

def inverse(b):
 old=recover_parent(b);need(b==assemble(old),'whole canonical new512 source and full6651 inverse');need(all(b[n]==raw for n,raw in old.items()if n not in CHANGED),'all unrelated96 bodies unchanged');return old

def construct(parent,output):
 parent,output=map(P.ordinary,(parent,output));need(not output.exists()and not output.is_relative_to(parent)and not parent.is_relative_to(output),'fresh disjoint output');old=parent_bodies(parent);b=assemble(old);need(inverse(b)==old,'whole original6651 bytes/modes/membership inverse');output.mkdir(mode=0o700)
 for n,raw in b.items():
  p=output/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw);p.chmod(0o644)
 spec=importlib.util.spec_from_file_location('minimal206_512_closed_source',output/NO/'data.py');D=importlib.util.module_from_spec(spec);spec.loader.exec_module(D);D.source(output,pin(b['source-map.json'])['sha256'])
 return dict(status='SOURCE_DATA_ONLY_BUILD_ONLY_UNISSUED',files=len(b),bytes=sum(map(len,b.values())),tree=tree(b),source_map=pin(b['source-map.json']),policy=pin(b[NO+'policy.json']),program=pin(b[NO+'owner-program.json']),parent_map=MAP,actual=decode(b['source-map.json'])['actual'],Root_selection=None,publication=None,signature_authentication=None,native=None,M2=None)
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--parent',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();print(json.dumps(construct(a.parent,a.output),indent=2,sort_keys=True))
