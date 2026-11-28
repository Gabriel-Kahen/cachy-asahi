#!/usr/bin/python3 -I -B
# SPDX-License-Identifier: MIT
"""Separate minimal206 BUILD_ONLY llhttp source; no actor/publication/Root role."""
import argparse,base64,hashlib,importlib.util,json,os,re,stat,zlib
from pathlib import Path
HERE=Path(__file__).resolve().parent
OLD='scripts/ci/llhttp-reference-native-source/'
NEW='scripts/ci/llhttp-minimal-builder-source/'
OB='held-source/'+OLD+'base/'
NB='held-source/'+NEW+'base/'
NO=NEW+'owner/'
MARKER='minimal206-build-only-projection.json'
PARENT_MAP=dict(bytes=20200,sha256='ab743415f602ba8c5f81a063fc7cc5d25587be0d535601396f2ee617fb4149ce')
PARENT_TREE='b73f92b1ed4e6f6ab8c4210fdaa19617b1a5721f'
INTAKE_REVISION='b0f47fe258d64831f70818dcb1750ef50e26d1b2'
INTAKE_LOCK=dict(bytes=2377,sha256='4730b8f6df4ad17140ec3dddcedbafd78b7012538361ae866757635269ac6bd3')
ORIGINAL_INTAKE_REVISION='e947d24c3cb2f9facfd897d5e65ce6f19942cbca'
ORIGINAL_INTAKE_LOCK=dict(bytes=2377,sha256='6fac7419f32e2c370840dc9ee587b0cdf9d265f2dc9b57ff38bb945a468d090f')
BUILDER=dict(bytes=1189335,sha256='c5c9f4450575b6c66f7991c48f9bb227e78ea1e605f57df0a46778ba9d4d6f65')
NATIVE=dict(bytes=236589,sha256='629ef92976d17f13443897b0711a54ecb3e404eea4d0d997447407d76a9baf16')
EXPECTED=dict(bytes=4048,sha256='303cb32db7378e2cdd5d7645df1dc1f5e7a30fc9ea588f0d2867eede21127e66')
SIGNER='68B3537F39A313B3E574D06777193F152BDBE6A6'
SIGNATURES=dict(bytes=166243,sha256='5820331662cdd5c49adac3fc26dca22308734ce51f2e997b1c2ba5313f3e6a20')
PROOFS=dict(package_metadata=dict(bytes=204,sha256='e13386f6f7dd4e7ac41d946b417e4af44b840f63e94b6954d9ea92db107fd34c'),retrieval=dict(bytes=68251,sha256='001a8e7213858a3ff92379f8b489d214c5b08ac505ec5b44aa98384f17c05aed'))

def need(ok,why):
 if not ok:raise ValueError(why)
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def encoded(v):return(json.dumps(v,indent=2,sort_keys=True)+'\n').encode()
def decode(b):
 def pairs(rows):
  d={}
  for k,v in rows:need(k not in d,'duplicate DATA key');d[k]=v
  return d
 return json.loads(b,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'finite DATA only'))
def ordinary(p):
 p=Path(p);need(p.is_absolute()and p==p.resolve()and not any(x.is_symlink()for x in(p,*p.parents)),'ordinary exact absolute DATA path');return p

def read(p,cap=2*1024**2):
 p=ordinary(p);s=p.lstat();need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and s.st_uid==os.getuid()and not s.st_mode&0o022 and 0<s.st_size<=cap,'bounded owned ordinary DATA')
 b=p.read_bytes();identity=lambda x:tuple(getattr(x,k)for k in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'));need(len(b)==s.st_size and identity(s)==identity(p.lstat()),'whole stable DATA identity');return b

# Exact maintained successor_v2 Git-tree function (whole source pin in provenance).
def tree(bodies):
 def oid(kind,body):return hashlib.sha1(kind.encode()+b' '+str(len(body)).encode()+b'\0'+body).digest()
 def walk(prefix):
  names={n[len(prefix):].split('/')[0]for n in bodies if n.startswith(prefix)};rows=[]
  for name in names:
   path=prefix+name;leaf=path in bodies;mode=b'100644'if leaf else b'40000';digest=oid('blob',bodies[path])if leaf else walk(path+'/')
   rows.append(((name if leaf else name+'/').encode(),mode+b' '+name.encode()+b'\0'+digest))
  return oid('tree',b''.join(row for key,row in sorted(rows)))
 return walk('').hex()

def validate_parent(bodies):
 need(pin(bodies['source-map.json'])==PARENT_MAP,'whole immutable Source95 map');d=decode(bodies['source-map.json'])
 need(set(bodies)==set(d['files'])|{'source-map.json'}and len(bodies)==95 and sum(map(len,bodies.values()))==1318237 and tree(bodies)==PARENT_TREE,'complete95 bodies/namespace/tree')
 need(all(v is None for v in d['actual'].values()),'parent actuals NULL')
 for n,r in d['files'].items():need(dict(pin(bodies[n]),mode=0o644)==r,'whole95 body/mode '+n)

def census(p,cap):
 found=set()
 for i,x in enumerate(p.rglob('*')):
  need(i<512 and len(x.relative_to(p).parts)<=32,'finite DATA namespace walk')
  if x.is_file()or x.is_symlink():found.add(x.relative_to(p).as_posix());need(len(found)<=cap,'finite closed leaf census')
 return found

def parent_bodies(p):
 p=ordinary(p);found=census(p,95);b={n:read(p/n)for n in sorted(found)};need(all(stat.S_IMODE((p/n).stat().st_mode)==0o644 for n in found),'whole physical95 modes');validate_parent(b);return b

def intake(p,package_proof,acquisition_proof):
 p=ordinary(p);lock=read(p/'source.lock.json');need(pin(lock)==INTAKE_LOCK,'whole maintained intake family lock');rows=decode(lock)['files'];need(census(p,15)==set(rows)|{'source.lock.json'},'whole intake family membership')
 for n,r in rows.items():need(dict(pin(read(p/n)),mode=stat.S_IMODE((p/n).stat().st_mode))==r,'whole intake source/mode '+n)
 builder=read(p/'builder.lock.json');native=read(p/'native-inputs.lock.json');expected=read(p/'expected206.lock');need(pin(builder)==BUILDER and pin(native)==NATIVE and pin(expected)==EXPECTED,'exact206 builder/native/inventory operands')
 d=decode(builder);need(d['metadata_graph_status']=='PASS'and not d['graph_blockers']and not d['rootfs_reconciliation']['missing']and len(d['packages'])==206,'complete coherent206 graph')
 evidence=decode(read(p/'actual-intake.DATA.json'));proofs={}
 for label,path,key in(('package_metadata',package_proof,'material-check.DATA.json'),('retrieval',acquisition_proof,'acquisition-with-catalogs.DATA.json')):
  raw=read(path);need(pin(raw)=={k:evidence['records'][key][k]for k in('bytes','sha256')},'whole genuine '+label+' proof');proofs[label]=pin(raw)
 a=decode(read(acquisition_proof));m=decode(read(package_proof));need(a['all_inputs_retrieved']is True and a['failures']==[]and len(a['inputs'])==422 and m['PKGINFO']=='PASS'and m['signature_authentication']is None,'genuine422 retrieval and206 full PKGINFO DATA only')
 need(m['Root_native_authority']is None and a['Root_selection']is None and a['native']is None,'no acceptance carryforward')
 need(proofs==PROOFS,'exact committed genuine prerequisite proofs');signatures={r['archive']['filename']+'.sig':r['archive']['signature_b64']for r in d['packages']};need(pin(encoded(signatures))==SIGNATURES,'whole exact public signature payload map');return native,expected,proofs,signatures

def renamed(n):
 if n.startswith('held-source/'+OLD):n='held-source/'+NEW+n[len('held-source/'+OLD):]
 elif n.startswith(OLD):n=NEW+n[len(OLD):]
 if n=='.github/workflows/native-arm-llhttp-reference-source.yml':n='.github/workflows/native-arm-llhttp-minimal-builder-source.yml'
 if n==NB+'expected349.lock':n=NB+'expected206.lock'
 return n

def operation_text(raw):
 text=raw.decode()
 for before,after in((OLD,NEW),('native-arm-llhttp-reference-source','native-arm-llhttp-minimal-builder-source'),('CACHY_LLHTTP_REFERENCE','CACHY_LLHTTP_MINIMAL_BUILDER'),('ROOT_LLHTTP_REFERENCE','ROOT_LLHTTP_MINIMAL206_BUILD_ONLY'),('LLHTTP_REFERENCE','LLHTTP_MINIMAL206_BUILD_ONLY'),('cachy-llhttp-reference-','cachy-llhttp-minimal-builder-'),('org.cachy-asahi.llhttp-reference.','org.cachy-asahi.llhttp-minimal-builder.'),('llhttp-reference-native','llhttp-minimal-builder-native'),('llhttp-reference-owned-v2','llhttp-minimal-builder-owned-v1'),('expected349','expected206'),('freshly provisioned349 inventory','freshly provisioned206 BUILD_ONLY inventory')):text=text.replace(before,after)
 return text.encode()

GATE='''
def seed_minimal_public_signatures(cache,inputs,profile):
    import base64
    need(pin(json.dumps(profile['minimal_public_signatures'],indent=2,sort_keys=True).encode()+b'\\n')==profile['minimal_builder']['public_signature_seed'],'whole pinned public signature payload map')
    cache=ordinary(cache);need(cache.is_dir()and cache.stat().st_uid==os.getuid()and stat.S_IMODE(cache.stat().st_mode)==0o700,'exact owned private builder cache')
    rows={r['filename']+'.sig':r for r in inputs['packages']};need(len(rows)==206 and set(rows)==set(profile['minimal_public_signatures']),'complete public206 signature namespace')
    total=0
    for name,row in rows.items():
        need('/'not in name and row['signature_size']<=4096,'finite literal public signature file')
        raw=base64.b64decode(profile['minimal_public_signatures'][name],validate=True);total+=len(raw);need(total<=256*1024 and pin(raw)==dict(bytes=row['signature_size'],sha256=row['signature_sha256']),'exact public signature bytes')
        path=cache/name
        if path.exists()or path.is_symlink():need(pin(read(path,4096))==pin(raw),'existing public signature differs')
        else:
            with path.open('xb')as stream:os.fchmod(stream.fileno(),0o600);stream.write(raw)
    return dict(files=len(rows),bytes=total,authentication='NOT RUN; unchanged ordinary native audit required')

def minimal_inputs(admission,runtime,profile):
    value=admission.get('builder_input_authentication')
    need(type(value)is dict and value==runtime.get('builder_input_authentication'),'separate same whole Root input authentication adoption required')
    need(set(value)=={'issuer','status','accepted','builder_lock','signer_fingerprint','signatures','all_verifiers_naturally_retired','Root_native_authority','current_official_trust_reviewed'},'closed minimal input authentication schema')
    need(value['issuer']=='Root'and value['status']=='ROOT_ADOPTED_MINIMAL_NATIVE_BUILDER_INPUT_AUTHENTICATION_ONLY'and value['accepted']is True,'Root input authentication UNISSUED')
    need(value['builder_lock']==profile['minimal_builder']['builder_lock']and value['signer_fingerprint']==profile['minimal_builder']['signer_fingerprint']and value['Root_native_authority']is None,'exact build-only206 trust/manifest adoption')
    need(value['all_verifiers_naturally_retired']is True and value['current_official_trust_reviewed']is True,'actual verifier retirement and official trust review')
    proof=value['signatures'];need(type(proof)is dict and set(proof)=={'path','bytes','sha256'}and type(proof['path'])is str and proof['path'].startswith('/')and type(proof['bytes'])is int and 0<proof['bytes']<=4*1024**2 and re.fullmatch('[0-9a-f]{64}',proof['sha256']or''),'whole actual207-signature verification transcript pin')
    need(profile['minimal_builder']['package_count']==206 and profile['minimal_builder']['target']=='llhttp'and profile['minimal_builder']['scope']=='BUILD_ONLY','first target llhttp BUILD_ONLY only')
    return value

'''

def once(text,before,after):need(text.count(before)==1,'one exact operation projection seam');return text.replace(before,after,1)

def assemble(old,native,expected,signatures,*,historical=False):
 validate_parent(old);need(pin(native)==NATIVE and pin(expected)==EXPECTED and pin(encoded(signatures))==SIGNATURES,'exact fixed206 operands and public signatures');b={renamed(n):raw for n,raw in old.items()};need(len(b)==len(old),'one-to-one path projection')
 operational={n for n in old if n.startswith(OLD+'owner/')or n.startswith(OB)and('/runtime/'in n or n.endswith(('.py','profile.json','admission.TEMPLATE.json','runtime.TEMPLATE.json')))}|{'.github/workflows/native-arm-llhttp-reference-source.yml'}
 for n in operational:
  if '/recipe/'not in n and not n.endswith(('.tar.gz','recipe-pin.json','reviewed-inputs.json','source-map.json')):b[renamed(n)]=operation_text(old[n])
 # The new fully retrievable206 profile has no inherited private349 seed role.
 # Keep the old helper bytes historical/unused; do not widen its input guard.
 entry=b[NB+'entry.py'].decode();entry=once(entry,"        seed=C.module(HERE/'runtime/scripts/ci/old_four_seed.py','llhttp-reference_seed');seed.seed_current_build_cache(output/'cache',profile['inputs_sha256'])", "        C.need(profile['inputs_sha256']=='629ef92976d17f13443897b0711a54ecb3e404eea4d0d997447407d76a9baf16','exact independent206 public input profile before ordinary complete audit')");b[NB+'entry.py']=entry.encode()
 controller=b[NO+'hosted_owner.py'].decode();controller=once(controller,"k.startswith(('GITHUB_','CACHY_RETAINED_','CACHY_OLD_FOUR_'))","k.startswith('GITHUB_')");b[NO+'hosted_owner.py']=controller.encode()
 workflow_name='.github/workflows/native-arm-llhttp-minimal-builder-source.yml';workflow=b[workflow_name].decode();lines=[]
 for line in workflow.splitlines(True):
  if line.lstrip().startswith(('CACHY_OLD_FOUR_','CACHY_RETAINED_BUBBLEWRAP_')):continue
  if '--preserve-env='in line:
   line=re.sub(r',CACHY_OLD_FOUR_SCHEMA.*(?= \\)', '',line)
  lines.append(line)
 workflow=''.join(lines);need('secrets.'not in workflow and 'CACHY_OLD_FOUR_'not in workflow and 'CACHY_RETAINED_'not in workflow,'new operation has no old private input environment');b[workflow_name]=workflow.encode()
 b[NB+'runtime/scripts/ci/inputs.lock.json']=native;b[NB+'expected206.lock']=expected
 profile=decode(b[NB+'profile.json']);profile['expected206_sha256']=EXPECTED['sha256'];profile['inputs_sha256']=NATIVE['sha256'];profile['minimal_public_signatures']=signatures;profile['minimal_builder']=dict(public_signature_seed=SIGNATURES,scope='BUILD_ONLY',target='llhttp',package_count=206,builder_lock=BUILDER,native_inputs=NATIVE,expected_inventory=EXPECTED,signer_fingerprint=SIGNER,rootfs_package_count=165,libgit2='BLOCKED_UNTIL_SEPARATE_SIGNED_PROJECT_LLHTTP_PROVIDER')
 for n,row in profile['held_inputs'].items():
  actual=b[NB+n];row.update(pin(actual))
  if n=='expected206.lock':row['source_path']='scripts/port/minimal-native-builder-inputs/expected206.lock'
  if n=='runtime/scripts/ci/inputs.lock.json':row['source_path']='scripts/port/minimal-native-builder-inputs/native-inputs.lock.json'
 b[NB+'profile.json']=encoded(profile)
 for prefix in(NB,NO):
  for name in('admission.TEMPLATE.json','runtime.TEMPLATE.json'):
   d=decode(b[prefix+name]);d['builder_input_authentication']=None;b[prefix+name]=encoded(d)
 contract=b[NB+'contract.py'].decode();contract=once(contract,'def admitted(admission,runtime,source_map,env,profile,now=None):',GATE+'def admitted(admission,runtime,source_map,env,profile,now=None):');contract=once(contract,'    return admission[\'nonce\']',"    minimal_inputs(admission,runtime,profile)\n    return admission['nonce']");b[NB+'contract.py']=contract.encode()
 entry=b[NB+'entry.py'].decode();entry=once(entry,"        native.audit(inputs,output/'cache',output/'bootstrap');image=native.build(inputs,output/'cache',output/'bootstrap',{})","        C.seed_minimal_public_signatures(output/'cache',inputs,profile)\n        native.audit(inputs,output/'cache',output/'bootstrap');image=native.build(inputs,output/'cache',output/'bootstrap',{})");b[NB+'entry.py']=entry.encode()
 data=b[NO+'data.py'].decode();anchor='    return a,r';data=once(data,anchor,"    spec=__import__('importlib.util',fromlist=['']).spec_from_file_location('minimal206_input_gate',root/'held-source'/BASE_PREFIX/'contract.py');gate=__import__('importlib.util',fromlist=['']).module_from_spec(spec);spec.loader.exec_module(gate)\n    gate.minimal_inputs(a,r,profile)\n"+anchor);b[NO+'data.py']=data.encode()
 # All resource values, guards, read-only projections and finite retention rules
 # are inherited. Only operation identifiers and exact206 operands change.
 policy=decode(b[NO+'policy.json']);policy['scope']='BUILD_ONLY';policy['minimal_builder']=profile['minimal_builder'];b[NO+'policy.json']=encoded(policy)
 # Rebind exact held Source subtree after the finite operational projection.
 base={n[len('held-source/'):]:raw for n,raw in b.items()if n.startswith('held-source/')and n!=NB+'source-map.json'}
 oldbase=decode(old[OB+'source-map.json']);b[NB+'source-map.json']=encoded(dict(oldbase,kind='LLHTTP_MINIMAL206_BUILD_ONLY_MINIMAL_HOSTED_SOURCE_MAP_V1',files={n:dict(pin(raw),mode=0o644)for n,raw in sorted(base.items())}))
 base[NEW+'base/source-map.json']=b[NB+'source-map.json'];b[NO+'base-binding.json']=encoded(dict(map=pin(b[NB+'source-map.json']),files=len(base),bytes=sum(map(len,base.values()))))
 # Exact compressed preimages, not a full Source copy or duplicate old maps.
 changed={n:dict(pin=pin(raw),mode=0o644,zlib_base64=base64.b64encode(zlib.compress(raw,9)).decode())for n,raw in old.items()if b.get(renamed(n))!=raw and n not in('source-map.json',OLD+'owner/owner-program.json')}
 changed['source-map.json']=dict(pin=pin(old['source-map.json']),mode=0o644,zlib_base64=base64.b64encode(zlib.compress(old['source-map.json'],9)).decode());changed[OLD+'owner/owner-program.json']=dict(pin=pin(old[OLD+'owner/owner-program.json']),mode=0o644,zlib_base64=base64.b64encode(zlib.compress(old[OLD+'owner/owner-program.json'],9)).decode())
 # The resolver repin changes the intake profile, while all projected operands
 # keep their original pins. Historical replay still emits the original ledger.
 intake_revision,intake_lock=(ORIGINAL_INTAKE_REVISION,ORIGINAL_INTAKE_LOCK)if historical else(INTAKE_REVISION,INTAKE_LOCK)
 b[MARKER]=encoded(dict(kind='SEPARATE_MINIMAL206_BUILD_ONLY_PROJECTION_V1',parent_map=PARENT_MAP,parent_tree=PARENT_TREE,parent_files=95,parent_bytes=1318237,intake_revision=intake_revision,intake_lock=intake_lock,builder_lock=BUILDER,native_inputs=NATIVE,expected_inventory=EXPECTED,public_signature_seed=SIGNATURES,prerequisite_proofs=PROOFS,changed=changed,renames={n:renamed(n)for n in old if renamed(n)!=n},actual=None,Root_selection=None,native=None,scope='BUILD_ONLY'))
 b.pop('source-map.json');b.pop(NO+'owner-program.json');b[NO+'owner-program.json']=encoded(dict(schema=1,base_source_map_sha256=pin(b[NB+'source-map.json'])['sha256'],files={n:dict(pin(raw),mode=0o644)for n,raw in sorted(b.items())if not n.startswith('held-source/')}))
 d=decode(old['source-map.json']);b['source-map.json']=encoded(dict(d,kind='LLHTTP_MINIMAL206_BUILD_ONLY_OWNED_HOSTED_SOURCE_V2',files={n:dict(pin(raw),mode=0o644)for n,raw in sorted(b.items())}))
 need(len(b)==96 and sum(map(len,b.values()))<2*1024**2,'unchanged96-leaf/2MiB Source cap');return b

def inverse(b):
 need(type(b)is dict and len(b)==96 and sum(map(len,b.values()))<2*1024**2,'finite exact96 successor input')
 marker=decode(b[MARKER]);need(marker['parent_map']==PARENT_MAP and marker['parent_tree']==PARENT_TREE and marker['scope']=='BUILD_ONLY','exact original95 inverse binding');need(type(marker['changed'])is dict and 2<=len(marker['changed'])<=95 and type(marker['renames'])is dict and len(marker['renames'])<=95 and all(renamed(k)==v for k,v in marker['renames'].items()),'finite exact preimage/rename ledger');need(sum(r['pin']['bytes']for r in marker['changed'].values())<=1318237,'finite total preimage extent');renames={v:k for k,v in marker['renames'].items()};old={renames.get(n,n):raw for n,raw in b.items()if n!=MARKER}
 for n,r in marker['changed'].items():
  need(set(r)=={'pin','mode','zlib_base64'}and type(r['pin']['bytes'])is int and 0<r['pin']['bytes']<=1318237,'bounded complete preimage row');packed=base64.b64decode(r['zlib_base64'],validate=True);need(len(packed)<=2*1024**2,'bounded compressed preimage');stream=zlib.decompressobj();raw=stream.decompress(packed,2*1024**2+1);need(stream.eof and not stream.unused_data and not stream.unconsumed_tail and pin(raw)==r['pin']and r['mode']==0o644,'complete exact bounded inverse preimage');old[n]=raw
 historical=marker['intake_revision']==ORIGINAL_INTAKE_REVISION
 validate_parent(old);need(b==assemble(old,b[NB+'runtime/scripts/ci/inputs.lock.json'],b[NB+'expected206.lock'],decode(b[NB+'profile.json'])['minimal_public_signatures'],historical=historical),'whole canonical minimal206 successor/inverse');return old

def construct(parent,intake_root,package_proof,acquisition_proof,output,*,historical=False):
 parent,intake_root,output=map(ordinary,(parent,intake_root,output));need(not output.exists()and not output.is_relative_to(parent)and not parent.is_relative_to(output)and not output.is_relative_to(intake_root),'fresh disjoint output')
 old=parent_bodies(parent);native,expected,proofs,signatures=intake(intake_root,package_proof,acquisition_proof);b=assemble(old,native,expected,signatures,historical=historical);need(inverse(b)==old,'full95 byte/mode inverse');output.mkdir(mode=0o700)
 for n,raw in b.items():
  p=output/n;p.parent.mkdir(parents=True,exist_ok=True)
  with p.open('xb')as f:f.write(raw)
  p.chmod(0o644)
 spec=importlib.util.spec_from_file_location('minimal206_closed_source_data',output/NO/'data.py');D=importlib.util.module_from_spec(spec);spec.loader.exec_module(D);D.source(output,pin(b['source-map.json'])['sha256'])
 return dict(status='SOURCE_DATA_ONLY_BUILD_ONLY',files=len(b),bytes=sum(map(len,b.values())),tree=tree(b),source_map=pin(b['source-map.json']),policy=pin(b[NO+'policy.json']),program=pin(b[NO+'owner-program.json']),prerequisite_proofs=proofs,actual=decode(b['source-map.json'])['actual'],Root_selection=None,signature_authentication=None,native=None,M2=None)
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for n in('parent','intake-root','package-proof','acquisition-proof','output'):p.add_argument('--'+n,type=Path,required=True)
 a=p.parse_args();print(json.dumps(construct(a.parent,a.intake_root,a.package_proof,a.acquisition_proof,a.output),indent=2,sort_keys=True))
