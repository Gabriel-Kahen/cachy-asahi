#!/usr/bin/python3 -I -B
# SPDX-License-Identifier: MIT
"""Unbound libgit2 v4 successor: exact frozen501/182,512 counters, strict provider."""
import argparse,ast,base64,hashlib,importlib.util,json,math,os,re,stat,zlib
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
PREFIX='scripts/ci/libgit2-reference-native-source/owner/'
BASE='held-source/scripts/ci/libgit2-reference-native-source/base/'
OLD_WF='.github/workflows/native-arm-libgit2-reference-source.yml'
NEW_WF='.github/workflows/native-arm-libgit2-pinned-input-source.yml'
MARKER='libgit2-frozen501-pinned182-v1.json'
LOCK=dict(bytes=328101,sha256='beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f')
CHANGED=tuple(PREFIX+n for n in('hosted_owner.py','payload.py','policy.json','owner-program.json'))+('source-map.json',OLD_WF)

def need(ok,why):
 if not ok:raise ValueError(why)
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def encode(v):return(json.dumps(v,indent=2,sort_keys=True)+'\n').encode()
def read(p,cap=8*1024**2):
 p=Path(p);need(p.is_absolute()and p==p.resolve()and not any(x.is_symlink()for x in(p,*p.parents)),'ordinary absolute source path');s=p.lstat();need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and not s.st_mode&0o022 and 0<s.st_size<=cap,'bounded ordinary source file');b=p.read_bytes();need(len(b)==s.st_size and (s.st_dev,s.st_ino,s.st_mtime_ns,s.st_ctime_ns)==(p.stat().st_dev,p.stat().st_ino,p.stat().st_mtime_ns,p.stat().st_ctime_ns),'stable whole source');return b

def load(p,name):
 spec=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
A=load(HERE/'adapter.py','libgit2_carrier_namespace_adapter')

def predecessor():
 rows=json.loads(read(HERE/'profile.DATA.json'))['libgit2_family'];root=ROOT/'scripts/ci/libgit2-reference-native-source';found={p.relative_to(root).as_posix()for p in root.rglob('*')if p.is_file()or p.is_symlink()};need(found==set(rows),'complete immutable libgit2 preparation family')
 for n,r in rows.items():need(dict(pin(read(root/n)),mode=stat.S_IMODE((root/n).stat().st_mode))==r,'whole predecessor helper '+n)
 return load(root/'successor_v4/prepare.py','libgit2_exact_v4_predecessor')

def input_check(raw):
 need(pin(raw)==LOCK,'actual frozen501 lock must equal beca39 before any carrier assumption');d=json.loads(raw);rows={}
 for r in [*d['keyring_files'],d['rootfs'],*d['packages']]:
  need(r['filename']not in rows,'unique frozen input');rows[r['filename']]=dict(bytes=r['size'],sha256=r['sha256'])
  if 'signature_size'in r:need(r['filename']+'.sig'not in rows,'unique frozen signature');rows[r['filename']+'.sig']=dict(bytes=r['signature_size'],sha256=r['signature_sha256'])
 expected=json.loads(A.frozen('expected-files.json'));need(len(rows)==501 and expected['input_lock_sha256']==LOCK['sha256']and expected['all501_required']is True and len(expected['files'])==182,'exact501/182 contract')
 for n,r in expected['files'].items():need(n.startswith('packages/')and r['mode']==0o644 and rows.get(n.removeprefix('packages/'))=={k:r[k]for k in('bytes','sha256')},'every182 input matches actual501 without substitution')
 need(sum(r['bytes']for r in expected['files'].values())==544634853,'exact missing182 byte count');return d

def cadence(text):
 seams=[]
 def change(before,after):
  nonlocal text
  need(text.count(before)==1,'one exact cadence/control seam');text=text.replace(before,after);seams.append(dict(before=before,after=after))
 node=next(n for n in ast.walk(ast.parse(text))if isinstance(n,ast.FunctionDef)and n.name=='start');old=ast.get_source_segment(text,node);need(old.count('time.sleep(.1)')==1,'one service-start poll delay');change(old,old.replace('time.sleep(.1)',"time.sleep(min(1,max(0,until-time.monotonic())))"))
 change('            time.sleep(.2)',"            time.sleep(min(10,max(0,owner.end-time.monotonic())))")
 return text,seams

def controller_projection(raw):
 text=raw.decode();seams=[]
 def change(before,after):
  nonlocal text
  need(text.count(before)==1,'one controller carrier/retention seam');text=text.replace(before,after);seams.append(dict(before=before,after=after))
 anchor="s=importlib.util.spec_from_file_location('libgit2_source_readonly_v4',HERE/'source_readonly.py');Q=importlib.util.module_from_spec(s);s.loader.exec_module(Q)"
 change(anchor,anchor+"\ns=importlib.util.spec_from_file_location('libgit2_exact182_carrier',HERE/'native349_carrier.py');N=importlib.util.module_from_spec(s);s.loader.exec_module(N)\ns=importlib.util.spec_from_file_location('libgit2_finite_public_retention',HERE/'public_evidence.py');E=importlib.util.module_from_spec(s);s.loader.exec_module(E)")
 change("    for name in ('root','output'):parser.add_argument('--'+name,type=Path,required=True)","    for name in ('root','output','carrier-root'):parser.add_argument('--'+name,type=Path,required=True)")
 anchor="        daemon,available,disk=owner.setup();volume=a.output/'volume';work=volume/'work';marker=work/'actual-owner.json'"
 change(anchor,anchor+"\n        report['pinned_input_carrier']=N.stage(a.carrier_root,work/'native349-pinned-inputs',a.runner_uid,a.runner_gid)")
 change("                    marker=str(marker),output=str(work/'libgit2-reference-native'))","                    marker=str(marker),output=str(work/'libgit2-reference-native'),pinned_inputs=str(work/'native349-pinned-inputs'))")
 start=text.index('        # Copy only original finite public evidence, never cache/keyring/config or Docker data.');stop=text.index("        report.update(status='PAIR_PASSED_PENDING_EXTERNAL_CLEANUP'",start);change(text[start:stop],'        # Strict finite public receipts are copied in finally before cleanup.\n')
 anchor="    finally:\n        report['host_preflight']=owner.host_facts"
 change(anchor,"    finally:\n        E.preserve(report,a.output/'volume/work/libgit2-reference-native',a.output/'evidence',\n                   dict(source=actual['source'],ref=actual['ref'],source_map_sha256=a.source_map_sha256,run=os.environ['GITHUB_RUN_ID'],attempt=1,job=os.environ['GITHUB_JOB'],nonce=actual['nonce']),a.runner_uid)\n        report['host_preflight']=owner.host_facts")
 text,extra=cadence(text);seams.extend(extra)
 restored=text
 for r in reversed(seams):need(restored.count(r['after'])==1,'one exact controller inverse');restored=restored.replace(r['after'],r['before'])
 need(restored.encode()==raw,'whole previous controller inverse');return text.encode(),seams

def payload_projection(raw):
 text=raw.decode();seams=[]
 def change(before,after):
  nonlocal text
  need(text.count(before)==1,'one exact carrier payload seam');text=text.replace(before,after);seams.append(dict(before=before,after=after))
 anchor="s = importlib.util.spec_from_file_location('libgit2_payload_diagnostic_v3',HERE/'payload_diagnostic.py');X=importlib.util.module_from_spec(s);s.loader.exec_module(X)"
 change(anchor,anchor+"\ns = importlib.util.spec_from_file_location('libgit2_exact182_carrier',HERE/'native349_carrier.py');N=importlib.util.module_from_spec(s);s.loader.exec_module(N)")
 change("    namespace = dict(__name__='libgit2-reference_v2_held_entry',__file__=str(entry_path))","    namespace = dict(__name__='libgit2-reference_v2_held_entry',__file__=str(entry_path),PINNED_CARRIER=N,PINNED_INPUTS=Path(config['pinned_inputs']))")
 change("    exec(compile(D.projected_entry(D.read(entry_path)),str(entry_path),'exec'),namespace)","    exec(compile(N.project_entry(D.projected_entry(D.read(entry_path))),str(entry_path),'exec'),namespace)")
 restored=text
 for r in reversed(seams):restored=restored.replace(r['after'],r['before'])
 need(restored.encode()==raw,'whole previous payload inverse');return text.encode(),seams

def workflow(raw):
 need(pin(raw)==json.loads(read(HERE/'profile.DATA.json'))['libgit2_workflow'],'whole frozen libgit2 workflow');text=raw.decode();carrier_raw=read(HERE/'frozen/carrier-workflow.yml.in');need(pin(carrier_raw)==json.loads(read(HERE/'profile.DATA.json'))['carrier_whole_pins']['workflow.yml.in'],'whole29c2 canonical fetch workflow');carrier_workflow=carrier_raw.decode();start=carrier_workflow.index('      - name: Root-admitted exact private');stop=carrier_workflow.index('      - name: Admitted existing-host',start);step=carrier_workflow[start:stop].replace('llhttp-reference-native-source','libgit2-reference-native-source').replace('ROOT_LLHTTP_REFERENCE','ROOT_LIBGIT2_REFERENCE')
 anchor='      - name: Admitted existing-host XZ-only libgit2 reference pair';need(text.count(anchor)==1,'one new private-fetch step');text=text.replace(anchor,step+anchor);anchor='            --runner-uid "$(id -u)" --runner-gid "$(id -g)" \\\n';need(text.count(anchor)==1,'one carrier argument seam');text=text.replace(anchor,'            --carrier-root "$RUNNER_TEMP/native349-carrier-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT/public" \\\n'+anchor)
 text=text.replace('name: native-arm-libgit2-reference-source\n','name: native-arm-libgit2-pinned-input-source\n',1);need(text.count('CACHY_NATIVE349_INPUTS_SSH_PRIVATE_KEY:')==1,'secret only in new fetch step');return text.encode()

def validate_parent(bodies,parent_map):
 P4=predecessor();need(re.fullmatch('[0-9a-f]{64}',parent_map or '')and pin(bodies['source-map.json'])['sha256']==parent_map,'externally pinned genuine libgit2v4 parent map');d=json.loads(bodies['source-map.json']);need(d['kind']=='LIBGIT2_REFERENCE_OWNED_HOSTED_SOURCE_V2'and set(bodies)==set(d['files'])|{'source-map.json'}and 32<len(bodies)<512 and sum(map(len,bodies.values()))<128*1024**2 and all(x is None for x in d['actual'].values()),'complete unissued libgit2 parent')
 for n,r in d['files'].items():need(dict(pin(bodies[n]),mode=0o644)==r,'whole parent byte/mode '+n)
 P4.inverse(bodies);input_check(bodies[BASE+'runtime/scripts/ci/inputs.lock.json']);need(json.loads(bodies[BASE+'profile.json'])['inputs_sha256']==LOCK['sha256'],'same frozen501 profile')
 return P4,d

def assemble(old,parent_map,binding=None):
 P4,d=validate_parent(old,parent_map);b=dict(old);seams={};b[PREFIX+'hosted_owner.py'],seams['controller']=controller_projection(old[PREFIX+'hosted_owner.py']);b[PREFIX+'payload.py'],seams['payload']=payload_projection(old[PREFIX+'payload.py'])
 b[PREFIX+'native349_carrier.py']=A.runtime(binding);b[PREFIX+'public_evidence.py']=A.public_runtime();b[NEW_WF]=workflow(old[OLD_WF]);b.pop(OLD_WF)
 policy=json.loads(old[PREFIX+'policy.json']);policy['pinned_input_carrier']=dict(input_lock=LOCK,files=182,bytes=544634853,all501_required=True,canonical_GPG_required=True,binding=json.loads(A.frozen('binding.TEMPLATE.json'))if binding is None else binding,Root_registration=None,fetch_seconds=180,fetch_commands_max=24,staging_bytes=2*544634853+64*1024**2,old_resources_unchanged=True)
 policy['command_ledger']=dict(inner_limit=512,inner_normal_max=282,inner_failure_cleanup_max=302,outer_limit=512,outer_lifetime_max=373,startup_seconds=1,status_seconds=10,deadlines_resources_unchanged=True,actual=None)
 E={};exec(compile(A.public_runtime(),'<libgit2 fixed public export>','exec'),E);policy['inner_public_retention']=E['DECLARATION'];b[PREFIX+'policy.json']=encode(policy)
 b[MARKER]=encode(dict(kind='LIBGIT2_FROZEN501_PRIVATE182_SOURCE_V1',parent_map=pin(old['source-map.json']),parent_tree=P4.tree(old),parent_files=len(old),parent_bytes=sum(map(len,old.values())),before={n:dict(pin=pin(old[n]),mode=0o644,zlib_base64=base64.b64encode(zlib.compress(old[n],9)).decode())for n in CHANGED},seams=seams,binding=policy['pinned_input_carrier']['binding'],carrier_source='29c2ab22f047f3639c35f5fcceeaf4e6000b3302',actual_provider=None,actual_carrier=None,Root_registration=None,Root_roles=None,native=None))
 b.pop('source-map.json');b.pop(PREFIX+'owner-program.json');b[PREFIX+'owner-program.json']=P4.P3.P2.program(b,json.loads(old[PREFIX+'owner-program.json'])['base_source_map_sha256']);b['source-map.json']=encode(dict(d,files={n:dict(pin(raw),mode=0o644)for n,raw in sorted(b.items())}));need(len(b)<512 and sum(map(len,b.values()))<128*1024**2,'unchanged libgit2 Source limits');return b

def inverse(b,parent_map=None):
 need(len(b)<512 and sum(map(len,b.values()))<128*1024**2,'finite full successor');m=json.loads(b[MARKER]);need(set(m['before'])==set(CHANGED),'complete previous libgit2 preimages');old={n:raw for n,raw in b.items()if n not in(MARKER,NEW_WF,PREFIX+'native349_carrier.py',PREFIX+'public_evidence.py')}
 for n,r in m['before'].items():
  packed=base64.b64decode(r['zlib_base64'],validate=True);s=zlib.decompressobj();raw=s.decompress(packed,8*1024**2+1);need(s.eof and not s.unconsumed_tail and not s.unused_data and pin(raw)==r['pin']and r['mode']==0o644,'exact bounded previous preimage');old[n]=raw
 expected=parent_map or m['parent_map']['sha256'];validate_parent(old,expected);need(b==assemble(old,expected,m['binding']),'whole canonical libgit2 successor/full predecessor inverse');return old

def provider_check(parent,bodies):
 need(BASE+'project-test.json'in bodies,'genuine accepted/signed llhttp dependency tuple UNISSUED')
 binding=json.loads(bodies[BASE+'project-test.json']);T=load(parent/BASE/'project_test.py','libgit2_required_actual_provider');paths={key:parent/BASE/('dependency-evidence'if key=='native_receipt'else'project-test')/binding['paths'][key]for key in T.KEYS}
 value=T.validate_compatible_tuple(paths,binding['expected'],consumer_root=parent/BASE/'consumer-v1')
 need(value['tuple_sha256']==binding['project_test_tuple_sha256']and value['pins']['root_receipt']['sha256']==binding['project_test_root_receipt_sha256'],'exact actual Root-accepted TEST-signed provider context')
 return value

def construct(parent,parent_map,out,carrier_binding=None):
 need(parent is not None and parent_map is not None,'genuine Root-accepted TEST-signed llhttp provider parent remains UNISSUED; no default Source')
 parent=Path(parent);out=Path(out);need(parent.is_absolute()and parent==parent.resolve()and out.is_absolute()and out==out.resolve()and not out.exists()and not out.is_relative_to(parent)and not parent.is_relative_to(out),'fresh disjoint source output')
 raw=read(parent/'source-map.json');need(pin(raw)['sha256']==parent_map,'whole actual parent map before body reads');d=json.loads(raw);need(32<len(d['files'])<512 and sum(r['bytes']for r in d['files'].values())<128*1024**2,'finite genuine parent')
 found={p.relative_to(parent).as_posix()for p in parent.rglob('*')if p.is_file()or p.is_symlink()};need(found==set(d['files'])|{'source-map.json'},'complete genuine provider parent namespace');old={n:read(parent/n)for n in found};need(all(stat.S_IMODE((parent/n).stat().st_mode)==0o644 for n in found),'whole genuine parent modes');provider_check(parent,old)
 if carrier_binding is not None:A.module(carrier_binding).binding()
 b=assemble(old,parent_map,carrier_binding);need(inverse(b,parent_map)==old,'whole predecessor inverse');out.mkdir(mode=0o700)
 for n,body in b.items():
  p=out/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(body);p.chmod(0o644)
 D=load(out/PREFIX/'data.py','libgit2_new_closed_data');D.source(out,pin(b['source-map.json'])['sha256']);return dict(files=len(b),bytes=sum(map(len,b.values())),tree=predecessor().tree(b),source_map=pin(b['source-map.json']),actual_provider=None,actual_carrier=None,Root_registration=None,native=None)
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--parent',type=Path);p.add_argument('--parent-map-sha256');p.add_argument('--output',type=Path,required=True);p.add_argument('--carrier-binding',type=Path);p.add_argument('--carrier-binding-sha256');a=p.parse_args();binding=None
 if a.carrier_binding is not None:raw=read(a.carrier_binding);need(pin(raw)['sha256']==a.carrier_binding_sha256,'whole externally selected public carrier binding');binding=json.loads(raw)
 else:need(a.carrier_binding_sha256 is None,'no unpaired carrier selection')
 print(json.dumps(construct(a.parent,a.parent_map_sha256,a.output,binding),indent=2,sort_keys=True))
