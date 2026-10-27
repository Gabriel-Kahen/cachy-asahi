# SPDX-License-Identifier: MIT
"""Reproduce the bounded GUI observer progress forwarding source."""
import argparse,ast,hashlib,json,os,stat
from pathlib import Path
HERE=Path(__file__).resolve().parent
PROFILE={'bytes': 842626, 'sha256': '2e5b6d7ac80a56ddae36a89151f73ff0fc61f0cd650c22c5b0e3253aefe013e7'}

def need(ok, message):
    if not ok:
        raise ValueError(message)

def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()

def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())

def ordinary(value):
    raw = os.fspath(value)
    need(type(raw) is str and os.path.isabs(raw) and raw == os.path.normpath(raw),
         'absolute normalized path required')
    path = Path(raw)
    need(path == path.resolve(), 'canonical resolved path required')
    need(not any(p.is_symlink() for p in (path, *path.parents)), 'ordinary nonalias ancestry')
    return path

def identity(info):
    # Reading a file/directory may update atime; it is never identity evidence.
    return tuple(getattr(info, key) for key in (
        'st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
        'st_size', 'st_mtime_ns', 'st_ctime_ns'))

def read_state(value):
    path = ordinary(value)
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
             0 <= before.st_size <= 8 * 1024**2, 'bounded ordinary single-link source file')
        parts, size = [], 0
        while part := os.read(fd, 1024**2):
            parts.append(part)
            size += len(part)
            need(size <= before.st_size, 'source file grew during read')
        need(size == before.st_size and identity(before) == identity(os.fstat(fd)) ==
             identity(path.lstat()), 'whole stable descriptor and path identity')
        return b''.join(parts), identity(before)
    finally:
        os.close(fd)

def read(path):
    return read_state(path)[0]

def scan(value):
    root = ordinary(value)
    need(root.is_dir(), 'ordinary source root required')
    files, state, directories = {}, {}, {}
    for path in (root, *sorted(root.rglob('*'))):
        info = path.lstat()
        need(not path.is_symlink(), 'source alias refused')
        name = path.relative_to(root).as_posix() if path != root else ''
        if stat.S_ISDIR(info.st_mode):
            directories[name] = (identity(info), tuple(sorted(p.name for p in path.iterdir())))
        else:
            raw, record = read_state(path)
            files[name], state[name] = raw, record
    required = {''}
    for name in files:
        required.update('' if str(p) == '.' else p.as_posix() for p in Path(name).parents)
    need(set(directories) == required, 'closed source directory membership, no foreign empty dirs')
    for name, (record, names) in directories.items():
        path = root / name
        need(identity(path.lstat()) == record and
             tuple(sorted(p.name for p in path.iterdir())) == names, 'stable whole source namespace')
    return files, dict(files=state, directories=directories)

def tree(root):
    return scan(root)[0]

def paths(source, output):
    source, output = ordinary(source), ordinary(output)
    need(output.parent.is_dir() and not os.path.lexists(output), 'fresh output required')
    need(not any('native-actual' in p.name for p in (output, *output.parents)),
         'native actual roots are not source-factory destinations')
    for protected in (source, HERE):
        need(not output.is_relative_to(protected) and not protected.is_relative_to(output),
             'disjoint supplied source/factory/output paths')
    return source, output


D=HERE
enc=encoded
def edit(raw,a,b,count=1):
 a=a.encode();b=b.encode();need(raw.count(a)==count,'exact source seam '+a.decode()[:70]);v=raw.replace(a,b);need(v.count(b)==count and v.replace(b,a)==raw,'whole source seam inverse');return v

def assignment(raw,name,value):
 text=raw.decode();nodes=[n for n in ast.parse(raw).body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id==name for t in n.targets)];need(len(nodes)==1,'one fixed top-level assignment');n=nodes[0];lines=text.splitlines(keepends=True);start=sum(len(x.encode())for x in lines[:n.lineno-1])+n.col_offset;end=sum(len(x.encode())for x in lines[:n.end_lineno-1])+n.end_col_offset;need(raw[start:end].decode()==ast.get_source_segment(text,n),'exact AST source extent');return raw[:start]+value.encode()+raw[end:]

def transform(before,mode,policy,*,draft=False):
 out=dict(before);seams={}
 def change(name,a,b):out[name]=edit(out[name],a,b);seams.setdefault(name,[]).append(dict(before=a,after=b,count=1))
 n='implementation/observer_apply.py'
 change(n,read(D/'root-directory-before.py.txt').decode(),read(D/'root-directory-after.py.txt').decode())
 change(n,'def apply(out):',read(D/'forward-renderer.py.txt').decode()+'def apply(out):')
 a="guest.write_bytes(edited(guest.read_bytes(),[(\"logs,'installed606-preserved',timeout=600)\",\"logs,'installed606-preserved',timeout=1210)\")]))"
 b="guest.write_bytes(edited(edited(guest.read_bytes(),[(\"logs,'installed606-preserved',timeout=600)\",\"logs,'installed606-preserved',timeout=1210)\")]),forwarding_rows()))"
 change(n,a,b)
 change('implementation/test_observer.py',"if __name__=='__main__':",read(D/'test-progress-methods.py.txt').decode()+"\nif __name__=='__main__':")
 raw=enc(policy);out['implementation/runner-context-policy.json']=raw
 old=next(ast.get_source_segment(before['implementation/runner_context.py'].decode(),x)for x in ast.parse(before['implementation/runner_context.py']).body if isinstance(x,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='POLICY_SHA'for t in x.targets))
 change('implementation/runner_context.py',old,'POLICY_SHA='+repr(pin(raw)['sha256']))
 root=json.loads(before['implementation/build-inventory-parent.json']);guard=before['implementation/build_inventory_guard.py'];guard_seams=[]
 def guard_change(a,b):
  nonlocal guard
  guard=edit(guard,a,b);guard_seams.append(dict(before=a,after=b,count=1))
 guard_change('def verify(require_known=False):','PROGRESS_PINS='+repr(json.loads(read(D/'parent-pins.json')))+'\n'+read(D/'progress-guard.py.txt').decode()+'def verify(require_known=False):')
 guard_change(" raw=G.read(HERE/'build_inventory_guard.py');needle=", " raw=G.read(HERE/'build_inventory_guard.py')\n if 'observer_progress'in G.obj(HERE/'build-inventory-parent.json'):return progress_verify(raw,require_known)\n needle=")
 # The two original inverse chains remain unchanged inside the before source.
 root['observer_progress']=dict(schema=1,variant=mode,source='0bb0c9c3ff62b85227127ea82dbf05f5f56ebee1'if mode=='known'else None,ref='codex/latest607-gui-descriptor-query-v1'if mode=='known'else None,actual=None,files={n:pin(b)for n,b in before.items()},seams=seams,guard_seams=guard_seams,policy_before=json.loads(before['implementation/runner-context-policy.json']),annotation_before=ast.literal_eval(next(x.value for x in ast.parse(before['implementation/observer_apply.py']).body if isinstance(x,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='ANNOTATION'for t in x.targets))))
 out['implementation/build-inventory-parent.json']=enc(root)
 guard=assignment(guard,'PRODUCTS','PRODUCTS='+repr({n:pin(b)for n,b in out.items()if n not in('implementation/build_inventory_guard.py','source-manifest.json')}));guard=assignment(guard,'SELF_SHA',"SELF_SHA='@SELF@'");guard=assignment(guard,'SELF_SHA','SELF_SHA='+repr(pin(guard)['sha256']));out['implementation/build_inventory_guard.py']=guard
 manifest=json.loads(before['source-manifest.json']);manifest['files']={n:pin(b)for n,b in out.items()if n!='source-manifest.json'};out['source-manifest.json']=enc(manifest)
 changed={n for n in before if before[n]!=out[n]};need(set(out)==set(before)and len(out)==692 and len(changed)<=7,'same692 bounded progress child')
 return payload_transform(out,mode,json.loads(read(D/'payload-generated-policy.json'))),root['observer_progress']

def payload_inverse(values):
 """Pure DATA reconstruction of every immediate6e86 source byte."""
 out=dict(values);root=json.loads(out['implementation/build-inventory-parent.json']);p=root.pop('payload_progress');before=p['files']
 need(p['schema']==1 and p['actual']is None and p['variant']in('known','null') and len(before)==len(out)==692 and set(before)==set(out),'whole692 immediate package-progress context')
 need((p['source'],p['ref'])==(('6e86e6e14f29bbeff2f4e8733915dd43a244a588','codex/latest607-gui-root-traversal-v1')if p['variant']=='known'else(None,None)),'exact genuine6e86 predecessor or disabled variant')
 def inverse(raw,rows):
  for row in reversed(rows):
   a=row['before'].encode();b=row['after'].encode();need(raw.count(b)==row['count'],'exact counted package-progress source inverse');raw=raw.replace(b,a)
  return raw
 for name,rows in p['seams'].items():out[name]=inverse(out[name],rows)
 out['implementation/build-inventory-parent.json']=enc(root);out['implementation/runner-context-policy.json']=enc(p['policy_before']);guard=out['implementation/build_inventory_guard.py']
 guard=assignment(guard,'PRODUCTS','PRODUCTS='+repr({n:w for n,w in before.items()if n not in('implementation/build_inventory_guard.py','source-manifest.json')}));guard=assignment(guard,'SELF_SHA',"SELF_SHA='@SELF@'");guard=inverse(guard,p['guard_seams']);guard=assignment(guard,'SELF_SHA','SELF_SHA='+repr(pin(guard)['sha256']));out['implementation/build_inventory_guard.py']=guard
 manifest=json.loads(out['source-manifest.json']);manifest['files']={n:w for n,w in before.items()if n!='source-manifest.json'};out['source-manifest.json']=enc(manifest);need({n:pin(b)for n,b in out.items()}==before,'ENTIRE immediate6e86 source before inverse');return out

def payload_transform(before,mode,policy):
 pins=json.loads(read(D/'payload-parent-pins.json'));need(mode in('known','null')and len(before)==692 and pin(enc({n:pin(b)for n,b in before.items()}))==pins[mode],'entire genuine6e86/NULL before692');out=dict(before);seams={}
 def change(name,a,b):out[name]=edit(out[name],a,b);seams.setdefault(name,[]).append(dict(before=a,after=b,count=1))
 raw=before['implementation/observer_apply.py'];node=next(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)and n.name=='observer_rows');original=ast.get_source_segment(raw.decode(),node);need(original.count(' return [')==1,'one original observer row factory')
 current=original.replace(' return [',' rows=[',1)+'\n'+read(D/'payload-observer-rows-footer.py.txt').decode().rstrip()
 change('implementation/observer_apply.py',original,"PAYLOAD_BODY607=r'''"+read(D/'payload-body.py.txt').decode()+"'''\n"+current)
 change('implementation/observer_apply.py','types.FunctionType(observe.__code__,namespace,observe.__name__,observe.__defaults__,observe.__closure__)','types.FunctionType((_payload_observe607.__code__ if observe is _payload_original607 else observe.__code__),namespace,observe.__name__,observe.__defaults__,observe.__closure__)')
 change('implementation/test_observer.py',"if __name__=='__main__':",read(D/'payload-source-tests.py.txt').decode()+"if __name__=='__main__':")
 out['implementation/runner-context-policy.json']=enc(policy);raw=before['implementation/runner_context.py'];node=next(n for n in ast.parse(raw).body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='POLICY_SHA'for t in n.targets));change('implementation/runner_context.py',ast.get_source_segment(raw.decode(),node),'POLICY_SHA='+repr(pin(enc(policy))['sha256']))
 guard=before['implementation/build_inventory_guard.py'];guard_seams=[]
 def guard_change(a,b):
  nonlocal guard
  guard=edit(guard,a,b);guard_seams.append(dict(before=a,after=b,count=1))
 guard_change('def verify(require_known=False):','PROGRESS607_PINS='+repr(pins)+'\n'+read(D/'payload-progress-guard.py.txt').decode()+'def verify(require_known=False):')
 a=" raw=G.read(HERE/'build_inventory_guard.py')";guard_change(a,a+"\n if 'payload_progress'in G.obj(HERE/'build-inventory-parent.json'):return payload_progress_verify(raw,require_known)")
 root=json.loads(before['implementation/build-inventory-parent.json']);annotation=ast.literal_eval(next(n.value for n in ast.parse(before['implementation/observer_apply.py']).body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='ANNOTATION'for t in n.targets)))
 root['payload_progress']=dict(schema=1,variant=mode,source='6e86e6e14f29bbeff2f4e8733915dd43a244a588'if mode=='known'else None,ref='codex/latest607-gui-root-traversal-v1'if mode=='known'else None,actual=None,files={n:pin(b)for n,b in before.items()},seams=seams,guard_seams=guard_seams,policy_before=json.loads(before['implementation/runner-context-policy.json']),annotation_before=annotation);out['implementation/build-inventory-parent.json']=enc(root)
 guard=assignment(guard,'PRODUCTS','PRODUCTS='+repr({n:pin(b)for n,b in out.items()if n not in('implementation/build_inventory_guard.py','source-manifest.json')}));guard=assignment(guard,'SELF_SHA',"SELF_SHA='@SELF@'");guard=assignment(guard,'SELF_SHA','SELF_SHA='+repr(pin(guard)['sha256']));out['implementation/build_inventory_guard.py']=guard
 manifest=json.loads(before['source-manifest.json']);manifest['files']={n:pin(b)for n,b in out.items()if n!='source-manifest.json'};out['source-manifest.json']=enc(manifest);need(set(out)==set(before)and len(out)==692 and sum(out[n]!=before[n]for n in before)==7,'same692 only seven changed members');need(payload_inverse(out)==before,'complete immediate6e86 source byte inverse');return out

def reserved_transform(before,mode,p):
 policy=json.loads(read(D/'reserved-generated-policy.json'));draft=False
 q={mode:p['payload_result']['files']};need(mode=='known'and{n:pin(b)for n,b in before.items()}==q[mode],'whole exact public3f859 or NULL source');out=dict(before);seams={}
 def change(name,a,b):out[name]=edit(out[name],a,b);seams.setdefault(name,[]).append(dict(before=a,after=b,count=1))
 operand=read(D/'reserved-recheck-runtime.py.txt').decode()+'\n'+read(D/'reserved-runtime-profile.py.txt').decode()
 n='implementation/observer_apply.py';a="m=types.ModuleType('_fixed_lexical_observer_factory');vars(m).update(space);return m\n";change(n,a,a+'\n'+operand)
 n='implementation/runner_context.py'
 change(n,"proof['service_validation_profile']==V.annotation()and C.read(Path(runner)/'service-vm-profile.json')==V.enc(V.SPEC)","proof['service_validation_profile']==O.reservation_annotation()and C.read(Path(runner)/'service-vm-profile.json')==O.enc(O.reservation_spec())")
 wrapper="def _reserved_run607(*args,**kwargs):\n return F.load('_reserved607_actual_owner',Path(__file__).resolve().parents[1]/'observer_apply.py').reserved_owner(globals(),*args,**kwargs)\n\n"
 change(n,'def owner(original):',wrapper+'def owner(original):');change(n,'fn=original.run_service1800;',"fn=_reserved_run607;")
 n='implementation/test_observer.py'
 for a,b in(("fact['service_seconds'],1800","fact['service_seconds'],3460"),('TimeoutStartSec=1800','TimeoutStartSec=3460'),('time.monotonic() + 1900','time.monotonic() + 3560'),('ITIMER_REAL, 2350','ITIMER_REAL, 4010'),("['owner_wait_seconds'],2800","['owner_wait_seconds'],4460"),("({'_ObserverStageForward'}if current else set())","({'_ObserverStageForward','_RecheckForward607','_ObserverAndRecheck607'}if current else set())"),("self.assertIs(m._payload_observe607.__globals__,vars(m));self.assertEqual(len(notes),1214)","self.assertIs(m._payload_observe607.__globals__,vars(m));self.assertEqual(len([r for r in notes if r.startswith(b'INSTALLED607_RECHECK_DATA ')]),7);notes=[r for r in notes if r.startswith(b'INSTALLED607_PAYLOAD_DATA ')];self.assertEqual(len(notes),1214)"),('old=ast.parse(O.edited(raw,O.observer_rows()))','old=ast.parse(O.unrecheck_installed607(O.edited(raw,O.observer_rows())))')):change(n,a,b)
 change(n,"if __name__=='__main__':",read(D/'reserved-recheck-tests.py.txt').decode()+'\n'+read(D/'reserved-reservation-tests.py.txt').decode()+"\nif __name__=='__main__':")
 change('implementation/test_runner_context.py',"self.assertRaisesRegex(ValueError,'ready source-owned606')","self.assertRaisesRegex(ValueError,'selected owner requires whole source-sealed1800 runner')")
 out['implementation/runner-context-policy.json']=enc(policy)
 raw=out['implementation/runner_context.py'];node=next(n for n in ast.parse(raw).body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='POLICY_SHA'for t in n.targets));change('implementation/runner_context.py',ast.get_source_segment(raw.decode(),node),'POLICY_SHA='+repr(pin(enc(policy))['sha256']))
 guard=before['implementation/build_inventory_guard.py'];guard_seams=[]
 def guard_change(a,b):
  nonlocal guard
  guard=edit(guard,a,b);guard_seams.append(dict(before=a,after=b,count=1))
 guard_change('def verify(require_known=False):','RESERVED607_PINS='+repr(json.loads(read(D/'reserved-parent-pins.json')))+'\n'+read(D/'reserved-guard.py.txt').decode()+'def verify(require_known=False):')
 a=" raw=G.read(HERE/'build_inventory_guard.py')";guard_change(a,a+"\n if 'reserved_recheck'in G.obj(HERE/'build-inventory-parent.json'):return reserved_recheck_verify(raw,require_known)")
 raw=read(D/'reserved-runtime-profile.py.txt');spec=ast.literal_eval(next(n.value for n in ast.parse(raw).body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='RESERVATION607'for t in n.targets)))
 root=json.loads(before['implementation/build-inventory-parent.json']);root['reserved_recheck']=dict(schema=1,variant=mode,source='3f8594cbbed6e8f9c774c00d540427a8f914c4c3'if mode=='known'else None,ref='codex/latest607-gui-payload-progress-v1'if mode=='known'else None,actual=None,files=q[mode],seams=seams,guard_seams=guard_seams,policy_before=json.loads(before['implementation/runner-context-policy.json']),reservation=spec);out['implementation/build-inventory-parent.json']=enc(root)
 guard=assignment(guard,'PRODUCTS','PRODUCTS='+repr({n:pin(b)for n,b in out.items()if n not in('implementation/build_inventory_guard.py','source-manifest.json')}));guard=assignment(guard,'SELF_SHA',"SELF_SHA='@SELF@'");guard=assignment(guard,'SELF_SHA','SELF_SHA='+repr(pin(guard)['sha256']));out['implementation/build_inventory_guard.py']=guard
 manifest=json.loads(before['source-manifest.json']);manifest['files']={n:pin(b)for n,b in out.items()if n!='source-manifest.json'};out['source-manifest.json']=enc(manifest);need(set(out)==set(before)and len(out)==692 and (sum(out[n]!=before[n]for n in before)<=8 if draft else sum(out[n]!=before[n]for n in before)==8),'same692 exactly eight final changes');return out


def expectation_transform(before,mode,p):
 q={mode:p['reserved_result']['files']};need(mode=='known'and{n:pin(b)for n,b in before.items()}==q[mode],'whole exact c361 or matching NULL692');out=dict(before);seams={}
 declaration=json.loads(read(D/'expectation-seam.json'));need(declaration['basis_source']=='c361cd76b0be15c78122385e3f5b49468547e109'and declaration['file']=='implementation/test_source.py','exact inherited source gate only')
 for row in declaration['edits']:
  need(row['count']==1,'one exact test expectation seam');name=declaration['file'];out[name]=edit(out[name],row['before'],row['after']);seams.setdefault(name,[]).append({k:row[k]for k in('before','after','count')})
 guard=before['implementation/build_inventory_guard.py'];guard_seams=[]
 def guard_change(a,b):
  nonlocal guard
  guard=edit(guard,a,b);guard_seams.append(dict(before=a,after=b,count=1))
 guard_change('def verify(require_known=False):','PROFILE_EXPECTATION_PINS='+repr(json.loads(read(D/'expectation-parent-pins.json')))+'\n'+read(D/'expectation-guard.py.txt').decode()+'def verify(require_known=False):')
 a=" raw=G.read(HERE/'build_inventory_guard.py')";guard_change(a,a+"\n if 'source_profile_expectation'in G.obj(HERE/'build-inventory-parent.json'):return profile_expectation_verify(raw,require_known)")
 root=json.loads(before['implementation/build-inventory-parent.json']);reservation=root['reserved_recheck']['reservation'];root['source_profile_expectation']=dict(schema=1,variant=mode,source='c361cd76b0be15c78122385e3f5b49468547e109'if mode=='known'else None,ref='codex/latest607-gui-readback-reserved-v1'if mode=='known'else None,actual=None,files=q[mode],seams=seams,guard_seams=guard_seams,policy_before=json.loads(before['implementation/runner-context-policy.json']),reservation=reservation);out['implementation/build-inventory-parent.json']=enc(root)
 guard=assignment(guard,'PRODUCTS','PRODUCTS='+repr({n:pin(b)for n,b in out.items()if n not in('implementation/build_inventory_guard.py','source-manifest.json')}));guard=assignment(guard,'SELF_SHA',"SELF_SHA='@SELF@'");guard=assignment(guard,'SELF_SHA','SELF_SHA='+repr(pin(guard)['sha256']));out['implementation/build_inventory_guard.py']=guard
 manifest=json.loads(before['source-manifest.json']);manifest['files']={n:pin(b)for n,b in out.items()if n!='source-manifest.json'};out['source-manifest.json']=enc(manifest)
 need(set(out)==set(before)and len(out)==692 and sum(out[n]!=before[n]for n in before)==4,'same692 four source-test/guard/inverse/manifest changes only');return out


def layer_inverse(values,key,source,ref):
 """Pure DATA whole692 inverse of one finite reserved/test-profile layer."""
 out=dict(values);root=json.loads(out['implementation/build-inventory-parent.json']);c=root.pop(key);before=c['files']
 need(c['schema']==1 and c['variant']=='known'and c['actual']is None and(c['source'],c['ref'])==(source,ref)and len(out)==len(before)==692 and set(out)==set(before),'exact whole known692 source-only layer')
 for name,rows in c['seams'].items():
  for row in reversed(rows):
   a,b=row['before'].encode(),row['after'].encode();need(row['count']==1 and out[name].count(b)==1,'one exact finite layer source inverse');out[name]=out[name].replace(b,a,1)
 out['implementation/build-inventory-parent.json']=enc(root);out['implementation/runner-context-policy.json']=enc(c['policy_before'])
 guard=out['implementation/build_inventory_guard.py'];guard=assignment(guard,'PRODUCTS','PRODUCTS='+repr({n:w for n,w in before.items()if n not in('implementation/build_inventory_guard.py','source-manifest.json')}));guard=assignment(guard,'SELF_SHA',"SELF_SHA='@SELF@'")
 for row in reversed(c['guard_seams']):
  a,b=row['before'].encode(),row['after'].encode();need(row['count']==1 and guard.count(b)==1,'one exact finite guard inverse');guard=guard.replace(b,a,1)
 guard=assignment(guard,'SELF_SHA','SELF_SHA='+repr(pin(guard)['sha256']));out['implementation/build_inventory_guard.py']=guard
 manifest=json.loads(out['source-manifest.json']);manifest['files']={n:w for n,w in before.items()if n!='source-manifest.json'};out['source-manifest.json']=enc(manifest)
 need({n:pin(b)for n,b in out.items()}==before,'ENTIRE692 immediate '+key+' source byte inverse')
 return out

def reserved_inverse(values):return layer_inverse(values,'reserved_recheck','3f8594cbbed6e8f9c774c00d540427a8f914c4c3','codex/latest607-gui-payload-progress-v1')
def expectation_inverse(values):return layer_inverse(values,'source_profile_expectation','c361cd76b0be15c78122385e3f5b49468547e109','codex/latest607-gui-readback-reserved-v1')


def historical_transform(before,p):
 need({n:pin(b)for n,b in before.items()}==p['expectation_result']['files'],'whole exact public01eff692 historical source predecessor')
 out={n:before[n]for n in sorted(before)};seams={};name='implementation/test_source.py'
 a="f=load('_latest607_actual_factory_'+profile+mode,HERE/'factory/factory.py');selected=f.service1800();out=self.work/(profile+'-'+mode)"
 b="f=load('_latest607_actual_factory_'+profile+mode,HERE/'factory/factory.py');selected=load('_explicit_historical_source',HERE/'historical_source.py').historical_factory(f,ROOT/'parent574/original',ARGS.assets);out=self.work/(profile+'-'+mode)"
 out[name]=edit(out[name],a,b);seams[name]=[dict(before=a,after=b,count=1)]
 for name,rows in json.loads(read(D/'historical-test-seams.json')).items():
  need(name in('implementation/test_observer.py','implementation/test_runner_context.py'),'only explicit SOURCE test module seams')
  for row in rows:out[name]=edit(out[name],row['before'],row['after'],row['count']);seams.setdefault(name,[]).append(row)
 oldline='python3 -I -B "$SLICE/test_lane.py"';newline='python3 -I -B gui607-source/implementation/historical_source.py legacy-source-tests --source "$GITHUB_WORKSPACE/gui607-source" --assets "$RUNNER_TEMP/welcome5-assets"'
 a=json.dumps(oldline)[1:-1];b=json.dumps(newline)[1:-1]
 for name in('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-latest607-welcome8-gui.yml'):
  out[name]=edit(out[name],a,b);seams[name]=[dict(before=a,after=b,count=1)]
 name='implementation/workflow_contract.py';a=out[name].decode();b=a+'\n'+read(D/'historical-workflow.py.txt').decode();out[name]=edit(out[name],a,b);seams[name]=[dict(before=a,after=b,count=1)]
 name='implementation/workflow-derivation.json';original=out[name].decode();derivation=json.loads(out[name]);raw=before['parent574/.github/workflows/native-arm-current606-welcome8-gui.yml']
 for row in derivation['seams']:raw=edit(raw,row['before'],row['after'],row['count'])
 need(pin(raw)==derivation['after'],'entire prior source workflow derivation')
 raw=edit(raw,json.dumps(oldline)[1:-1],json.dumps(newline)[1:-1]);derivation.update(after=pin(raw),seams=derivation['seams']+[dict(before=json.dumps(oldline)[1:-1],after=json.dumps(newline)[1:-1],count=1)],historical_source_scope='SOURCE_ONLY_NOT_CURRENT_SIGNATURE_AUTHORITY');out[name]=enc(derivation);seams[name]=[dict(before=original,after=out[name].decode(),count=1)]
 out['implementation/historical_source.py']=read(D/'historical-source.py.txt');guard=before['implementation/build_inventory_guard.py'];guard_seams=[]
 def change(a,b):
  nonlocal guard
  guard=edit(guard,a,b);guard_seams.append(dict(before=a,after=b,count=1))
 change('def verify(require_known=False):','HISTORICAL_SOURCE_PINS='+repr(json.loads(read(D/'historical-parent-pins.json')))+'\nHISTORICAL_HELPER_PIN='+repr(pin(out['implementation/historical_source.py']))+'\n'+read(D/'historical-guard.py.txt').decode()+'def verify(require_known=False):')
 a=" raw=G.read(HERE/'build_inventory_guard.py')";change(a,a+"\n if 'historical_source'in G.obj(HERE/'build-inventory-parent.json'):return historical_source_verify(raw,require_known)")
 parent=json.loads(before['implementation/build-inventory-parent.json']);parent['historical_source']=dict(schema=1,variant='known',source='01eff67f3c2674eeea3a70999c5a3282f211f087',ref='codex/latest607-gui-profile-expectation-v1',actual=None,files=p['expectation_result']['files'],seams=seams,guard_seams=guard_seams,policy_before=json.loads(before['implementation/runner-context-policy.json']),reservation=parent['reserved_recheck']['reservation'],added={'implementation/historical_source.py':pin(out['implementation/historical_source.py'])});out['implementation/build-inventory-parent.json']=enc(parent)
 guard=assignment(guard,'PRODUCTS','PRODUCTS='+repr({n:pin(b)for n,b in out.items()if n not in('implementation/build_inventory_guard.py','source-manifest.json')}));guard=assignment(guard,'SELF_SHA',"SELF_SHA='@SELF@'");guard=assignment(guard,'SELF_SHA','SELF_SHA='+repr(pin(guard)['sha256']));out['implementation/build_inventory_guard.py']=guard
 manifest=json.loads(before['source-manifest.json']);manifest['files']={n:pin(b)for n,b in out.items()if n!='source-manifest.json'};out['source-manifest.json']=enc(manifest)
 need(len(out)==693 and set(out)-set(before)=={'implementation/historical_source.py'}and sum(out[n]!=before[n]for n in before)==10,'exact SOURCE-only helper and ten finite SOURCE-only changes')
 return out

def historical_inverse(values):
 out=dict(values);parent=json.loads(out['implementation/build-inventory-parent.json']);c=parent['historical_source'];name='implementation/historical_source.py'
 need(c['variant']=='known'and c['actual']is None and c['source']=='01eff67f3c2674eeea3a70999c5a3282f211f087'and c['ref']=='codex/latest607-gui-profile-expectation-v1'and c['added']=={name:pin(read(D/'historical-source.py.txt'))}and pin(out[name])==c['added'][name],'exact SOURCE helper identity and ordinary known predecessor')
 del out[name]
 return layer_inverse(out,'historical_source','01eff67f3c2674eeea3a70999c5a3282f211f087','codex/latest607-gui-profile-expectation-v1')

def compose(source):
    own=read_state(HERE/'prepare.py');raw,state=read_state(HERE/'profile.json');need(pin(raw)==PROFILE,'entry-pinned profile');p=json.loads(raw)
    need(all(p[k]is None for k in('actual_source','actual_ref','actual_run','Root_acceptance')) and p['acceptance_authority']is False,'source-only factory')
    source=ordinary(source);before,bstate=scan(source);need({n:pin(b)for n,b in before.items()}==p['parent']['files']and len(before)==692,'whole exact692 parent')
    operands={};states={'prepare.py':own,'profile.json':(raw,state)}
    for name,w in p['operands'].items():
        body,identity=read_state(HERE/name);need(pin(body)==w,'fixed readable operand '+name);operands[name]=body;states[name]=(body,identity)
    values,desc=transform({n:before[n]for n in sorted(before)},'known',json.loads(operands['generated-policy.json']))
    need({n:pin(b)for n,b in values.items()}==p['payload_result']['files'],'all exact public3f859 payload intermediate')
    values=reserved_transform(values,'known',p)
    need({n:pin(b)for n,b in values.items()}==p['reserved_result']['files'],'all exact publicc361 reserved3460 intermediate')
    values=expectation_transform(values,'known',p)
    need({n:pin(b)for n,b in expectation_inverse(values).items()}==p['reserved_result']['files'],'complete four-file c361 inverse')
    need({n:pin(b)for n,b in reserved_inverse(expectation_inverse(values)).items()}==p['payload_result']['files'],'complete reserved3460 to3f859 inverse')
    need({n:pin(b)for n,b in values.items()}==p['expectation_result']['files'],'all exact public01eff692 bytes')
    prior=values;values=historical_transform(prior,p);need(historical_inverse(values)==prior,'entire immediate01eff692 source inverse')
    need({n:pin(b)for n,b in values.items()}==p['result']['files'],'entire reproducible unpublished693 SOURCE-only boundary')
    need(set(values)==set(before)|set(p['added'])and {n for n in before if values[n]!=before[n]}==set(p['changed']) and all(values[n]==before[n]for n in p['held']),'nine changed/683 held')
    need(scan(source)==(before,bstate)and all(read_state(HERE/n)==v for n,v in states.items()),'late whole source and operand identities')
    return values,p,(before,bstate),states

def emit(source,output,context):
    need(context in('known','null'),'known/NULL receipt only');source,output=paths(source,output);values,p,before,states=compose(source);paths(source,output)
    need(scan(source)==before and all(read_state(HERE/n)==v for n,v in states.items()),'late inputs before writes');output.mkdir(mode=0o700)
    for n,b in sorted(values.items()):
        q=output/n;q.parent.mkdir(parents=True,exist_ok=True);fd=os.open(q,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb')as f:f.write(b);os.fchmod(f.fileno(),0o644)
    need(tree(output)==values and all(stat.S_IMODE((output/n).stat().st_mode)==0o644 for n in values),'exact production692 bytes/modes')
    return dict(status='UNPUBLISHED_HISTORICAL_SOURCE_ONLY_NOT_CURRENT_AUTHORITY',context=context,files=p['result']['files'],source=p['result']['source']if context=='known'else None,ref=p['result']['ref']if context=='known'else None,actual_source=None,actual_ref=None,actual_run=None,Root_acceptance=None)

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in('source','output','context'):parser.add_argument('--'+name,required=True)
    args=parser.parse_args();print(json.dumps(emit(args.source,args.output,args.context),sort_keys=True,indent=2))
