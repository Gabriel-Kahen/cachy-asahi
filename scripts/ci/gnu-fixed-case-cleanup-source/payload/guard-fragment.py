# BEGIN_FIXED_CASE_CLEANUP600_SOURCE
# The current closure AND the complete original747 source entry are mandatory.
def lifetime_validation_source(root):
 import base64,tempfile,zlib
 root=Path(root);fact=_IMMUTABLE_NODE_MAP_PREVIOUS_SOURCE(root)
 raw=read(root/LANE/'lifetime-validation-profile.json',4*1024**2);need(pin(raw)==_LIFETIME_VALIDATION_PIN,'exact closed cleanup600 profile');q=obj(raw);before=q['before'];changed=set(q['before_bodies_zlib'])
 actual={p.relative_to(root).as_posix():pin(read(p,16*1024**2))for p in root.rglob('*')if p.is_file()and p.relative_to(root).parts[0]!='.git'}
 need(len(before)==747 and set(actual)==set(before)|{LANE+'/fixed_case.py',LANE+'/lifetime-validation-profile.json'}and len(actual)==749,'whole749 current namespace')
 need({n for n in before if actual[n]!=before[n]}==changed,'whole finite747 source inverse')
 need(q['scope']=='EXPLICIT_FIXED_CASE_CLEANUP600_DEFAULT_TWO_CASE120'and q['publication']['source']=='3d6f8f994c89d1ba55f31aed947ded987837d8cd'and q['publication']['files']==747 and q['authorization']==before and q['git']['files']==before and q['git']['source']==q['publication']['source']and all(q[k]is None for k in('actual_source','actual_ref','actual_run','Root_acceptance')),'whole genuine747 context and current actualNULL')
 need(q['publication']==dict(status='COMMITTED_EXACT_CLOSED_TRIAL_SOURCE',source='3d6f8f994c89d1ba55f31aed947ded987837d8cd',ref='codex/gnu747-root7200-v1',files=747,git_joins=747,actual='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED')and q['git']==dict(status='PASS_INDEPENDENT_FULL_GIT_BLOB_JOIN',source=q['publication']['source'],ref=q['publication']['ref'],files=before),'complete genuine747 publication and Git')
 need(pin(read(root/LANE/'fixed_case.py'))==q['helper'],'exact readable fixed-case helper')
 bodies={}
 for n,w in before.items():
  if n in changed:
   packed=base64.b64decode(q['before_bodies_zlib'][n],validate=True);decoder=zlib.decompressobj();b=decoder.decompress(packed,w['bytes']+1);need(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail,'bounded whole old747 operand')
  else:b=read(root/n,16*1024**2)
  need(pin(b)==w,'whole old747 byte '+n);bodies[n]=b
 helper=load('_exact_fixed_case_helper',root/LANE/'fixed_case.py');runtime={n[len('runtime/'):]:b for n,b in bodies.items()if n.startswith('runtime/')}
 need(len(runtime)==667 and all(read(root/'runtime'/n)==b for n,b in runtime.items()),'ALL original747 public runtime bytes held')
 for case in helper.CASES:
  after,ledger=helper.render(runtime,case);need(set(after)==set(runtime)and(case!='both'or after==runtime),'default two-case branch byte-identical')
  need({n:pin(b)for n,b in after.items()}==q['runtime_profiles'][case],'complete derived fixed-case runtime pins')
 # Whole binding/entry/workflow counted inverses, beyond the runtime products.
 for n,steps in q['source_edits'].items():
  b=read(root/n).decode()
  for step in reversed(steps):need(b.count(step['after'])==1,'one current source seam');b=b.replace(step['after'],step['before'],1)
  need(b.encode()==bodies[n],'entire original747 source body inverse')
 marker='\n# BEGIN_FIXED_CASE_CLEANUP600_SOURCE\n';text=read(root/LANE/'deploy.py').decode();parts=text.split(marker);footer='\n_LIFETIME_VALIDATION_PIN='+repr(pin(raw))+'\ndef source(root=ROOT):\n return lifetime_validation_source(root)\n';need(len(parts)==2 and parts[0].encode()==bodies[LANE+'/deploy.py']and parts[1].endswith(footer)and pin(parts[1].removesuffix(footer).encode())==q['guard_fragment'],'entire original deploy plus exact complete current guard and footer')
 saved,paths=dict(sys.modules),sys.path[:]
 try:
  with tempfile.TemporaryDirectory(prefix='gnu-whole747-')as td:
   old=Path(td)/'source';old.mkdir()
   for n,b in bodies.items():p=old/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b)
   for p in old.rglob('*.py'):sys.modules.pop(p.stem,None)
   sys.path.insert(0,str(old/LANE));entry=load('_fixed_case_whole747_entry',old/LANE/'entry.py');parent=entry.source(old);need(parent['files']==747 and parent['whole_capacity_parent746']['files']==746,'complete747 and older source/runtime guards')
 finally:
  sys.path[:]=paths
  for n in set(sys.modules)-set(saved):sys.modules.pop(n,None)
  sys.modules.update(saved)
 return dict(fact,whole_lifetime_parent747=parent,validation='EXPLICIT_FIXED_CASE_CLEANUP600_DEFAULT_TWO_CASE120',required_acceptance='BOTH_SEPARATE_SAME_SOURCE_CASES',cleanup600_fit='UNKNOWN',two_case_fit='NOT_ESTABLISHED',native_fit='UNKNOWN')
