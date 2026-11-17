# SPDX-License-Identifier: MIT
"""Pure exact-r2 derivative: one input, five artifacts streams, narrowed FSIZE."""
import ast,hashlib
PINS={'run_metadata.py':(40623,'47e0ee2185ddad74c94a92e97aa41ee4c6d754ea683006e804f8723251b7a886'),
      'exec_limiter.py':(4973,'4f820b19cab90c8afec2838644e28cf660ed0608e195cf8c76035706663687d1'),
      'Root-issue.DRAFT.py':(5855,'b343a70a71c4f3d5d210103491ebe3b96e2e75a2cf5e0c442d1b4db855f7bc73'),
      'Root-enter.DRAFT.py':(7871,'579f1fff3dd315a8316d41ace3d35efc3b33121fdc047f9c662d2213077e6262')}
CORE=('proof','cleanup','census','docker','publish_go','rename_go_noreplace','check_rootless_server','expected_inspect_labels','ordinary','whole','read','kernel','decoder_kernel_scope','permit_decoder','wait_ready','capacity')
def need(ok,why):
 if not ok:raise ValueError(why)
def replace(s,a,b):
 need(s.count(a)==1,'exact single baseline derivative seam: '+a[:70]);return s.replace(a,b)
def function(s,name,body):
 node=next(n for n in ast.parse(s).body if isinstance(n,ast.FunctionDef)and n.name==name);rows=s.splitlines(keepends=True)
 return ''.join(rows[:node.lineno-1])+body.rstrip()+'\n'+''.join(rows[node.end_lineno:])
def functions(s):return {n.name:ast.dump(n,include_attributes=False)for n in ast.walk(ast.parse(s))if isinstance(n,ast.FunctionDef)}
def apply(files):
 need(set(files)==set(PINS),'exact four maintained r2 code preimages')
 for name,raw in files.items():need((len(raw),hashlib.sha256(raw).hexdigest())==PINS[name],'whole immutable r2 predecessor '+name)
 result={k:v.decode()for k,v in files.items()}
 s=result['run_metadata.py']
 s=s.replace('ROOT_R86_PUBLIC_LDCACHE_RECOVERY_OUTER_V1','ROOT_BASELINE_PUBLIC_LDCACHE_OUTER_V1').replace('readonly-r86-cache-and-etc-only','readonly-baseline-cache-and-etc-only').replace('COMPLETE_PUBLIC_LDCACHE_RECOVERY_ONLY','COMPLETE_BASELINE_PUBLIC_LDCACHE_ONLY')
 s=s.replace("(f['input_prepared']['path'],'/inputs/overlay.qcow2',True),",'')
 s=replace(s,"len(row['Mounts']) == 6","len(row['Mounts']) == 5")
 s=replace(s,"and request['overlay']['path']==f['input_prepared']['path']", "")
 s=replace(s,"input_prepared=dict(path=request['overlay']['path'],**request['overlay']['pin']),", "")
 s=replace(s,"for k in ('input_raw','input_prepared')","for k in ('input_raw',)")
 s=replace(s,";need(Path(f['input_prepared']['path']).stat().st_blocks*512<=268435456,'Root-reviewed overlay allocated cap distinct from EOF')",'')
 s=replace(s,"for role in ('input_raw','input_prepared'):","for role in ('input_raw',):")
 s=replace(s,"len(inputs_before)==2","len(inputs_before)==1")
 s=replace(s,"                    need(Path(f['input_prepared']['path']).stat().st_blocks*512<=268435456,'same final overlay allocated cap')\n",'')
 s=s.replace('1610612736','4194304')
 s=function(s,'validate_observation',"""def validate_observation(v,c,f):
    need(type(v)is dict and len(encoded(v))<=16384,'bounded baseline public cache summary')
    need(v.get('kind')=='OBSERVED_BASELINE_PUBLIC_LDCACHE_DATA_V1'and v.get('status')=='BASELINE_CACHE_BODY_ONLY_NOT_TRANSITION_ACCEPTANCE'and v.get('Source_lock')==f['source_lock'],'exact baseline public-only operation identity')
    need(v.get('request')=={n:c['qualification_authority'][n]for n in('bytes','sha256')}and v.get('tools_reverified')is True and v.get('commands')==5 and v.get('all_tools_naturally_reaped')is True,'same Root request/debugfs/five natural commands')
    need(all(v.get(n)is None for n in('Root_acceptance','VM_acceptance','lifecycle_acceptance','M2','release')),'no lifecycle or runtime acceptance')
    names={label+suffix for label in('cache-before','etc-before','cache-body','cache-after','etc-after')for suffix in('.log','.retirement.json')}|{'cache.bin'}
    need(type(v.get('files'))is dict and set(v['files'])==names,'exact small baseline artifact membership; no raw output')
    for name,row in v['files'].items():
        cap=1048576 if name=='cache.bin'else 16384
        need(type(row)is dict and set(row)=={'bytes','sha256'}and type(row['bytes'])is int and 0<=row['bytes']<=cap and type(row['sha256'])is str and re.fullmatch('[0-9a-f]{64}',row['sha256']),'bounded exact artifact pin')
    expected=dict(bytes=17551,sha256='0128a732a8b926232b5065374176194ea4a1f5c1628728037109bbdbb3d53215')
    need(v['files']['cache.bin']==expected and v.get('cache_observation',{}).get('cache')==expected,'exact fixed known baseline cache body pin')
    need(sum(row['bytes']for row in v['files'].values())+16384<=4*M,'whole small output budget including summary')
    return {n:v[n]for n in('kind','status','request','Source_lock','cache_observation','tools_reverified','commands','all_tools_naturally_reaped','Root_acceptance','VM_acceptance','lifecycle_acceptance','M2','release')}""")
 s=function(s,'retain_artifact_descriptors',"""def retain_artifact_descriptors(directory,summary,deadline):
    directory=ordinary(str(directory));expected=set(summary['files'])|{'observation.DATA.json'}
    need({p.name for p in directory.iterdir()}==expected,'complete fixed baseline public artifacts')
    rows={};total=0
    for name in sorted(expected):
        p=directory/name;st=p.lstat();need(stat.S_ISREG(st.st_mode)and st.st_nlink==1 and st.st_uid==1000 and stat.S_IMODE(st.st_mode)==0o600,'fresh private owned baseline artifact')
        value,_=whole(p,1048576 if name=='cache.bin'else 16384,deadline);total+=value['bytes'];need(total<=4*M,'bounded four-MiB baseline aggregate')
        if name!='observation.DATA.json':need(value==summary['files'][name],'whole artifact pin matches producer')
        rows[name]=dict(path=str(p),**value,mode=0o600)
    return rows,total""")
 before=functions(result['run_metadata.py']);after=functions(s)
 for name in CORE:
  need(name in before and name in after and before[name]==after[name],'unchanged critical core function '+name)
 result['run_metadata.py']=s
 result['exec_limiter.py']=replace(result['exec_limiter.py'],'[1610612736,1610612736]','[4194304,4194304]')
 s=result['Root-issue.DRAFT.py'];s=replace(s,"input_prepared=dict(path=request['overlay']['path'],**request['overlay']['pin']),", "")
 s=replace(s,"request['overlay']['path']==R.fixed()['input_prepared']['path']and ", "")
 result['Root-issue.DRAFT.py']=s
 s=result['Root-enter.DRAFT.py'].replace('COMPLETE_PUBLIC_LDCACHE_RECOVERY_ONLY','COMPLETE_BASELINE_PUBLIC_LDCACHE_ONLY').replace('COMPLETE_PUBLIC_LDCACHE_RECOVERY_AND_CLEANUP_ONLY','COMPLETE_BASELINE_PUBLIC_LDCACHE_AND_CLEANUP_ONLY')
 s=replace(s,'total<=1610612736+4*1024**2','total<=4*1024**2')
 s=replace(s,"for role in('input_raw','input_prepared'):","for role in('input_raw',):")
 result['Root-enter.DRAFT.py']=s
 for name,s in result.items():compile(s,name,'exec')
 return {k:v.encode()for k,v in result.items()}
def inverse(files,generated):
 need(apply(files)==generated,'exact scoped baseline derivative');return files
