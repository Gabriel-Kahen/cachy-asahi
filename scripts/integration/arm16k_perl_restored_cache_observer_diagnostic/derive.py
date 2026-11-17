# SPDX-License-Identifier: MIT
"""Pure exact-r2 derivative: three inputs, three public nodes, no persistent raw publication."""
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
 result={k:v.decode()for k,v in files.items()};s=result['run_metadata.py']
 s=s.replace('ROOT_R86_PUBLIC_LDCACHE_RECOVERY_OUTER_V1','ROOT_R94_THREE_PUBLIC_CACHE_DIAGNOSTIC_OUTER_V2').replace('readonly-r86-cache-and-etc-only','readonly-r94-three-public-caches-diagnostic-v2').replace('COMPLETE_PUBLIC_LDCACHE_RECOVERY_ONLY','COMPLETE_R94_THREE_PUBLIC_CACHE_DIAGNOSTIC_ONLY')
 needle="(f['input_raw']['path'],'/prepared/guest.raw',True),";need(s.count(needle)==2,'exact create/inspect mount seams');s=s.replace(needle,needle+"(f['input_baseline']['path'],'/baseline/guest.raw',True),")
 s=replace(s,"len(row['Mounts']) == 6","len(row['Mounts']) == 7")
 s=replace(s,"and request['backing']['path']==f['input_raw']['path']","and request['backing']['path']==f['input_raw']['path']and request['baseline']['path']==f['input_baseline']['path']")
 s=replace(s,"input_prepared=dict(path=request['overlay']['path'],**request['overlay']['pin']),","input_prepared=dict(path=request['overlay']['path'],**request['overlay']['pin']),input_baseline=dict(path=request['baseline']['path'],**request['baseline']['pin']),")
 s=s.replace("('input_raw','input_prepared')","('input_raw','input_prepared','input_baseline')")
 s=replace(s,"need(p=={k:r[k] for k in ('bytes','sha256')},'whole original opaque input pin')","need(p=={k:r[k] for k in ('bytes','sha256')}and list(i)==r['identity'],'whole Root-selected original opaque input pin and identity')")
 for role in('input_raw','input_prepared','input_baseline'):s=replace(s,role+'=dict(path=',role+"=dict(f['"+role+"'],path=")
 s=replace(s,'len(inputs_before)==2','len(inputs_before)==3')
 s=function(s,'validate_observation',"""def validate_observation(v,c,f):
    Q=module('exact_restored_cache_summary',Path(f['prior_packet']['path']).parent/'recovery.py')
    return Q.validate_summary(v,{n:c['qualification_authority'][n]for n in('bytes','sha256')},f['source_lock'])""")
 s=function(s,'retain_artifact_descriptors',"""def retain_artifact_descriptors(directory,summary,deadline):
    directory=ordinary(str(directory));expected=set(summary['files'])|{'observation.DATA.json'}
    need({p.name for p in directory.iterdir()}==expected,'complete fixed public cache artifacts; no raw output')
    rows={};total=0
    for name in sorted(expected):
        p=directory/name;st=p.lstat();need(stat.S_ISREG(st.st_mode)and st.st_nlink==1 and st.st_uid==1000 and stat.S_IMODE(st.st_mode)==0o600,'private owned public artifact')
        value,_=whole(p,1048576 if name.endswith('.bin')else 65536 if name=='commands.DATA.json'else 16384,deadline);total+=value['bytes'];need(total<=4*M,'bounded four-MiB public artifact aggregate')
        if name!='observation.DATA.json':need(value==summary['files'][name],'whole artifact matches producer pin')
        rows[name]=dict(path=str(p),**value,mode=0o600)
    return rows,total""")
 a=functions(result['run_metadata.py']);b=functions(s)
 for name in CORE:need(a[name]==b[name],'unchanged custody/GO/PIDFD/NB/cgroup/cleanup core '+name)
 result['run_metadata.py']=s
 # FSIZE remains r90's1.5GiB for exactly one temporary sparse conversion.
 s=result['Root-issue.DRAFT.py'];s=replace(s,"input_prepared=dict(path=request['overlay']['path'],**request['overlay']['pin']),","input_prepared=dict(path=request['overlay']['path'],**request['overlay']['pin']),input_baseline=dict(path=request['baseline']['path'],**request['baseline']['pin']),")
 s=replace(s,"and request['backing']['path']==R.fixed()['input_raw']['path']","and request['backing']['path']==R.fixed()['input_raw']['path']and request['baseline']['path']==R.fixed()['input_baseline']['path']")
 for role in('input_raw','input_prepared','input_baseline'):s=replace(s,role+'=dict(path=',role+"=dict(f['"+role+"'],path=")
 result['Root-issue.DRAFT.py']=s
 s=result['Root-enter.DRAFT.py'].replace('COMPLETE_PUBLIC_LDCACHE_RECOVERY_ONLY','COMPLETE_R94_THREE_PUBLIC_CACHE_DIAGNOSTIC_ONLY').replace('COMPLETE_PUBLIC_LDCACHE_RECOVERY_AND_CLEANUP_ONLY','COMPLETE_R94_THREE_PUBLIC_CACHE_DIAGNOSTIC_AND_CLEANUP_ONLY')
 s=replace(s,'total<=1610612736+4*1024**2','total<=4*1024**2');s=replace(s,"for role in('input_raw','input_prepared'):","for role in('input_raw','input_prepared','input_baseline'):")
 result['Root-enter.DRAFT.py']=s
 for name,body in result.items():compile(body,name,'exec')
 return {k:v.encode()for k,v in result.items()}
def inverse(files,generated):need(apply(files)==generated,'exact bounded three-input public-cache derivative');return files
