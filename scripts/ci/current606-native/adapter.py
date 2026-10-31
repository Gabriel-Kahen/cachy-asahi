# SPDX-License-Identifier: MIT
"""Whole-source guarded exact insertion; historical604 methods stay unchanged."""
import ast
import contract as P

def one(raw,before,after):
 P.need(raw.count(before)==1,'one exact606 seam: '+before[:90]);return raw.replace(before,after)
def held(root,name):
 return P.checked(root/'held604'/P.OLD/name,P.read(P.HERE/'base-pins.json')[P.OLD+'/'+name]).read_text()
def lifecycle(root):
 raw=held(root,'lifecycle.py');return one(raw,"        install();checkpoint('install604',after,rows)\n","        install();checkpoint('install604',after,rows)\n        import tools606\n        previous_ld,previous_aux=tools606.exercise(globals(),locals())\n")
def owner(root):
 raw=held(root,'run.py')
 raw=one(raw,"        planroot,plan=prepare_plan(ready,target,out,args.code,args.legacy_source,policy,summary['audios'])\n","        planroot,plan=prepare_plan(ready,target,out,args.code,args.legacy_source,policy,summary['audios'])\n        tools606,runner606=X.prepare(args.code.parent,producerout,out,owned,ready,C)\n")
 raw=one(raw,"(HERE,'/runner',True)","(runner606,'/runner',True),(tools606,'/tools606',True)")
 raw=one(raw,"        C.validate_combined(C.read(C.checked(resultdir,life['combined_shell'],1024**2)))","        C.validate_combined(C.read(C.checked(resultdir,life['combined_shell'],1024**2)))\n        X.validate(life.get('tools606'))")
 raw=one(raw,"C.need(len(owned.rows)==1,'exactly one lifecycle consumer; accepted pairs are never rebuilt')","C.need(len(owned.rows)==5,'four new distinct builders and one lifecycle consumer')")
 raw=one(raw,"status='PASS_NATIVE_PUBLIC_PAIRS_APPS6_CURRENT604_COMPOSITION'","status='PASS_NATIVE606_DNS2_SYSCTL2_COMPOSITION'")
 raw=one(raw,"def export(out,report,args,summary):\n","def export(out,report,args,summary):\n    X.prepare_export(out,report)\n")
 raw=one(raw,"    names += ['container/'+prefix+phase+suffix for phase in phases for prefix,suffix in [('ld-','.json'),('aux-','.bin')]]","    names += ['container/'+prefix+phase+suffix for phase in phases for prefix,suffix in [('ld-','.json'),('aux-','.bin')]]\n    names += X.export_names(out)")
 return raw

def proof(root):
 raw=held(root,'lifecycle.py');derived=lifecycle(root);tree=ast.parse(derived);main=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='main');main.body=[n for n in main.body] # Exact reverse insertion establishes complete method conservation.
 restored=one(derived,"        import tools606\n        previous_ld,previous_aux=tools606.exercise(globals(),locals())\n",'');P.need(restored==raw,'all historical lifecycle bytes preserved outside insertion')
 own=owner(root);P.need('signal.setitimer(signal.ITIMER_REAL,6600)'in own and 'active.process.wait(timeout=1800)'in own and own.count('cap-add=')==held(root,'run.py').count('cap-add='),'original owner/runtime bounds/caps held')
 return dict(status='SOURCE_ONLY_EXACT_DERIVATION',lifecycle='ONE_INSERTION_ALL_OTHER_BYTES_HELD',original_methods='BYTE_IDENTICAL_AFTER_REMOVING_INSERTION',owner_deltas=7,worker_seconds=1800,owner_seconds=6600,build_seconds=240)
