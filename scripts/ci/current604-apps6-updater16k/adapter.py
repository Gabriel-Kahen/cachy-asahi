# SPDX-License-Identifier: MIT
"""Only outer dispatch and the native-Docker entry predicate change."""
import ast
from pathlib import Path
import contract as C

def change(raw,before,after):
 text=raw.decode();C.need(text.count(before)==1,'one exact16K adapter anchor: '+before[:90]);text=text.replace(before,after);ast.parse(text);return text.encode()

def caller(raw):
 return change(raw,"and os.geteuid() == 0 and Path('/.dockerenv').is_file()", "and os.geteuid() == 0 and os.sysconf('SC_PAGE_SIZE') == 16384 and 'caa_apps6_update16k=1' in Path('/proc/cmdline').read_text().split()")

def owner(raw):
 old="old.command(argv+['--entrypoint=/usr/bin/python3',image,'-I','-B','/runner.py'],public/'transaction.log',3900)"
 new="vm.run(a,argv,image,public,raw,old,3900)"
 out=change(raw,old,new)
 out=change(out,"'audio-inputs','output')", "'audio-inputs','output','kernel-work','kernel-receipt','updater-decisions')")
 out=change(out,"a=p.parse_args(argv);policy=C.policy()", "a=p.parse_args(argv);vm.authorize(a);policy=C.policy()")
 out=change(out,"scope='GENERIC4K_APPS5_TO6_CURRENT604_COPIED_ROOT_SOFTWARE_ONLY'", "scope='GENERIC16K_VM_APPS5_TO6_CURRENT604_COPIED_ROOT_SOFTWARE_ONLY'")
 out=change(out,"result.update(status='PASS',composition=row)","result.update(status='PASS',composition=row,generic16k=C.read(public/'updater16k-result.json'))")
 # Never alter transaction/case verification or producer/cache/volume disposal bodies.
 out=change(out,"failures=old.retire_outer(actor_owned,result);retired=not failures","failures=vm.retire_outer(old,actor_owned,result,public);retired=not failures")
 funcs=lambda r:{n.name:ast.dump(n,include_attributes=False) for n in ast.parse(r).body if isinstance(n,ast.FunctionDef)}
 a,b=funcs(raw),funcs(out);C.need([n for n in a if a[n]!=b[n]]==['main'],'only owner main routing may change')
 return out


def prepare_selected(selected,source,target,case,**options):
 config,calling=selected.prepare(source,target,case,**options)
 q=calling/'container.py';original=q.read_bytes();q.write_bytes(caller(original))
 value=C.decode(C.read(config));name='scripts/ci/full-root-upgrade-caller/container.py'
 C.need(value['code_pins'].get(name)==C.sha(original),'original caller source pin required');value['code_pins'][name]=C.sha(q.read_bytes());C.save(config,value)
 proof=dict(status='SOURCE_DERIVED_NOT_EXECUTED',before=C.sha(original),after=C.sha(q.read_bytes()),counted_edits=1,config_sha256=C.sha(config.read_bytes()),unchanged='ALL_NON_GUARD_CALLER_AND_TRANSACTION_BODIES')
 C.save(calling/'updater16k-adapter.json',proof)
 receipt=C.decode(C.read(target/'adapter.json'));receipt['config_sha256']=proof['config_sha256'];receipt['updater16k_dispatch']=proof;C.save(target/'adapter.json',receipt)
 return config,calling
