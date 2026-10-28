# SPDX-License-Identifier: MIT
"""Whole original native owner, with the held copier preparation and exact4K entry."""
import ast,json,sys
from pathlib import Path
import case as C
PREDICATE16="and os.geteuid() == 0 and os.sysconf('SC_PAGE_SIZE') == 16384 and 'caa_apps6_update16k=1' in Path('/proc/cmdline').read_text().split()"
PREDICATE4="and os.geteuid() == 0 and Path('/.dockerenv').is_file() and os.sysconf('SC_PAGE_SIZE') == 4096"
def native_caller(raw):
 text=raw.decode();C.need(text.count(PREDICATE16)==1,'one exact held16K caller predicate');changed=text.replace(PREDICATE16,PREDICATE4,1);C.need(changed.replace(PREDICATE4,PREDICATE16,1)==text,'whole caller inverse outside actualnative4K predicate');ast.parse(changed);return changed.encode()
def preparation(held,old,A,source,target,selected_case):
 C.need(selected_case in C.CASES,'one explicit native4K recovery case');selected=old.scoped('_native4k_original_adapter',held/C.OLD/'adapter.py',{'contract':old});config,calling=A.prepare_selected(selected,source,target,selected_case);container=calling/'container.py';before=C.read(container);after=native_caller(before);value=old.read(config);name='scripts/ci/full-root-upgrade-caller/container.py';C.need(value['code_pins'][name]==C.pin(before)['sha256'],'whole held caller config pin');original=dict(value);value['code_pins']=dict(value['code_pins']);value['code_pins'][name]=C.pin(after)['sha256'];C.need({k:v for k,v in value.items()if k!='code_pins'}=={k:v for k,v in original.items()if k!='code_pins'},'all original configuration/clock/crypto/scale fields held');C.need({k:value[k]for k in('stage_seconds','copy_seconds','driver_seconds','verify_seconds')}==dict(stage_seconds=1200,copy_seconds=1200,driver_seconds=2400,verify_seconds=600),'same explicit original nested budgets');container.write_bytes(after);config.write_bytes(old.encoded(value));receipt=old.read(target/'adapter.json');receipt['native4k_entry']=dict(status='EXACT_HELD_OWNER_PREPARATION_WITH_NATIVE4K_CALLER_NOT_ACCEPTANCE',held_source=C.HELD,caller_before=C.pin(before),caller_after=C.pin(after),prior_config_sha256=receipt['config_sha256'],config_sha256=C.pin(C.read(config))['sha256'],unchanged='FULL_COPY_CRYPTO_PRESERVATION_TRANSACTION_LIFETIME_CLEANUP_AND_CLOCKS');receipt['config_sha256']=C.pin(C.read(config))['sha256'];(target/'adapter.json').write_bytes(C.enc(receipt));return config,calling

def execute(held,argv):
 C.need(argv.count('--case')==1 and argv.index('--case')+1<len(argv),'one explicit held recovery case');selected_case=argv[argv.index('--case')+1];C.need(selected_case in C.CASES,'exact recovery case before owner');contract,W,A=C.apis(held);old,policy,binding=W.authorize(held,C.HELD,C.HELD,selected_case);gate=W.old_gate(held,old);cache=old.scoped('_native4k_exact_before_cache',held/C.OLD/'before_cache.py',{'contract':old})
 class Adapter:
  @staticmethod
  def prepare(source,target,case):return preparation(held,old,A,source,target,case)
 # This imports the whole source-held original body in an independent module.
 # No VM-route rewrite, shared live mutation, patched success or accepted result.
 owner=old.scoped('_native4k_whole_owner',held/C.OLD/'run.py',{'contract':old,'adapter':Adapter,'gate':gate,'before_cache':cache});raw=C.read(held/C.OLD/'run.py');C.need(C.pin(raw)==policy_owner_pin(held),'whole original owner source');return owner.main(argv)
def policy_owner_pin(held):return C.obj(C.HERE/'profile.json')['held_files'][C.OLD+'/run.py']
