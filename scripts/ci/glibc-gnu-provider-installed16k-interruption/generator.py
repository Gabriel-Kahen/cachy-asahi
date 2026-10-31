#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite source-only native interruption/full-root16K adapter. No actor executes."""
import argparse,ast,hashlib,json
from pathlib import Path
HERE=Path(__file__).resolve().parent
OLD='scripts/ci/glibc-gnu-provider-installed16k'
NEW='scripts/ci/glibc-gnu-provider-installed16k-interruption'
NATIVE='scripts/ci/glibc-gnu-provider-interruption'
OWNER='scripts/ci/glibc-gnu-provider-interruption-owner/job.py'
MODULES=('contract.py','adapter.py','prepare.py','guest.py','run.py','export.py','sandbox.py','scrub.py','support.py','snapshot_progress.py','observer_progress.py')
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(v):return (json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
# Filled once from the exact source-pinned canonical files; each count is fixed.
RULES={'contract.py': [('scripts/ci/glibc-gnu-provider-installed16k', 'scripts/ci/glibc-gnu-provider-installed16k-interruption', 1), ('org.cachy-asahi.gnu-installed16k', 'org.cachy-asahi.gnu-interrupted16k', 1), ('_installed16k_', '_interrupted16k_', 1), ("NATIVE='scripts/ci/glibc-gnu-provider-lifecycle'", "NATIVE='scripts/ci/glibc-gnu-provider-interruption'", 1), ('PASS_GENERIC16K_ALPM_PROVIDER_NORMAL_LIFECYCLE_AND_RECOVERY', 'PASS_GENERIC16K_ALPM_PROVIDER_INTERRUPTED_REPLACEMENT_AND_RECOVERY', 1)], 'adapter.py': [('caa_gnu_installed16k=1', 'caa_gnu_interrupted16k=1', 1), ('CACHY_GNU_PROVIDER_LIFECYCLE', 'CACHY_GNU_PROVIDER_INTERRUPTION', 2)], 'prepare.py': [('/installed16k', '/installed16k-interruption', 2), ("'installed16k'", "'installed16k-interruption'", 2), ('init-installed16k', 'init-interrupted16k', 2), ('CAA_INSTALLED16K_PREPARE', 'CAA_INTERRUPTED16K_PREPARE', 1), ('GNU16K_', 'GNUINT16K_', 1), ("('guest.py','contract.py','sandbox.py','snapshot_progress.py','observer_progress.py')", "('guest.py','contract.py','sandbox.py','snapshot_progress.py','observer_progress.py','recovery.py')", 1), ("'installed16k/", "'installed16k-interruption/", 3)], 'guest.py': [('/installed16k', '/installed16k-interruption', 7), ('caa_gnu_installed16k=1', 'caa_gnu_interrupted16k=1', 1), ('GNU_INSTALLED16K', 'GNU_INTERRUPTED16K', 4), ('CACHY_GNU_PROVIDER_LIFECYCLE', 'CACHY_GNU_PROVIDER_INTERRUPTION', 1), ('PASS_GENERIC_ARM_SYSTEM_PROVIDER_LIFECYCLE', 'PASS_GENERIC_ARM_PROVIDER_INTERRUPTION_RECOVERY', 1), ('PASS_NORMAL_DISPOSABLE_PROVIDER_SEQUENCE', 'PASS_INTERRUPTED_RECOVERED_NORMAL_PROVIDER_SEQUENCE', 1), ("'held574','source-after')", "'held574','source-after','interrupted-before-unlock','recovered-held574')", 2), ("('before_runtime','provider_runtime','reinstalled_runtime','held_runtime')", "('before_runtime','recovered_runtime','provider_runtime','reinstalled_runtime','held_runtime')", 1), ('normal_runtime_observations=8', 'normal_runtime_observations=10', 1), ('NOT_IMPLEMENTED_SEPARATE_FUTURE_CASE', 'REMOVE_PHASE_ONLY_ACTUAL_STOP_KILL_RECOVERY_REQUIRED', 1)], 'run.py': [('/installed16k', '/installed16k-interruption', 2), ('init-installed16k', 'init-interrupted16k', 1), ('caa_gnu_installed16k=1', 'caa_gnu_interrupted16k=1', 1), ('GNU_INSTALLED16K', 'GNU_INTERRUPTED16K', 2), ('CAA_INSTALLED16K_PREPARE', 'CAA_INTERRUPTED16K_PREPARE', 1), ('caa-gnu-installed16k-', 'caa-gnu-interrupted16k-', 1), ("result['normal_runtime_observations']==8", "result['normal_runtime_observations']==10", 1), ("result['capabilities']['stages']==8", "result['capabilities']['stages']==10", 1), ('for n in files)==16', 'for n in files)==20', 1), ('all16 complete root snapshots required', 'all20 complete root snapshots required', 1), ('exact16 capability observations required', 'exact20 capability observations required', 1), ('PASS_LIFECYCLE_PENDING_ORDERED_PRODUCER_CLEANUP', 'PASS_INTERRUPTION_PENDING_ORDERED_PRODUCER_CLEANUP', 1), ("'lifecycle-runner'", "'interruption-runner'", 1), ('lifecycle-input.json', 'interruption-input.json', 2)], 'export.py': [('CAA_INSTALLED16K_PREPARE', 'CAA_INTERRUPTED16K_PREPARE', 1), ('PASS_GENERIC_ARM_SYSTEM_PROVIDER_LIFECYCLE', 'PASS_GENERIC_ARM_PROVIDER_INTERRUPTION_RECOVERY', 1), ('PASS_NORMAL_DISPOSABLE_PROVIDER_SEQUENCE', 'PASS_INTERRUPTED_RECOVERED_NORMAL_PROVIDER_SEQUENCE', 1), ("'held574','source-after')", "'held574','source-after','interrupted-before-unlock','recovered-held574')", 1)], 'snapshot_progress.py': [], 'observer_progress.py': [], 'sandbox.py': [], 'scrub.py': [('CAA_INSTALLED16K_PREPARE', 'CAA_INTERRUPTED16K_PREPARE', 1)], 'support.py': []}
GATE='''def gate(acceptances):
    policy=decode(read(HERE/'input-policy.json',65536))
    need(policy['schema_version']==1 and policy['status']=='BOUND_BY_ROOT' and type(policy['binding']) is dict,'UNBOUND interrupted16K: both actual Root decisions required before actors')
    binding=policy['binding'];expected={'native_interruption':'ROOT_ACCEPTED_CONVENTIONAL_PROVIDER_INTERRUPTION_RECOVERY','normal_installed16k':'ROOT_ACCEPTED_GENERIC16K_ALPM_PROVIDER_NORMAL_LIFECYCLE_AND_RECOVERY'}
    need(set(binding)==set(expected),'native interruption plus completed normal installed16K only')
    result={}
    for kind,status in expected.items():
        value=decode(read(ref(acceptances,binding[kind])))
        need(value['status']==status and value['hardware']=='NOT_RUN' and value['ordered_cleanup']=='PASS' and value['provider_archive_sha256']=='b852e3fc647d63699c5f42003a748cbd2268991dc2615a494dc3cdda4d757d12','same provider actual accepted result and cleanup required')
        need(re.fullmatch('[0-9a-f]{40}',value['source_sha']) and type(value['run_id']) in (int,str) and re.fullmatch('[1-9][0-9]{0,19}',str(value['run_id'])),'actual source/run decision identity')
        if kind=='normal_installed16k':need(value['page_size']==16384 and value['ALPM_installation']=='PASS','normal full installed16K required, staged16K is insufficient')
        result[kind]=value
    return result
'''

def source(root):
 value=json.loads((HERE/'source-pins.json').read_bytes())
 for name,row in value['files'].items():
  p=root/name;need(not any(x.is_symlink() for x in (p,*p.parents)) and p.is_file() and p.stat().st_nlink==1 and p.stat().st_size<=2*1024**2 and pin(p.read_bytes())==row,'exact current frozen helper/source: '+name)
 need('CACHY_GNU_PROVIDER_INTERRUPTION' in (root/'scripts/ci/glibc-gnu-provider-lifecycle/proc_mount.py').read_text(),'shared exact interruption role guard required')
 return value

def adapt(raw,name):
 text=raw.decode();counts=[]
 for before,after,count in RULES[name]:
  need(text.count(before)==count,'counted interruption adapter anchor: '+name+' '+before[:80]);text=text.replace(before,after);counts.append(count)
 if name=='contract.py':
  tree=ast.parse(text);node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='gate');old=ast.get_source_segment(text,node);need(text.count(old)==1,'one exact gate body');text=text.replace(old,GATE.rstrip())
 if name=='guest.py':
  anchor="    stages=('source-before'";need(text.count(anchor)==1,'one worker stage gate');text=text.replace(anchor,"    recovery=C.load('actual_interruption_records',Path(__file__).with_name('recovery.py'))\n    recovery_receipt=recovery.consumer_records(Path('/out'),index['source_nodes_sha256'])\n"+anchor)
  anchor="normal_runtime_observations=10,";need(text.count(anchor)==1,'one interruption result metadata');text=text.replace(anchor,anchor+'interruption=recovery_receipt,')
 if name=='run.py':
  anchor="        report['status']='PASS_VM_AWAITING_CONSUMER_TEARDOWN'";need(text.count(anchor)==1,'one post-readback gate');text=text.replace(anchor,"        recovery=C.load('actual_interruption_readback',C.HERE/'recovery.py');report['interruption_readback']=recovery.consumer_records(public/'guest',selection['source_nodes_sha256'])\n"+anchor)
  anchor="    isolation=result['isolation'];";need(text.count(anchor)==1,'one host isolation gate');text=text.replace(anchor,"    C.need(result['interruption']['status']=='PASS_COMPLETE_INTERRUPTION_AND_NORMAL_RUNTIME_RECORDS' and len(result['interruption']['files'])==21,'complete guest interruption witness and20maps')\n"+anchor)
 ast.parse(text);return text.encode(),sum(counts)

def recovery(root):
 raw=(root/OWNER).read_text();tree=ast.parse(raw);names=('ordinary','read','consumer_records');pieces=[]
 for name in names:
  nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name==name];need(len(nodes)==1,'one unchanged native owner validation body');pieces.append(ast.get_source_segment(raw,nodes[0]))
 text='import json,signal,stat\nfrom pathlib import Path\nimport contract as C\nneed=C.need\n\n'+'\n\n'.join(pieces)+'\n'
 for before,after in (("public=output/'inner/public'","public=output"),("runtime['result']['page_size']==4096","runtime['result']['page_size']==16384")):
  need(text.count(before)==1,'two exact owner-to-guest readback adapter edits');text=text.replace(before,after)
 ast.parse(text);return text.encode()

def emit(root,output):
 root=root.absolute();output=output.absolute();held=source(root);need(not output.exists() and not any(p.is_symlink() for p in (output,*output.parents)),'fresh ordinary emission');target=output/NEW;target.mkdir(parents=True,mode=0o700);counts={}
 for name in MODULES:
  raw,count=adapt((root/OLD/name).read_bytes(),name);(target/name).write_bytes(raw);counts[name]=count
 (target/'recovery.py').write_bytes(recovery(root));policy=dict(schema_version=1,status='UNBOUND_DO_NOT_EXECUTE',binding=dict(native_interruption=None,normal_installed16k=None),authority='PRIVATE_TEST_ONLY_NO_RELEASE_ADMISSION',required_before_binding=['Actual Root accepted generic4K interruption REMOVE-phase stopped/killed writer and external recovery','Actual Root accepted full ALPM-installed normal16384 lifecycle for this exact provider','Current owned native interruption snapshot/runner/inputs and live leased574 producer','No staged-only16K, normal4K or source-only receipt substitutes'])
 (target/'input-policy.json').write_bytes(encoded(policy));(target/'dependencies.json').write_bytes(encoded(dict(schema_version=1,files=held['files'])))
 own={p.relative_to(output).as_posix():pin(p.read_bytes()) for p in target.iterdir() if p.is_file()};(target/'source-manifest.json').write_bytes(encoded(dict(schema_version=1,files=own)))
 result=dict(status='DERIVED_SOURCE_ONLY_INTERRUPTED16K_INPUTS_UNBOUND',native_semantics=NATIVE,source_files=len(held['files']),literal_edits=counts,owner_validator_edits=2,files={p.relative_to(output).as_posix():pin(p.read_bytes()) for p in target.iterdir() if p.is_file()},runtime_observations=10,root_maps=20,scope='DISPOSABLE_FULL574_ALPM_INTERRUPTED_REMOVE_PHASE_ONLY',native='NOT_RUN',generic16k='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED');(output/'adaptation.json').write_bytes(encoded(result));return result
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();print(json.dumps(emit(a.source,a.output),sort_keys=True))
