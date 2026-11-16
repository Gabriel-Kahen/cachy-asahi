#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Fenced MODEL qualification-plan, raw proof and all fourteen child joins."""
import copy
import importlib.util
from pathlib import Path
import sys
import unittest


def fence(event,args):
 if event.startswith(('subprocess.','socket.','ctypes.'))or event in('os.system','os.exec','os.fork','os.posix_spawn','fcntl.flock','resource.setrlimit'):
  raise AssertionError('Reader13 qualification MODEL forbids actor/network/authority: '+event)


sys.addaudithook(fence)
HERE=Path(__file__).resolve().parent
def load(name):
 spec=importlib.util.spec_from_file_location('reader13_qual_model_'+name,HERE/(name+'.py'))
 module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
R=load('reader');S,E=R.S,R.E;M=load('test_mounts');M.S=S;M.E=E


def life():return dict(natural_exit=True,group_absent=True,leader_held_until_group_inspection=True,exit_observed_via_waitpid=True,retirement='REAPED',ownership_lost=False,forced_cleanup=False,exit=0)


def model():
 source_binding=dict(sha='1'*40,ref='refs/heads/codex/MODEL-v13',map_sha256='2'*64,approval='3'*64,run='100',job='101')
 bootstrap=dict(source=source_binding,dispatch_sha256='4'*64);image='sha256:'+'5'*64
 token=S.pin(S.canonical(source_binding))['sha256'][:24];base='rust199-qual-'+token
 owner=dict(source=source_binding,image=image,root_admission_sha256=bootstrap['dispatch_sha256'],token=token,init=base+'-init',prepare=base+'-data',makepkg=base+'-probe',volume=base+'-work',operation='rust199-source-reference-native-v1')
 materials={name:dict(role='stage0'if name.startswith(('cargo','rust-std','rustc-1.98'))else'source')for name in('cargo-1.98.0-aarch64-unknown-linux-gnu.tar.xz','llvm-project-23.1.1.src.tar.xz','rust-std-1.98.0-aarch64-unknown-linux-gnu.tar.xz','rustc-1.98.0-src.tar.xz','rustc-1.99.0-src.tar.xz')}
 source={'actor/mount_proof.py':(b'MODEL independent helper bytes',0o644),'packages/port/rust199-source-reference/inputs.json':(S.canonical(dict(archives=materials)),0o644)}
 q=dict(image_id=image,source_audit=dict(MODEL_review_only=True),rootfs_tree_sha256='6'*64,stage0_tree_sha256='7'*64,source_tree_sha256='8'*64,library_cargo_config_sha256='9'*64)
 plan=dict(schema=4,status='ROOT_PREGRANTED_NATIVE_SOURCE_QUALIFICATION_ONLY',qualification_allowed=True,holds_preserved=True,provider=bootstrap,image_id=image,source_audit=q['source_audit'],rootfs_tree_sha256=q['rootfs_tree_sha256'],volume_owner=owner)
 raw_plan=S.canonical(plan);bodies={'qualification-plan.json':raw_plan};q['qualification_plan']=dict(file='qualification-plan.json',**S.pin(raw_plan));proofs={}
 for phase in('qualification-data','qualification-probe'):
  context=dict(source=source_binding,dispatch_sha256=bootstrap['dispatch_sha256'],input_admission_sha256=S.pin(raw_plan)['sha256'],image_id=image,volume_token=token,phase=phase)
  envelope,rows,*_=M.proof_model(phase,context=context,helper_sha256=S.pin(source['actor/mount_proof.py'][0])['sha256']);proofs[phase]=envelope;bodies.update(rows)
 q['kernel_mount_proofs']=proofs
 data=[];probes=[]
 for phase,vectors,rows in [('data',[['/usr/bin/bsdtar','--no-same-owner','--no-same-permissions','-xf','/materials/'+name,'-C','/work/build/stage0-unpack'if row['role']=='stage0'else'/work/build']for name,row in materials.items()],data),('probe',E.PROBES,probes)]:
  for index,argv in enumerate(vectors):
   stdout,stderr=phase+'-'+str(index)+'.stdout',phase+'-'+str(index)+'.stderr';bodies[stdout]=b'MODEL child output\n';bodies[stderr]=b''
   rows.append(dict(argv=argv,returncode=0,lifecycle=life(),stdout=stdout,stderr=stderr,kernel_mount_proof_sha256=proofs['qualification-'+phase]['receipt']['sha256']))
 bodies['data-commands.json']=S.canonical(data);bodies['probe-commands.json']=S.canonical(probes);q['probe_receipts']=probes
 q['data_commands']=dict(file='data-commands.json',**S.pin(bodies['data-commands.json']))
 assembly=dict(status='PASS_SOURCE_STAGE0_ASSEMBLY_DATA_ONLY',native_runtime_qualified=False,kernel_mount_proof=proofs['qualification-data'],qualification_plan=q['qualification_plan'],data_commands=q['data_commands'],**{k:q[k]for k in('stage0_tree_sha256','source_tree_sha256','library_cargo_config_sha256')})
 bodies['assembly.json']=S.canonical(assembly)
 return q,bootstrap,source,bodies


def verify(args):return E.qualification_kernel(*args[:3],args[3].__getitem__)


class QualificationControls(unittest.TestCase):
 def setUp(self):S.END=None
 def refuses(self,args):
  with self.assertRaises((S.Hold,KeyError)):verify(args)
 def test_both_proofs_and_all_fourteen_children_join(self):
  args=model();result=verify(args);self.assertEqual(set(result),{'qualification-data','qualification-probe'})
  self.assertEqual(result['qualification-data']['context']['input_admission_sha256'],args[0]['qualification_plan']['sha256'])
 def test_missing_plan_or_raw_receipt_is_not_substituted_by_summary(self):
  for name in('qualification-plan.json','kernel-mountinfo-qualification-data.raw','kernel-mount-proof-qualification-probe.json','data-commands.json','assembly.json','probe-commands.json'):
   args=model();args[3].pop(name)
   with self.subTest(name=name):self.refuses(args)
 def test_both_phase_envelopes_required(self):
  for phase in('qualification-data','qualification-probe'):
   args=model();args[0]['kernel_mount_proofs'].pop(phase);self.refuses(args)
 def test_plan_source_provider_image_and_owner_are_whole_bound(self):
  for mutate in(lambda p:p['provider']['source'].update(job='999'),lambda p:p.update(image_id='sha256:'+'a'*64),lambda p:p['volume_owner'].update(token='b'*24)):
   args=model();plan=S.decode(args[3]['qualification-plan.json']);mutate(plan);args[3]['qualification-plan.json']=S.canonical(plan)
   # Even the supplied descriptor is updated: kernel context must still refuse.
   args[0]['qualification_plan'].update(S.pin(args[3]['qualification-plan.json']));self.refuses(args)
 def test_every_data_and_probe_child_requires_same_phase_proof(self):
  for phase,count in(('data',5),('probe',9)):
   for index in range(count):
    args=model();name=phase+'-commands.json';rows=S.decode(args[3][name]);rows[index]['kernel_mount_proof_sha256']='a'*64
    args[3][name]=S.canonical(rows)
    if phase=='data':
     args[0]['data_commands'].update(S.pin(args[3][name]));assembly=S.decode(args[3]['assembly.json']);assembly['data_commands']=args[0]['data_commands'];args[3]['assembly.json']=S.canonical(assembly)
    else:args[0]['probe_receipts']=rows
    with self.subTest(phase=phase,index=index):self.refuses(args)
 def test_incomplete_or_changed_data_vector_refuses(self):
  for change in('missing','argv'):
   args=model();rows=S.decode(args[3]['data-commands.json'])
   if change=='missing':rows.pop()
   else:rows[0]['argv'][0]='/usr/bin/true'
   args[3]['data-commands.json']=S.canonical(rows);args[0]['data_commands'].update(S.pin(args[3]['data-commands.json']))
   assembly=S.decode(args[3]['assembly.json']);assembly['data_commands']=args[0]['data_commands'];args[3]['assembly.json']=S.canonical(assembly);self.refuses(args)
 def test_forced_failed_child_and_wrong_capture_refuse(self):
  for mutate in(lambda r:r['lifecycle'].update(forced_cleanup=True),lambda r:r.update(returncode=1),lambda r:r.update(stdout='MODEL-foreign.stdout')):
   args=model();rows=S.decode(args[3]['probe-commands.json']);mutate(rows[0]);args[0]['probe_receipts']=rows;args[3]['probe-commands.json']=S.canonical(rows);self.refuses(args)
 def test_probe_command_file_cannot_be_detached_from_result(self):
  args=model();rows=S.decode(args[3]['probe-commands.json']);rows[0]['kernel_mount_proof_sha256']='f'*64;args[3]['probe-commands.json']=S.canonical(rows);self.refuses(args)
 def test_assembly_cannot_select_different_data_proof_plan_or_command_file(self):
  for key in('kernel_mount_proof','qualification_plan','data_commands'):
   args=model();assembly=S.decode(args[3]['assembly.json']);assembly[key]=None;args[3]['assembly.json']=S.canonical(assembly);self.refuses(args)
 def test_changed_helper_or_alias_profile_refuses(self):
  args=model();args[2]['actor/mount_proof.py']=(b'MODEL different helper',0o644);self.refuses(args)
  args=model();ref=args[0]['kernel_mount_proofs']['qualification-probe']['receipt'];doc=S.decode(args[3][ref['file']]);doc['profile']='work-only';args[3][ref['file']]=S.canonical(doc);ref.update(S.pin(args[3][ref['file']]));self.refuses(args)


if __name__=='__main__':unittest.main()
