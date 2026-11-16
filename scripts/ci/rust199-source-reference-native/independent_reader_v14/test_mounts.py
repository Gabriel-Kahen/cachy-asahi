#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Independent sanitized ACTUAL API plus explicit MODEL kernel mountinfo controls."""
import copy
import importlib.util
from pathlib import Path
import sys
import unittest


def fence(event,args):
 if event.startswith(('subprocess.','socket.','ctypes.'))or event in('os.system','os.exec','os.fork','os.posix_spawn','fcntl.flock','resource.setrlimit'):
  raise AssertionError('Reader13 mount MODEL forbids actor/network/authority: '+event)


sys.addaudithook(fence)
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('reader13_mount_model',HERE/'reader.py')
R=importlib.util.module_from_spec(spec);spec.loader.exec_module(R)
S,E=R.S,R.E
ACTUAL=dict(bytes=6302,sha256='e8cf3b1f7dbefc763f93fc91c501e6d28d9a79e0d83cde6a57e9c180d83edf74')


def kernel_model(profile='stage0-aliases'):
 # These rows are deliberately MODEL data, not observations from43900684447.
 rows=['1 2 0:1 / / ro,nosuid - overlay MODEL-root ro',
       '10 1 8:1 /MODEL/volume/_data /work rw,nosuid,nodev - ext4 /dev/MODEL rw']
 if profile=='stage0-aliases':
  rows+=['11 1 8:1 /MODEL/volume/_data/build/stage0 /stage0 ro,nosuid,nodev - ext4 /dev/MODEL rw',
         '12 10 8:1 /MODEL/volume/_data/build/stage0 /work/build/stage0 ro,nosuid,nodev - ext4 /dev/MODEL rw']
 return ('\n'.join(rows)+'\n').encode()


def proof_model(phase='qualification-probe',context=None,helper_sha256='7'*64,invocation=None):
 profile='work-only'if phase in('qualification-data','prepare')else'stage0-aliases'
 suffix=phase if phase.startswith('qualification-')else phase+'-'+(invocation or('123-'+'a'*32))
 source=dict(sha='1'*40,ref='refs/heads/codex/MODEL-v13',map_sha256='2'*64,approval='3'*64,run='100',job='101')
 context=copy.deepcopy(context)if context is not None else dict(source=source,dispatch_sha256='4'*64,input_admission_sha256='5'*64,
  image_id='sha256:'+'6'*64,volume_token=S.pin(S.canonical(source))['sha256'][:24],phase=phase)
 raw=kernel_model(profile);name='kernel-mountinfo-'+suffix+'.raw';raw_ref=dict(file=name,**S.pin(raw))
 replay=E.kernel_mountinfo(raw,profile)
 doc=dict(schema=13,status='PASS_KERNEL_MOUNTINFO_PREENTRY_DATA_ONLY',context=copy.deepcopy(context),
  profile=profile,helper_sha256=helper_sha256,mountinfo=raw_ref,mounts=replay['mounts'],alias_root=replay['alias_root'],
  order=dict(stage='BEFORE_WORKSPACE_MUTATION_AND_TOOLS',commands_before=0,workspace_writes_before=0),native_acceptance=False,holds_preserved=True)
 receipt_raw=S.canonical(doc);receipt_name='kernel-mount-proof-'+suffix+'.json'
 envelope=dict(receipt=dict(file=receipt_name,**S.pin(receipt_raw)),mountinfo=raw_ref)
 bodies={name:raw,receipt_name:receipt_raw}
 return envelope,bodies,context,profile,helper_sha256


def changed_proof(args,mutate):
 envelope,bodies,*_=args;name=envelope['receipt']['file'];doc=S.decode(bodies[name]);mutate(doc)
 bodies[name]=S.canonical(doc);envelope['receipt'].update(S.pin(bodies[name]));return args


def verify(args):
 envelope,bodies,*other=args
 return E.kernel_proof(envelope,bodies.__getitem__,*other)


class KernelControls(unittest.TestCase):
 def setUp(self):S.END=None
 def refuses(self,raw,profile='stage0-aliases'):
  with self.assertRaisesRegex(S.Hold,'MOUNTINFO_'):E.kernel_mountinfo(raw,profile)
 def test_sanitized_actual_is_api_only_without_kernel_credit(self):
  raw=(HERE/'fixtures/source344-probe-mount.ACTUAL.json').read_bytes();self.assertEqual(S.pin(raw),ACTUAL)
  actual=S.decode(raw);self.assertEqual(actual['run'],43900684447);self.assertFalse(actual['acceptance'])
  observed=actual['projection'];rows={v['Destination']:v for v in observed['Mounts']};configured={v['Target']:v for v in observed['HostConfig']['Mounts']}
  root=rows['/work']['Source']
  for target in('/stage0','/work/build/stage0'):
   self.assertEqual(rows[target]['Source'],root);self.assertNotIn('Subpath',rows[target])
   self.assertEqual(configured[target]['VolumeOptions']['Subpath'],'build/stage0')
   self.assertFalse(rows[target]['RW']);self.assertEqual(E.api_volume_source(rows[target],root,'build/stage0'),root)
  self.assertNotIn('mountinfo',actual);self.refuses(b'')
 def test_model_exact_aliases_and_work_profile(self):
  proof=E.kernel_mountinfo(kernel_model(),'stage0-aliases')
  self.assertEqual(proof['alias_root'],'/MODEL/volume/_data/build/stage0')
  self.assertEqual(set(proof['mounts']),{'/work','/stage0','/work/build/stage0'})
  self.assertEqual(E.kernel_mountinfo(kernel_model('work-only'),'work-only')['mounts']['/work']['root'],'/MODEL/volume/_data')
 def test_absent_raw_never_replaced_by_hostconfig(self):
  for raw in(None,b'',b'HostConfig.Subpath=build/stage0\n'):
   self.refuses(raw)
 def test_each_alias_root_and_work_root_changed_refuses(self):
  raw=kernel_model()
  for old,new in[(b'_data/build/stage0 /stage0',b'_data/build /stage0'),
                (b'_data/build/stage0 /work/build/stage0',b'_data/stage0 /work/build/stage0'),
                (b'_data /work',b'_data/OTHER /work')]:
   with self.subTest(change=(old,new)):self.refuses(raw.replace(old,new))
 def test_wrong_device_filesystem_or_source_refuses(self):
  raw=kernel_model()
  for old,new in[(b'11 1 8:1',b'11 1 8:2'),(b'12 10 8:1',b'12 10 9:1'),
                (b'/stage0 ro,nosuid,nodev - ext4',b'/stage0 ro,nosuid,nodev - xfs'),
                (b'/stage0 ro,nosuid,nodev - ext4 /dev/MODEL',b'/stage0 ro,nosuid,nodev - ext4 /dev/OTHER')]:
   with self.subTest(change=(old,new)):self.refuses(raw.replace(old,new))
 def test_work_readonly_or_alias_writable_refuses(self):
  raw=kernel_model()
  for old,new in[(b'/work rw,',b'/work ro,'),(b'/stage0 ro,',b'/stage0 rw,'),
                (b'/work/build/stage0 ro,',b'/work/build/stage0 rw,'),
                (b'/stage0 ro,',b'/stage0 ro,rw,')]:
   with self.subTest(change=(old,new)):self.refuses(raw.replace(old,new))
 def test_effectively_readonly_superblock_or_inconsistent_superblock_refuses(self):
  self.refuses(kernel_model().replace(b'/dev/MODEL rw',b'/dev/MODEL ro'))
  self.refuses(kernel_model().replace(b'/stage0 ro,nosuid,nodev - ext4 /dev/MODEL rw',b'/stage0 ro,nosuid,nodev - ext4 /dev/MODEL ro'))
 def test_nested_alias_parent_must_be_work_mount(self):
  self.refuses(kernel_model().replace(b'12 10 ',b'12 999 '))
 def test_top_alias_and_work_parent_require_visible_readonly_root(self):
  self.refuses(kernel_model().replace(b'11 1 ',b'11 999 '))
  self.refuses(kernel_model().replace(b'10 1 ',b'10 999 ').replace(b'11 1 ',b'11 999 '))
  self.refuses(kernel_model().replace(b'/ / ro,nosuid',b'/ / rw,nosuid'))
  self.refuses(b'\n'.join(kernel_model().splitlines()[1:])+b'\n')
 def test_selected_mounts_are_not_shared_or_slave(self):
  for field in(b'shared:1',b'master:1',b'propagate_from:1',b'unbindable'):
   with self.subTest(field=field):self.refuses(kernel_model().replace(b'/work rw,nosuid,nodev -',b'/work rw,nosuid,nodev '+field+b' -'))
 def test_both_targets_mandatory(self):
  lines=kernel_model().splitlines(keepends=True)
  for index in(1,2,3):self.refuses(b''.join(v for i,v in enumerate(lines)if i!=index))
 def test_duplicate_targets_and_ids_refuse(self):
  raw=kernel_model();self.refuses(raw+raw.splitlines(keepends=True)[-1]);self.refuses(raw.replace(b'12 10',b'11 10'))
  self.refuses(raw+b'13 1 8:1 /MODEL/other /stage0 ro - ext4 /dev/MODEL rw\n')
 def test_work_or_alias_descendant_shadow_mount_refuses(self):
  for target in('/work/build','/stage0/bin','/work/build/stage0/bin','/work/recipe'):
   with self.subTest(target=target):self.refuses(kernel_model()+f'15 10 8:1 /MODEL/other {target} ro - ext4 /dev/MODEL rw\n'.encode())
 def test_ambiguous_unknown_or_recursive_escapes_refuse(self):
  raw=kernel_model()
  for path in(b'/wo\\162k',b'/wo\\134162k',b'/wo\\011rk',b'/wo\\012rk',b'/wo\\134rk'):
   with self.subTest(path=path):self.refuses(raw.replace(b'/work rw',path+b' rw'))
 def test_target_canonicality_refuses(self):
  raw=kernel_model()
  for path in(b'/work/',b'/work//',b'/./work',b'/other/../work',b'work'):
   with self.subTest(path=path):self.refuses(raw.replace(b'/work rw',path+b' rw'))
 def test_wrong_alias_profile_refuses(self):
  self.refuses(kernel_model(),'work-only');self.refuses(kernel_model('work-only'),'stage0-aliases');self.refuses(kernel_model(),'unknown')
 def test_whole_raw_bounds_and_terminal_newline(self):
  for raw in(kernel_model()[:-1],kernel_model().replace(b'\n',b'\r\n'),b'\0'+kernel_model(),b'x'*(S.MIB+1),b'\xff\n'):
   self.refuses(raw)
 def test_row_and_field_count_bounds(self):
  for raw in(kernel_model()+b'x\n'*4096,kernel_model().replace(b' - ext4 ',b' - ext4  '),kernel_model().replace(b'10 1 ',b'10  1 '),kernel_model().replace(b'10 1 ',b'0 1 '),kernel_model().replace(b'8:1',b'08:1')):
   self.refuses(raw)
 def test_api_only_narrow_observed_source_representations(self):
  for source in('/MODEL/_data','/MODEL/_data/build/stage0'):
   self.assertEqual(E.api_volume_source(dict(Source=source),'/MODEL/_data','build/stage0'),source)
  for row in(dict(Source='/MODEL/_data/OTHER'),dict(Source='/MODEL/_data',Subpath=''),dict(Source='/MODEL/_data',Subpath='stage0')):
   with self.assertRaisesRegex(S.Hold,'MOUNTINFO_API_EXACT'):E.api_volume_source(row,'/MODEL/_data','build/stage0')

 def test_all_six_phase_proofs_replay_only_model_data(self):
  for phase in('qualification-data','qualification-probe','prepare','makepkg','build','package'):
   with self.subTest(phase=phase):
    args=proof_model(phase);value=verify(args)
    self.assertEqual(value['receipt_sha256'],args[0]['receipt']['sha256'])
    self.assertEqual(value['order_scope'],'SOURCE_ENFORCED_NO_RETAINED_COMMAND_TIMESTAMPS')
 def test_kernel_raw_and_receipt_both_required(self):
  for role in('receipt','mountinfo'):
   args=proof_model();del args[1][args[0][role]['file']]
   with self.subTest(role=role),self.assertRaisesRegex(S.Hold,'MOUNTINFO_RETAINED_FILE_MISSING'):verify(args)
 def test_raw_and_receipt_whole_pin_changes_refuse(self):
  for role in('receipt','mountinfo'):
   args=proof_model();args[1][args[0][role]['file']]+=b'changed\n'
   with self.subTest(role=role),self.assertRaisesRegex(S.Hold,'MOUNTINFO_WHOLE_RETAINED'):verify(args)
 def test_each_source_context_binding_is_exact(self):
  for key in('sha','ref','map_sha256','approval','run','job'):
   args=changed_proof(proof_model(),lambda d:d['context']['source'].update({key:'MODEL_CHANGED'}))
   with self.subTest(key=key),self.assertRaisesRegex(S.Hold,'MOUNTINFO_EXACT_SOURCE_HELPER_CONTEXT'):verify(args)
 def test_dispatch_admission_image_token_phase_are_exact(self):
  for key in('dispatch_sha256','input_admission_sha256','image_id','volume_token','phase'):
   args=changed_proof(proof_model(),lambda d:d['context'].update({key:'MODEL_CHANGED'}))
   with self.subTest(key=key),self.assertRaisesRegex(S.Hold,'MOUNTINFO_EXACT_SOURCE_HELPER_CONTEXT'):verify(args)
 def test_helper_profile_native_flags_and_receipt_schema_cannot_drift(self):
  for key,value in[('helper_sha256','8'*64),('profile','work-only'),('native_acceptance',True),('holds_preserved',False),('schema',True),('status','PASS')]:
   args=changed_proof(proof_model(),lambda d:d.update({key:value}))
   with self.subTest(key=key),self.assertRaises(S.Hold):verify(args)
 def test_both_zero_counts_require_exact_integer_and_preentry_stage(self):
  for key,value in[('commands_before',1),('workspace_writes_before',1),('commands_before',False),('workspace_writes_before',0.0),('stage','AFTER_TOOLS')]:
   args=changed_proof(proof_model(),lambda d:d['order'].update({key:value}))
   with self.subTest(key=key,value=value),self.assertRaisesRegex(S.Hold,'MOUNTINFO_SOURCE_ENFORCED_PREENTRY_ONLY'):verify(args)
 def test_producer_summary_cannot_replace_raw_kernel_rows(self):
  for mutate in(lambda d:d['mounts']['/stage0'].update(root='/MODEL/FORGED'),
                lambda d:d['mounts']['/work'].update(mount_id=10.0),
                lambda d:d.update(alias_root='/MODEL/FORGED')):
   args=changed_proof(proof_model(),mutate)
   with self.assertRaisesRegex(S.Hold,'MOUNTINFO_INDEPENDENT_RAW_REPLAY'):verify(args)
 def test_phase_specific_raw_receipt_name_join(self):
  args=proof_model('build');args[0]['receipt']['file']='kernel-mount-proof-build-999-'+'a'*32+'.json'
  with self.assertRaisesRegex(S.Hold,'MOUNTINFO_SAME_ACTOR_INVOCATION_FILES'):verify(args)
 def test_unknown_receipt_fields_and_noncanonical_json_refuse(self):
  args=changed_proof(proof_model(),lambda d:d.update(Root_acceptance=True))
  with self.assertRaisesRegex(S.Hold,'MOUNTINFO_EXACT_RECEIPT_SCHEMA'):verify(args)
  args=proof_model();name=args[0]['receipt']['file'];args[1][name]+=b'\n';args[0]['receipt'].update(S.pin(args[1][name]))
  with self.assertRaisesRegex(S.Hold,'MOUNTINFO_EXACT_RECEIPT_SCHEMA'):verify(args)


if __name__=='__main__':unittest.main()
