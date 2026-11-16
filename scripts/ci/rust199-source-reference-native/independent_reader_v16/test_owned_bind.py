#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Fenced MODEL private job directory/private-bind chain; no daemon/path access."""
import ast
import copy
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


def fence(event,args):
 if event.startswith(('subprocess.','socket.','ctypes.'))or event in('os.system','os.exec','os.fork','os.posix_spawn','fcntl.flock','resource.setrlimit'):
  raise AssertionError('Reader15 owned-bind MODEL forbids actors/network/authority: '+event)


sys.addaudithook(fence)
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('reader15_owned_bind_model',HERE/'reader.py')
R=importlib.util.module_from_spec(spec);spec.loader.exec_module(R);S,E=R.S,R.E


def model(phase='build',binding=None):
 binding=copy.deepcopy(binding)if binding is not None else dict(sha='1'*40,ref='refs/heads/codex/MODEL-v15',map_sha256='2'*64,approval='3'*64,run='100',job='101')
 token=S.pin(S.canonical(binding))['sha256'][:24];volume=('rust199-qual-'if phase=='bootstrap'else'rust199-')+token+'-work'
 labels={'cachy-asahi.'+k:v for k,v in dict(operation='rust199-source-reference-native-v1',source=binding['sha'],run=binding['run'],job=binding['job'],token=token,role=('qualification-'if phase=='bootstrap'else'')+'volume').items()}
 daemon=dict(ID='MODEL-DAEMON-ID',DockerRootDir='/MODEL/docker',OSType='linux',Architecture='aarch64',CgroupVersion='2',SecurityOptions=['name=seccomp,profile=builtin'],OperatingSystem='MODEL hosted Linux VM')
 root='/MODEL/private-job/rust199-hosted';work=root+'/'+volume
 def snapshot(value):
  raw=S.canonical(value);return dict(json=raw.decode(),pin=S.pin(raw))
 node=dict(device=12,inode=103,uid=1001,gid=1001,mode=0o700)
 record=dict(schema=15,status='OWNED_EXTERNAL_JOB_DIRECTORY_PRIVATE_BIND_ONLY',endpoint='unix:///var/run/docker.sock',daemon_inspect=snapshot(daemon),volume=volume,labels=labels,daemon_root=daemon['DockerRootDir'],job_root=root,job_root_node=dict(node,inode=102),job_root_mount_id=54,work_source=work,stage0_source=work+'/build/stage0',workspace_node=node,workspace_mount_id=54,nonce='a'*64,producer=dict(source=binding,token=token,operation='rust199-source-reference-native-v1'),bind_propagation='rprivate',native_acceptance=False,holds_preserved=True)
 return record,binding,phase,daemon


def observed(target,source,readonly):
 return dict(Type='bind',Source=source,Target=target,ReadOnly=readonly,BindOptions=dict(Propagation='rprivate')),dict(Type='bind',Source=source,Destination=target,RW=not readonly,Propagation='rprivate')


def change_snapshot(args,field,mutate):
 row=args[0][field];value=S.decode(row['json'].encode());mutate(value);raw=S.canonical(value);row.update(json=raw.decode(),pin=S.pin(raw));return args


class OwnedBindControls(unittest.TestCase):
 def setUp(self):S.END=None
 def refuses(self,args):
  with self.assertRaisesRegex(S.Hold,'OWNED_BIND_'):E.owned_work_bind(*args)
 def test_both_phase_models_derive_only_exact_job_token_paths(self):
  for phase in('bootstrap','build'):
   args=model(phase);facts=E.owned_work_bind(*args)
   self.assertEqual(facts['work_source'],args[0]['work_source']);self.assertEqual(facts['stage0_source'],args[0]['work_source']+'/build/stage0')
 def test_daemon_json_is_exact_whole_body(self):
  args=model();args[0]['daemon_inspect']['json']+='\n';self.refuses(args)
 def test_daemon_snapshot_only_has_exact_seven_safe_fields(self):
  for mutate in(lambda d:d.update(HTTPProxy='MODEL_FORBIDDEN'),lambda d:d.pop('ID')):
   self.refuses(change_snapshot(model(),'daemon_inspect',mutate))
 def test_rootless_desktop_remote_and_wrong_platform_refuse(self):
  for key,value in[('OSType','windows'),('Architecture','amd64'),('CgroupVersion','1'),('OperatingSystem','Docker Desktop'),('SecurityOptions',['name=rootless'])]:
   args=change_snapshot(model(),'daemon_inspect',lambda d:d.update({key:value}))
   with self.subTest(key=key):self.refuses(args)
  args=model();args[0]['endpoint']='tcp://MODEL_REMOTE:2375';self.refuses(args)
 def test_safe_daemon_identity_must_match_selected_phase_daemon(self):
  args=change_snapshot(model(),'daemon_inspect',lambda d:d.update(ID='MODEL_OTHER_DAEMON'));self.refuses(args)
 def test_daemon_root_is_never_selected_as_workspace_or_ancestor(self):
  for path in('/MODEL/docker','/MODEL/docker/work','/MODEL'):
   args=model();r=args[0];r.update(job_root=path,work_source=path+'/'+r['volume'],stage0_source=path+'/'+r['volume']+'/build/stage0');self.refuses(args)
 def test_no_live_path_resolve_stat_or_daemon_traversal(self):
  args=model()
  with patch.object(Path,'stat',side_effect=AssertionError('retained DATA only')),patch.object(Path,'resolve',side_effect=AssertionError('retained DATA only')):
   self.assertEqual(E.owned_work_bind(*args)['work_source'],args[0]['work_source'])
 def test_directory_nodes_owner_mode_types_and_mount_shadow_refuse(self):
  for field,value in(('uid',0),('gid',1002),('mode',0o755),('device',-1),('inode',0),('inode',True)):
   for key in('job_root_node','workspace_node'):
    args=model();args[0][key][field]=value;self.refuses(args)
  for key,value in(('workspace_mount_id',55),('workspace_mount_id',True),('job_root_mount_id',0),('job_root_mount_id',True)):
   args=model();args[0][key]=value;self.refuses(args)
  args=model();args[0]['workspace_node']['inode']=args[0]['job_root_node']['inode'];self.refuses(args)
  args=model();args[0]['workspace_node']['device']+=1;self.refuses(args)
 def test_fixed_direct_token_child_no_path_alias_selection(self):
  for path in('/MODEL/arbitrary','/MODEL/private-job/rust199-hosted/../private-job','/MODEL//private-job','relative','/MODEL/private-job/rust199-hosted/'):
   args=model();args[0]['job_root']=path;self.refuses(args)
  for key in('work_source','stage0_source','daemon_root','volume'):
   args=model();args[0][key]='/MODEL/FORGED';self.refuses(args)
  args=model();r=args[0];root='/MODEL/arbitrary-owned-job';r.update(job_root=root,work_source=root+'/'+r['volume'],stage0_source=root+'/'+r['volume']+'/build/stage0')
  with self.assertRaisesRegex(S.Hold,'OWNED_BIND_FIXED_HOSTED_ENTRY_JOB_ROOT'):E.owned_work_bind(*args)
 def test_exact_source_token_six_labels_and_creator_nonce(self):
  for mutate in(lambda r:r['labels'].update(extra='MODEL'),lambda r:r['labels'].update({'cachy-asahi.job':'999'}),lambda r:r['producer']['source'].update(approval='f'*64),lambda r:r['producer'].update(operation='MODEL'),lambda r:r['producer'].update(token='f'*24),lambda r:r.update(nonce='a'*63)):
   args=copy.deepcopy(model());mutate(args[0]);self.refuses(args)
 def test_unknown_fields_or_claimed_runtime_pass_refuse(self):
  for mutate in(lambda d:d.update(extra=True),lambda d:d.update(native_acceptance=True),lambda d:d.update(status='PASS'),lambda d:d.update(bind_propagation='rslave'),lambda d:d.update(schema=True),lambda d:d.update(volume_inspect={})):
   args=model();mutate(args[0]);self.refuses(args)
 def test_exact_configured_and_realized_private_bind_for_work_and_aliases(self):
  args=model();work=args[0]['work_source']
  for target in('/work','/stage0','/work/build/stage0'):
   source=work+('/build/stage0'if target!='/work'else'');c,a=observed(target,source,target!='/work')
   E.private_bind(c,a,target,source,target!='/work')
 def test_bind_propagation_source_access_and_volume_fallback_refuse(self):
  for mutate in(lambda c,a:c['BindOptions'].update(Propagation='rslave'),lambda c,a:c['BindOptions'].update(NonRecursive=False),lambda c,a:a.update(Propagation=''),lambda c,a:a.update(Source='/MODEL/foreign'),lambda c,a:a.update(RW=True),lambda c,a:a.update(Type='volume'),lambda c,a:c.update(VolumeOptions={'NoCopy':True})):
   c,a=observed('/stage0','/MODEL/work/build/stage0',True);mutate(c,a)
   with self.assertRaisesRegex(S.Hold,'OWNED_BIND_'):E.private_bind(c,a,'/stage0','/MODEL/work/build/stage0',True)
 def test_kernel_and_phase_command_proof_guards_remain_exact_reader13(self):
  def functions(path):
   text=path.read_text();return {n.name:ast.get_source_segment(text,n)for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)}
  before=functions(HERE.parent/'independent_reader_v13/evidence.py');after=functions(HERE/'evidence.py')
  for name in('kernel_mountinfo','kernel_proof','qualification_kernel','actor_output','natural','operations','qualification','producer','qualifier_inspected'):
   self.assertEqual(before[name],after[name],name)


if __name__=='__main__':unittest.main()
