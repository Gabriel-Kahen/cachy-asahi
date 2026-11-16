#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Fenced MODEL API-owned volume/private-bind chain; no daemon/path access."""
import ast
import copy
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


def fence(event,args):
 if event.startswith(('subprocess.','socket.','ctypes.'))or event in('os.system','os.exec','os.fork','os.posix_spawn','fcntl.flock','resource.setrlimit'):
  raise AssertionError('Reader14 owned-bind MODEL forbids actors/network/authority: '+event)


sys.addaudithook(fence)
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('reader14_owned_bind_model',HERE/'reader.py')
R=importlib.util.module_from_spec(spec);spec.loader.exec_module(R);S,E=R.S,R.E


def model(phase='build',binding=None):
 binding=copy.deepcopy(binding)if binding is not None else dict(sha='1'*40,ref='refs/heads/codex/MODEL-v14',map_sha256='2'*64,approval='3'*64,run='100',job='101')
 token=S.pin(S.canonical(binding))['sha256'][:24];volume=('rust199-qual-'if phase=='bootstrap'else'rust199-')+token+'-work'
 labels={'cachy-asahi.'+k:v for k,v in dict(operation='rust199-source-reference-native-v1',source=binding['sha'],run=binding['run'],job=binding['job'],token=token,role=('qualification-'if phase=='bootstrap'else'')+'volume').items()}
 daemon=dict(ID='MODEL-DAEMON-ID',DockerRootDir='/MODEL/docker',OSType='linux',Architecture='aarch64',CgroupVersion='2',SecurityOptions=['name=seccomp,profile=builtin'],OperatingSystem='MODEL hosted Linux VM')
 work=daemon['DockerRootDir']+'/volumes/'+volume+'/_data';row=dict(Name=volume,Driver='local',Scope='local',Options=None,Labels=labels,Mountpoint=work)
 def snapshot(value):
  raw=S.canonical(value);return dict(json=raw.decode(),pin=S.pin(raw))
 record=dict(schema=14,status='API_OWNED_LOCAL_VOLUME_BIND_DERIVATION_ONLY',endpoint='unix:///var/run/docker.sock',daemon_inspect=snapshot(daemon),volume_inspect=snapshot([row]),volume=volume,labels=labels,daemon_root=daemon['DockerRootDir'],work_source=work,stage0_source=work+'/build/stage0',bind_propagation='rprivate',native_acceptance=False,holds_preserved=True)
 return record,binding,phase,daemon


def observed(target,source,readonly):
 return dict(Type='bind',Source=source,Target=target,ReadOnly=readonly,BindOptions=dict(Propagation='rprivate')),dict(Type='bind',Source=source,Destination=target,RW=not readonly,Propagation='rprivate')


def change_snapshot(args,field,mutate):
 row=args[0][field];value=S.decode(row['json'].encode());mutate(value);raw=S.canonical(value);row.update(json=raw.decode(),pin=S.pin(raw));return args


class OwnedBindControls(unittest.TestCase):
 def setUp(self):S.END=None
 def refuses(self,args):
  with self.assertRaisesRegex(S.Hold,'OWNED_BIND_'):E.owned_work_bind(*args)
 def test_both_phase_models_derive_only_exact_daemon_volume_paths(self):
  for phase in('bootstrap','build'):
   args=model(phase);facts=E.owned_work_bind(*args)
   self.assertEqual(facts['work_source'],args[0]['work_source']);self.assertEqual(facts['stage0_source'],args[0]['work_source']+'/build/stage0')
 def test_daemon_and_volume_json_are_exact_whole_bodies(self):
  for field in('daemon_inspect','volume_inspect'):
   args=model();args[0][field]['json']+='\n';self.refuses(args)
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
 def test_mountpoint_cannot_be_a_different_host_path_or_lexical_alias(self):
  for path in('/MODEL/arbitrary','/MODEL/docker/../docker','/MODEL//docker','relative','/MODEL/docker/'):
   args=change_snapshot(model(),'volume_inspect',lambda rows:rows[0].update(Mountpoint=path))
   with self.subTest(path=path):self.refuses(args)
 def test_daemon_root_labels_are_not_filesystem_paths_to_open(self):
  args=model()
  with patch.object(Path,'stat',side_effect=AssertionError('daemon-owned directory must not be statted')),patch.object(Path,'resolve',side_effect=AssertionError('daemon-owned directory must not be resolved')):
   self.assertEqual(E.owned_work_bind(*args)['work_source'],args[0]['work_source'])
 def test_default_driver_local_scope_empty_options_only(self):
  for key,value in[('Driver','MODEL-plugin'),('Scope','global'),('Options',[]),('Options',False),('Options',{'device':'/MODEL/foreign'})]:
   with self.subTest(key=key,value=value):self.refuses(change_snapshot(model(),'volume_inspect',lambda rows:rows[0].update({key:value})))
 def test_exact_current_owned_name_and_six_labels(self):
  for mutate in(lambda rows:rows[0].update(Name='MODEL-foreign'),lambda rows:rows[0]['Labels'].update({'cachy-asahi.job':'999'}),lambda rows:rows[0]['Labels'].update(extra='MODEL')):
   self.refuses(change_snapshot(model(),'volume_inspect',mutate))
 def test_no_paths_from_record_can_replace_api_derived_sources(self):
  for key in('work_source','stage0_source','daemon_root','volume'):
   args=model();args[0][key]='/MODEL/FORGED';self.refuses(args)
 def test_unknown_fields_or_claimed_runtime_pass_refuse(self):
  for mutate in(lambda d:d.update(extra=True),lambda d:d.update(native_acceptance=True),lambda d:d.update(status='PASS'),lambda d:d.update(bind_propagation='rslave')):
   args=model();mutate(args[0]);self.refuses(args)
 def test_one_and_only_one_api_volume_row(self):
  for mutate in(lambda rows:rows.clear(),lambda rows:rows.append(copy.deepcopy(rows[0]))):self.refuses(change_snapshot(model(),'volume_inspect',mutate))
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
