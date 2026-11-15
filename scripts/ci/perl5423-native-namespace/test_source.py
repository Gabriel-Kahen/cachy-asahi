#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Actor-fenced pure Source/operand controls. All observations are modeled."""
import importlib.util
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent


def fence(event,args):
    if event.startswith(('subprocess.','socket.','ctypes.')) or event in ('os.system','os.exec','os.fork','os.posix_spawn'):
        raise AssertionError('actor forbidden in Source controls: '+event)
sys.addaudithook(fence)


def module(name,file):
    spec=importlib.util.spec_from_file_location(name,file);result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result);return result


d=module('perl_namespace_data_controls',HERE/'data.py')
p=module('perl_namespace_probe_controls',HERE/'probe.py')
e=module('perl_namespace_entry_controls',HERE/'entry.py')


def modeled():
    a=json.loads((HERE/'admission.TEMPLATE.json').read_bytes())
    a.update(source='1'*40,run='123',job='456',image='sha256:'+'2'*64,approval='3'*64,source_map_sha256='4'*64,token='5'*24,container='perl-namespace-123-'+'5'*12,volume='perl-namespace-123-'+'5'*12+'-work',inputs='/MODELED/inputs')
    return a


class SourceControls(unittest.TestCase):
    def test_null_and_3937_are_never_admission(self):
        with self.assertRaises(ValueError):d.admission(json.loads((HERE/'admission.TEMPLATE.json').read_bytes()))
        a=modeled();d.admission(a);a['source']=d.OLD_SOURCE
        with self.assertRaisesRegex(ValueError,'Source3937'):d.admission(a)

    def test_closed_binding_wrong_domain_path_and_authority_refuse(self):
        for key,value in [('domain_sha256','0'*64),('inputs','/MODELED/../escape'),('image','latest'),('approval',None),('run',True),('container','foreign')]:
            a=modeled();a[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):d.admission(a)
        a=modeled();a['waiver']=True
        with self.assertRaises(ValueError):d.admission(a)

    def test_strict_json_duplicate_nonfinite_and_fraction_refuse(self):
        for raw in (b'{"x":1,"x":2}',b'{"x":NaN}',b'{"x":1e999}',b'{"x":1.5}'):
            with self.assertRaises(ValueError):d.decode(raw)

    def test_bounded_stable_regular_data_and_alias_refusal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);path=root/'DATA';path.write_bytes(b'MODELED')
            self.assertEqual(d.read(path,7),b'MODELED')
            with self.assertRaises(ValueError):d.read(path,6)
            alias=root/'alias';alias.symlink_to(path)
            with self.assertRaises(OSError):d.read(alias)
            alias.unlink();os.link(path,alias)
            with self.assertRaises(ValueError):d.read(path)

    def test_null_entry_stops_before_source_observation_or_actor(self):
        raw=(HERE/'admission.TEMPLATE.json').read_bytes()
        with patch.object(e.data,'read',return_value=raw),patch.object(e.data,'verify_source',side_effect=AssertionError('must not reach source or actors')):
            with self.assertRaises(ValueError):e.run()

    def test_fixed_probe_argv_same_semantics_and_new_source(self):
        a=modeled();sha='6'*64
        for case in p.CASES:
            outer=p.arguments(case,sha,a['source_map_sha256'],a['token'],'--exec-probe')
            tool=p.arguments(case,sha,a['source_map_sha256'],a['token'])
            self.assertEqual(outer[:5],['/usr/bin/python3','-I','-B','/inputs/probe.py','--exec-probe'])
            self.assertEqual(tool[0],'/usr/bin/bwrap' if case==p.CASES[0] else '/usr/bin/unshare')
            self.assertIn('--inner',tool);self.assertNotIn('unconfined',str(tool));self.assertNotIn('--unshare-pid',tool)

    def test_original_helper_and_domain_are_unchanged(self):
        self.assertEqual(d.pin((HERE/'helpers/owned_child.py').read_bytes())['sha256'],d.OWNED_SHA)
        self.assertEqual(d.pin((HERE/'domain.json').read_bytes())['sha256'],d.DOMAIN_SHA)
        provenance=json.loads((HERE/'provenance.json').read_bytes());self.assertFalse(provenance['original_namespace']['equivalent'])

    def test_source_closure_binds_all_modes_bytes_and_no_extra_dirs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);names=['domain.json','entry.sh'];rows={}
            for name in names:
                raw=(HERE/name).read_bytes();(root/name).write_bytes(raw);(root/name).chmod(0o644);rows[name]=dict(**d.pin(raw),mode=0o644)
            m=dict(schema=1,actual=dict(source=None,ref=None,run=None,job=None,approval=None,artifact=None,image=None),files=rows)
            raw=d.encode(m);(root/'source-map.json').write_bytes(raw)
            for name in ('admission.json','host.json'):(root/name).write_bytes(b'{}\n')
            sha=d.pin(raw)['sha256'];d.verify_source(root,sha)
            (root/'EMPTY').mkdir()
            with self.assertRaises(ValueError):d.verify_source(root,sha)
            (root/'EMPTY').rmdir();(root/'entry.sh').write_bytes(b'changed')
            with self.assertRaises(ValueError):d.verify_source(root,sha)

    def test_modeled_proc_capture_rejects_process_reuse(self):
        observer=p.observe;fields=['0']*20;fields[0:4]=['S','1','22','22'];fields[19]='321'
        status='Uid:\t1001 1001 1001 1001\nGid:\t1001 1001 1001 1001\nGroups:\t1001\n'+''.join(k+':\t'+('1' if k=='NoNewPrivs' else '0')+'\n' for k in observer.STATUS)
        count=[0];reuse=[False]
        def raw(path,cap):
            name=Path(path).name
            if name=='stat':
                count[0]+=1;row=list(fields)
                if reuse[0] and count[0]%2==0:row[19]='322'
                return ('22 (MODELED python3) '+' '.join(row)+'\n').encode()
            if name=='status':return status.encode()
            if name in ('uid_map','gid_map'):return b'0 0 4294967295\n'
            if name=='cmdline':return b'/usr/bin/python3\0-I\0-B\0/inputs/entry.py\0'
            return b'MODELED DATA\n'
        def link(path):
            name=Path(path).name
            return '/work/recipe' if name=='cwd' else '/usr/bin/python3.14' if name=='exe' else name+':[123]'
        with patch.object(observer,'bounded',side_effect=raw),patch.object(observer.os,'readlink',side_effect=link),patch.object(observer.os,'uname',return_value=SimpleNamespace(machine='aarch64')),patch.object(observer.os,'sysconf',return_value=4096),patch.object(observer.Path,'iterdir',return_value=iter([Path('/sys/class/net/lo')])),patch.object(observer.socket,'gethostname',return_value='perl5423-native'):
            context=observer.context(22);self.assertEqual((context['starttime'],context['uid'],context['groups']),(321,1001,[1001]))
            reuse[0]=True
            with self.assertRaisesRegex(ValueError,'identity/parent changed'):observer.context(22)


if __name__=='__main__':unittest.main(verbosity=2)
