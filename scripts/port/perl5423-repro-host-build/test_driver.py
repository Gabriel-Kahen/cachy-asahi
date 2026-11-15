#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Controller controls only. Simulated Docker is never build evidence."""
import importlib.util
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('perl13_driver',HERE/'run.py')
api=importlib.util.module_from_spec(spec);spec.loader.exec_module(api)


class Controls(unittest.TestCase):
    def test_capacity_shared_filesystem_peak_and_reserve(self):
        with tempfile.TemporaryDirectory() as tmp:
            def space(path):return types.SimpleNamespace(f_bavail=20*1024, f_frsize=api.MIB, f_favail=200000)
            row=api.guard(Path(tmp),Path(tmp),'test',statvfs=space,meminfo='MemAvailable: 16777216 kB\n')
            self.assertEqual(row['status'],'PASS')
            commit=api.guard(Path(tmp),Path(tmp),'commit',committing=True,inputs=True,statvfs=space,meminfo='MemAvailable: 16777216 kB\n')
            self.assertEqual(sum(r['bytes'] for r in commit['requirements']),4608*api.MIB)
            self.assertEqual(sum(r['bytes'] for r in row['requirements']),5696*api.MIB)
            def tight(path):return types.SimpleNamespace(f_bavail=5695, f_frsize=api.MIB, f_favail=200000)
            self.assertEqual(api.guard(Path(tmp),Path(tmp),'test',statvfs=tight,meminfo='MemAvailable: 16777216 kB\n')['status'],'HOLD_CAPACITY')
            self.assertEqual(api.guard(Path(tmp),Path(tmp),'test',statvfs=space,meminfo='MemAvailable: 8388607 kB\n')['status'],'HOLD_CAPACITY')
            def no_inodes(path):return types.SimpleNamespace(f_bavail=20000,f_frsize=api.MIB,f_favail=0)
            self.assertEqual(api.guard(Path(tmp),Path(tmp),'test',statvfs=no_inodes,meminfo='MemAvailable: 16777216 kB\n')['status'],'HOLD_CAPACITY')

    def test_comparison_checks_entire_archive_and_all_entries(self):
        with tempfile.TemporaryDirectory() as tmp:
            previous=tempfile.tempdir
            with self.assertRaises(OSError):
                with api.scratch(tmp):
                    self.assertEqual(tempfile.tempdir,tmp)
                    raise OSError('scratch failure')
            self.assertEqual(tempfile.tempdir,previous)
            first=Path(tmp)/'a';second=Path(tmp)/'b';first.mkdir();second.mkdir()
            for p in (first,second):
                (p/api.ARCHIVE).write_bytes(b'one');(p/'payload-map.json').write_text('{".MTREE":{"sha256":"a"}}')
            self.assertTrue(api.compare(first,second)['archive_bytes_equal'])
            (second/api.ARCHIVE).write_bytes(b'two')
            self.assertFalse(api.compare(first,second)['archive_bytes_equal'])
            (second/'payload-map.json').write_text('{".MTREE":{"sha256":"b"}}')
            self.assertEqual(api.compare(first,second)['changed'],['.MTREE'])
            self.assertFalse(api.compare(first,second)['all_payload_entries_equal'])

    def test_export_refuses_old_identity_or_wrong_effective_timestamp(self):
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp)
            (out/'makepkg-exit.txt').write_text('0\n')
            (out/'PKGINFO').write_text('pkgname = perl\npkgver = 5.42.3-1.2\narch = x86_64\n')
            with self.assertRaisesRegex(ValueError,'exact 1.3'):api.check_export(out)
            (out/'PKGINFO').write_text('pkgname = perl\npkgver = 5.42.3-1.3\narch = x86_64\n')
            (out/'BUILDINFO').write_text('pkgbuild_sha256sum = '+api.PINS['files']['PKGBUILD']['sha256']+'\n')
            (out/'makepkg.log').write_text('All tests successful.\n')
            (out/'source-config.over').write_text("cf_time='wall clock'\n")
            with self.assertRaisesRegex(ValueError,'source override'):api.check_export(out)
            (out/'source-config.over').write_text("cf_time='"+api.TIME+"'\n")
            (out/'staged-cf-time.txt').write_text('wall clock\n')
            with self.assertRaisesRegex(ValueError,'staged Config'):api.check_export(out)

    def exercise(self,*,capacity=True,capacity_only=False,remote=False,changed=False,cancel=False):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);root=Path(tmp.name)
        sock=socket.socket(socket.AF_UNIX);sock.bind(str(root/'docker.sock'));self.addCleanup(sock.close)
        output=root/'out';source=root/'source';source.write_bytes(b'simulated source')
        calls=[];containers=set();volumes=set();images=set();verify_calls=[]
        class FakeRunner:
            def __init__(self,*args):pass
            def run(self,argv,**kwargs):
                calls.append(argv);body=b'';code=0
                if argv[1:3]==['context','inspect']:body=json.dumps('ssh://remote' if remote else 'unix://'+str(root/'docker.sock')).encode()
                elif argv[1]=='info':body=str(root).encode()
                elif argv[1:3]==['image','inspect']:body=json.dumps([{'Id':'sha256:'+api.old.BASE.split('sha256:')[1],'Architecture':'amd64'}]).encode()
                elif argv[1]=='create':containers.add(argv[argv.index('--name')+1])
                elif argv[1]=='commit':images.add(argv[-1]);body=b'sha256:simulated'
                elif argv[1:3]==['volume','create']:volumes.add(argv[-1])
                elif argv[1:3]==['volume','rm']:
                    if argv[-1] in volumes:volumes.remove(argv[-1])
                    else:code=1;body=('Error response from daemon: get '+argv[-1]+': no such volume').encode()
                elif argv[1]=='rm':
                    if argv[-1] in containers:containers.remove(argv[-1])
                    else:code=1;body=('Error response from daemon: No such container: '+argv[-1]).encode()
                elif argv[1:3]==['image','rm']:images.discard(argv[-1])
                elif argv[1:3]==['container','ls']:body='\n'.join(containers).encode()
                elif argv[1:3]==['volume','ls']:body='\n'.join(volumes).encode()
                elif argv[1:3]==['image','ls']:body='\n'.join(images).encode()
                elif argv[1]=='inspect':body=b'[{}]' if argv[-1] in containers else b'[]';code=0 if argv[-1] in containers else 1
                elif argv[1]=='start' and 'perl13-build-' in argv[-1] and cancel:raise api.runtime.Cancelled()
                elif argv[1]=='cp' and argv[-1]!='-':
                    p=Path(argv[-1]);p.mkdir();(p/api.ARCHIVE).write_bytes(b'simulated byte identity');(p/'payload-map.json').write_text('{}')
                return subprocess.CompletedProcess(argv,code,body)
        def verify(*args):
            verify_calls.append(args)
            if changed and len(verify_calls)>1:raise ValueError('changed input')
        def gate(*args,**kwargs):return dict(status='PASS' if capacity else 'HOLD_CAPACITY',phase=args[2])
        previous_tempdir=tempfile.tempdir
        argv=['run.py','--source',str(source),'--output',str(output)]+(['--capacity-only'] if capacity_only else [])
        with patch.object(sys,'argv',argv),patch.dict(api.os.environ,{'DOCKER_HOST':'','DOCKER_CONTEXT':''}),patch.object(api.runtime,'Runner',FakeRunner),patch.object(api,'guard',gate),patch.object(api,'verify',verify),patch.object(api.old,'check_host'),patch.object(api.old,'validate_actor',return_value={'simulated':True}),patch.object(api,'check_export',side_effect=lambda p:{'archive':api.old.identity(p/api.ARCHIVE)}):
            code=api.main()
        self.assertEqual(tempfile.tempdir,previous_tempdir)
        return code,json.loads((output/'report.json').read_bytes()),calls

    def test_capacity_refusal_does_not_create_resources(self):
        code,report,calls=self.exercise(capacity=False)
        self.assertEqual(code,2);self.assertEqual(report['status'],'HOLD_CAPACITY')
        self.assertEqual([a[1] for a in calls],['context','info'])

    def test_remote_daemon_refused_before_local_capacity(self):
        code,report,calls=self.exercise(remote=True)
        self.assertEqual(code,2);self.assertEqual(len(calls),1)
        self.assertIn('local Unix',report['failure'])

    def test_capacity_only_success_has_no_actors(self):
        code,report,calls=self.exercise(capacity_only=True)
        self.assertEqual(code,0);self.assertEqual(report['status'],'PASS_CAPACITY_ONLY_NO_ACTORS')
        self.assertEqual([a[1] for a in calls],['context','info'])

    def test_capacity_only_rechecks_inputs_before_exit_status(self):
        code,report,calls=self.exercise(capacity_only=True,changed=True)
        self.assertEqual(code,2);self.assertEqual(report['status'],'HOLD_INPUTS_CHANGED')
        self.assertEqual([a[1] for a in calls],['context','info'])

    def test_sequential_exports_are_pinned_and_retired_before_second_volume(self):
        code,report,calls=self.exercise()
        self.assertEqual(code,0);self.assertEqual(len(report['builds']),2);self.assertEqual(len(report['retired']),2)
        self.assertTrue(report['owned_resources_absence_verified'])
        allocations=[i for i,a in enumerate(calls) if a[1:3]==['volume','create']]
        retire=next(i for i,a in enumerate(calls) if a[1:3]==['volume','rm'])
        self.assertLess(allocations[0],retire);self.assertLess(retire,allocations[1])
        self.assertTrue(report['comparison']['all_payload_entries_equal'])

    def test_cancel_keeps_operation_record_and_cleans_owned_resources(self):
        code,report,calls=self.exercise(cancel=True)
        self.assertEqual(code,130);self.assertEqual(report['status'],'CANCELLED')
        self.assertTrue(report['owned_resources_absence_verified'])
        self.assertTrue(any('Cancelled' in row.get('failure','') for row in report['operations']))
        self.assertTrue(any(a[1]=='stop' for a in calls))
        self.assertTrue(any(a[1]=='cp' and a[-1]=='-' for a in calls))


if __name__=='__main__':unittest.main(verbosity=2)
