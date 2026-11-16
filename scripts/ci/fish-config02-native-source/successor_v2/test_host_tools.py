# SPDX-License-Identifier: MIT
"""Inert host executable DATA fixtures; no host command or privilege execution."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent


def fence(event,args):
    if event.startswith(('subprocess.','socket.','ctypes.')) or event in ('os.system','os.fork','os.exec','os.posix_spawn','resource.setrlimit'):
        raise RuntimeError('DATA-only actor fence: '+event)


sys.addaudithook(fence)


def load(name):
    spec=importlib.util.spec_from_file_location('fish_tools_test_'+name,HERE/(name+'.py'))
    result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result);return result


H=load('host_tools');O=load('hosted_owner');R=load('retain')


class HostTools(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='fish-tools-INERT-');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        (self.root/'usr/bin').mkdir(parents=True);(self.root/'usr/sbin').mkdir()

    def leaf(self,name,where='bin'):
        path=self.root/'usr'/where/name;path.write_bytes(b'INERT EXECUTABLE DATA '+name.encode()+b'\n');path.chmod(0o755);return path

    def observe(self,candidate):
        return H.inspect(candidate,root=self.root,trusted_uid=os.getuid())

    def populate(self):
        for name in H.NAMES:self.leaf(name)

    def test_sbin_only_tools_are_selected_and_pinned_without_path(self):
        self.populate()
        for name in ('losetup','mkfs.ext4','dockerd'):
            (self.root/'usr/bin'/name).unlink();path=self.leaf(name,'sbin')
        with patch.dict(os.environ,PATH='/attacker/arbitrary'):
            facts=H.probe_all(self.observe)
        self.assertEqual(facts['missing_or_invalid'],[])
        for name in ('losetup','mkfs.ext4','dockerd'):
            row=facts['tools'][name]['selected'];body=(self.root/'usr/sbin'/name).read_bytes()
            self.assertEqual(row['candidate'],'/usr/sbin/'+name)
            self.assertEqual(row['path'],str(self.root/'usr/sbin'/name))
            self.assertEqual(row['sha256'],hashlib.sha256(body).hexdigest())
            self.assertEqual(row['metadata']['st_uid'],os.getuid())  # Fixture, not a Root host fact.

    def test_mkfs_and_python_aliases_record_original_and_canonical_bytes(self):
        target=self.leaf('mke2fs','sbin');(self.root/'usr/sbin/mkfs.ext4').symlink_to('mke2fs')
        row=self.observe('/usr/sbin/mkfs.ext4')
        self.assertEqual(row['path'],str(target));self.assertEqual(row['candidate'],'/usr/sbin/mkfs.ext4')
        self.assertEqual(row['chain'][-1]['link'],'mke2fs')
        target=self.leaf('python3.12');(self.root/'usr/bin/python3').symlink_to('python3.12')
        self.assertEqual(self.observe('/usr/bin/python3')['path'],str(target))
        body=(HERE/'hosted_owner.py').read_text()
        self.assertIn("self.tool('mkfs.ext4'),'-t','ext4'",body)

    def test_merged_sbin_directory_alias_is_observed(self):
        (self.root/'usr/sbin').rmdir();(self.root/'usr/sbin').symlink_to('bin')
        target=self.leaf('losetup')
        self.assertEqual(self.observe('/usr/sbin/losetup')['path'],str(target))

    def test_all_missing_candidates_collected_even_after_first_missing(self):
        facts=H.probe_all(self.observe)
        self.assertEqual(facts['missing_or_invalid'],list(H.NAMES))
        self.assertTrue(all(len(row['candidates'])==2 for row in facts['tools'].values()))
        self.assertTrue(all(c['status']=='MISSING' for row in facts['tools'].values() for c in row['candidates']))

    def test_unsafe_candidate_does_not_silently_fallback(self):
        self.leaf('losetup').chmod(0o777);self.leaf('losetup','sbin')
        facts=H.probe_all(self.observe)
        self.assertIsNone(facts['tools']['losetup']['selected'])
        self.assertEqual(facts['tools']['losetup']['candidates'][0]['status'],'INVALID')

    def test_wrong_owner_nonexecutable_writable_escaping_and_dangling_refuse(self):
        path=self.leaf('losetup')
        with self.assertRaises(ValueError):H.inspect('/usr/bin/losetup',root=self.root,trusted_uid=os.getuid()+1)
        for mode in (0o644,0o777):
            path.chmod(mode)
            with self.assertRaises(ValueError):self.observe('/usr/bin/losetup')
        path.unlink();path.symlink_to('/bin/sh')
        with self.assertRaises(ValueError):self.observe('/usr/bin/losetup')
        path.unlink();path.symlink_to('missing')
        self.assertEqual(H.probe_all(self.observe)['tools']['losetup']['candidates'][0]['status'],'INVALID')
        with self.assertRaises(ValueError):self.observe('/opt/bin/losetup')

    def test_body_mode_replacement_and_alias_drift_before_use_refuse(self):
        path=self.leaf('losetup');row=self.observe('/usr/bin/losetup')
        original=H.inspect
        observer=lambda candidate:original(candidate,root=self.root,trusted_uid=os.getuid())
        for change in ('body','mode','replacement'):
            path.write_bytes(b'INERT EXECUTABLE DATA losetup\n');path.chmod(0o755);row=observer('/usr/bin/losetup')
            if change=='body':path.write_bytes(b'different inert body')
            if change=='mode':path.chmod(0o700)
            if change=='replacement':
                path.unlink();self.leaf('losetup')
            with patch.object(H,'inspect',side_effect=observer),self.assertRaises(ValueError):H.checked(row)
        path.unlink();self.leaf('mke2fs');path.symlink_to('mke2fs')
        with self.assertRaises(ValueError):observer('/usr/bin/losetup')
        alias=self.root/'usr/bin/mkfs.ext4';alias.symlink_to('mke2fs');self.leaf('mke2fs','sbin')
        row=observer('/usr/bin/mkfs.ext4');alias.unlink();alias.symlink_to('../sbin/mke2fs')
        with patch.object(H,'inspect',side_effect=observer),self.assertRaises(ValueError):H.checked(row)

    def test_mutation_during_streamed_hash_refuses(self):
        path=self.leaf('losetup');original=os.read;changed=[]
        def consume(fd,size):
            body=original(fd,size)
            if not changed:
                changed.append(True);path.write_bytes(b'MUTATED EXECUTABLE DATA\n')
            return body
        with patch.object(H.os,'read',side_effect=consume),self.assertRaises(ValueError):self.observe('/usr/bin/losetup')

    def test_read_atime_is_not_security_drift(self):
        path=self.leaf('losetup');info=path.stat();os.utime(path,ns=(1,info.st_mtime_ns))
        before=self.observe('/usr/bin/losetup');after=self.observe('/usr/bin/losetup')
        self.assertEqual(before,after)

    def test_preflight_retains_missing_tools_and_systemd_version_before_hold(self):
        facts=H.probe_all(self.observe)
        facts['tools']['systemctl']['selected']=dict(path='/usr/bin/systemctl')
        facts['missing_or_invalid'].remove('systemctl')
        value=O.Controller.__new__(O.Controller);value.out=self.root;value.tools={}
        calls=[]
        def run(argv,*args,**kwargs):calls.append(argv);return 0,b'systemd 255 (255.4)\n+PAM +AUDIT\n'
        value.run=run
        with patch.object(O.H,'probe_all',return_value=facts),patch.object(O.H,'checked',side_effect=lambda row:row['path']):
            with self.assertRaisesRegex(ValueError,'missing/invalid'):value.preflight()
        report=json.loads((self.root/'host-tools.json').read_bytes())
        self.assertEqual(report['systemd']['version'],255)
        self.assertIn('losetup',report['missing_or_invalid']);self.assertIn('zstd',report['missing_or_invalid'])
        self.assertEqual(calls,[['/usr/bin/systemctl','--version']])
        (self.root/'owner-report.json').write_bytes(b'{"status":"HOLD"}')
        # Restrict retention to its ordinary public receipt directory.
        import shutil
        shutil.rmtree(self.root/'usr')
        self.assertIn('host-tools.json',R.selected(self.root))


if __name__=='__main__':unittest.main()
