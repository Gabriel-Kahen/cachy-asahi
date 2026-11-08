# SPDX-License-Identifier: MIT
"""Standalone retained-data CLIs must import current helper source, never stale PYC."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import py_compile
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
SOURCES=('scripts/platform/target_snapshot.py','scripts/platform/recovery_preflight.py',
         'scripts/platform/snapshot_compare.py','scripts/platform/capture.py',
         'scripts/platform/tuple_audit.py','scripts/platform/recovery_inputs.py',
         'scripts/platform/authenticate_missing.py','scripts/platform/archive_coverage.py',
         'scripts/platform/retained_bundle.py','scripts/platform/transaction.py',
         'scripts/platform/platform_transition.py','scripts/platform/prepare_transition.py',
         'scripts/hardware/capture-baseline.py','scripts/port/preview.py',
         'scripts/port/authenticate.py','scripts/ci/native_arm.py',
         'scripts/checks/package_checks.py','scripts/integration/lifecycle.py',
         'scripts/release/compare_releases.py','scripts/release/release.py')


class SourceCacheTests(unittest.TestCase):
    def check_cache(self,inherited):
        with tempfile.TemporaryDirectory(prefix='snapshot-source-cache-fixture-')as directory:
            root=Path(directory);stage=root/'checkout'
            for name in SOURCES:
                path=stage/name;path.parent.mkdir(parents=True,exist_ok=True)
                path.write_bytes((ROOT/name).read_bytes())
            helper=stage/'scripts/platform/tuple_audit.py';original=helper.read_bytes();info=helper.stat()
            sentinel=root/'new_sentinel.py';code=b"raise RuntimeError('NEW_SNAPSHOT_STALE_PYC_SENTINEL')\n"
            sentinel.write_bytes(code+b'#'*(len(original)-len(code)));os.utime(sentinel,ns=(info.st_atime_ns,info.st_mtime_ns))
            inherited_cache=root/'inherited-cache';inherited_cache.mkdir()
            if inherited:
                with patch.object(sys,'pycache_prefix',str(inherited_cache)):
                    cache=Path(importlib.util.cache_from_source(str(helper)))
            else:
                cache=helper.parent/'__pycache__'/('tuple_audit.'+sys.implementation.cache_tag+'.pyc')
            cache.parent.mkdir(parents=True,exist_ok=True)
            py_compile.compile(str(sentinel),cfile=str(cache),dfile=str(helper),doraise=True,
                               invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP)
            held_cache=cache.read_bytes();scratch=root/'scratch';scratch.mkdir(mode=0o700)
            env=dict(os.environ,TMPDIR=str(scratch));env.pop('PYTHONPYCACHEPREFIX',None)
            if inherited:env['PYTHONPYCACHEPREFIX']=str(inherited_cache)
            flags=['-B']if inherited else['-I','-B']
            loader="import importlib.util,sys;s=importlib.util.spec_from_file_location('new_snapshot_cache_sentinel',sys.argv[1]);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)"
            bare=subprocess.run([sys.executable,*flags,'-c',loader,str(helper)],env=env,capture_output=True,timeout=10)
            self.assertEqual(bare.returncode,1);self.assertIn(b'NEW_SNAPSHOT_STALE_PYC_SENTINEL',bare.stderr)
            contract=root/'new-malformed-contract.json';contract.write_bytes(b'{"schema_version":true}')
            digest=hashlib.sha256(contract.read_bytes()).hexdigest()
            for entry in SOURCES[:3]:
                with self.subTest(entry=entry,inherited=inherited):
                    argv=[sys.executable,*flags,str(stage/entry)]
                    result=subprocess.run([*argv,'--help'],env=env,capture_output=True,timeout=10)
                    self.assertEqual(result.returncode,0,result.stderr.decode());self.assertIn(b'--contract-sha256',result.stdout)
                    self.assertEqual(list(scratch.iterdir()),[])
                    output=root/('uncreated-'+Path(entry).stem)
                    args=['--contract',str(contract),'--contract-sha256',digest]
                    if Path(entry).name!='snapshot_compare.py':args+=['--output',str(output)]
                    refused=subprocess.run([*argv,*args],env=env,capture_output=True,timeout=10)
                    self.assertEqual(refused.returncode,1,refused.stderr.decode());self.assertIn(b'refused:',refused.stderr)
                    self.assertNotIn(b'NEW_SNAPSHOT_STALE_PYC_SENTINEL',refused.stderr);self.assertEqual(refused.stdout,b'')
                    self.assertFalse(output.exists());self.assertEqual(list(scratch.iterdir()),[])
                    self.assertEqual(helper.read_bytes(),original);self.assertEqual(cache.read_bytes(),held_cache)

    def test_adjacent_valid_timestamp_cache_cannot_replace_helper(self):self.check_cache(False)
    def test_inherited_valid_timestamp_cache_cannot_replace_helper(self):self.check_cache(True)


if __name__=='__main__':unittest.main()
