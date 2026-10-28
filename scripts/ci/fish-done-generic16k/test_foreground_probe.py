# SPDX-License-Identifier: MIT
"""Inert parser controls; the separate host probe is recorded by the handoff script."""
import base64
import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest

HERE=Path(__file__).resolve().parent
CANONICAL=HERE if (HERE/'support.py').exists() else next(p for p in HERE.parents if (p/'AGENTS.md').is_file())/'scripts/ci/fish-done-generic16k'
sys.path.insert(0,str(CANONICAL))

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec)
    sys.modules[name]=module;spec.loader.exec_module(module);return module

guest=load('guest',Path(__file__).with_name('guest.py'))
run=load('run',Path(__file__).with_name('run.py'))
original_tests=load('done_original_diagnostics',CANONICAL/'test_diagnostics.py')


class ProbeControls(original_tests.Diagnostics):
    def probe(self):
        raw,manifest=self.diagnostic();value=json.loads(raw)
        fields={'fixture_sha256':'fixtures/done.py','runtime_sha256':'usr/share/cachy-asahi/fish-done/done.fish','wrapper_sha256':'usr/share/cachy-asahi/fish-done/opt-in.fish'}
        manifest['files']={path:{'sha256':'a'*64} for path in fields.values()}
        value['payload_manifest_sha256']=run.s.sha((json.dumps(manifest,sort_keys=True,indent=2)+'\n').encode())
        observed=dict(schema_version=1,status='FOREGROUND_PROBE_ONLY',acceptance_credit=False,product_change='NONE',
            workload='sleep .12',threshold=80,files={'probe-timeout-stderr':guest.sample(b'injected transport failure',2048)})
        observed.update(dict.fromkeys(fields,'a'*64))
        stdout=(json.dumps(observed,sort_keys=True,separators=(',',':'))+'\n').encode()
        command=dict(argv=['/usr/bin/python3','-I','-B','/guest.py','--foreground-probe','/tmp/done16k/foreground-probe'],
            exit=0,expected_exit=0,natural_exit=True,group_absent=True,stdout_bytes=len(stdout),stdout_sha256=run.s.sha(stdout))
        value['foreground_probe']=dict(command=command,value=observed,owned_processes_absent=True)
        return value,manifest

    def accept(self,value,manifest):
        return run.failed_driver_diagnostic(b'DONE16K_DIAGNOSTIC '+json.dumps(value).encode(),'a'*32,'test16k',manifest)

    def test_probe_retains_failure_status_and_source_join(self):
        value,manifest=self.probe();parsed=self.accept(value,manifest)
        self.assertEqual(parsed['value']['status'],'FAILED_DRIVER_DIAGNOSTIC_ONLY')
        self.assertFalse(parsed['value']['foreground_probe']['value']['acceptance_credit'])

    def test_probe_source_stdout_or_cleanup_tampering_refused(self):
        value,manifest=self.probe()
        for field,bad in [('fixture_sha256','b'*64),('acceptance_credit',True),('product_change','CHANGED')]:
            changed=copy.deepcopy(value);changed['foreground_probe']['value'][field]=bad
            with self.subTest(field=field),self.assertRaises(ValueError):self.accept(changed,manifest)
        for field,bad in [('natural_exit',False),('group_absent',False),('stdout_sha256','0'*64)]:
            changed=copy.deepcopy(value);changed['foreground_probe']['command'][field]=bad
            with self.subTest(field=field),self.assertRaises(ValueError):self.accept(changed,manifest)
        value['foreground_probe']['owned_processes_absent']=False
        with self.assertRaises(ValueError):self.accept(value,manifest)

    def test_probe_sample_hash_tampering_refused(self):
        value,manifest=self.probe();value['foreground_probe']['value']['files']['probe-timeout-stderr']['sha256']='f'*64
        observed=value['foreground_probe']['value'];stdout=(json.dumps(observed,sort_keys=True,separators=(',',':'))+'\n').encode()
        value['foreground_probe']['command'].update(stdout_bytes=len(stdout),stdout_sha256=run.s.sha(stdout))
        with self.assertRaises(ValueError):self.accept(value,manifest)

    def test_probe_cannot_enter_success_acceptance(self):
        value,manifest=self.probe()
        with self.assertRaises(ValueError):run.guest_report(b'DONE16K_DIAGNOSTIC '+json.dumps(value).encode(),0,'a'*32,'test16k',manifest)

    def test_transport_failure_is_diagnostic_and_output_is_joined(self):
        value,manifest=self.probe();observed=value['foreground_probe']['value'];rows=[]
        for kind,argv in (
            ('bounded-timeout',['timeout','--foreground','--signal=TERM','--kill-after=1s','2s','notify-send','--diagnostic-only']),
            ('direct-recorder',['notify-send','--diagnostic-only'])):
            argv[0]='/tmp/done16k/foreground-probe/transport/bin/'+argv[0]
            streams={name:guest.sample(b'',2048) for name in ('stdout','stderr')}
            command=dict(argv=argv,expected_exit=0,exit=124 if kind=='bounded-timeout' else 0)
            for name,row in streams.items():command.update({name+'_bytes':row['bytes'],name+'_sha256':row['sha256']})
            rows.append(dict(kind=kind,command=command,notification_count=0,recorder_sha256='c'*64,**streams))
        observed['transport_commands']=rows
        def join():
            raw=(json.dumps(observed,sort_keys=True,separators=(',',':'))+'\n').encode()
            value['foreground_probe']['command'].update(stdout_bytes=len(raw),stdout_sha256=run.s.sha(raw))
        join();self.accept(value,manifest)
        rows[0]['command']['stdout_sha256']='d'*64;join()
        with self.assertRaisesRegex(ValueError,'command/sample'):self.accept(value,manifest)
        rows[0]['command']['stdout_sha256']=rows[0]['stdout']['sha256']
        rows[0]['command']['argv'][4]='3s';join()
        with self.assertRaisesRegex(ValueError,'identity differs'):self.accept(value,manifest)


if __name__=='__main__':unittest.main()
