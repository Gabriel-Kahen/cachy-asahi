# SPDX-License-Identifier: MIT
"""FENCED entry orchestration model: no provider, daemon, actor or native role."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('v4_entry_orchestration_DATA',HERE/'payload/hosted/entry.py')
e=importlib.util.module_from_spec(spec);spec.loader.exec_module(e)


class Controls(unittest.TestCase):
    def model(self,phase,fail=None):
        events=[];state={};raw=b'{"FENCED":"NOT_A_ROOT_GRANT"}\n';digest=hashlib.sha256(raw).hexdigest()
        dispatch=dict(FENCED='NOT_A_ROOT_GRANT',resources={phase:dict(native_seconds=12200 if phase=='bootstrap' else 20400,cleanup_seconds=300),'minimum_host':dict(disk_available_bytes_per_device=1,available_inodes=1)},delivery={'FENCED':'NO_SELECTORS'})
        current=dict(phase=phase,source={'job':'21' if phase=='bootstrap' else '22'},dispatch_sha256=digest)
        bootstrap_provider=dict(phase='bootstrap',source={'job':'21'},dispatch_sha256=digest)
        delivered=dict(materials=['FENCED_NO_MATERIAL'],files={});boot=dict(image='FENCED_NO_IMAGE');qual=dict(status='FENCED_NO_QUALIFICATION')
        def step(name,*args):
            events.append(name)
            if fail==name:raise ValueError('FENCED '+name+' failure')
        class Commands:
            def __init__(self,work,seconds):
                step('commands');self.cleaning=False;self.deadline=100+seconds;self.on_tick='FENCED';state.update(command=self,seconds=seconds)
        def acquire(root,work,plan,command,token):
            step('acquire');self.assertIs(plan,dispatch['delivery']);self.assertIs(command,state['command']);self.assertEqual(token,'FENCED_NOT_A_CREDENTIAL');return delivered
        def retained(root,work,command):step('retained');return {'FENCED':'RETAINED_DATA'}
        def bootstrap_run(root,work,provider,plan,data,command):
            step('bootstrap');self.assertIs(provider,current);self.assertIs(plan,dispatch);self.assertIs(data,delivered);self.assertEqual(data['bootstrap'],{'FENCED':'RETAINED_DATA'});return boot
        def qualification_run(root,work,provider,plan,data,image,command):
            step('qualification');self.assertIs(provider,current);self.assertIs(data,delivered);self.assertIs(image,boot);return qual
        def export(root,work,plan,provider,data,image,result,command):
            step('export');self.assertIs(plan,dispatch);self.assertIs(provider,current);self.assertIs(result,qual);return {'FENCED':'NO_EXPORT'}
        def import_phase(root,work,plan,provider,args,command):
            step('import');self.assertIs(plan,dispatch);self.assertIs(provider,current)
            return dict(delivered=delivered,boot=boot,qual=qual,bootstrap_provider=bootstrap_provider)
        def operational(plan,bridge,data,image,result,work):
            step('operational');self.assertIs(plan,dispatch);self.assertEqual(bridge,dict(schema=4,status='PROVIDER_PHASE_BRIDGE',dispatch_sha256=digest,bootstrap=bootstrap_provider,build=current));self.assertIs(data,delivered);self.assertIs(image,boot);self.assertIs(result,qual)
            state['operational']={'FENCED':'NOT_AN_OPERATIONAL_ADMISSION'};return state['operational']
        def producer_run(root,work,admission,command):
            step('producer');self.assertIs(admission,state['operational']);return dict(status='COMPLETED_EXPORTED_RETIRED' if fail!='producer_status' else 'FAIL')
        def retire(root,work,provider,image,command):
            step('retire');self.assertTrue(command.cleaning);self.assertIsNone(command.on_tick);self.assertEqual(command.deadline,400)
            self.assertIs(provider,current if phase=='bootstrap' else bootstrap_provider)
            self.assertIs(image,None if fail in ('acquire','retained','bootstrap') else boot)
            return {'FENCED':'NO_IMAGES_RETIRED'}
        modules={'materials.py':SimpleNamespace(acquire=acquire,retained=retained),'bootstrap.py':SimpleNamespace(run=bootstrap_run,retire=retire),'qualification.py':SimpleNamespace(run=qualification_run),'phase_transfer.py':SimpleNamespace(export=export,import_phase=import_phase),'producer.py':SimpleNamespace(run=producer_run)}
        gate=SimpleNamespace(operational=operational)
        with tempfile.TemporaryDirectory(prefix='rust199-FENCED-orchestration-')as temp:
            runner=Path(temp);original_stat=Path.stat
            def stat(path,*args,**kwargs):
                value=original_stat(path,*args,**kwargs)
                if path==runner:
                    fields=list(value);fields[4]=1001;return os.stat_result(fields)
                return value
            def dispatch_gate(args,env):step('dispatch_gate');return gate,dispatch,raw
            def provider(*args):step('provider');return current,b'{"FENCED":"NO_PROVIDER_METADATA"}\n'
            def fresh_host(work,plan,command,image=None):step('fresh_image' if image else 'fresh_host');self.assertIs(plan,dispatch)
            args=SimpleNamespace(check_only=False,execute=True,phase=phase)
            with patch.dict(e.os.environ,{'RUNNER_TEMP':temp,'GH_TOKEN':'FENCED_NOT_A_CREDENTIAL'},clear=True),patch.object(e,'ROOT',runner/'FENCED-source'),patch.object(Path,'stat',stat),patch.object(e,'dispatch_gate',dispatch_gate),patch.object(e,'storage',lambda *a:None),patch.object(e,'Commands',Commands),patch.object(e,'readback',lambda *a:step('readback')),patch.object(e,'actual_provider',provider),patch.object(e,'fresh_host',fresh_host),patch.object(e,'load',lambda name,path:modules[path.name]),patch.object(e.time,'monotonic',lambda:100),patch.object(e.signal,'signal'),patch.object(e.signal,'getsignal',return_value=None):
                status=e.run(args)
            report=json.loads((runner/'rust199-hosted/hosted.json').read_bytes())
        return status,events,report,state

    def test_bootstrap_acquires_retained_data_before_image_qualification_and_transfer(self):
        status,events,report,state=self.model('bootstrap')
        self.assertEqual(status,0);self.assertEqual(state['seconds'],12200)
        self.assertEqual(events,['dispatch_gate','commands','readback','provider','fresh_host','acquire','retained','bootstrap','qualification','export','retire'])
        self.assertEqual(report['status'],'BOOTSTRAP_QUALIFIED_TRANSFER_DATA_EXPORTED')
    def test_build_imports_bootstrap_evidence_then_normalizes_and_retires_bootstrap_owner(self):
        status,events,report,state=self.model('build')
        self.assertEqual(status,0);self.assertEqual(state['seconds'],20400)
        self.assertEqual(events,['dispatch_gate','commands','readback','provider','fresh_host','import','fresh_image','operational','producer','retire'])
        self.assertEqual(report['status'],'RUST199_BUILD_EXPORTED_RETIRED_PENDING_INDEPENDENT_READER')
    def test_failures_stop_later_phases_and_still_retire_images(self):
        for phase,fail in [('bootstrap',name)for name in ('acquire','retained','bootstrap','qualification','export')]+[('build',name)for name in ('import','operational','producer','producer_status')]:
            with self.subTest(phase=phase,fail=fail):
                status,events,report,_=self.model(phase,fail)
                self.assertEqual(status,2);self.assertEqual(report['status'],'FAIL')
                if fail=='import':
                    self.assertEqual(events[-1],'import');self.assertNotIn('retire',events)
                    self.assertEqual(report['image_retirement']['status'],'NOT_APPLICABLE_IMPORTER_OWNS_FAILED_IMPORT_RETIREMENT')
                    self.assertNotIn('cleanup_error',report)
                else:self.assertEqual(events[-1],'retire')
                self.assertNotIn('producer',events if phase=='bootstrap' or fail=='import' else [])
    def test_retirement_failure_cannot_report_success(self):
        for phase in ('bootstrap','build'):
            status,events,report,_=self.model(phase,'retire')
            self.assertEqual(status,2);self.assertEqual(report['status'],'FAIL');self.assertIn('cleanup_error',report)


if __name__=='__main__':unittest.main()
