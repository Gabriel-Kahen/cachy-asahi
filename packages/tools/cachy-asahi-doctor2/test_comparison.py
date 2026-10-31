#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline fixtures and tempfile CLI controls; no installed or hardware evidence."""
import copy
import io
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import test_doctor as fixtures
doctor=fixtures.doctor


def fixture():return fixtures.Diagnostics().collect()[0]


def row(report,name):return next(r for r in report['checks'] if r['check']==name)


def coverage(report):
    report['coverage']={s:sum(r['state']==s for r in report['checks']) for s in doctor.STATES}
    return report


def compare(before,after):return doctor.compare_reports(doctor.validate_report(before),doctor.validate_report(after))


class Comparison(unittest.TestCase):
    def test_unchanged_ignores_timestamp_notes_and_order(self):
        before=fixture();after=copy.deepcopy(before)
        after['collected_utc']='2026-10-27T00:00:00+00:00';after['checks'].reverse()
        for r in after['checks']:r['note']='PRIVATE NOTE'
        after['limitations']=['PRIVATE LIMITATION']
        result=compare(before,after)
        self.assertFalse(result['changed']);self.assertEqual(result['change_count'],0)
        self.assertEqual(result['unchanged_count'],len(before['checks']))
        self.assertNotIn('PRIVATE',json.dumps(result));self.assertIn('No observation changes',doctor.comparison_human(result))
    def test_versions_absence_and_service_failure_are_changes_not_verdicts(self):
        before=fixture();after=copy.deepcopy(before)
        row(after,'package/linux-asahi')['value']['version']='6.12-2'
        row(after,'package/m1n1')['value'].update(presence='absent',version=None)
        row(after,'system/asahi-audio.service')['value'].update(ActiveState='failed',SubState='dead')
        result=compare(before,after)
        self.assertEqual(result['change_count'],3)
        self.assertEqual({c['kind'] for c in result['changes']},{'value'})
        self.assertIn('regression',doctor.comparison_human(result));self.assertNotIn('healthy',result)
    def test_unknown_unavailable_and_checked_absence_transitions(self):
        for state in ('unknown','unavailable'):
            with self.subTest(state=state):
                before=fixture();after=copy.deepcopy(before)
                r=row(after,'package/m1n1');r.update(state=state);r['value'].update(presence='unknown',version=None)
                r=row(after,'user/pipewire.service');r.update(state=state,value=None)
                coverage(after);result=compare(before,after)
                self.assertEqual(result['change_count'],2);self.assertEqual(result['coverage']['after'][state],before['coverage'][state]+2)
                self.assertTrue(all(c['kind']=='state-and-value' for c in result['changes']))
                self.assertEqual(compare(after,before)['change_count'],2)
    def test_unknown_to_unavailable_has_state_change_with_null_value(self):
        before=fixture();r=row(before,'user/pipewire.service');r.update(state='unknown',value=None);coverage(before)
        after=copy.deepcopy(before);row(after,r['check'])['state']='unavailable';coverage(after)
        self.assertEqual(compare(before,after)['changes'][0]['kind'],'state')
    def test_platform_session_tools_and_unknown_model_changes(self):
        before=fixture();after=copy.deepcopy(before)
        row(after,'platform')['value'].update(kernel='new-kernel',page_size_bytes=4096)
        row(after,'session').update(state='checked',value=dict(type='wayland',wayland_environment=True,hyprland_environment=True))
        row(after,'tools')['value']['Hyprland']=False
        row(after,'apple-model').update(state='unknown',value=dict(identifier=None,observed_board='apple,j999',model=None,model_property_available=False))
        result=compare(before,coverage(after));self.assertEqual(result['change_count'],4)
    def test_different_known_models_refused(self):
        before=fixture();after=copy.deepcopy(before)
        row(after,'apple-model')['value'].update(identifier='apple,j415',observed_board='apple,j415',model=doctor.MODELS['apple,j415'])
        with self.assertRaises(ValueError):compare(before,after)
    def test_doctor2_known_audio_coverage_is_added_not_an_inferred_before_value(self):
        before=fixture();before['version']='0.1.0';before['checks']=[r for r in before['checks'] if r['check']!='audio/default-output'];coverage(before)
        after=copy.deepcopy(before);after['version']='0.2.0'
        after['checks'].append(doctor.item('audio/default-output','checked',dict(displayed_volume='0.50',muted=False,default_sink_responded=True),'PRIVATE'))
        result=compare(before,coverage(after));change=result['changes'][0]
        self.assertEqual(change['kind'],'check-added');self.assertIsNone(change['before'])
        self.assertEqual(compare(after,before)['changes'][0]['kind'],'check-removed')
    def test_invalid_structures_and_unknown_extra_fields_refused(self):
        changes=[lambda r:r.update(schema_version=True),lambda r:r.update(schema_version=2),lambda r:r.update(version='9.0'),
            lambda r:r.update(tool='other'),lambda r:r.update(scope='other'),lambda r:r.update(secret='PRIVATE'),
            lambda r:r.update(collected_utc='yesterday'),lambda r:r.update(collected_utc='2026-01-01T00:00:00'),
            lambda r:r['checks'].pop(),lambda r:r['checks'].__setitem__(0,copy.deepcopy(r['checks'][1])),lambda r:r['checks'].append(copy.deepcopy(r['checks'][0])),
            lambda r:row(r,'platform')['value'].update(secret='PRIVATE'),lambda r:row(r,'platform')['value'].update(page_size_bytes=True),
            lambda r:row(r,'platform')['value'].update(page_size_bytes=1234),lambda r:row(r,'platform')['value'].update(kernel='bad\x1bkernel'),
            lambda r:row(r,'tools')['value'].update(pacman='yes'),lambda r:row(r,'session')['value'].update(type='secret'),
            lambda r:row(r,'package/m1n1')['value'].update(version='a\nPRIVATE'),lambda r:row(r,'package/m1n1')['value'].update(group='other'),
            lambda r:row(r,'package/m1n1').update(state='unknown'),lambda r:row(r,'system/asahi-audio.service')['value'].update(ExecStart='PRIVATE'),
            lambda r:row(r,'system/asahi-audio.service')['value'].update(ActiveState='healthy'),lambda r:row(r,'apple-model')['value'].update(model='other'),
            lambda r:r['coverage'].update(checked=999),lambda r:r['limits'].update(command_seconds=True),
            lambda r:row(r,'platform').update(note='x'*513),lambda r:r.update(limitations=['x'*513])]
        for mutate in changes:
            with self.subTest(mutate=mutate):
                report=fixture();mutate(report)
                with self.assertRaises(ValueError):doctor.validate_report(report)


    def test_doctor2_audio_volume_mute_changes_are_observed_values(self):
        before=fixture();row(before,'audio/default-output').update(state='checked',value=dict(displayed_volume='0.50',muted=False,default_sink_responded=True));coverage(before)
        after=copy.deepcopy(before);row(after,'audio/default-output')['value'].update(displayed_volume='0.00',muted=True)
        result=compare(before,after);self.assertEqual(result['change_count'],1)
        change=result['changes'][0];self.assertEqual(change['check'],'audio/default-output');self.assertEqual(change['kind'],'value')
        self.assertEqual(change['before']['value']['displayed_volume'],'0.50');self.assertTrue(change['after']['value']['muted'])
    def test_doctor2_audio_unknown_unavailable_transition_keeps_null(self):
        before=fixture();after=copy.deepcopy(before);row(after,'audio/default-output')['state']='unknown';coverage(after)
        result=compare(before,after);self.assertEqual(result['change_count'],1)
        change=result['changes'][0];self.assertEqual(change['kind'],'state')
        self.assertEqual(change['before'],dict(state='unavailable',value=None));self.assertEqual(change['after'],dict(state='unknown',value=None))
    def test_doctor2_default_json_and_audio_human_preserve_report(self):
        report=fixture();row(report,'audio/default-output').update(state='checked',value=dict(displayed_volume='0.40',muted=True,default_sink_responded=True));coverage(report)
        self.assertEqual(report['version'],'0.2.0')
        for args in ([],['--json']):
            with patch.object(doctor,'collect',return_value=report),patch.object(sys,'stdout',io.StringIO()) as out:
                self.assertEqual(doctor.main(args),0)
                self.assertEqual(out.getvalue(),json.dumps(report,indent=2,sort_keys=True)+'\n' if args else doctor.human(report))



class OfflineFiles(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.before=self.root/'before.json';self.after=self.root/'after.json'
        self.before.write_text(json.dumps(fixture()));self.after.write_bytes(self.before.read_bytes())
    def main(self,*args):
        with patch.object(sys,'stdout',io.StringIO()) as out,patch.object(sys,'stderr',io.StringIO()) as err,\
             patch.object(doctor,'collect',side_effect=AssertionError('collection forbidden')),\
             patch.object(doctor,'query',side_effect=AssertionError('query forbidden')),\
             patch.object(doctor.subprocess,'Popen',side_effect=AssertionError('process forbidden')),\
             patch.object(socket,'socket',side_effect=AssertionError('network forbidden')):
            code=doctor.main(['--compare',str(self.before),str(self.after),*args])
            return code,out.getvalue(),err.getvalue()
    def test_json_and_text_cli_collect_nothing_and_publish_private_output(self):
        code,out,err=self.main('--json');self.assertEqual(code,0);self.assertFalse(json.loads(out)['changed']);self.assertEqual(err,'')
        dest=self.root/'comparison.json';code,out,err=self.main('--output',str(dest))
        self.assertEqual(code,0);self.assertIn('No observation changes',out)
        self.assertEqual(stat.S_IMODE(dest.stat().st_mode),0o600)
        self.assertFalse(json.loads(dest.read_text())['changed'])
    def test_existing_output_and_input_output_alias_refused(self):
        for dest in (self.before,self.after,self.root/'existing'):
            dest.write_bytes(self.before.read_bytes());original=dest.read_bytes()
            code,out,err=self.main('--output',str(dest));self.assertEqual(code,2);self.assertEqual(out,'');self.assertTrue(err)
            self.assertEqual(dest.read_bytes(),original)
    def test_symlink_input_parent_and_fifo_are_refused(self):
        target=self.root/'saved';target.write_bytes(self.after.read_bytes());self.after.unlink();self.after.symlink_to(target)
        self.assertEqual(self.main()[0],2);self.after.unlink();os.mkfifo(self.after)
        self.assertEqual(self.main()[0],2);self.after.unlink();self.after.mkdir()
        self.assertEqual(self.main()[0],2);self.after.rmdir()
        nested=self.root/'real';nested.mkdir();(nested/'report').write_bytes(target.read_bytes());(self.root/'linked').symlink_to(nested)
        self.after=self.root/'linked/report';self.assertEqual(self.main()[0],2)
    def test_malformed_duplicate_deep_oversize_and_nonfinite_are_refused_without_echo(self):
        for raw in (b'',b'PRIVATE SECRET',b'{"schema_version":1,"schema_version":1}',b'['*2000+b']'*2000,
                    b'x'*(doctor.REPORT_BYTES+1),b'{"n":NaN}',b'{"n":1.5}',b'\xff'):
            with self.subTest(raw=raw[:20]):
                self.after.write_bytes(raw);code,out,err=self.main()
                self.assertEqual(code,2);self.assertEqual(out,'');self.assertNotIn('PRIVATE',err)
                self.assertEqual(sorted(p.name for p in self.root.iterdir()),['after.json','before.json'])
    def test_invalid_inputs_never_publish_output_and_duplicate_nested_keys_refused(self):
        raw=self.after.read_text().replace('"page_size_bytes": 16384','"page_size_bytes": 16384, "page_size_bytes": 16384')
        self.after.write_text(raw);dest=self.root/'result.json'
        code,out,_=self.main('--output',str(dest))
        self.assertEqual(code,2);self.assertEqual(out,'');self.assertFalse(dest.exists())
    def test_audio_value_validation(self):
        report=fixture();report['checks']=[r for r in report['checks'] if r['check']!='audio/default-output']
        report['checks'].append(doctor.item('audio/default-output','checked',dict(displayed_volume='0.50',muted=False,default_sink_responded=True),'fixture'))
        coverage(report)
        for key,value in (('muted',1),('displayed_volume','PRIVATE'),('default_sink_responded',False)):
            invalid=copy.deepcopy(report);row(invalid,'audio/default-output')['value'][key]=value
            with self.assertRaises(ValueError):doctor.validate_report(invalid)
    def test_output_missing_parent_symlink_and_directory_refused(self):
        (self.root/'link').symlink_to(self.before)
        for path in (self.root/'absent/file',self.root/'link',self.root):
            code,out,_=self.main('--output',str(path));self.assertEqual(code,2);self.assertEqual(out,'')
        self.assertFalse((self.root/'absent').exists())
    def test_actual_cli_tempfile_success_and_failure_exit_codes(self):
        command=[sys.executable,'-B',str(Path(doctor.__file__).resolve()),'--compare',str(self.before),str(self.after),'--json']
        result=subprocess.run(command,capture_output=True,timeout=5)
        self.assertEqual(result.returncode,0);self.assertEqual(json.loads(result.stdout)['change_count'],0)
        self.after.write_text('{"PRIVATE":');result=subprocess.run(command,capture_output=True,timeout=5)
        self.assertEqual(result.returncode,2);self.assertEqual(result.stdout,b'');self.assertNotIn(b'PRIVATE',result.stderr)
    def test_default_json_remains_original_schema_and_report(self):
        report=fixture()
        with patch.object(doctor,'collect',return_value=report),patch.object(sys,'stdout',io.StringIO()) as out:
            self.assertEqual(doctor.main(['--json']),0);self.assertEqual(json.loads(out.getvalue()),report)


if __name__=='__main__':unittest.main()
