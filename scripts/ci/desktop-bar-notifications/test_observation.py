# SPDX-License-Identifier: MIT
"""Bounded proc fixture and mocked journal controls; no desktop or proc actors."""
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import Mock,patch
import session as S


class Observation(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        p=self.root/'101';p.mkdir();(p/'task/101').mkdir(parents=True)
        self.process=SimpleNamespace(process=SimpleNamespace(pid=101,poll=lambda:None))
        fields=['S']+['0']*18+['123'];(p/'stat').write_text('101 (waybar) '+' '.join(fields))
        (p/'status').write_text('Uid:\t23001\t23001\t23001\t23001\n');(p/'exe').symlink_to('/usr/bin/waybar')
        (p/'environ').write_bytes(b'WAYLAND_DISPLAY=wayland-1\0DISPLAY=:0\0SECRET=excluded\0')
        for folder in (p,p/'task/101'):
            for name in ('wchan','syscall','stack','comm'):(folder/name).write_text('fixture '+name)

    def test_owned_identity_selected_environment_and_bounded_threads(self):
        value=S.process_observation(self.process,'/usr/bin/waybar',self.root)
        self.assertEqual(value['identity']['starttime'],123);self.assertEqual(value['environment'],dict(WAYLAND_DISPLAY='wayland-1',DISPLAY=':0'))
        self.assertEqual(value['total_threads'],1);self.assertNotIn('SECRET',str(value))

    def test_foreign_identity_exited_child_and_oversized_field_refused(self):
        with self.assertRaises(ValueError):S.process_observation(self.process,'/usr/bin/mako',self.root)
        self.process.process.poll=lambda:0
        with self.assertRaises(ValueError):S.process_observation(self.process,'/usr/bin/waybar',self.root)
        self.process.process.poll=lambda:None;(self.root/'101/environ').write_bytes(b'x'*65537)
        with self.assertRaises(ValueError):S.process_observation(self.process,'/usr/bin/waybar',self.root)

    def test_unavailable_task_fields_are_qualified(self):
        (self.root/'101/task/101/stack').unlink()
        value=S.process_observation(self.process,'/usr/bin/waybar',self.root)
        self.assertEqual(value['threads'][0]['stack'],dict(unavailable='FileNotFoundError'))

    def test_failure_observation_once_with_three_finite_readonly_queries(self):
        emitted=[];calls=[]
        def command(argv,label,timeout):
            calls.append((argv,label,timeout));return 'DISPLAY=:0\nSECRET=excluded\n' if label.endswith('activation_now') else 'fixture'
        base=SimpleNamespace(emit=lambda event,**kw:emitted.append((event,kw)))
        with patch.object(S,'base',base),patch.object(S,'process_observation',return_value=dict(scope='fixture')):
            S.failure_observation('minimal',ValueError('original'),[('waybar',self.process,'/usr/bin/waybar')],command,{},dict(dbus_updated=True))
        self.assertEqual(len(emitted),1);self.assertEqual(emitted[0][0],'bar_phase_diagnostic')
        self.assertEqual(emitted[0][1]['reason'],'original');self.assertNotIn('SECRET',str(emitted))
        self.assertEqual(len(calls),3);self.assertTrue(all(row[2]==5 for row in calls))
        self.assertIn('-n',calls[-1][0]);self.assertIn('32',calls[-1][0]);self.assertNotIn('--follow',calls[-1][0])

    def test_secondary_proc_and_journal_errors_remain_qualified(self):
        emitted=[];base=SimpleNamespace(emit=lambda event,**kw:emitted.append(kw))
        with patch.object(S,'base',base),patch.object(S,'process_observation',side_effect=PermissionError):
            S.failure_observation('minimal',ValueError('first'),[('waybar',self.process,'/usr/bin/waybar')],Mock(side_effect=TimeoutError),{},None)
        self.assertEqual(emitted[0]['reason'],'first');self.assertEqual(emitted[0]['processes']['waybar']['unavailable'],'PermissionError')
        self.assertEqual(emitted[0]['activation_journal']['unavailable'],'TimeoutError')


if __name__=='__main__':unittest.main(verbosity=2)
