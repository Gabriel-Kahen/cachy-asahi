#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fixture-only diagnostics; no pacman, service, hardware or network actors."""
import copy
import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

HERE=Path(__file__).resolve().parent
loader=importlib.machinery.SourceFileLoader('doctor',str(HERE/'cachy-asahi-doctor'))
spec=importlib.util.spec_from_loader(loader.name,loader);doctor=importlib.util.module_from_spec(spec);loader.exec_module(doctor)
MACHINE=dict(architecture='aarch64',page_size_bytes=16384,kernel='fixture-asahi')
NAMES=[n for group in doctor.PACKAGES.values() for n in group]


def packages(missing=()):
    return ('checked',1 if missing else 0,
        ''.join(n+' 1.0-1\n' for n in NAMES if n not in missing).encode(),
        ''.join("error: package '"+n+"' was not found\n" for n in missing).encode())


def service():return ('checked',0,b'LoadState=loaded\nActiveState=active\nSubState=running\n',b'')


class Diagnostics(unittest.TestCase):
    def collect(self,*,dt=b'apple,j413\0apple,t8112\0',bus='/run/user/123/bus',env=None,run=None):
        probes=[]
        def query(argv,seconds,selected_bus):
            probes.append((argv,seconds,selected_bus));return packages() if argv[0].endswith('pacman') else service()
        report=doctor.collect(run=run or query,read=lambda p:dt if p.endswith('compatible') else b'PRIVATE MODEL SERIAL SENTINEL',
            has=lambda _:True,bus_check=lambda:bus,audio_check=lambda:None,machine=dict(MACHINE),environ=env or {})
        return report,probes
    def test_known_dt_identity_is_observation_with_real_page_size(self):
        report,_=self.collect();row=next(r for r in report['checks'] if r['check']=='apple-model')
        self.assertEqual(row['value']['identifier'],'apple,j413');self.assertEqual(row['state'],'checked')
        self.assertEqual(report['checks'][0]['value']['page_size_bytes'],16384)
        self.assertNotIn('PASS',json.dumps(report));self.assertNotIn('SERIAL SENTINEL',json.dumps(report))
    def test_unknown_missing_or_ambiguous_model_stays_unknown(self):
        for dt in (b'apple,j999\0',b'linux,dummy-virt\0',b'apple,j413\0apple,j415\0',b'apple,j413\xff\0',None):
            with self.subTest(dt=dt):
                report,_=self.collect(dt=dt);row=report['checks'][1]
                self.assertIsNone(row['value']['model']);self.assertIn(row['state'],('unknown','unavailable'))
    def test_all_queries_fixed_read_only_local_bounded_and_no_session_ids_retained(self):
        report,probes=self.collect(env=dict(XDG_SESSION_TYPE='wayland',HYPRLAND_INSTANCE_SIGNATURE='PRIVATE SESSION HASH',
            WAYLAND_DISPLAY='PRIVATE SOCKET',DBUS_SESSION_BUS_ADDRESS='tcp:remote,secret',HOME='PRIVATE HOME',LD_PRELOAD='PRIVATE LIBRARY'))
        self.assertEqual(len(probes),9)
        for argv,seconds,bus in probes:
            self.assertGreater(seconds,0);self.assertLessEqual(seconds,2)
            if argv[0].endswith('pacman'):self.assertEqual(argv[1:],['-Q','--',*NAMES])
            else:
                self.assertIn('show',argv);self.assertEqual(argv[-1],'--property=LoadState,ActiveState,SubState')
                self.assertFalse(any(x in argv for x in ('start','restart','enable','status','journalctl')))
                if '--user' in argv:self.assertEqual(bus,'/run/user/123/bus')
        self.assertNotIn('PRIVATE',json.dumps(report));self.assertNotIn('tcp:',json.dumps(report))
    def test_no_local_user_bus_skips_user_queries(self):
        report,probes=self.collect(bus=None)
        self.assertEqual(len(probes),4)
        rows=[r for r in report['checks'] if r['check'].startswith('user/')]
        self.assertEqual(len(rows),5);self.assertTrue(all(r['state']=='unavailable' for r in rows))
    def test_missing_tools_never_launch_commands_or_infer_absence(self):
        run=Mock()
        report=doctor.collect(run=run,read=lambda _:None,has=lambda _:False,bus_check=lambda:None,audio_check=lambda:None,machine=MACHINE,environ={})
        run.assert_not_called();rows=[r for r in report['checks'] if r['check'].startswith('package/')]
        self.assertTrue(all(r['state']=='unavailable' and r['value']['presence']=='unknown' for r in rows))
        self.assertGreater(report['coverage']['unavailable'],0)
    def test_deadline_exhaustion_marks_unknown_without_further_queries(self):
        run=Mock()
        with patch.object(doctor.time,'monotonic',side_effect=[0]+[30]*10):
            report,_=self.collect(run=run)
        run.assert_not_called();self.assertGreater(report['coverage']['unknown'],0)
    def test_confirmed_absence_differs_from_query_failure(self):
        rows=doctor.package_rows(packages(['m1n1']))
        missing=next(r for r in rows if r['check']=='package/m1n1')
        self.assertEqual(missing['state'],'checked');self.assertEqual(missing['value']['presence'],'absent')
        rows=doctor.package_rows(('checked',1,b'',b'error: local database unavailable; PRIVATE DETAIL'))
        self.assertTrue(all(r['state']=='unknown' and r['value']['presence']=='unknown' for r in rows))
        self.assertNotIn('PRIVATE',json.dumps(rows))
    def test_malformed_unexpected_or_duplicate_package_rows_are_unknown(self):
        for out in (b'linux-asahi 1\nlinux-asahi 2\n',b'other 1\n',b'linux-asahi bad\x1bversion\n'):
            rows=doctor.package_rows(('checked',0,out,b''));self.assertTrue(all(r['state']=='unknown' for r in rows))
    def test_failed_inactive_and_missing_services_are_observed_not_healthy(self):
        for active in ('failed','inactive'):
            row=doctor.service_row('system','asahi-audio.service',('checked',0,
                ('LoadState=loaded\nActiveState='+active+'\nSubState=dead\n').encode(),b''))
            self.assertEqual(row['state'],'checked');self.assertIn('failed' if active=='failed' else 'not active',row['note'])
        row=doctor.service_row('user','pipewire.service',('checked',0,b'LoadState=not-found\nActiveState=inactive\nSubState=dead\n',b''))
        self.assertIn('not installed',row['note'])
    def test_unexpected_service_output_is_never_retained(self):
        for raw in (b'ExecStart=PRIVATE\n',b'LoadState=loaded\n',b'LoadState=loaded\nActiveState=active\nSubState=running\nPRIVATE=secret\n'):
            row=doctor.service_row('user','pipewire.service',('checked',0,raw,b'PRIVATE'))
            self.assertEqual(row['state'],'unknown');self.assertIsNone(row['value']);self.assertNotIn('PRIVATE',json.dumps(row))


class QueryControls(unittest.TestCase):
    def invoke(self,overflow=False):
        streams=[Mock(),Mock()];process=SimpleNamespace(pid=999999,stdout=streams[0],stderr=streams[1],returncode=0,wait=Mock())
        selector=Mock();selector.get_map.return_value={1:True};selector.select.return_value=[(SimpleNamespace(fd=1,data=0),None)]
        calls=[]
        with patch.object(doctor.subprocess,'Popen',return_value=process) as spawned,\
             patch.object(doctor.selectors,'DefaultSelector',return_value=selector),patch.object(doctor.os,'set_blocking'),\
             patch.object(doctor.os,'read',return_value=b'x'*(doctor.MAX_OUTPUT+1)),patch.object(doctor.os,'killpg',side_effect=lambda *a:calls.append('kill')),\
             patch.object(doctor.time,'monotonic',side_effect=[0,0] if overflow else [0,3]):
            process.wait.side_effect=lambda **kw:calls.append('wait')
            value=doctor.query(['/usr/bin/systemctl','--user','show','pipewire.service'],1,'/run/user/123/bus')
            self.assertEqual(value[0],'unknown');self.assertEqual(calls,['kill','wait'])
            env=spawned.call_args.kwargs['env'];self.assertEqual(env['DBUS_SESSION_BUS_ADDRESS'],'unix:path=/run/user/123/bus')
            self.assertNotIn('LD_PRELOAD',env);self.assertNotIn('HOME',env)
    def test_timeout_is_unknown_and_query_group_retired(self):self.invoke()
    def test_output_overflow_is_unknown_and_query_group_retired(self):self.invoke(overflow=True)


class Reports(unittest.TestCase):
    def test_private_complete_atomic_no_overwrite_publication(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'report.json';raw=b'{"complete":true}\n';link=doctor.os.link
            def publish(source,target,**kwargs):
                self.assertFalse(path.exists());self.assertEqual((path.parent/source).read_bytes(),raw)
                return link(source,target,**kwargs)
            with patch.object(doctor.os,'link',side_effect=publish):doctor.publish(path,raw)
            self.assertEqual(path.read_bytes(),raw);self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o600)
            self.assertEqual(path.stat().st_nlink,1)
            with self.assertRaises(FileExistsError):doctor.publish(path,b'REPLACED')
            self.assertEqual(path.read_bytes(),raw);self.assertEqual(list(path.parent.iterdir()),[path])
    def test_symlink_destination_and_parent_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);target=root/'target';target.write_bytes(b'KEEP');alias=root/'alias';alias.symlink_to(target)
            with self.assertRaises(FileExistsError):doctor.publish(alias,b'NEW')
            directory=root/'dir';directory.mkdir();(root/'linked').symlink_to(directory,target_is_directory=True)
            with self.assertRaises(OSError):doctor.publish(root/'linked/report',b'NEW')
            self.assertEqual(target.read_bytes(),b'KEEP');self.assertFalse((directory/'report').exists())
    def test_stdout_is_default_and_report_errors_have_nonzero_exit(self):
        report,_=Diagnostics().collect()
        with patch.object(doctor,'collect',return_value=report),patch.object(sys,'stdout',io.StringIO()) as out:
            self.assertEqual(doctor.main([]),0);self.assertIn('Coverage:',out.getvalue());self.assertIn('not an all-healthy',out.getvalue())
        with tempfile.TemporaryDirectory() as temp,patch.object(doctor,'collect',return_value=report),\
             patch.object(sys,'stdout',io.StringIO()),patch.object(sys,'stderr',io.StringIO()):
            path=Path(temp)/'report';path.write_bytes(b'KEEP')
            self.assertEqual(doctor.main(['--output',str(path)]),2);self.assertEqual(path.read_bytes(),b'KEEP')
    def test_json_stdout_has_same_explicit_unknown_coverage(self):
        report,_=Diagnostics().collect(bus=None)
        with patch.object(doctor,'collect',return_value=report),patch.object(sys,'stdout',io.StringIO()) as out:
            self.assertEqual(doctor.main(['--json']),0);self.assertEqual(json.loads(out.getvalue()),report)


if __name__=='__main__':unittest.main()
