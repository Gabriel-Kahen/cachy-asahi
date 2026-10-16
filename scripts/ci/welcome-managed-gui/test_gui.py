"""Inert transport/semantic/ownership controls. No native GUI/compiler/package actors."""
import base64
import copy
import json
import os
from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import candidates
import gui_contract as G
import observed
import prepare

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
ASSETS=Path(os.environ.get('WELCOME_GUI_ASSETS',str(ROOT/'artifacts/development/welcome-native-inputs-20261016/payload')))


def node(name, *, selected=False, text=None):
    row=dict(name_base64=base64.b64encode(name.encode()).decode(),role=42,showing=True,selected=selected,checked=False)
    if text is not None:row.update(text_sha256=G.sha(text),text_bytes=len(text),prefix_base64=base64.b64encode(text[:192]).decode())
    return row


def window(pid,kind):
    at,size=G.RECTS[kind]
    return dict(pid=pid,address='0x'+format(pid,'x'),mapped=True,visible=True,hidden=False,xwayland=False,
        floating=True,at=at,size=size,monitor=0,workspace=dict(id=1,name='1'),
        title=G.TITLE if kind.startswith('welcome') else G.DOCTOR_TITLE,
        **{'class':'io.github.GabrielKahen.CachyAsahiWelcome' if kind.startswith('welcome') else G.DOCTOR_ID})


def doctor(stage='minimal',nonce='a'*32,pid=101):
    checks=[dict(check='platform',state='checked',value=dict(architecture='aarch64',page_size_bytes=4096,kernel='7.2.10-generic')),
        dict(check='apple-model',state='unavailable',value=dict(identifier=None))]
    checks += [dict(check='package/'+name,state='checked',value=dict(group='project',presence='present',version='0.1.0-1'))
               for name in candidates.NAMES]
    return dict(status='PASS_INSTALLED_DOCTOR_REPORT',stage=stage,nonce=nonce,terminal_pid=pid,worker_pid=999,
        terminal_isatty=True,pty='/dev/pts/7',doctor=dict(tool='cachy-asahi-doctor',scope='local observations only',checks=checks,
            coverage=dict(checked=3,unknown=1,unavailable=1)),report_sha256='f'*64,report_mode='0600',no_overwrite='PASS',symlink_refusal='PASS')


class Transport(unittest.TestCase):
    def test_frozen_four_archives_sources_payloads_elf_and_history_are_joined(self):
        rows=candidates.verify(ROOT,ASSETS)
        self.assertEqual(set(rows),set(candidates.NAMES))
        self.assertEqual(len(rows[candidates.NAMES[0]]['payload']),9)
        self.assertEqual(len(rows[candidates.NAMES[1]]['payload']),4)
        self.assertTrue(all(r['producer_lifecycle']=='FAIL_USER_PRESERVATION_CHECK' for r in rows.values()))
        with tempfile.TemporaryDirectory() as d:
            out=Path(d)/'candidates';lock=candidates.stage(ROOT,ASSETS,out)
            self.assertEqual(lock['eligibility'],'PRIVATE_GUI_TRIAL_ONLY')
            self.assertEqual(len(list(out.glob('*.pkg.tar.xz'))),2)
            with self.assertRaises(ValueError):candidates.stage(ROOT,ASSETS,out)

    def test_index_and_archive_drift_are_refused_before_staging(self):
        for mutate in ('index','archive'):
            with tempfile.TemporaryDirectory() as d:
                assets=Path(d)/'assets';shutil.copytree(ASSETS,assets)
                target=assets/'index.json' if mutate=='index' else next((assets/'packages').rglob('*.pkg.tar.xz'))
                target.write_bytes(target.read_bytes()+b'corruption')
                with self.assertRaises(ValueError):candidates.verify(ROOT,assets)

    def test_recipe_source_drift_is_not_current_acceptance(self):
        with tempfile.TemporaryDirectory() as d:
            source=Path(d)
            index=json.loads((ASSETS/'index.json').read_text())
            for relative in index['recipe_sources']:
                destination=source/relative;destination.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/relative,destination)
            changed=source/'packages/tools/cachy-asahi-welcome/welcome.c';changed.write_text('changed')
            with patch.object(candidates,'verify_source'):
                with self.assertRaisesRegex(ValueError,'current product source differs'):candidates.verify(source,ASSETS)

    def test_prepare_installs_only_verified_candidates_and_bounds_fourteen_frames(self):
        with tempfile.TemporaryDirectory() as d:
            output=prepare.prepare(ROOT,Path(d)/'runner',ASSETS)
            runtime=(output/'desktop574_runtime.py').read_text();fixture=(output/'desktop574_fixture.sh').read_text()
            self.assertIn('/tmp/products/*.pkg.tar.xz',runtime)
            self.assertIn('candidate_lock["products"]',runtime)
            self.assertIn('overlay-recovery',runtime);self.assertIn('minimal-terminal-action',runtime)
            self.assertIn('managed_session.SETPRIV',(output/'base_guest.py').read_text())
            self.assertNotIn('dbus-run-session',(output/'base_guest.py').read_text())
            self.assertIn('pkg-config --cflags --libs atspi-2 gobject-2.0',fixture)
            self.assertIn('session.wait(timeout=1080)',(output/'base_guest.py').read_text())
            self.assertNotIn('active_owner',json.dumps(json.loads((HERE/'source-pins.json').read_text())))


class Semantic(unittest.TestCase):
    def test_layout_is_idempotent_for_actual_floating_to_action_transition(self):
        row=window(566,'welcome');calls=[]
        def command(argv,label):
            calls.append(argv[-1])
            if '.float(' in argv[-1]:row['floating']=not row['floating']
            return 'ok\n'
        G.layout(command,row,'welcome-action')
        self.assertTrue(row['floating']);self.assertEqual(len(calls),2)
        self.assertFalse(any('.float(' in expression for expression in calls))
        self.assertIn('x=550,y=550,relative=false',calls[0]);self.assertIn('x=12,y=12,relative=false',calls[1])
        G.layout(command,row,'welcome');self.assertTrue(row['floating']);self.assertEqual(len(calls),4)

    def test_layout_floats_only_observed_tiled_window_and_refuses_unknown_state(self):
        row=window(566,'welcome');row['floating']=False;calls=[]
        def command(argv,label):
            calls.append(argv[-1])
            if '.float(' in argv[-1]:row['floating']=not row['floating']
            return 'ok\n'
        G.layout(command,row,'welcome-action')
        self.assertTrue(row['floating']);self.assertEqual(len(calls),3);self.assertIn('.float(',calls[0])
        for state in (None,1,'true'):
            row['floating']=state
            with self.assertRaisesRegex(ValueError,'safe layout target required'):G.layout(command,row,'welcome-action')
        self.assertEqual(len(calls),3)

    def test_visible_selected_guide_requires_exact_full_installed_text(self):
        text=b'installed guide\n';value=dict(status='PASS',pid=10,nodes=[node('First steps',selected=True),node('text',text=text)])
        result=G.validate_snapshot(value,10,'first-steps',G.sha(text));self.assertIn(G.sha(text),result['showing_text_sha256'])
        with self.assertRaises(G.ViewPending):G.validate_snapshot(value,10,'first-steps','0'*64)
        with self.assertRaises(ValueError):G.validate_snapshot(value,11,'first-steps',G.sha(text))
        value['nodes'][0]['selected']=False
        with self.assertRaises(G.ViewPending):G.validate_snapshot(value,10,'first-steps',G.sha(text))

    def test_home_and_system_state_are_observed_not_inferred_from_action_success(self):
        home=dict(status='PASS',pid=10,nodes=[node(n) for n in ('Open Terminal','Open Files','First steps','Updates','Recovery')])
        G.validate_snapshot(home,10,'home')
        with self.assertRaises(G.ViewPending):G.validate_snapshot(home,10,'system',G.sha(b'status'))
        system=dict(status='PASS',pid=10,nodes=[node('Refresh system status'),node('status',text=b'status')])
        G.validate_snapshot(system,10,'system',G.sha(b'status'))

    def test_malformed_or_oversized_accessibility_data_is_fatal(self):
        value=dict(status='PASS',pid=10,nodes=[node('text')])
        for bad in (value|dict(pid=True),value|dict(nodes=value['nodes']*193),
                    value|dict(nodes=[dict(value['nodes'][0],name_base64='not base64')])):
            with self.assertRaises((ValueError,TypeError)):G.validate_snapshot(bad,10,'terminal-action')

    def test_pid_owned_native_layout_workspace_and_both_windows_required(self):
        rows=[window(10,'welcome'),window(11,'doctor')];G.together(rows,10,11,'home')
        for change in (dict(xwayland=True),dict(visible=False),dict(at=[1,1]),dict(workspace=dict(id=2,name='2')),
                       {'class':'foreign'}):
            bad=copy.deepcopy(rows);bad[0].update(change)
            with self.subTest(change=change),self.assertRaises(ValueError):G.together(bad,10,11,'home')

    def test_installed_doctor_scope_and_private_no_overwrite_report_required(self):
        value=doctor();G.validate_doctor(value,'minimal','a'*32,101)
        for change in (dict(terminal_isatty=False),dict(no_overwrite='NOT_RUN'),dict(report_mode='0644')):
            with self.assertRaises(ValueError):G.validate_doctor(value|change,'minimal','a'*32,101)
        bad=copy.deepcopy(value);bad['doctor']['checks'][0]['value']['architecture']='x86_64'
        with self.assertRaises(ValueError):G.validate_doctor(bad,'minimal','a'*32,101)


class PidOwnership(unittest.TestCase):
    def test_pidfd_acquisition_checks_uid_executable_and_reuse_without_signalling(self):
        correct=dict(pid=10,uid=[23001]*4,starttime=100,executable='/usr/bin/alacritty')
        with patch.object(observed,'identity',side_effect=[correct,correct|dict(starttime=101)]),\
             patch.object(observed.os,'pidfd_open',return_value=44),patch.object(observed.os,'close') as close,\
             patch.object(observed.signal,'pidfd_send_signal') as signal:
            with self.assertRaisesRegex(ValueError,'PID changed'):observed.ObservedTerminal(10)
            close.assert_called_once_with(44);signal.assert_not_called()
        with patch.object(observed,'identity',return_value=correct|dict(uid=[1000]*4)),\
             patch.object(observed.os,'pidfd_open') as opening:
            with self.assertRaises(ValueError):observed.ObservedTerminal(10)
            opening.assert_not_called()


if __name__=='__main__':unittest.main()
