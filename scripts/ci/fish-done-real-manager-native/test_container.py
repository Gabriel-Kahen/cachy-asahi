#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Inert root-wrapper/export/refusal controls; no subprocess/native actors."""
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import container as M


class ContainerControls(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=HERE);self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)

    def test_host_refusal_precedes_source_and_actor(self):
        with patch.object(M.os,'getpid',return_value=50),patch.object(M.C,'verify',side_effect=AssertionError('source too early')), \
             patch.object(M.subprocess,'Popen',side_effect=AssertionError('native actor')):
            with self.assertRaisesRegex(ValueError,'native root PID1'):
                M.execute(Path('/not-used'),'trial')

    def test_alarm_command_has_exact_user_and_cleared_environment(self):
        argv=M.alarm_command(['/usr/bin/python','-I','-B','/inputs/native_build.py'],Path('/out/native'),
                             ['CACHY_ASAHI_NATIVE_HEADLESS_BUILD=1'])
        self.assertEqual(argv[:7],['/usr/bin/runuser','-u','alarm','--','/usr/bin/env','-i','PATH=/usr/bin'])
        self.assertIn('CACHY_ASAHI_NATIVE_HEADLESS_BUILD=1',argv)
        self.assertNotIn('DBUS_SESSION_BUS_ADDRESS',str(argv));self.assertNotIn('DISPLAY=',str(argv))

    def test_snapshot_records_links_without_following_and_detects_byte_change(self):
        parent=self.root/'tree';parent.mkdir();(parent/'file').write_bytes(b'held')
        (parent/'link').symlink_to('/not-a-real-target')
        before=M.snapshot(parent);self.assertEqual(before['link']['link'],'/not-a-real-target')
        (parent/'file').write_bytes(b'changed');self.assertNotEqual(M.snapshot(parent),before)

    def make_export(self):
        p=self.root/'payload';p.write_bytes(b'held native model bytes')
        parent=self.root/'host';parent.mkdir();out=parent/'export'
        mapping=M.export_files({'tools/sway':p},out,True)
        M.C.save(out/'build-export-map.json',mapping)
        return out

    def test_export_membership_and_byte_hashes_are_complete(self):
        out=self.make_export()
        with patch.object(M,'validate_native_build',return_value={'status':'inert model'}) as gate:
            self.assertEqual(M.verify_export(out,Path('/unused')),{'status':'inert model'})
            gate.assert_called_once_with(out,Path('/unused'))
        self.assertEqual((out/'tools/sway').stat().st_mode&0o777,0o555)
        self.assertEqual(json.loads((out.parent/'export-map.json').read_bytes())['tools/sway']['sha256'],M.C.digest(out/'tools/sway'))

    def test_export_tamper_extra_and_empty_alias_refused(self):
        out=self.make_export()
        (out/'tools/sway').chmod(0o644);(out/'tools/sway').write_bytes(b'drift')
        with patch.object(M,'validate_native_build',side_effect=AssertionError('gate after bad bytes')):
            with self.assertRaisesRegex(ValueError,'byte binding'):M.verify_export(out,Path('/unused'))
        (out/'unexpected').write_bytes(b'unknown')
        with self.assertRaisesRegex(ValueError,'membership'):M.verify_export(out,Path('/unused'))
        (out/'unexpected').unlink();(out/'empty-alias').symlink_to(self.root,target_is_directory=True)
        with self.assertRaisesRegex(ValueError,'directory alias'):M.verify_export(out,Path('/unused'))

    def test_partial_fixture_export_preserves_available_failure_data(self):
        ordinary=self.root/'ordinary';(ordinary/'old18/foreground').mkdir(parents=True)
        (ordinary/'old18/receipt.json').write_text('{"status":"FAIL"}')
        (ordinary/'old18/foreground/terminal.log').write_bytes(b'original failed PTY')
        with patch.object(M,'OUT',self.root):
            files=M.ordinary_export_files(ordinary,complete=False)
        self.assertIn('old18/receipt.json',files)
        self.assertIn('old18/foreground/terminal.log',files)
        with patch.object(M,'OUT',self.root),self.assertRaisesRegex(ValueError,'all18'):
            M.ordinary_export_files(ordinary,complete=True)

    def test_ordinary_aliases_are_metadata_only_and_unknown_targets_refuse(self):
        ordinary=self.root/'ordinary';(ordinary/'old18/foreground/bin').mkdir(parents=True)
        link=ordinary/'old18/foreground/bin/sleep';link.symlink_to('/usr/bin/sleep')
        with patch.object(M,'OUT',self.root):files=M.ordinary_export_files(ordinary)
        self.assertNotIn('old18/foreground/bin/sleep',files)
        self.assertEqual(json.loads((self.root/'ordinary-aliases.json').read_bytes()),
                         {'old18/foreground/bin/sleep':'/usr/bin/sleep'})
        link.unlink();link.symlink_to('/etc/passwd')
        with patch.object(M,'OUT',self.root),self.assertRaisesRegex(ValueError,'original old18'):
            M.ordinary_export_files(ordinary)

    def test_native_build_declared_machine_cannot_transfer_x86_credit(self):
        build=self.root/'build';build.mkdir();data=self.root/'data';data.mkdir();(data/'context.json').write_text('{}')
        value=dict(status='PASS_NATIVE_AARCH64_HEADLESS_DEPENDENCY_BUILD_ONLY',native_arch='x86_64',
            installed_delivery='NOT_RUN',errors=[],context_sha256=M.C.digest(data/'context.json'))
        M.C.save(build/'native-build-result.json',value)
        with self.assertRaisesRegex(ValueError,'actual native build'):M.validate_native_build(build,data)

    def test_real_proofs_and_product_guards_remain_in_recipe(self):
        text=(HERE/'container.py').read_text()
        self.assertIn("'--package-context','alpm-installed'",text)
        self.assertIn("'--noscriptlet'",text)
        self.assertIn("'timeout_pid_proof'",text)
        self.assertIn("'Failed (143)'",text)
        self.assertNotIn('caa_done_min_duration',text)
        self.assertNotIn('function __done_notify',text)

    def test_only_waited_child_drain_body_is_used(self):
        with patch.object(M.os,'waitpid',side_effect=[(123,0),ChildProcessError()]) as waited:
            self.assertEqual(M.drain_adopted(),[{'pid':123,'wait_status':0}])
        self.assertEqual(waited.call_args_list[0].args,(-1,os.WNOHANG))

    def test_final_build_map_includes_wrapper_proofs_and_has_no_circular_hash(self):
        out=self.make_export();parent=out.parent
        (parent/'command-1.stdout').write_bytes(b'original command stdout')
        (parent/'command-1.stderr').write_bytes(b'')
        M.C.save(parent/'commands.json',[{'exit':0,'group_absent':True}])
        M.C.save(parent/'orphan-reaping.json',{'adopted':[],'remaining':[]})
        with patch.object(M,'OUT',parent):M.finish_export('build')
        outer=json.loads((parent/'export-map.json').read_bytes())
        inner=json.loads((out/'build-export-map.json').read_bytes())
        self.assertNotIn('build-export-map.json',inner)
        self.assertEqual(set(outer),set(inner)|{'build-export-map.json'})
        self.assertEqual((out/'wrapper/command-1.stdout').read_bytes(),b'original command stdout')
        with patch.object(M,'validate_native_build',return_value={}):M.verify_export(out,Path('/unused'))

    def test_rebase_keeps_original_complete_fish_multicall_exception(self):
        parent=self.root/'ordinary';parent.mkdir();built=self.root/'built';built.mkdir();data=self.root/'data';data.mkdir()
        systems={name:'/usr/bin/'+name for name in ('fish','busctl','dbus_daemon','notify_send','timeout','bwrap','sleep','shell','python','pacman')}
        paths=dict(systems,mako='/usr/bin/mako',makoctl='/usr/bin/makoctl',sway='/old/sway',swaymsg='/old/swaymsg')
        value=dict(tools={n:{'path':p,'sha256':'0'*64} for n,p in paths.items()},
            libraries=[{'path':'/old/lib.so','sha256':'0'*64}],mako_config={'path':'/old/style','sha256':'0'*64},
            done_archive={'path':'/old/pkg','sha256':'0'*64})
        M.C.save(built/'trial-inputs.json',value)
        calls=[]
        base=types.SimpleNamespace(ordinary=lambda *a:calls.append(a),native_architecture=lambda:{'name':'aarch64','elf_machine':183})
        original=types.SimpleNamespace(SYSTEM=systems,inherited=lambda:base)
        with patch.object(M.C,'load',return_value=original),patch.object(M.C,'digest',return_value='0'*64),patch.object(M.os,'chown'):
            target=M.rebase_inputs(data,built,parent,{'native_mako_payload':{'/usr/bin/mako':'0'*64}})
        fish=next(a for a in calls if a[0]=='/usr/bin/fish')
        self.assertEqual(fish[4],('/usr/bin/fish','/usr/bin/fish_indent','/usr/bin/fish_key_reader'))
        rebased=json.loads(target.read_bytes())
        self.assertEqual(rebased['tools']['sway']['path'],str(built/'tools/sway'))
        self.assertEqual(rebased['libraries'][0]['path'],str(built/'libs/libwlroots-0.19.so'))

    def test_hosted_source_copy_keeps_exact_bytes_and_readonly_modes(self):
        data=self.root/'data';(data/'delivery').mkdir(parents=True)
        (data/'delivery/run.py').write_bytes(b'held source')
        (data/'done.pkg.tar.xz').write_bytes(b'held archive');(data/'mako.conf').write_bytes(b'held style')
        lock={'delivery_files':{'run.py':M.sha(b'held source')}}
        with patch.object(M,'OUT',self.root):target=M.stage_trial_sources(data,lock)
        self.assertEqual((target/'delivery/run.py').read_bytes(),b'held source')
        self.assertEqual((target/'delivery/run.py').stat().st_mode&0o777,0o444)
        mapping=json.loads((self.root/'input-copy-map.json').read_bytes())
        self.assertEqual(mapping['delivery/run.py']['sha256'],M.sha(b'held source'))
        self.assertEqual(set(mapping),{'delivery/run.py','done.pkg.tar.xz','mako.conf'})


if __name__=='__main__':unittest.main()
