# SPDX-License-Identifier: MIT
"""Private filesystem/CLI lifecycle cases for explicitly selected shell modules."""
import copy
import importlib.util
import itertools
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest
from unittest import mock
import test_setup

setup = test_setup.setup


class ShellModuleTests(unittest.TestCase):
    setUp = test_setup.SetupTests.setUp
    target = test_setup.SetupTests.target
    put = test_setup.SetupTests.put
    state = test_setup.SetupTests.state
    snapshot = test_setup.SetupTests.snapshot

    def cli(self, operation, components=(), apply=False, script=None):
        command = [sys.executable, '-B', str(script or Path(setup.__file__)), operation,
                   '--home', str(self.home), '--template-root', str(self.templates)]
        if components:command += ['--components', *components]
        if apply:command += ['--apply']
        return subprocess.run(command, env=self.env(), capture_output=True, text=True, timeout=10)

    def env(self):
        return dict(PATH='/usr/bin:/bin', HOME=str(self.home), TERM='dumb',
                    XDG_CONFIG_HOME=str(self.home/'.config'), XDG_DATA_HOME=str(self.home/'.local/share'),
                    XDG_STATE_HOME=str(self.home/'.local/state'), ZDOTDIR=str(self.home), PYTHONDONTWRITEBYTECODE='1')

    def pending(self, operation='activate'):
        state = self.engine.load(self.engine.state_path, {'schema_version':1,'roots':self.engine.roots,'components':{}})
        entries, actions, new_state = self.engine.plan(operation, setup.ORDER, state)
        return dict(schema_version=1, roots=self.engine.roots, id='a'*32,
                    template_root=str(self.templates), operation=operation, entries=entries,new_state=new_state)

    def crash_cli(self, operation, components, checkpoint, script=None):
        # Real child exits after an actual fsynced write; no mocked filesystem/PID result.
        code = '''import importlib.util,os,sys
from pathlib import Path
s=importlib.util.spec_from_file_location('held_setup',sys.argv[1]);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
e=m.Setup(Path(sys.argv[2]),Path(sys.argv[3]));original=e.fs.atomic
checkpoint=e.state_path if sys.argv[4]=='state' else e.targets[sys.argv[4]]
def atomic(path,data,expected,private=False):
 original(path,data,expected,private)
 if path==checkpoint:os._exit(71)
e.fs.atomic=atomic
e.run(sys.argv[5],sys.argv[6:],True)
'''
        result=subprocess.run([sys.executable,'-B','-c',code,str(script or Path(setup.__file__)),str(self.home),str(self.templates),checkpoint,operation,*components],env=self.env(),capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,71,result.stdout+result.stderr)
        self.assertTrue((self.home/self.engine.journal_path).is_file())

    def test_literal_paths_and_explicit_selection_only(self):
        expected = {name:name+('/opt-in.fish' if name.startswith('fish-') else '/opt-in.zsh') for name in setup.MODULES}
        self.assertEqual({n:setup.TEMPLATES[n] for n in setup.MODULES},expected)
        self.engine.run('activate',setup.COMPONENTS,True)
        self.assertEqual(set(self.state()['components']),set(setup.COMPONENTS))
        for component in setup.MODULES:self.assertNotIn(setup.markers(component)[0],self.target(component).read_text())
        before=self.snapshot();result=self.cli('activate');self.assertEqual(result.returncode,1);self.assertEqual(self.snapshot(),before)

    def test_module_only_cli_preview_apply_repeat_remove_and_reinstall(self):
        self.assertEqual(self.cli('activate',setup.MODULES).returncode,0)
        self.assertEqual(list(self.home.iterdir()),[])
        self.assertEqual(self.cli('activate',tuple(reversed(setup.MODULES)),True).returncode,0)
        self.assertEqual(set(self.state()['components']),set(setup.MODULES))
        first=self.snapshot();self.assertEqual(self.cli('activate',setup.MODULES,True).returncode,0);self.assertEqual(self.snapshot(),first)
        self.assertEqual(self.cli('remove',apply=True).returncode,0)
        self.assertFalse(self.target('fish').exists());self.assertFalse(self.target('zsh').exists())
        self.assertEqual(self.cli('activate',setup.MODULES,True).returncode,0)

    def test_all_nine_components_share_two_atomic_shell_writes(self):
        journal=self.pending();self.assertEqual(len(journal['entries']),3)
        self.assertEqual(sorted(len(e.get('chain',[e])) for e in journal['entries']),[1,4,4])
        self.engine.run('activate',tuple(reversed(setup.ALL_COMPONENTS)),True)
        self.assertEqual(len(self.state()['components']),9)
        self.engine.run('remove',apply=True)
        self.assertEqual(self.state()['components'],{})
        self.assertTrue(all(not self.target(n).exists() for n in setup.ALL_COMPONENTS))

    def test_separate_invocation_orders_are_deterministic(self):
        for family in (setup.MODULES[:3],setup.MODULES[3:]):
            for order in itertools.permutations(family):
                with self.subTest(order=order):
                    for component in order:self.engine.run('activate',(component,),True)
                    text=self.target(family[0]).read_text();positions=[text.index(setup.markers(c)[0]) for c in family]
                    self.assertEqual(positions,sorted(positions))
                    self.engine.run('remove',apply=True)
                    self.assertFalse(self.target(family[0]).exists())

    def test_existing_custom_bytes_modes_and_subset_removal(self):
        originals={'fish':b'# custom fish\n','zsh':b'# custom zsh\n'}
        for shell,raw in originals.items():self.put(shell,raw,0o640)
        self.engine.run('activate',setup.ALL_COMPONENTS,True)
        self.engine.run('remove',('fish-bang-bang','zsh-syntax-highlighting'),True)
        self.assertNotIn('fish-bang-bang',self.state()['components'])
        self.assertIn('fish-autopair',self.state()['components'])
        self.engine.run('remove',apply=True)
        for shell,raw in originals.items():
            self.assertEqual(self.target(shell).read_bytes(),raw)
            self.assertEqual(self.target(shell).stat().st_mode&0o777,0o640)

    def test_existing_empty_files_survive_shared_removal(self):
        for shell in ('fish','zsh'):self.put(shell,b'')
        self.engine.run('activate',setup.MODULES,True);self.engine.run('remove',apply=True)
        for shell in ('fish','zsh'):self.assertEqual(self.target(shell).read_bytes(),b'')

    def test_edited_module_preserved_other_owned_blocks_removed(self):
        self.engine.run('activate',setup.MODULES,True)
        path=self.target('fish');path.write_text(path.read_text().replace('source '+setup.shlex.quote(str(self.templates/setup.TEMPLATES['fish-autopair'])),'# user changed source'))
        result=self.cli('remove',apply=True);self.assertEqual(result.returncode,2)
        self.assertEqual(set(self.state()['components']),{'fish-autopair'})
        self.assertIn('# user changed source',path.read_text());self.assertFalse(self.target('zsh').exists())

    def test_edited_ordering_anchor_is_not_overwritten(self):
        self.engine.run('activate',('zsh-history-substring-search',),True)
        path=self.target('zsh');path.write_text(path.read_text().replace('    source ','    # user source '));before=self.snapshot()
        with self.assertRaisesRegex(setup.Error,'edited or duplicated'):
            self.engine.run('activate',('zsh-syntax-highlighting',),True)
        self.assertEqual(self.snapshot(),before)

    def test_missing_selected_module_fails_before_any_mutation(self):
        (self.templates/setup.TEMPLATES['zsh-history-substring-search']).unlink()
        for apply in (False,True):
            result=self.cli('activate',setup.ALL_COMPONENTS,apply)
            self.assertEqual(result.returncode,1);self.assertIn('zsh-history-substring-search',result.stderr)
            self.assertEqual(list(self.home.iterdir()),[])

    def test_module_source_symlink_refused_before_any_mutation(self):
        path=self.templates/setup.TEMPLATES['fish-done'];path.unlink();path.symlink_to(self.templates/setup.TEMPLATES['fish'])
        self.assertEqual(self.cli('activate',setup.MODULES,True).returncode,1)
        self.assertEqual(list(self.home.iterdir()),[])

    def test_source_root_replacement_and_removal_after_packages_disappear(self):
        self.engine.run('activate',setup.ALL_COMPONENTS,True)
        replacement=self.root/'replacement';shutil.copytree(self.templates,replacement)
        engine=setup.Setup(self.home,replacement);self.addCleanup(engine.close)
        engine.run('activate',setup.MODULES,True)
        for c in setup.MODULES:self.assertEqual(self.state()['components'][c]['source_root'],str(replacement))
        for c in ('fish','zsh'):self.assertEqual(self.state()['components'][c]['source_root'],str(self.templates))
        shutil.rmtree(self.templates);shutil.rmtree(replacement)
        self.engine.run('remove',apply=True);self.assertEqual(self.state()['components'],{})

    def test_actual_process_interruption_activate_recover_remove_and_reinstall(self):
        self.crash_cli('activate',setup.ALL_COMPONENTS,'fish')
        self.assertTrue(self.target('fish').exists());self.assertFalse(self.target('zsh').exists())
        pending=self.cli('recover');self.assertEqual(pending.returncode,2)
        self.assertEqual(self.cli('recover',apply=True).returncode,0)
        self.assertEqual(len(self.state()['components']),9)
        self.crash_cli('remove',(), 'fish')
        self.assertFalse(self.target('fish').exists())
        self.assertEqual(self.cli('recover',apply=True).returncode,0)
        self.assertEqual(self.cli('activate',setup.ALL_COMPONENTS,True).returncode,0)

    def test_actual_process_interruption_after_state_commit_is_idempotent(self):
        self.crash_cli('activate',setup.ALL_COMPONENTS,'state')
        files={s:self.target(s).read_bytes() for s in ('fish','zsh','hyprland')}
        self.assertEqual(self.cli('recover',apply=True).returncode,0)
        self.assertEqual(files,{s:self.target(s).read_bytes() for s in files})
        self.assertFalse((self.home/self.engine.journal_path).exists())

    def test_edit_after_shared_write_interrupt_retains_journal(self):
        self.crash_cli('activate',setup.MODULES,'fish');self.target('fish').write_text('# private user edit\n')
        before=self.snapshot();self.assertEqual(self.cli('recover',apply=True).returncode,1)
        self.assertEqual(self.snapshot(),before)

    def test_grouped_journal_tampering_refused_before_configuration_write(self):
        self.engine.run('recover',apply=True)
        original=self.pending();group=next(e for e in original['entries'] if 'chain' in e)
        variants=[]
        bad=copy.deepcopy(original);bad['entries'][0]['after']='0'*64;variants.append(bad)
        bad=copy.deepcopy(original);g=next(e for e in bad['entries'] if 'chain' in e);g['chain'][1]['before']='0'*64;variants.append(bad)
        bad=copy.deepcopy(original);bad['entries'].append(copy.deepcopy(bad['entries'][0]));variants.append(bad)
        bad=copy.deepcopy(original);g=next(e for e in bad['entries'] if 'chain' in e);g['chain'][1]['component']=g['chain'][0]['component'];variants.append(bad)
        bad=copy.deepcopy(original);g=next(e for e in bad['entries'] if 'chain' in e);g['chain'][1]=[];variants.append(bad)
        bad=copy.deepcopy(original);g=next(e for e in bad['entries'] if 'chain' in e);g['chain'][0]=[];variants.append(bad)
        for bad in variants:
            with self.subTest(bad=variants.index(bad)):
                self.engine.save(self.engine.journal_path,bad);before=self.snapshot()
                with self.assertRaises(setup.Error):self.engine.run('recover',apply=True)
                self.assertEqual(self.snapshot(),before)

    def test_changed_later_group_prevents_any_new_write(self):
        journal=self.pending();self.engine.save(self.engine.journal_path,journal)
        self.put('zsh',b'# concurrent edit\n');before=self.target('zsh').read_bytes()
        with self.assertRaisesRegex(setup.Error,'user edits preserved'):self.engine.run('recover',apply=True)
        self.assertFalse(self.target('fish').exists());self.assertFalse(self.target('hyprland').exists())
        self.assertEqual(self.target('zsh').read_bytes(),before)

    def test_oversized_later_shared_delta_prevents_any_configuration_write(self):
        self.put('zsh',b'#'+b'x'*(setup.MAX_BYTES-2)+b'\n')
        with self.assertRaisesRegex(setup.Error,'size limit'):self.engine.run('activate',setup.ALL_COMPONENTS,True)
        self.assertFalse(self.target('fish').exists());self.assertFalse((self.home/self.engine.journal_path).exists())

    def test_legacy_v1_state_and_single_entry_journal_remain_readable(self):
        # Literal pre-module contract, independent of current block()/plan().
        source=setup.shlex.quote(str(self.templates/'fish/config.fish'))
        text=('# >>> cachy-asahi setup fish v1 >>>\n'
              f'if status is-interactive; and test -r {source}\n    source {source}\nend\n'
              '# <<< cachy-asahi setup fish v1 <<<\n')
        record=dict(path='.config/fish/config.fish',kind='block',block=text,created_file=True,source_root=str(self.templates))
        state=dict(schema_version=1,roots=self.engine.roots,components={'fish':record})
        entry=dict(component='fish',path=record['path'],before=None,after=setup.checksum(text.encode()),
                   change=dict(type='append',new=text),old_record=None,new_record=record)
        journal=dict(schema_version=1,roots=self.engine.roots,id='b'*32,template_root=str(self.templates),
                     operation='activate',entries=[entry],new_state=state)
        self.engine.save(self.engine.journal_path,journal)
        self.assertEqual(self.cli('recover',apply=True).returncode,0)
        self.assertEqual(self.target('fish').read_text(),text)
        self.assertEqual(self.state(),state)
        self.assertEqual(self.cli('activate',setup.MODULES,True).returncode,0)
        self.assertEqual(self.state()['components']['fish'],record)
        self.assertEqual(self.cli('remove',setup.MODULES,True).returncode,0)
        self.assertEqual(self.target('fish').read_text(),text)
        self.assertEqual(self.state(),state)

    def test_moved_exact_owned_blocks_refuse_unsafe_order_reconciliation(self):
        self.engine.run('activate',setup.MODULES[3:],True)
        records=self.state()['components'];path=self.target('zsh')
        path.write_text(''.join(records[c]['block'] for c in reversed(setup.MODULES[3:])))
        before=self.snapshot()
        for apply in (False,True):
            with self.assertRaisesRegex(setup.Error,'source order was changed'):
                self.engine.run('activate',setup.MODULES[3:],apply)
            self.assertEqual(self.snapshot(),before)

    def test_canonical_new_module_record_without_delta_is_not_adopted(self):
        state=dict(schema_version=1,roots=self.engine.roots,components={})
        entries,_,new_state=self.engine.plan('activate',('fish',),state)
        new_state['components']['fish-done']=dict(path=self.engine.targets['fish-done'],kind='block',
            block=setup.block('fish-done',self.templates/setup.TEMPLATES['fish-done']),
            created_file=True,source_root=str(self.templates))
        journal=dict(schema_version=1,roots=self.engine.roots,id='d'*32,template_root=str(self.templates),
                     operation='activate',entries=entries,new_state=new_state)
        self.engine.run('recover',apply=True);self.engine.save(self.engine.journal_path,journal);before=self.snapshot()
        with self.assertRaisesRegex(setup.Error,'ownership change lacks'):self.engine.run('recover',apply=True)
        self.assertEqual(self.snapshot(),before)

    def test_unapproved_insertion_anchor_record_is_refused(self):
        self.engine.run('activate',('zsh-history-substring-search',),True)
        state=self.state();entries,_,new_state=self.engine.plan('activate',('zsh-syntax-highlighting',),state)
        journal=dict(schema_version=1,roots=self.engine.roots,id='c'*32,template_root=str(self.templates),
                     operation='activate',entries=entries,new_state=new_state)
        anchor=entries[0]['change']['anchor_record'];forged=dict(anchor,source_root='/unapproved')
        forged['block']=setup.block('zsh-history-substring-search',Path('/unapproved')/setup.TEMPLATES['zsh-history-substring-search'])
        entries[0]['change']['anchor_record']=forged
        self.engine.save(self.engine.journal_path,journal);before=self.snapshot()
        with self.assertRaisesRegex(setup.Error,'lacks ordered ownership'):self.engine.run('recover',apply=True)
        self.assertEqual(self.snapshot(),before)

    @unittest.skipUnless(shutil.which('fish') and shutil.which('zsh'),'Actual Fish/Zsh unavailable')
    def test_actual_shell_guards_order_quoted_paths_and_missing_modules(self):
        templates=self.root/"module user's files";self.templates.rename(templates)
        engine=setup.Setup(self.home,templates);self.addCleanup(engine.close)
        for component in setup.MODULES:(templates/setup.TEMPLATES[component]).write_text("printf '%s\\n' "+component+'\n')
        engine.run('activate',tuple(reversed(setup.MODULES)),True)
        for shell,modules in [('fish',setup.MODULES[:3]),('zsh',setup.MODULES[3:])]:
            path=self.home/engine.targets[shell];command='source '+setup.shlex.quote(str(path))
            for interactive in (False,True):
                argv=['fish','--no-config','--private']+(['--interactive'] if interactive else [])+['--command',command] if shell=='fish' else ['zsh','-dfi' if interactive else '-df','-c',command]
                result=subprocess.run(argv,env=self.env(),capture_output=True,text=True,timeout=5)
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertEqual(result.stdout,'' if not interactive else ''.join(c+'\n' for c in modules))
        shutil.rmtree(templates)
        for shell in ('fish','zsh'):
            command='source '+setup.shlex.quote(str(self.home/engine.targets[shell]))
            argv=['fish','--no-config','--private','--interactive','--command',command] if shell=='fish' else ['zsh','-dfi','-c',command]
            result=subprocess.run(argv,env=self.env(),capture_output=True,text=True,timeout=5)
            self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(result.stdout,'')
        engine.run('remove',apply=True)


if __name__=='__main__':unittest.main()
