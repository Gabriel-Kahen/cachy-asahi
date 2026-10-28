"""Inert gates and command controls; no compiler, package or container actor."""
import copy
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace
import contract as C
import lifecycle
import run

ROOT=next(root for root in Path(__file__).resolve().parents if (root/'scripts/checks/package_checks.py').is_file())
CHECKS=C.load('product_inert_shared_checks',ROOT/'scripts/checks/package_checks.py')


def binary():
    data=bytearray(2048);ident=b'\x7fELF\x02\x01\x01'+b'\0'*9
    struct.pack_into('<16sHHIQQQIHHHHHH',data,0,ident,3,183,1,0,64,0,0,64,56,3,0,0,0)
    interpreter=b'/lib/ld-linux-aarch64.so.1\0';table=b'\0libgtk-3.so.0\0libglib-2.0.so.0\0libc.so.6\0'
    entries=[(1,table.index(n)) for n in (b'libgtk',b'libglib',b'libc')]+[(5,0x400400),(10,len(table)),(0,0)]
    for i,segment in enumerate(((1,5,0,0x400000,0,2048,2048,16384),
        (3,4,0x300,0x400300,0,len(interpreter),len(interpreter),1),(2,4,0x500,0x400500,0,len(entries)*16,len(entries)*16,8))):
        struct.pack_into('<IIQQQQQQ',data,64+56*i,*segment)
    data[0x300:0x300+len(interpreter)]=interpreter;data[0x400:0x400+len(table)]=table
    for i,value in enumerate(entries):struct.pack_into('<qQ',data,0x500+16*i,*value)
    return data


def package(name=C.NAME):
    files=C.FILES if name==C.NAME else {'usr/bin/'+name:(name,0o755),
        'usr/share/doc/'+name+'/README.md':('README.md',0o644),
        **{'usr/share/licenses/'+name+'/'+n:(n,0o644) for n in ('LICENSE','NOTICE')}}
    members={p:dict(type='0',mode=mode,uid=0,gid=0,sha256=C.digest(ROOT/'packages/tools'/name/original))
             for p,(original,mode) in files.items() if not (name==C.NAME and original==C.NAME)}
    if name==C.NAME:members['usr/bin/'+name]=dict(type='0',mode=0o755,uid=0,gid=0,sha256='a'*64)
    return dict(errors=[],members=members,elf={'usr/bin/'+C.NAME:{}} if name==C.NAME else {})


class NativeControls(unittest.TestCase):
    def test_pin_scope_excludes_unused_desktop_and_optional_owner_helpers(self):
        here=Path(__file__).resolve().parent
        pins=json.loads((here/'source-pins.json').read_text())
        self.assertEqual(len(pins),33)
        self.assertFalse(any('active_owner' in n or 'desktop574_guest' in n or n.startswith('packages/desktop/') for n in pins))
        workflow=here/'ci/workflow.yml'
        if not workflow.exists():workflow=ROOT/'.github/workflows/native-arm-welcome-doctor-products.yml'
        self.assertNotIn('test_desktop574_guest.py',workflow.read_text())

    def test_exact_pinned_original_source_recipes_and_payloads(self):
        C.verify_source(ROOT)
        for name,count in ((C.NAME,16),(C.DOCTOR,7)):
            reviewed=C.recipe(ROOT,name);self.assertEqual(len(reviewed['input_sha256']),count)
            self.assertEqual(reviewed['metadata']['pkgname'],[name]);C.payload(package(name),ROOT,name)

    def test_payload_refuses_unowned_extra_links_mode_ownership_and_data(self):
        for change in ('extra','link','mode','owner','data','empty-dir'):
            report=package();key='usr/share/doc/'+C.NAME+'/README.md'
            if change=='extra':report['members']['etc/foreign']=dict(type='0')
            elif change=='empty-dir':report['members']['unexpected']=dict(type='5')
            elif change=='link':report['members'][key]['type']='2'
            elif change=='mode':report['members'][key]['mode']=0o777
            elif change=='owner':report['members'][key]['uid']=1000
            else:report['members'][key]['sha256']='0'*64
            with self.subTest(change=change),self.assertRaises(ValueError):C.payload(report,ROOT)

    def test_doctor_requires_exact_script_no_elf_or_config_payload(self):
        for change in ('elf','changed-script','extra'):
            report=package(C.DOCTOR)
            if change=='elf':report['elf']['usr/bin/'+C.DOCTOR]={}
            elif change=='extra':report['members']['etc/doctor.conf']=dict(type='0')
            else:report['members']['usr/bin/'+C.DOCTOR]['sha256']='0'*64
            with self.assertRaises(ValueError):C.payload(report,ROOT,C.DOCTOR)

    def test_welcome_structural_elf_interpreter_linkage_and_actual_16k_limit(self):
        result=C.elf(bytes(binary()),CHECKS)
        self.assertEqual(result['machine'],183);self.assertEqual(result['actual_16k_execution'],'NOT_RUN')
        self.assertEqual(result['loads'][0]['alignment'],16384)
        for change in ('machine','alignment','interpreter','needed'):
            data=binary()
            if change=='machine':struct.pack_into('<H',data,18,62)
            elif change=='alignment':struct.pack_into('<Q',data,64+48,4096)
            elif change=='interpreter':data[0x300]=ord('x')
            else:data[0x400+data[0x400:].index(b'libgtk')]=ord('x')
            with self.subTest(change=change),self.assertRaises(ValueError):C.elf(bytes(data),CHECKS)

    def test_future_builds_nonroot_network_none_no_install_and_reviewed_check_enabled(self):
        argv=run.docker('sha256:'+'a'*64,'owned',Path('/owned'))
        self.assertIn('--network=none',argv);self.assertIn('--read-only',argv);self.assertIn('--cap-drop=ALL',argv)
        self.assertNotIn('--privileged',argv)
        entry=(ROOT/'scripts/build/container-entry.sh').read_text()
        self.assertIn('makepkg --verifysource --noconfirm',entry)
        self.assertIn('makepkg --cleanbuild --clean --force --log --noconfirm',entry)
        self.assertNotIn('--nocheck',entry);self.assertNotIn('--skipchecksums',entry)

    def test_lifecycle_refuses_host_before_any_native_command(self):
        with patch.object(lifecycle.os,'getuid',return_value=1000),patch.object(lifecycle,'command') as actor:
            with self.assertRaisesRegex(ValueError,'dedicated ARM'):lifecycle.main()
            actor.assert_not_called()

    def test_inventory_parser_and_path_aliases_refuse(self):
        self.assertEqual(run.inventory('a 1\nb 2\n'),dict(a='1',b='2'))
        for text in ('a 1\na 2\n','a 1 2\n',''):
            with self.assertRaises(ValueError):run.inventory(text)
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'alias').symlink_to(root)
            with self.assertRaises(ValueError):C.safe(root/'alias'/'file')

    def test_config_snapshot_links_modes_and_content_drift(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'file').write_text('original');(root/'alias').symlink_to('file')
            before=lifecycle.snapshot(root);self.assertEqual(before,lifecycle.snapshot(root))
            (root/'file').write_text('changed');self.assertNotEqual(before,lifecycle.snapshot(root))
            self.assertEqual(before['alias']['value'],'file')

    def test_native_check_logs_require_actual_complete_test_markers(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'log'
            for name,text in ((C.NAME,'Starting check()\n1..7\nok 7 /status/json-controls\nRan 5 tests\nPASS_SOURCE_PAYLOAD_CONTRACT\n'),
                              (C.DOCTOR,'Starting check()\nRan 16 tests\nOK\n')):
                path.write_text(text);self.assertTrue(C.check_log(path,name)['check_enabled'])
                path.write_text(text.replace('Starting check()','build only'))
                with self.assertRaises(ValueError):C.check_log(path,name)

    def test_fresh_unprivileged_build_records_have_distinct_owned_containers(self):
        with tempfile.TemporaryDirectory() as d:
            out=Path(d);lock=out/'base.lock';lock.write_text('fixture 1\n');containers=[];commands=[]
            def execute(argv,log,seconds):
                commands.append(argv);directory=log.parent;artifacts=directory/'artifacts'
                log.write_text('Starting check()\nRan 16 tests\nOK\n')
                for f in ('environment.txt','config.sha256','makepkg.conf','pacman.conf'):(artifacts/f).write_text('fixture\n')
                (artifacts/'packages.lock').write_text(lock.read_text())
                (artifacts/'generated.SRCINFO').write_text((ROOT/'packages/tools'/C.DOCTOR/'.SRCINFO').read_text())
                (artifacts/(C.DOCTOR+'-0.1.0-1-any.pkg.tar.xz')).write_bytes(b'synthetic inert package')
            checks=SimpleNamespace(package=lambda path:package(C.DOCTOR),metadata=CHECKS.metadata)
            bind=SimpleNamespace(bind_generated=lambda *args:None,bind_artifact=lambda *args:[])
            for side in ('a','b'):
                run.build(ROOT,out,dict(fixture='1'),'sha256:'+'a'*64,lock,C.DOCTOR,side,1,execute,containers,checks,bind)
            self.assertEqual(len(set(containers)),2)
            for argv in commands:
                self.assertIn('--network=none',argv);self.assertIn('--read-only',argv)
                self.assertIn('--env=CACHY_ASAHI_CONTAINER=1',argv)
            for side in ('a','b'):
                proof=json.loads((out/(C.DOCTOR+'-'+side)/'provenance.json').read_text())
                self.assertEqual(proof['status'],'built-package-static-pass')
                self.assertEqual(proof['expected_packages_sha256'],C.digest(lock))


class PreservationControls(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        root=Path(self.tmp.name);self.home=root/'home';self.output=root/'output'
        self.home.mkdir(mode=0o700);self.output.mkdir(mode=0o700)
        (self.output/'outside').write_text('PRIVATE outside contents')
        self.session=lifecycle.session_paths(self.home,self.output)
        (self.home/'.config/user-edited').write_text('PRIVATE existing configuration')
        (self.home/'.config/alias').symlink_to('user-edited')
        self.before=lifecycle.snapshot(self.home);self.outside=lifecycle.entry(self.output/'outside')

    def check(self):return lifecycle.preservation_check(self.home,self.before,self.output,self.outside)

    def failure(self):
        captured=io.StringIO()
        with redirect_stdout(captured),self.assertRaisesRegex(ValueError,'user config/outside changed'):self.check()
        text=captured.getvalue();self.assertNotIn('PRIVATE',text)
        return json.loads(text)

    def test_generated_session_state_and_reports_do_not_count_as_user_config(self):
        for name in ('cache','data','state','runtime'):
            (self.session/name/'generated').write_text('fixture generated state')
        (self.output/'install.json').write_text('test-owned report')
        (self.output/'install-alias').symlink_to('outside')
        self.check();self.assertEqual(lifecycle.snapshot(self.home),self.before)
        env=lifecycle.user_environment(self.home,self.session)
        self.assertEqual(Path(env['XDG_CONFIG_HOME']),self.home/'.config')
        for key in ('XDG_CACHE_HOME','XDG_DATA_HOME','XDG_STATE_HOME','XDG_RUNTIME_DIR'):
            self.assertFalse(Path(env[key]).is_relative_to(self.home))
            self.assertEqual(Path(env[key]).stat().st_mode&0o777,0o700)

    def test_preexisting_config_content_still_fails_without_content_export(self):
        (self.home/'.config/user-edited').write_text('PRIVATE changed configuration')
        row=self.failure()
        self.assertTrue(any(e['path']=='.config/user-edited' and 'value' in e['fields'] for e in row['changed']))

    def test_preexisting_config_mode_and_symlink_targets_still_fail(self):
        (self.home/'.config/user-edited').chmod(0o777)
        self.assertTrue(any('mode' in e['fields'] for e in self.failure()['changed']))
        alias=self.home/'.config/alias';alias.unlink();alias.symlink_to('PRIVATE replacement target')
        row=self.failure();self.assertTrue(any(e['path']=='.config/alias' and 'value' in e['fields'] for e in row['changed']))

    def test_arbitrary_added_or_removed_home_paths_are_not_exempted(self):
        (self.home/'unexpected').write_text('PRIVATE')
        self.assertTrue(any(e['path']=='unexpected' and e['fields']==['added'] for e in self.failure()['changed']))
        (self.home/'.config/user-edited').unlink()
        self.assertTrue(any(e['path']=='.config/user-edited' and e['fields']==['removed'] for e in self.failure()['changed']))

    def test_directory_metadata_is_not_blanket_ignored(self):
        (self.home/'.config').chmod(0o777)
        self.assertTrue(any(e['path']=='.config' and 'mode' in e['fields'] for e in self.failure()['changed']))

    def test_outside_contents_and_metadata_remain_protected(self):
        (self.output/'outside').chmod(0o777)
        self.assertIn('mode',self.failure()['outside_fields'])
        (self.output/'outside').write_text('PRIVATE overwritten')
        self.assertIn('value',self.failure()['outside_fields'])

    def test_diagnostics_have_finite_path_only_rows(self):
        for i in range(40):(self.home/('added-'+str(i))).write_text('PRIVATE')
        row=self.failure();self.assertEqual(len(row['changed']),32)
        self.assertGreater(row['omitted'],0)
        self.assertTrue(all(set(e)=={'path','fields'} for e in row['changed']))
        self.assertLess(len(json.dumps(row)),16384)

    def test_generated_roots_cannot_be_placed_inside_protected_home(self):
        nested=self.home/'nested';nested.mkdir()
        with self.assertRaises(ValueError):lifecycle.session_paths(self.home,nested)


if __name__=='__main__':unittest.main()
