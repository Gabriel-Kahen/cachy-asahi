# SPDX-License-Identifier: MIT
"""Portable DATA/argv controls only: never Docker, namespaces, build or Reader."""
import ast
from io import BytesIO
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BUILD = HERE.parent
HELD_V2 = (ROOT / 'scripts/ci/llhttp-minimal-native-source-data/fixtures/Source95/held-source'
           / 'scripts/ci/llhttp-reference-native-source/base/runtime/scripts/build')
HISTORICAL_V3 = {
    'build_v3.py': '9616cbc8ff6ec49f0f0a53ddcc6bdf39fb583d74aaff2c00f9baebf28e5a1159',
    'compare_v3.py': 'e028251c1e85cfc0a94ff45da44041341c02198cb14b312e21fa404cf1676a86',
}
sys.path.insert(0, str(BUILD))
from nested_userns_v1 import policy as P
import build_v3 as B
import compare_v3 as C


def fence(event, args):
    if event.startswith(('subprocess.', 'socket.', 'ctypes.')) or event in ('os.fork', 'os.exec', 'os.system', 'fcntl.flock'):
        raise RuntimeError('portable controls forbid operational actors: ' + event)
sys.addaudithook(fence)


class Controls(unittest.TestCase):
    def raw(self):return (HERE / 'nested-seccomp.json').read_bytes()

    def test_exact_default_inverse_and_seven_rules(self):
        raw = self.raw();self.assertEqual(P.validate(raw, P.PROFILE['sha256']), raw)
        base = json.loads((HERE / 'default.json').read_bytes());profile = json.loads(raw)
        self.assertEqual(len(base['syscalls']), 31);self.assertEqual(profile.pop('syscalls'), base['syscalls'] + P.additions())
        self.assertEqual(profile, {k:v for k,v in base.items() if k != 'syscalls'})
        self.assertEqual(P.pin((HERE/'default.json').read_bytes()), P.BASE)

    def test_changed_profile_or_expected_digest_refused(self):
        for raw, digest in ((self.raw(), '0'*64), (self.raw()+b'\n', P.PROFILE['sha256']),
                            (b'{"defaultAction":"SCMP_ACT_ALLOW"}', P.PROFILE['sha256'])):
            with self.assertRaises(ValueError):P.validate(raw, digest)

    def test_option_pair_offline_native_and_ordinary_uid(self):
        self.assertIsNone(P.request(None, None, 'bridge', 'emulated'))
        for path, digest in ((None, P.PROFILE['sha256']), (HERE/'nested-seccomp.json', None)):
            with self.assertRaises(ValueError):P.request(path, digest, 'none', 'native')
        for network, mode in (('bridge','native'), ('none','emulated')):
            with self.assertRaises(ValueError):P.request(HERE/'nested-seccomp.json', P.PROFILE['sha256'], network, mode)
        with patch.object(P.os, 'getuid', return_value=0), patch.object(P.os, 'geteuid', return_value=0):
            with self.assertRaises(ValueError):P.request(HERE/'nested-seccomp.json', P.PROFILE['sha256'], 'none', 'native')

    def test_normal_clone_and_namespace_extensions_are_distinct(self):
        def allowed(name, args):
            return any(r['names'] == [name] and all(args.get(a['index']) == a['value'] and a['op'] == 'SCMP_CMP_EQ' for a in r.get('args', [])) for r in P.additions())
        self.assertTrue(allowed('clone', {0:0x50020011}))
        for flags in (17, 0x40020011, 0x10020011, 0x70020011, 0x50020011|0x04000000):self.assertFalse(allowed('clone', {0:flags}))
        self.assertTrue(allowed('unshare', {0:0x10000000}))
        for flags in (0, 0x20000, 0x10020000, 0x40000000):self.assertFalse(allowed('unshare', {0:flags}))
        for name in ('setns','chroot','bpf','fsopen','fsmount','open_tree','move_mount','clone3'):self.assertFalse(allowed(name, {}))

    def test_required_setattr_flags_size_and_detach_only(self):
        rules=P.additions()
        for flags in (4096,36864):self.assertIn(P.rule('mount_setattr',P.eq(2,flags),P.eq(4,32)),rules)
        self.assertEqual([r for r in rules if r['names']==['umount2']], [P.rule('umount2',P.eq(1,2))])
        for flags,size in ((0,32),(32768,32),(4096,16),(36864,64)):
            self.assertNotIn(P.rule('mount_setattr',P.eq(2,flags),P.eq(4,size)),rules)

    def test_unsafe_paths_hardlinks_and_writable_files(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'policy';p.write_bytes(self.raw());alias=p.with_name('alias');alias.symlink_to(p)
            with self.assertRaises(ValueError):P.read(alias)
            alias.unlink();os.link(p,alias)
            with self.assertRaises(ValueError):P.read(p)
            alias.unlink();p.chmod(0o666)
            with self.assertRaises(ValueError):P.read(p)
        with self.assertRaises(ValueError):P.read('relative')

    def test_fresh_engine_query_server_not_client(self):
        good=SimpleNamespace(returncode=0,stderr=b'',stdout=json.dumps(dict(P.SERVER,GitCommit='PUBLIC_MODEL')).encode())
        with patch.object(P.subprocess,'run',return_value=good)as run:
            self.assertEqual(P.engine(),P.SERVER)
            run.assert_called_once_with(P.COMMAND,stdin=subprocess.DEVNULL,capture_output=True,timeout=10)
        for key,value in (('Version','29.8.0'),('Version','28.0.5'),('Arch','amd64'),('Os','windows'),('Version',28)):
            with self.assertRaises(ValueError):P.server(dict(P.SERVER,**{key:value}))

    def test_engine_unknown_error_stderr_timeout_refuse(self):
        for result in (SimpleNamespace(returncode=1,stdout=b'{}',stderr=b''), SimpleNamespace(returncode=0,stdout=b'{}',stderr=b''), SimpleNamespace(returncode=0,stdout=json.dumps(P.SERVER).encode(),stderr=b'warning')):
            with patch.object(P.subprocess,'run',return_value=result),self.assertRaises(ValueError):P.engine()
        with patch.object(P.subprocess,'run',side_effect=subprocess.TimeoutExpired(P.COMMAND,10)),self.assertRaises(subprocess.TimeoutExpired):P.engine()

    def test_profile_is_private_retained_and_rechecked(self):
        with tempfile.TemporaryDirectory()as d:
            out=Path(d);value=P.retain(self.raw(),P.SERVER,out)
            self.assertEqual((out/'nested-seccomp.json').stat().st_mode&0o777,0o444)
            self.assertEqual(P.arguments(out,value),['--security-opt','seccomp='+str(out/'nested-seccomp.json')])
            self.assertEqual(value['namespace_qualification'],'NOT_RUN')
            with self.assertRaises(FileExistsError):P.retain(self.raw(),P.SERVER,out)
            (out/'nested-seccomp.json').chmod(0o600);(out/'nested-seccomp.json').write_bytes(b'changed')
            with self.assertRaises(ValueError):P.verify(out,value)
        self.assertEqual(P.arguments('/unused',None),[])

    def test_descriptor_has_no_policy_or_qualification_waiver(self):
        value=P.descriptor(P.SERVER)
        with tempfile.TemporaryDirectory()as d:
            out=Path(d);P.retain(self.raw(),P.SERVER,out)
            for key,item in (('kind','unconfined'),('namespace_qualification','PASS'),('extra',True),('profile',dict(P.PROFILE,sha256='0'*64))):
                with self.subTest(key=key),self.assertRaises(ValueError):P.verify(out,dict(value,**{key:item}))

    def test_historical_builder_and_comparator_exact_v2_inverse(self):
        v=json.loads((HERE/'derivation.json').read_bytes())
        self.assertEqual(v['source'],'522e7cc8d2446416849dc5c1f84642cc46f82a06')
        self.assertEqual(v['files'].keys(), HISTORICAL_V3.keys())
        for name,row in v['files'].items():
            parent = (HELD_V2 / row['parent']).read_bytes()
            self.assertEqual(P.pin(parent), row['parent_pin'])
            raw = parent.decode()
            for edit in row['edits']:
                self.assertEqual(raw.count(edit['before']), 1)
                raw = raw.replace(edit['before'], edit['after'], 1)
            self.assertEqual(P.pin(raw.encode())['sha256'], HISTORICAL_V3[name])
            for edit in reversed(row['edits']):
                self.assertEqual(raw.count(edit['after']),1);raw=raw.replace(edit['after'],edit['before'],1)
            self.assertEqual(raw.encode(), parent)
        self.assertNotIn('namespace_policy',(BUILD/'build_v2.py').read_text())

    def test_public522_recipe_exact_inputs_and_selected_namespace_argv(self):
        v=json.loads((HERE/'provenance.json').read_bytes());r=ROOT/v['selected_recipe']['path']
        self.assertEqual(v['selected_recipe']['source'],'522e7cc8d2446416849dc5c1f84642cc46f82a06')
        self.assertEqual({p.name:P.pin(p.read_bytes())for p in r.iterdir()if p.is_file()},v['selected_recipe']['files'])
        tree=ast.parse((r/'test_package.py').read_bytes());assigns=[n for n in ast.walk(tree)if isinstance(n,ast.Assign)]
        prefix=next(n.value for n in assigns if any(isinstance(t,ast.Name)and t.id=='prefix'for t in n.targets))
        self.assertEqual([ast.literal_eval(x)for x in prefix.elts[:11]],['bwrap','--unshare-net','--ro-bind','/','/','--proc','/proc','--dev','/dev','--tmpfs','/tmp'])
        for name in ('revocation_command','refresh'):
            call=next(n.value for n in assigns if any(isinstance(t,ast.Name)and t.id==name for t in n.targets))
            self.assertEqual([ast.literal_eval(x)for x in call.elts[1:5]],['/usr/bin/unshare','--user','--map-root-user','--'])
        self.assertEqual(len(P.additions()),7)

    def build_command(self,custom):
        # Execute the maintained main through the pre-Popen boundary only.
        # Every daemon/contacting call is mocked and forbidden by the audit fence.
        with tempfile.TemporaryDirectory()as d:
            tmp=Path(d);recipe=ROOT/'packages/tools/cachy-asahi-repository-enrollment-v4';review=B.recipe(recipe/'PKGBUILD');self.assertEqual(review['errors'],[])
            inputs=tmp/'review.json';inputs.write_text(json.dumps(review['input_sha256']));lock=tmp/'packages.lock';lock.write_text('MODELED 1\n');out=tmp/'fresh';calls=[]
            argv=['build_v3.py',str(recipe),'--image','sha256:'+'1'*64,'--mode','native','--source-date-epoch','1791748800','--expected-packages',str(lock),'--reviewed-inputs',str(inputs),'--output',str(out)]
            if custom:argv+=['--nested-seccomp-profile',str(HERE/'nested-seccomp.json'),'--nested-seccomp-sha256',P.PROFILE['sha256']]
            def capture(args):return json.dumps([dict(Architecture='arm64',Os='linux',Id='sha256:'+'1'*64)])if args[1:3]==['image','inspect']else'aarch64'
            def boundary(command,**kw):calls.append(command);raise OSError('MODELED stop before Docker launch')
            with patch.object(sys,'argv',argv),patch.object(B,'capture',side_effect=capture),patch.object(P,'engine',return_value=P.SERVER)as engine,patch.object(B.subprocess,'run',side_effect=boundary):
                self.assertEqual(B.main(),1);self.assertEqual(engine.call_count,int(custom))
            self.assertEqual(len(calls),1);command=calls[0];record=json.loads((out/'provenance.json').read_bytes())
            self.assertEqual(record['status'],'failed');self.assertIn('--cap-drop=ALL',command);self.assertIn('--security-opt=no-new-privileges',command);self.assertIn('--read-only',command)
            for item in ('--pids-limit','512','--memory','4g','--cpus','4','--network','none'):self.assertIn(item,command)
            self.assertFalse(any('privileged'in x or 'unconfined'in x or 'cap-add'in x for x in command))
            if custom:
                self.assertEqual(command[2:4],['--security-opt','seccomp='+str(out/'nested-seccomp.json')]);P.verify(out,record['nested_namespaces'])
            else:self.assertEqual(command[:3],['docker','run','--rm']);self.assertIsNone(record['nested_namespaces'])
    def test_default_actual_command_preserves_policy(self):self.build_command(False)
    def test_optin_actual_command_retains_bounds_and_exact_profile(self):self.build_command(True)

    def test_invalid_explicit_profile_refuses_before_any_daemon_query(self):
        with tempfile.TemporaryDirectory()as d:
            output=Path(d)/'not-created'
            argv=['build_v3.py','/MODELED/recipe','--image','sha256:'+'1'*64,'--mode','native','--source-date-epoch','1','--expected-packages','/MODELED/lock','--reviewed-inputs','/MODELED/review','--output',str(output),'--nested-seccomp-sha256',P.PROFILE['sha256']]
            with patch.object(sys,'argv',argv),patch.object(B,'capture')as capture,patch.object(P,'engine')as engine,patch.object(B.subprocess,'run')as run:
                self.assertEqual(B.main(),1);capture.assert_not_called();engine.assert_not_called();run.assert_not_called()
            self.assertFalse(output.exists())

    def test_comparator_refuses_missing_v3_policy_binding(self):
        with tempfile.TemporaryDirectory()as d:
            (Path(d)/'provenance.json').write_text('{}')
            with self.assertRaisesRegex(ValueError,'policy binding missing'):C.verify(d)

    def test_comparator_binds_inventory_hash_and_observed_packages(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory)
            (out / 'inputs').mkdir()
            (out / 'artifacts').mkdir()
            recipe = out / 'inputs/PKGBUILD'
            payload = out / 'inputs/payload'
            payload.write_text('MODELED input\n')
            recipe.write_text("pkgname=example\npkgver=1\npkgrel=1\narch=('any')\nlicense=('MIT')\n"
                              f"source=('payload')\nsha256sums=('{C.digest(payload)}')\n")
            reviewed = B.recipe(recipe)
            recipe_hash = reviewed['input_sha256']['PKGBUILD']
            artifact = out / 'artifacts/example-1-1-any.pkg.tar.gz'
            with tarfile.open(artifact, 'w:gz') as archive:
                entries = {
                    '.PKGINFO': b'pkgname = example\npkgbase = example\npkgver = 1-1\narch = any\nlicense = MIT\n',
                    '.BUILDINFO': (b'format = 2\npkgname = example\npkgver = 1-1\npkgarch = any\n'
                                   + f'pkgbuild_sha256sum = {recipe_hash}\n'.encode()),
                    '.MTREE': b'MODELED manifest\n',
                    'usr/share/example/data': b'MODELED payload\n',
                }
                for name, body in entries.items():
                    member = tarfile.TarInfo(name)
                    member.size = len(body)
                    archive.addfile(member, BytesIO(body))
            for name in ('build.log', 'artifacts/environment.txt', 'artifacts/config.sha256',
                         'artifacts/makepkg.conf', 'artifacts/pacman.conf'):
                (out / name).write_text('MODELED evidence\n')
            (out / 'artifacts/generated.SRCINFO').write_text('pkgbase = example\n' + ''.join(
                f'{key} = {value}\n' for key, values in reviewed['metadata'].items() for value in values
            ))
            (out / 'validation.json').write_text(json.dumps({'artifacts': [C.package(artifact)], 'errors': []}))
            expected = out / 'expected-packages.lock'
            observed = out / 'artifacts/packages.lock'
            record_path = out / 'provenance.json'
            for claimed_hash, observed_lock, reason in (
                (None, 'base-devel 1-1\n', None),
                ('0' * 64, 'base-devel 1-1\n', 'recorded expected package lock checksum differs'),
                (None, 'base-devel 2-1\n', 'observed builder package lock differs'),
            ):
                with self.subTest(claimed_hash=claimed_hash, observed_lock=observed_lock):
                    expected.write_text('base-devel 1-1\n')
                    observed.write_text(observed_lock)
                    record = dict(
                        status='built-package-static-pass', nested_namespaces=None, exit_code=0, network='none',
                        expected_packages_sha256=claimed_hash or C.digest(expected),
                        recipe_inputs=reviewed['input_sha256'],
                        recipe_metadata=reviewed['metadata'],
                        artifacts={artifact.name: C.digest(artifact)},
                        files={str(path.relative_to(out)): C.digest(path) for path in out.rglob('*')
                               if path.is_file() and path != record_path and not path.is_relative_to(out / 'inputs')},
                    )
                    record_path.write_text(json.dumps(record))
                    if reason is None:
                        self.assertEqual(C.verify(out)[0], record)
                    else:
                        with self.assertRaisesRegex(ValueError, reason):
                            C.verify(out)

    def test_comparator_requires_same_default_or_custom_policy(self):
        a=dict(clean_environment_id='one',image='same',image_id='same',mode='native',source_date_epoch=1,recipe_inputs={'x':'y'},recipe_metadata={'x':'y'},expected_packages_sha256='a',entry_script_sha256='b',nested_namespaces=None,network='none')
        pkg={'p':dict(members={'usr/x':dict(mode=420,sha256='a')},metadata={'.PKGINFO':{},'.BUILDINFO':{}},sha256='a')}
        for left,right,passed in ((None,None,True),(P.descriptor(P.SERVER),P.descriptor(P.SERVER),True),(None,P.descriptor(P.SERVER),False)):
            x=dict(a,nested_namespaces=left);y=dict(a,clean_environment_id='two',nested_namespaces=right)
            with patch.object(C,'verify',side_effect=[(x,pkg),(y,pkg)]):result=C.compare('/MODELED/one','/MODELED/two')
            self.assertEqual(not result['errors'],passed)


if __name__=='__main__':unittest.main()
