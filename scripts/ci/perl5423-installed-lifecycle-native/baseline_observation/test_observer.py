# SPDX-License-Identifier: MIT
"""Synthetic DATA-only observer controls; no current-machine observation or actor."""
import base64
import copy
import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('baseline_observer_pure_data_test',HERE/'payload/hosted/observer.py')
o = importlib.util.module_from_spec(spec)
spec.loader.exec_module(o)


def file_row(raw,mode=0o644):
    return dict(type='file',mode=mode,uid=0,gid=0,bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


def fixture():
    lock = (HERE.parent/'expected349.lock').read_bytes()  # Frozen text DATA, no package query.
    config = b'SYNTHETIC CONFIG DATA ONLY\n'
    hook = b'SYNTHETIC HOOK DATA; NEVER EXECUTED\n'
    bodies = {o.LOCK:lock,o.CONFIG:config,'/usr/share/libalpm/hooks/example.hook':hook}
    database_files,database_contents = {},{}
    for line in lock.decode().splitlines():
        name,version = line.split(' ',1)
        raw = ('%NAME%\n'+name+'\n\n%VERSION%\n'+version+'\n\n').encode()
        database_files[name+'-'+version+'/desc'] = dict(file_row(raw),name=name,version=version)
        database_contents[name+'-'+version+'/desc'] = base64.b64encode(raw).decode()
    database = dict(root='/var/lib/pacman/local',fields=['NAME','VERSION'],inventory=lock.decode(),files=database_files,contents=database_contents)
    runtime = dict(uid=0,euid=0,gid=0,egid=0,status={**{key:'0000000000000000' for key in o.CAPS},'Uid':'0 0 0 0','Gid':'0 0 0 0','NoNewPrivs':'1'},cgroup=dict(o.CGROUP),interfaces=['lo'],mountinfo='1 0 0:1 / / ro - overlay overlay ro\n',cgroup_membership='0::/\n',namespaces={name:name+':[123]' for name in ('user','mnt','net','pid','cgroup')},pid=1,ppid=0,starttime=1)
    directory = dict(type='directory',mode=0o755,uid=0,gid=0)
    hooks = {
        '/builder-disabled-hooks':{'.':dict(directory),'example.hook':dict(type='symlink',mode=0o777,uid=0,gid=0,target='/dev/null')},
        '/etc/pacman.d/hooks':{'.':dict(type='absent')},
        '/usr/share/libalpm/hooks':{'.':dict(directory),'example.hook':file_row(hook)},
    }
    return dict(schema=1,status=o.STATUS,binding=dict(source='1'*40,ref='refs/heads/codex/synthetic-observer-data',run='123',job='456',image='sha256:'+'2'*64,token='3'*24,policy_sha256='4'*64),machine='aarch64',page_bytes=4096,runtime=runtime,
        package_inventory=dict(file=file_row(lock),packages=349,perl='5.42.3-1'),package_database=database,config_files={o.CONFIG:file_row(config)},hook_snapshots=hooks,
        file_contents={name:base64.b64encode(body).decode() for name,body in bodies.items()},metadata_file_bytes=sum(len(body) for body in bodies.values())+sum(row['bytes'] for row in database_files.values()),observed_seconds=0.01)


class ObserverTests(unittest.TestCase):
    def test_positive_synthetic_observation_is_only_data_not_mutation_authority(self):
        result = o.validate(fixture())
        self.assertEqual(result['mutation_qualification'],'NOT_ISSUED')

    def test_binding_is_exact_and_concrete(self):
        for field in ('source','ref','run','job','image','token','policy_sha256'):
            value = fixture()
            value['binding'][field] = None
            with self.subTest(field=field),self.assertRaises(ValueError):
                o.validate(value)

    def test_all_caps_and_no_new_privileges_are_checked(self):
        for field in (*o.CAPS,'NoNewPrivs'):
            value = fixture()
            value['runtime']['status'][field] = '0' if field=='NoNewPrivs' else '1'
            with self.subTest(field=field),self.assertRaises(ValueError):
                o.validate(value)

    def test_credentials_cgroup_network_root_geometry_and_deadline_refuse(self):
        mutations = [lambda v:v['runtime'].update(uid=1001),lambda v:v['runtime']['status'].update(Uid='1001 1001 1001 1001'),lambda v:v['runtime']['cgroup'].update(**{'pids.max':'32'}),lambda v:v['runtime'].update(interfaces=['lo','eth0']),lambda v:v['runtime'].update(mountinfo='1 0 0:1 / / rw - overlay overlay rw\n'),lambda v:v.update(page_bytes=16384),lambda v:v.update(observed_seconds=61)]
        for index,mutation in enumerate(mutations):
            value = fixture();mutation(value)
            with self.subTest(index=index),self.assertRaises(ValueError):
                o.validate(value)

    def test_raw_file_hash_size_encoding_and_accounting_must_join(self):
        mutations = [lambda v:v['file_contents'].__setitem__(o.CONFIG,base64.b64encode(b'CHANGED DATA').decode()),lambda v:v['config_files'][o.CONFIG].update(bytes=999),lambda v:v['file_contents'].__setitem__(o.CONFIG,'not base64!'),lambda v:v.update(metadata_file_bytes=1)]
        for index,mutation in enumerate(mutations):
            value = fixture();mutation(value)
            with self.subTest(index=index),self.assertRaises(ValueError):
                o.validate(value)

    def test_no_key_shadow_home_or_unmapped_contents_are_accepted(self):
        for path in ('/etc/shadow','/home/alarm/private','/etc/pacman.d/gnupg/pubring.gpg','/etc/pacman.d/gnupg/private-keys-v1.d/key'):
            value = fixture();value['file_contents'][path] = base64.b64encode(b'FORBIDDEN FIXTURE').decode()
            with self.subTest(path=path),self.assertRaises(ValueError):
                o.validate(value)

    def test_complete_hook_ancestry_and_exact_fixed_root_shape(self):
        for mutation in ('missing','traversal','parent'):
            value = fixture()
            if mutation=='missing':
                del value['hook_snapshots']['/etc/pacman.d/hooks']
            elif mutation=='traversal':
                value['hook_snapshots']['/builder-disabled-hooks']['../outside'] = dict(type='directory',mode=0o755,uid=0,gid=0)
            else:
                value['hook_snapshots']['/builder-disabled-hooks']['missing/child'] = dict(type='directory',mode=0o755,uid=0,gid=0)
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):
                o.validate(value)

    def test_mode_uid_gid_and_link_target_shapes_are_required(self):
        for field,bad in (('mode',True),('uid',-1),('gid',2**32),('target','')):
            value = fixture()
            value['hook_snapshots']['/builder-disabled-hooks']['example.hook'][field] = bad
            with self.subTest(field=field),self.assertRaises(ValueError):
                o.validate(value)

    def test_observed_builder_lock_cannot_be_substituted(self):
        value = fixture();raw = b'perl 5.42.3-1\n'
        value['package_inventory']['file'] = file_row(raw)
        old = len(base64.b64decode(value['file_contents'][o.LOCK]))
        value['file_contents'][o.LOCK] = base64.b64encode(raw).decode()
        value['metadata_file_bytes'] += len(raw)-old
        with self.assertRaisesRegex(ValueError,'fixed349'):
            o.validate(value)

    def test_passive_snapshot_captures_content_owner_mode_and_never_follows_link(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)/'hooks';root.mkdir()
            (root/'fixture.hook').write_bytes(b'PASSIVE DATA ONLY\n');(root/'fixture.hook').chmod(0o444)
            (root/'masked.hook').symlink_to('/dev/null')
            contents,budget = {},{'bytes':0}
            rows = o.snapshot(root,contents,budget,time.monotonic()+60)
            self.assertEqual(base64.b64decode(contents[str(root/'fixture.hook')]),b'PASSIVE DATA ONLY\n')
            self.assertEqual(rows['fixture.hook']['mode'],0o444)
            self.assertEqual(rows['fixture.hook']['uid'],(root/'fixture.hook').stat().st_uid)
            self.assertEqual(rows['masked.hook']['target'],'/dev/null')
            self.assertNotIn(str(root/'masked.hook'),contents)

    def test_passive_current_database_reads_only_real_desc_name_version(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lock = (HERE.parent/'expected349.lock').read_bytes()
            byte_count = 0
            for line in lock.decode().splitlines():
                name,version = line.split(' ',1)
                package = root/(name+'-'+version)
                package.mkdir()
                raw = ('%NAME%\n'+name+'\n\n%VERSION%\n'+version+'\n\n').encode()
                (package/'desc').write_bytes(raw)
                # Other local DB files are never opened or copied.
                os.mkfifo(package/'files')
                byte_count += len(raw)
            (root/'ALPM_DB_VERSION').write_text('FIXTURE MARKER NOT READ\n')
            budget = {'bytes':0}
            value = o.inventory_database(root,lock,budget,time.monotonic()+60)
            self.assertEqual(value['inventory'],lock.decode())
            self.assertEqual(len(value['files']),349)
            self.assertEqual(set(value['contents']),set(value['files']))
            self.assertEqual(budget['bytes'],byte_count)
            first = next(root.glob('*/desc'))
            raw = first.read_text()
            first.write_text(raw.replace('%VERSION%\n','%VERSION%\nCHANGED-',1))
            with self.assertRaises(ValueError):
                o.inventory_database(root,lock,{'bytes':0},time.monotonic()+60)

    def test_database_inventory_descriptor_path_and_count_are_bound(self):
        for mutation in ('version','path','missing'):
            value = fixture()
            rows = value['package_database']['files']
            name = next(iter(rows))
            if mutation=='version':
                rows[name]['version'] = 'CHANGED'
            elif mutation=='path':
                rows['../outside/desc'] = rows.pop(name)
            else:
                rows.pop(name)
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):
                o.validate(value)

    def test_original_desc_reparse_detects_misreported_scalar_fields(self):
        value = fixture()
        database = value['package_database']
        name = next(iter(database['files']))
        row = database['files'][name]
        raw = ('%NAME%\n'+row['name']+'\n\n%VERSION%\nCHANGED\n\n').encode()
        old_size = row['bytes']
        row.update(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
        database['contents'][name] = base64.b64encode(raw).decode()
        value['metadata_file_bytes'] += len(raw)-old_size
        with self.assertRaisesRegex(ValueError,'parsed fields differ'):
            o.validate(value)

    def test_desc_original_bytes_cannot_add_outside_paths_or_bad_encoding(self):
        for mutation in ('outside','encoding'):
            value = fixture()
            contents = value['package_database']['contents']
            if mutation=='outside':
                contents['../shadow'] = base64.b64encode(b'FORBIDDEN FIXTURE').decode()
            else:
                contents[next(iter(contents))] = 'not base64!'
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):
                o.validate(value)

    def test_special_files_aliases_and_aggregate_budgets_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            os.mkfifo(root/'fifo')
            with self.assertRaises(ValueError):
                o.node(root/'fifo',{}, {'bytes':0},time.monotonic()+60)
            file = root/'file';file.write_bytes(b'1234')
            with patch.object(o,'FILE_CAP',3):
                with self.assertRaises(ValueError):
                    o.node(file,{}, {'bytes':0},time.monotonic()+60)
            with self.assertRaisesRegex(ValueError,'8192'):
                o.node(file,{}, {'bytes':0,'nodes':8192},time.monotonic()+60)
            alias = root/'alias';alias.symlink_to(root,target_is_directory=True)
            with self.assertRaisesRegex(ValueError,'ancestry alias'):
                o.node(alias/'file',{}, {'bytes':0},time.monotonic()+60)

    def test_json_and_duplicate_binding_fields_are_bounded(self):
        with patch.object(o,'JSON_CAP',1):
            with self.assertRaisesRegex(ValueError,'32 MiB'):
                o.encode(fixture())
        with self.assertRaisesRegex(ValueError,'duplicate'):
            o.decode_binding('{"source":"a","source":"b"}')


if __name__ == '__main__':
    unittest.main()
