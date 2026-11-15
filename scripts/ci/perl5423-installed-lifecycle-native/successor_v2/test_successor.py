# SPDX-License-Identifier: MIT
"""Pure source/predicate controls, with every operational boundary fenced."""
import ast
import contextlib
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('installed_v2_edit_controls', HERE/'capabilities.py')
E = importlib.util.module_from_spec(spec)
spec.loader.exec_module(E)
ORIGINAL = (HERE/'data/original-producer.py.txt').read_bytes()
KNOWN = ['CHOWN','DAC_OVERRIDE','FOWNER','SETGID','SETUID','SETFCAP','SYS_CHROOT']


def need(ok, why):
    if not ok:
        raise ValueError(why)


def predicates(body):
    # Compile only these trusted pure predicates, never a producer module/entry.
    nodes = [n for n in ast.parse(body).body if isinstance(n, ast.FunctionDef)
             and n.name in ('labels','inspect','capability_names')]
    context = {'C': SimpleNamespace(need=need, OPERATION='perl5423-installed-lifecycle-v1')}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), '<pure-inspect-predicates>', 'exec'), context)
    return context


def fixture():
    domain = dict(hostname='perl-installed-lifecycle', memory=2147483648, memory_swap=2147483648,
                  cap_add=KNOWN, tmpfs={'/work':'rw,nosuid,nodev,size=256m,mode=0700'})
    a = dict(image='sha256:'+'a'*64, container='modeled-owned', inputs='/modeled-inputs',
             base_labels={'fixture':'SYNTHETIC_NOT_ACTUAL_DOMAIN'}, source_map_sha256='b'*64)
    p = predicates(E.patch(ORIGINAL))
    row = dict(Id='c'*64, Image=a['image'], Name='/'+a['container'],
        Config=dict(User='0:0', Hostname=domain['hostname'], Labels=p['labels'](a,'d'*64)),
        HostConfig=dict(NetworkMode='none', ReadonlyRootfs=False, Privileged=False, Init=True,
            Memory=domain['memory'], MemorySwap=domain['memory_swap'], NanoCpus=2000000000,
            PidsLimit=128, CapDrop=['ALL'], CapAdd=['CAP_'+name for name in KNOWN],
            SecurityOpt=['no-new-privileges'], Tmpfs=domain['tmpfs'], IpcMode='private'),
        Mounts=[dict(Type='bind', Source=a['inputs'], Destination='/inputs', RW=False)])
    return p, row, a, domain


class Controls(unittest.TestCase):
    def setUp(self):
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        for name in ('subprocess.run','subprocess.Popen','socket.socket','fcntl.flock','os.pidfd_open'):
            stack.enter_context(patch(name, side_effect=AssertionError('operational boundary fenced'), create=name=='os.pidfd_open'))

    def test_exact_original_and_single_edit_inverse(self):
        self.assertEqual((len(ORIGINAL),hashlib.sha256(ORIGINAL).hexdigest()),
            (14274,'9d4c681100328f2db7abefdc0ff894a569d3670667cf369613dd3d8ffb222b87'))
        self.assertEqual(E.inverse(E.patch(ORIGINAL)), ORIGINAL)

    def test_actual_single_CAP_CHOWN_observation_is_honestly_scoped(self):
        record = json.loads((HERE/'data/xs-v4-capability-observation.json').read_bytes())
        self.assertEqual(record['actual_CapAdd'], ['CAP_CHOWN'])
        self.assertEqual(record['create_cap_add'], ['CHOWN'])
        self.assertEqual(record['raw_inspect']['bytes'], 8584)
        self.assertEqual(record['raw_inspect']['sha256'], '39eb911a102ce8969f32bece90c13d8c98cf49b20b752f35fdbf4991fbc63cab')
        self.assertEqual(record['seven_cap_fixture_scope'], 'MODELED_USING_ACTUAL_SINGLE_CAP_SPELLING_ONLY')

    def test_seven_prefixed_names_refuse_old_and_pass_new_without_mutating_raw(self):
        p,row,a,d = fixture()
        before = copy.deepcopy(row)
        with self.assertRaises(ValueError):
            predicates(ORIGINAL)['inspect'](row,a,'d'*64,d,row['Id'])
        p['inspect'](row,a,'d'*64,d,row['Id'])
        self.assertEqual(row,before)

    def test_declared_plain_prefixed_mixed_reordered_exact_names(self):
        p,row,a,d = fixture()
        for names in (KNOWN, ['CAP_'+name for name in KNOWN],
                      [name if i%2 else 'CAP_'+name for i,name in enumerate(KNOWN)], list(reversed(KNOWN))):
            row['HostConfig']['CapAdd'] = names
            p['inspect'](row,a,'d'*64,d,row['Id'])

    def test_empty_missing_extra_duplicate_raw_or_semantic_capabilities_refuse(self):
        p,row,a,d = fixture()
        cases = [[], KNOWN[:-1], KNOWN+['SYS_ADMIN'], KNOWN[:-1]+[KNOWN[0]],
                 KNOWN[:-1]+['CAP_'+KNOWN[0]], KNOWN+['CAP_CHOWN'], None, 'CHOWN', tuple(KNOWN)]
        for caps in cases:
            row['HostConfig']['CapAdd'] = caps
            with self.subTest(caps=caps),self.assertRaises(ValueError):
                p['inspect'](row,a,'d'*64,d,row['Id'])

    def test_unknown_malformed_case_whitespace_double_prefix_and_nonstring_refuse(self):
        p,row,a,d = fixture()
        for bad in ('CAP_SYS_ADMIN','CAP_CAP_CHOWN','cap_chown','chown',' CHOWN','CHOWN ',
                    'CAP_','CHOWN\n','CAP_CHOWN\x00','',1,True,None):
            row['HostConfig']['CapAdd'] = [bad]+KNOWN[1:]
            with self.subTest(cap=bad),self.assertRaises(ValueError):
                p['inspect'](row,a,'d'*64,d,row['Id'])

    def test_declared_domain_cannot_be_changed_to_add_unknown_capability(self):
        p,row,a,d = fixture()
        d['cap_add'] = KNOWN[:-1]+['SYS_ADMIN']
        row['HostConfig']['CapAdd'] = d['cap_add']
        with self.assertRaises(ValueError):
            p['inspect'](row,a,'d'*64,d,row['Id'])

    def test_every_other_inspect_gate_remains_strict(self):
        changes = [
            ('Image','sha256:'+'b'*64), ('Name','/wrong'), ('Id','wrong'),
            ('Config.User','1001:1001'), ('Config.Hostname','wrong'), ('Config.Labels',{}),
            ('HostConfig.NetworkMode','host'), ('HostConfig.ReadonlyRootfs',True),
            ('HostConfig.Privileged',True), ('HostConfig.Init',False), ('HostConfig.Memory',1),
            ('HostConfig.MemorySwap',1), ('HostConfig.NanoCpus',1), ('HostConfig.PidsLimit',1),
            ('HostConfig.CapDrop',[]), ('HostConfig.SecurityOpt',[]), ('HostConfig.Tmpfs',{}),
            ('HostConfig.Binds',['/host:/inputs']), ('HostConfig.Devices',[{}]),
            ('HostConfig.DeviceRequests',[{}]), ('HostConfig.PublishAllPorts',True),
            ('HostConfig.PortBindings',{'1/tcp':[]}), ('HostConfig.PidMode','host'),
            ('HostConfig.IpcMode','host'), ('HostConfig.UsernsMode','host'), ('Mounts',[]),
        ]
        for path,value in changes:
            p,row,a,d = fixture()
            target = row
            parts = path.split('.')
            for part in parts[:-1]:
                target = target[part]
            target[parts[-1]] = value
            with self.subTest(path=path),self.assertRaises(ValueError):
                p['inspect'](row,a,'d'*64,d,'c'*64)
        for key,value in [('Type','volume'),('Source','/wrong'),('Destination','/wrong'),('RW',True)]:
            p,row,a,d = fixture()
            row['Mounts'][0][key] = value
            with self.subTest(mount=key),self.assertRaises(ValueError):
                p['inspect'](row,a,'d'*64,d,row['Id'])

    def test_all_other_producer_functions_are_AST_identical(self):
        get = lambda body: {n.name:n for n in ast.parse(body).body if isinstance(n,ast.FunctionDef)}
        old,new = get(ORIGINAL),get(E.patch(ORIGINAL))
        self.assertEqual(set(new)-set(old), {'capability_names'})
        for name in set(old)-{'inspect'}:
            self.assertEqual(ast.dump(old[name]),ast.dump(new[name]),name)

    def test_changed_or_repeated_edit_refuses(self):
        for body in (ORIGINAL.replace(E.OLD,b'wrong'),E.patch(ORIGINAL),ORIGINAL.replace(E.OLD,E.OLD+b' '+E.OLD)):
            with self.assertRaises(ValueError):
                E.patch(body)
        with self.assertRaises(ValueError):
            E.inverse(ORIGINAL)


if __name__ == '__main__':
    unittest.main()
