# SPDX-License-Identifier: MIT
"""Real temporary data + pure policy controls; never an original574 acceptance."""
import copy,importlib.util,io,json,os,struct,sys,tarfile,tempfile,time,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
def module(name,file):
    spec=importlib.util.spec_from_file_location(name,HERE/file);value=importlib.util.module_from_spec(spec);sys.modules[name]=value;spec.loader.exec_module(value);return value
C=module('test_full574_adapter','full574_closure.py');T=module('test_full574_backend','transaction.py')

def aux_bytes(order=(1,2)):
    names=bytearray(b'\0');rows=[]
    for n in order:
        offset=len(names);names.extend(b'libinert.so\0');rows.append(struct.pack('<QQQQiII',n,2,3,4,1,offset,0)+b'\0'*4)
    return C.aux.load_comparator(C.ROOT/'scripts/ci/full-development-composition/audio_aux.py',T.limits()).MAGIC+struct.pack('<II',len(rows),len(names))+b''.join(rows)+names

class Policy(unittest.TestCase):
    def test_only_four_exact_current_script_data_payloads(self):
        rows=C.current_payloads();self.assertEqual(set(rows),set(C.VERSIONS))
        for package,nodes in rows.items():
            T.payload_guard(nodes,{})
            self.assertTrue(all(row['uid']==row['gid']==0 for row in nodes.values()))
            self.assertLess(len(nodes),32)
            self.assertLess(sum(row.get('bytes',0) for row in nodes.values()),256*1024)
        self.assertEqual({name for nodes in rows.values() for name in nodes if name.count('/')==2 and name.startswith('usr/lib/')},{C.SCAN_DATA})
    def test_original574_lock_is_exact_supported_input(self):
        manifest=json.loads((C.ROOT/'scripts/ci/maintained-desktop574-inputs.json').read_bytes())
        inventory=dict(packages=[dict(name=r['name'],version=r['version']) for r in manifest['packages']])
        C.inventory_check(inventory,source=True)
        extended=copy.deepcopy(inventory);extended['packages'].append(dict(name='cachy-asahi-apps',version=C.VERSIONS['cachy-asahi-apps']))
        C.inventory_check(extended)
        with self.assertRaisesRegex(ValueError,'source-must'):C.inventory_check(extended,source=True)
        for bad in ('unknown-package','glibc'):
            changed=copy.deepcopy(inventory)
            if bad=='glibc':next(r for r in changed['packages'] if r['name']=='glibc')['version']='forged'
            else:changed['packages'].append(dict(name=bad,version='1'))
            with self.assertRaises(ValueError):C.inventory_check(changed)
    def test_missing_partial_pin_refuses_without_root_or_actor(self):
        with patch.object(C,'Adapter',side_effect=AssertionError('must not construct')):
            self.assertIsNone(C.connect(SimpleNamespace(),T,T.limits()))
            with self.assertRaisesRegex(ValueError,'explicit-policy'):C.connect(SimpleNamespace(full574_policy='x'),T,T.limits())
    def test_bad_policy_sha_before_source_or_alpm(self):
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'policy';path.write_text('{}')
            args=SimpleNamespace(full574_policy=path,full574_policy_sha256='0'*64,full574_lease=path,full574_lease_sha256='0'*64)
            with patch.object(T.F,'Alpm',side_effect=AssertionError('native actor forbidden')),self.assertRaisesRegex(ValueError,'policy-or-lease-pin'):C.connect(args,T,T.limits())
    def test_candidate_archive_and_old_payload_refuse_unpinned_bytes(self):
        adapter=object.__new__(C.Adapter);adapter.payloads=C.current_payloads();adapter.t=T
        adapter.policy=dict(candidates={n:dict(archive_sha256='0'*64) for n in C.VERSIONS})
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'archive';path.write_bytes(b'inert not an archive')
            with self.assertRaisesRegex(ValueError,'exact-current'):adapter.archive('cachy-asahi-apps',path,adapter.payloads['cachy-asahi-apps'])
        adapter.old_payload(adapter.payloads['cachy-asahi-apps'])
        for nodes in ({'usr/lib/libevil.so':dict(type='file')},{'usr/lib/cachy-asahi-apps/apps.py':dict(type='symlink',target='/etc/passwd')}):
            with self.assertRaisesRegex(ValueError,'installed-current'):adapter.old_payload(nodes)
    def test_source_reads_are_bounded_regular_and_nofollow(self):
        with tempfile.TemporaryDirectory() as temporary:
            base=Path(temporary);target=base/'source';target.write_bytes(b'ordinary source')
            self.assertEqual(C.source_bytes(target),b'ordinary source')
            alias=base/'alias';alias.symlink_to(target)
            with self.assertRaises(OSError):C.source_bytes(alias)
            with target.open('wb') as stream:stream.truncate(128*1024+1)
            with self.assertRaisesRegex(ValueError,'candidate-source-shape'):C.source_bytes(target)
    def test_pinned_policy_rejects_duplicate_keys(self):
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'policy';raw=b'{"purpose":"a","purpose":"b"}';path.write_bytes(raw)
            with self.assertRaisesRegex(ValueError,'duplicate-policy'):C.pinned_json(path,C.sha(raw),T.B.client.read_path)
    def test_real_writable_source_refuses_before_measurement(self):
        with tempfile.TemporaryDirectory() as temporary:
            adapter=object.__new__(C.Adapter);adapter.source=Path(temporary);adapter.t=T;adapter.lease=dict(source_identity=T.inode(adapter.source))
            before=len(os.listdir('/proc/self/fd'))
            with patch.object(C,'_measure',side_effect=AssertionError('read-only guard must precede measurement')),self.assertRaisesRegex(ValueError,'leased-source-must-be-readonly'):adapter.source_check()
            self.assertEqual(len(os.listdir('/proc/self/fd')),before)
    def test_owner_lease_cannot_be_swapped_or_omitted(self):
        adapter=object.__new__(C.Adapter);adapter.source=Path('/seed');adapter.policy=dict(source_tree_sha256='a'*64);adapter.binding=dict(policy_sha256='b'*64)
        good=dict(source='/seed',source_tree_sha256='a'*64,copy=dict(apps_full574_binding=adapter.binding))
        adapter.owner(good)
        for field,value in (('source','/different'),('source_tree_sha256','c'*64),('copy',{})):
            with self.assertRaisesRegex(ValueError,'copy-policy'):adapter.owner(good|{field:value})
    def test_shared_strict_helpers_remain_exact_and_refuse_baseline_extensions(self):
        function=C.roots.require_eligible;selection=copy.deepcopy(C.links.LINK_NODES)
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);(root/'usr').mkdir();(root/'usr/bin').mkdir();(root/'usr/bin/ldconfig').write_bytes(b'inert')
            with self.assertRaises(ValueError):T.observe(root,T.limits())
            with self.assertRaises(ValueError):C.measure(root,T.limits())
        self.assertIs(C.roots.require_eligible,function);self.assertEqual(C.links.LINK_NODES,selection)

class Capabilities(unittest.TestCase):
    def test_map_hash_and_lease_hash_must_agree_before_source_lookup(self):
        common=dict(schema_version=1,purpose=C.PURPOSE,execution_budget=dict(C.EXECUTION_BUDGET),**{n:'a'*64 for n in ('snapshot_sha256','extraction_receipt_sha256','source_tree_sha256','source_packages_sha256','source_closure_sha256','source_capabilities_sha256')})
        policy=dict(common,baseline_lock_sha256=C.LOCK_SHA256,candidates={n:dict(version=v,archive_sha256='b'*64,payload_sha256=C.digest(C.current_payloads()[n])) for n,v in C.VERSIONS.items()},source_capabilities={})
        lease=dict(common,token='c'*32,source='/INERT-MUST-NOT-LOOK-UP',source_identity=[1,2]);args=SimpleNamespace(full574_policy='policy',full574_policy_sha256='d'*64,full574_lease='lease',full574_lease_sha256='e'*64)
        with patch.object(C,'pinned_json',side_effect=[policy,lease]),self.assertRaisesRegex(ValueError,'source-capability-map-pin'):C.Adapter(args,T,T.limits())
        lease['source_capabilities_sha256']='f'*64
        with patch.object(C,'pinned_json',side_effect=[policy,lease]),self.assertRaisesRegex(ValueError,'policy-lease-source_capabilities_sha256'):C.Adapter(args,T,T.limits())
    def test_current_candidate_archives_refuse_capability_pax_before_install(self):
        for pax in ({},{'SCHILY.xattr.security.capability':bytes.fromhex('0100000240000000000000000000000000000000').decode('utf8','surrogateescape')},{'SCHILY.xattr.user.fixture':'unknown'}):
            output=io.BytesIO()
            with tarfile.open(fileobj=output,mode='w',format=tarfile.PAX_FORMAT) as stream:
                member=tarfile.TarInfo('usr/bin/inert');member.pax_headers=pax;stream.addfile(member,io.BytesIO(b''))
            if pax:
                with self.assertRaisesRegex(ValueError,'candidate-xattrs'):C.candidate_metadata(output.getvalue())
            else:self.assertEqual(C.candidate_metadata(output.getvalue()),'NO_CAPABILITIES_OR_OTHER_XATTRS')
    def test_complete_map_comparison_detects_candidate_and_original_changes(self):
        expected={'usr/bin/original':'0100000240000000000000000000000000000000'}
        with patch.object(C.caps,'observe',return_value=expected):
            self.assertEqual(C.capability_map('/INERT',{'nodes':{}},T.limits(),expected),expected)
        for actual in ({},expected|{'usr/bin/cachy-asahi-apps':next(iter(expected.values()))}):
            with patch.object(C.caps,'observe',return_value=actual),self.assertRaisesRegex(ValueError,'security-capabilities-changed'):C.capability_map('/INERT',{'nodes':{}},T.limits(),expected)
    def test_copy_restores_and_verifies_before_binding_can_be_returned(self):
        adapter=object.__new__(C.Adapter);adapter.source=Path('/seed');adapter.payloads={};adapter.policy={'source_capabilities':{'inert':'0100000240000000000000000000000000000000'}};adapter.binding={'source_capabilities_sha256':C.digest(adapter.policy['source_capabilities'])}
        nodes={'inert':{'type':'file'}};adapter.source_check=lambda:({'nodes':nodes},{})
        calls=[]
        def restore(root,actual,wanted,budget):calls.append((root,actual,wanted));return wanted
        with patch.object(C.copy_scope,'copy_data',return_value={'copied':True}),patch.object(C,'measure',return_value={'nodes':nodes}),patch.object(C,'baseline_nodes'),patch.object(C.caps,'restore',side_effect=restore):
            value=adapter.copy(adapter.source,Path('/owned'),limits=T.limits())
        self.assertEqual(len(calls),1);self.assertEqual(value['security_capabilities'],'EXACT_SOURCE_MAP_RESTORED_AND_VERIFIED');self.assertEqual(value['apps_full574_binding'],adapter.binding)
        with patch.object(C.copy_scope,'copy_data',return_value={}),patch.object(C,'measure',return_value={'nodes':nodes}),patch.object(C,'baseline_nodes'),patch.object(C.caps,'restore',side_effect=ValueError('unexpected capability')):
            with self.assertRaisesRegex(ValueError,'unexpected capability'):adapter.copy(adapter.source,Path('/owned'),limits=T.limits())
    def test_real_temp_unknown_xattr_refuses_without_running_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);path=root/'inert';path.write_bytes(b'never executed')
            nodes=C.roots.observe(root,limits=T.limits(),hardlinks='generic-development-internal')['nodes']
            self.assertEqual(C.capability_map(root,{'nodes':nodes},T.limits(),{}),{})
            os.setxattr(path,'user.UNIT-inert',b'unknown metadata')
            with self.assertRaisesRegex(ValueError,'unknown xattr'):C.capability_map(root,{'nodes':nodes},T.limits(),{})
            os.removexattr(path,'user.UNIT-inert')
            self.assertEqual(C.caps.restore(root,nodes,{},T.limits()),{})

class DataClosure(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        for name in ('usr/lib','usr/bin','etc','var/cache/ldconfig'):(self.root/name).mkdir(parents=True,exist_ok=True)
        for name,raw in (('usr/bin/ldconfig',b'inert never executed'),('usr/lib/libinert.so.1',b'not ELF; never loaded'),(C.aux.MAIN_CACHE,b'held opaque main cache'),(C.aux.AUX_CACHE,aux_bytes())):(self.root/name).write_bytes(raw)
        (self.root/'usr/lib/libinert.so').symlink_to('libinert.so.1')
        self.comparator=C.aux.load_comparator(C.ROOT/'scripts/ci/full-development-composition/audio_aux.py',T.limits())
    def state(self):
        observation=C.roots.observe(self.root,limits=T.limits(),hardlinks='generic-development-internal');reader=C.aux.Reader(self.root,observation,T.limits())
        scan={n:reader.capture(n) for n in reader.children('usr/lib',32)}
        caches={};data={}
        for name,key in ((C.aux.MAIN_CACHE,'main_bytes'),(C.aux.AUX_CACHE,'aux_bytes')):
            row=reader.capture(name,data_limit=256*1024);data[key]=row.pop('data');caches[name]={'node':row['node']}
        return dict(helper={'usr/bin/ldconfig':reader.capture('usr/bin/ldconfig')},configs={},aliases={},scan=scan,targets={},caches=caches,closure=tuple(sorted(set(scan)|set(caches)|{'usr/bin/ldconfig'})),scan_directories=('usr/lib',),**data)
    def test_actual_temp_link_and_raw_aux_baseline_preserved(self):
        before=self.state();after=self.state();value=C.unchanged(before,after,self.comparator)
        self.assertEqual(value['main_cache'],'RAW_EQUAL');self.assertEqual(value['auxiliary_transition'],dict(kind='RAW_EQUAL'))
        self.assertEqual(value['helper_execution'],'NOT_RUN');self.assertEqual(os.readlink(self.root/'usr/lib/libinert.so'),'libinert.so.1')
        self.assertEqual(len(self.comparator.parse(before['aux_bytes'])),2)
    def test_aux_valid_reordering_is_still_forbidden_for_apps(self):
        before=self.state();(self.root/C.aux.AUX_CACHE).write_bytes(aux_bytes((2,1)));after=self.state()
        self.assertEqual(len(self.comparator.parse(after['aux_bytes'])),2)
        with self.assertRaisesRegex(ValueError,'aux-changed-before'):C.unchanged(before,after,self.comparator)
    def test_main_helper_endpoint_and_new_soname_refuse(self):
        for kind in ('main','helper','endpoint','soname'):
            with self.subTest(kind=kind):
                self.setUp();before=self.state()
                if kind=='main':(self.root/C.aux.MAIN_CACHE).write_bytes(b'new cache')
                elif kind=='helper':(self.root/'usr/bin/ldconfig').write_bytes(b'changed helper')
                elif kind=='endpoint':
                    (self.root/'usr/lib/libinert.so').unlink();(self.root/'usr/lib/libinert.so').symlink_to('/etc/passwd')
                else:(self.root/'usr/lib/libextra.so.1').write_bytes(b'new unselected DSO')
                with self.assertRaises(ValueError):C.unchanged(before,self.state(),self.comparator)
    def test_only_exact_apps_scan_directory_projection(self):
        before=self.state();after=copy.deepcopy(before)
        row=dict(node=dict(type='directory',mode=0o755,uid=0,gid=0),identity=(1,2,3))
        after['scan'][C.SCAN_DATA]=row;after['closure']=tuple(sorted((*after['closure'],C.SCAN_DATA)))
        C.unchanged(before,after,self.comparator)
        for name,node in (('usr/lib/unselected',row),(C.SCAN_DATA,dict(node=dict(type='symlink',target='/elsewhere'))),(C.SCAN_DATA,dict(node=row['node']|dict(mode=0o777)))):
            changed=copy.deepcopy(before);changed['scan'][name]=node;changed['closure']=tuple(sorted((*changed['closure'],name)))
            with self.assertRaises(ValueError):C.unchanged(before,changed,self.comparator)
    def test_real_undeclared_absolute_link_refuses_without_host_read(self):
        outside=self.root.parent/(self.root.name+'-secret');outside.write_bytes(b'not to be read');self.addCleanup(outside.unlink)
        (self.root/'usr/lib/unknown.so').symlink_to(outside)
        with patch.object(Path,'resolve',side_effect=AssertionError('host resolution forbidden')),self.assertRaises(ValueError):C.measure(self.root,T.limits())
        self.assertEqual(outside.read_bytes(),b'not to be read')
    def test_actual_temp_full_baseline_refuses_user_trust_db_or_extra_changes(self):
        for name in ('home/user/note','etc/pacman.conf','var/lib/pacman/local/base-1/desc'):
            path=self.root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'original source data')
        before=C.roots.observe(self.root,limits=T.limits(),hardlinks='generic-development-internal')['nodes']
        C.baseline_nodes(before,before,C.current_payloads())
        for name in ('home/user/note','etc/pacman.conf','var/lib/pacman/local/base-1/desc'):
            path=self.root/name;path.write_bytes(b'changed data')
            with self.assertRaisesRegex(ValueError,'baseline-node-changed'):C.baseline_nodes(before,C.roots.observe(self.root,limits=T.limits(),hardlinks='generic-development-internal')['nodes'],C.current_payloads())
            path.write_bytes(b'original source data')
        (self.root/'home/user/new').write_bytes(b'extra')
        with self.assertRaisesRegex(ValueError,'unselected-new-node'):C.baseline_nodes(before,C.roots.observe(self.root,limits=T.limits(),hardlinks='generic-development-internal')['nodes'],C.current_payloads())
    def test_finite_candidate_db_shapes_only_and_base_never_removed(self):
        base={'usr':dict(type='directory',mode=0o755,uid=0,gid=0)};payloads=C.current_payloads()
        candidate=base|payloads['cachy-asahi-apps']
        prefix='var/lib/pacman/local/cachy-asahi-apps-'+C.VERSIONS['cachy-asahi-apps']
        candidate[prefix]=dict(type='directory',mode=0o755,uid=0,gid=0)
        candidate[prefix+'/desc']=dict(type='file',mode=0o644,uid=0,gid=0,bytes=1,sha256='a'*64)
        C.baseline_nodes(base,candidate,payloads)
        for name in (prefix+'/install','usr/lib/libevil.so','var/lib/pacman/local/cachy-asahi-apps-0.1.0-7/desc'):
            with self.assertRaisesRegex(ValueError,'unselected-new-node'):C.baseline_nodes(base,candidate|{name:candidate[prefix+'/desc']},payloads)
        with self.assertRaisesRegex(ValueError,'baseline-node-changed'):C.baseline_nodes(base,{},payloads)

class ReinstallRepair(unittest.TestCase):
    """Owned real leaves; policy/context positives are explicit inert models."""
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.block=patch.object(T.SUP.subprocess,'Popen',side_effect=AssertionError('actors forbidden'));self.block.start();self.addCleanup(self.block.stop)
        for name in ('usr/share','home/user','etc/pacman.d','var/lib/pacman/local/base-1'):(self.root/name).mkdir(parents=True,exist_ok=True)
        for name in ('home/user/note','etc/pacman.conf','var/lib/pacman/local/base-1/desc'):(self.root/name).write_bytes(b'original base, user and trust bytes')
        self.source=self.nodes();self.app='cachy-asahi-apps';self.cache='cachy-asahi-cache';self.path='usr/share/repair-app';self.other='usr/share/repair-cache'
        (self.root/self.path).write_bytes(b'exact Apps6 model payload');(self.root/self.other).write_bytes(b'exact unselected model cache');allnodes=self.nodes()
        self.payloads={name:{n:allnodes[n] for n in ('usr','usr/share',leaf)} for name,leaf in ((self.app,self.path),(self.cache,self.other))}
        self.inventory=dict(packages=[dict(name=r['name'],version=r['version']) for r in json.loads((C.ROOT/'scripts/ci/maintained-desktop574-inputs.json').read_bytes())['packages']]+[dict(name=n,version=C.VERSIONS[n]) for n in (self.app,self.cache)])
        metadata=dict(name=self.app,version=C.VERSIONS[self.app],arch='any',depend=[],provides=[],conflict=[],replaces=[],files=[self.path]);before=dict(metadata,source='caller-installed-inventory',metadata_sha256=C.digest(metadata));after=dict(metadata,source='signed-release',metadata_sha256=C.digest(metadata),release_archive_sha256='b'*64)
        self.plan=dict(operation='reinstall',requested_packages=[self.app],reinstalls=[dict(before=before,after=after)],additions=[],upgrades=[],removals=[],dependencies=[],conflicts=[],unchanged_selected=[],before_inventory_sha256='d'*64,after_inventory_sha256='d'*64,repair_policy='EXPLICIT_SELECTED_SAME_VERSION_AND_METADATA_ONLY_NO_DEPENDENCY_EXPANSION')
        self.context=dict(available={self.app:metadata},release=dict(packages=[dict(name=self.app,version=C.VERSIONS[self.app],sha256='b'*64)]))
    def nodes(self):
        value=C.roots.observe(self.root,limits=T.limits(),hardlinks='generic-development-internal');self.assertTrue(value['complete']);return value['nodes']
    def adapter(self):
        value=object.__new__(C.Adapter);value.payloads=self.payloads;value.policy=dict(candidates={self.app:dict(archive_sha256='b'*64)},source_capabilities={});value.source_check=lambda:(dict(nodes=self.source),{});return value
    def authorize(self):
        value=self.adapter();value.authorize_reinstall(self.plan,self.inventory,self.context,'e'*64);return value
    def test_default_refusal_then_explicit_selected_byte_damage_and_missing_leaf(self):
        adapter=self.authorize();target=self.root/self.path;target.write_bytes(b'damaged ordinary bytes')
        for missing in (False,True):
            if missing:target.unlink()
            nodes=self.nodes()
            with self.assertRaises(ValueError):self.adapter().selection({self.app:C.VERSIONS[self.app]}, {},self.inventory,nodes)
            if not missing:
                with self.assertRaises(ValueError):C.baseline_nodes(self.source,nodes,self.payloads)
            damage=C.reinstall_nodes(self.source,nodes,self.payloads,adapter.repair_names,adapter.repair_installed);self.assertEqual(set(damage),{self.path});self.assertEqual(damage[self.path],nodes.get(self.path))
            adapter.selection({self.app:C.VERSIONS[self.app]}, {},self.inventory,nodes)
        self.assertFalse(target.exists())
        before=self.nodes();old=T.reinstall_old(set(self.payloads[self.app]),before,self.payloads[self.app]);target.write_bytes(b'exact Apps6 model payload');after=self.nodes()
        T.check_preservation(before,after,old,self.payloads[self.app],set());self.assertEqual(C.reinstall_nodes(self.source,after,self.payloads,adapter.repair_names,adapter.repair_installed),{})
    def test_base_unselected_trust_user_and_database_drift_are_not_excluded(self):
        adapter=self.authorize()
        for name in ('home/user/note','etc/pacman.conf','var/lib/pacman/local/base-1/desc',self.other):
            path=self.root/name;raw=path.read_bytes();path.write_bytes(b'changed unselected bytes')
            with self.subTest(name=name),self.assertRaises(ValueError):C.reinstall_nodes(self.source,self.nodes(),self.payloads,adapter.repair_names,adapter.repair_installed)
            path.write_bytes(raw)
        (self.root/self.other).unlink()
        with self.assertRaisesRegex(ValueError,'unselected'):C.reinstall_nodes(self.source,self.nodes(),self.payloads,adapter.repair_names,adapter.repair_installed)
    def test_type_hardlink_mode_parent_and_unknown_xattr_are_refused(self):
        adapter=self.authorize();target=self.root/self.path;raw=target.read_bytes();target.chmod(0o600)
        with self.assertRaisesRegex(ValueError,'metadata'):C.reinstall_nodes(self.source,self.nodes(),self.payloads,adapter.repair_names,adapter.repair_installed)
        target.chmod(0o644);target.unlink();target.symlink_to('repair-cache')
        with self.assertRaisesRegex(ValueError,'ordinary'):C.reinstall_nodes(self.source,self.nodes(),self.payloads,adapter.repair_names,adapter.repair_installed)
        target.unlink();os.link(self.root/self.other,target)
        with self.assertRaises(ValueError):C.reinstall_nodes(self.source,self.nodes(),self.payloads,adapter.repair_names,adapter.repair_installed)
        target.unlink();os.mkfifo(target)
        with self.assertRaises(ValueError):C.reinstall_nodes(self.source,self.nodes(),self.payloads,adapter.repair_names,adapter.repair_installed)
        target.unlink();target.write_bytes(raw);parent=target.parent;parent.chmod(0o700)
        with self.assertRaisesRegex(ValueError,'directory|parent'):C.reinstall_nodes(self.source,self.nodes(),self.payloads,adapter.repair_names,adapter.repair_installed)
        parent.chmod(0o755);os.setxattr(target,'user.repair-unknown',b'no metadata waiver')
        with self.assertRaisesRegex(ValueError,'unknown xattr'):C.capability_map(self.root,dict(nodes=self.nodes()),T.limits(),{})
    def test_authentication_selection_version_archive_metadata_and_expansion_refuse(self):
        for kind in ('operation','addition','version','metadata','archive','selection','declared','inventory'):
            plan=copy.deepcopy(self.plan);context=copy.deepcopy(self.context);inventory=copy.deepcopy(self.inventory)
            if kind=='operation':plan['operation']='install'
            elif kind=='addition':plan['additions']=[plan['reinstalls'][0]['after']]
            elif kind=='version':plan['reinstalls'][0]['after']['version']='0.1.0-5'
            elif kind=='metadata':plan['reinstalls'][0]['before']['arch']='aarch64'
            elif kind=='archive':context['release']['packages'][0]['sha256']='f'*64
            elif kind=='selection':plan['requested_packages']=[self.cache]
            elif kind=='declared':plan['reinstalls'][0]['before']['declared_archive_sha256']='f'*64
            else:inventory['packages'][-1]['version']='forged'
            with self.subTest(kind=kind),self.assertRaises(ValueError):self.adapter().authorize_reinstall(plan,inventory,context,'e'*64)
        adapter=self.authorize()
        with self.assertRaisesRegex(ValueError,'single-authenticated'):adapter.authorize_reinstall(self.plan,self.inventory,self.context,'e'*64)
        with self.assertRaisesRegex(ValueError,'selection-differs'):adapter.selection({}, {self.app:C.VERSIONS[self.app]},self.inventory,self.nodes())
    def test_actual_damage_map_old_payload_and_complete_recheck_remain_exact(self):
        adapter=self.authorize();target=self.root/self.path;target.write_bytes(b'first actual damage');before=self.nodes();adapter.repair_before={n:r for n,r in before.items() if n in self.payloads[self.app]}
        adapter.old_payload({self.path:before[self.path]})
        with self.assertRaisesRegex(ValueError,'installed-current'):self.adapter().old_payload({self.path:before[self.path]})
        target.write_bytes(b'second drift');later=self.nodes();self.assertNotEqual(T.pins(dict(nodes=before),self.inventory),T.pins(dict(nodes=later),self.inventory))
        with self.assertRaisesRegex(ValueError,'installed-current'):adapter.old_payload({self.path:later[self.path]})
        for change in (dict(uid=before[self.path]['uid']+1),dict(gid=before[self.path]['gid']+1),dict(bytes=128*1024+1)):
            altered=copy.deepcopy(before);altered[self.path].update(change)
            with self.subTest(change=change),self.assertRaises(ValueError):C.reinstall_nodes(self.source,altered,self.payloads,adapter.repair_names,adapter.repair_installed)
        target.unlink();(self.root/'usr/share').rename(self.root/'usr/moved');(self.root/'usr/share').symlink_to('moved')
        with self.assertRaises(ValueError):C.reinstall_nodes(self.source,self.nodes(),self.payloads,adapter.repair_names,adapter.repair_installed)
    def test_repair_cannot_mask_original_base_leaf_or_change_capability_map(self):
        adapter=self.authorize();nodes=self.nodes();payloads=copy.deepcopy(self.payloads);name='etc/pacman.conf';payloads[self.app][name]=self.source[name]
        with self.assertRaisesRegex(ValueError,'original574'):C.reinstall_nodes(self.source,nodes,payloads,adapter.repair_names,adapter.repair_installed)
        with patch.object(C.caps,'observe',return_value={self.path:'0100000240000000000000000000000000000000'}),self.assertRaisesRegex(ValueError,'security-capabilities-changed'):C.capability_map(self.root,dict(nodes=nodes),T.limits(),{})


class RepairAuthenticationOrder(unittest.TestCase):
    def test_reinstall_auth_failure_precedes_any_repair_observation_install_stays_strict(self):
        from contextlib import nullcontext
        for operation,expected in (('reinstall','AUTHENTICATED_REPLAN_REFUSED'),('install','DEFAULT_STRICT_OBSERVATION'),('remove','DEFAULT_STRICT_OBSERVATION')):
            with self.subTest(operation=operation),tempfile.TemporaryDirectory() as temporary:
                work=Path(temporary);root=work/'root';root.mkdir();plan=work/'plan';plan.write_bytes(b'{}');calls=[]
                def execute(_):calls.append('authenticate');raise ValueError('AUTHENTICATED_REPLAN_REFUSED')
                app=SimpleNamespace(inventory_reader=lambda:SimpleNamespace(collect=lambda *a:dict(packages=[])),encoded=T.encoded,execute=execute)
                client=SimpleNamespace(read_path=lambda p,cap:p.read_bytes());closure=SimpleNamespace(owner=lambda _:None)
                args=SimpleNamespace(confirm_disposable_transaction=True,operation=operation,plan=str(plan),plan_sha256=T.sha(b'{}'))
                with patch.object(T,'root_guard',return_value=(work,root,{'copy':{}})),patch.object(T,'app_source',return_value=(app,client,None)),patch.object(T,'closure_for',return_value=closure),patch.object(T,'locked',return_value=nullcontext()),patch.object(T,'observe',side_effect=ValueError('DEFAULT_STRICT_OBSERVATION')) as observation,patch.object(T,'snapshot_inputs',side_effect=lambda a,*_:SimpleNamespace(**vars(a))),patch.object(T.SUP.subprocess,'Popen',side_effect=AssertionError('actors forbidden')):
                    result=T.apply(args)
                self.assertEqual(result['status'],'FAIL');self.assertFalse(result['commit_started']);self.assertIn(expected,result['error']);self.assertEqual(observation.call_count,0 if operation=='reinstall' else 1);self.assertEqual(calls,['authenticate'] if operation=='reinstall' else [])

if __name__=='__main__':unittest.main(verbosity=2)
