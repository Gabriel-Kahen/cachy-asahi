#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Inert complete-projection and exact derived-node controls; no native actors."""
import copy,hashlib,importlib.util,json,sys,time,unittest
from pathlib import Path

HERE=Path(__file__).resolve().parent
ROOT=next(parent for parent in HERE.parents if (parent/'manifests/packages.toml').is_file())
sys.path.insert(0,str(HERE))
import profile as p
spec=importlib.util.spec_from_file_location('soname_installer_controls',HERE/'installer.py');w=importlib.util.module_from_spec(spec);spec.loader.exec_module(w)
spec=importlib.util.spec_from_file_location('soname_path_controls',ROOT/'scripts/update/root_path.py');paths=importlib.util.module_from_spec(spec);spec.loader.exec_module(paths)

DIR=dict(type='directory',mode=0o755,uid=0,gid=0)
MAIN='# Dynamic linker/loader configuration.\n# See ld.so(8) and ldconfig(8) for details.\n\ninclude /etc/ld.so.conf.d/*.conf\ninclude /usr/lib/ld.so.conf.d/*.conf\n'

def file(data):return dict(type='file',mode=0o644,uid=0,gid=0,bytes=len(data),sha256=hashlib.sha256(data).hexdigest())

def fixture():
    nodes={'etc/ld.so.conf':file(MAIN.encode()),'usr/lib/ld.so.conf.d/fakeroot.conf':file(b'/usr/lib/libfakeroot\n'),
        p.SONAME_TARGET:copy.deepcopy(p.SONAME_TARGET_NODE),'usr/bin/ldconfig':dict(type='file',mode=0o755,uid=0,gid=0,bytes=865664,sha256='8794bf13f7a651963a219d8031fe04800d06ac6e44a29fbdfd81b64855b2bd98')}
    for name in ('usr/lib/libvapoursynth-script.so','usr/lib/libvapoursynth-script.so.0'):
        nodes[name]=dict(type='symlink',mode=0o777,uid=0,gid=0,target='python3.14/site-packages/vapoursynth/libvsscript.so')
    for name in list(nodes)+['usr/lib/libfakeroot/dummy']:
        parent=name.rpartition('/')[0]
        while parent:nodes.setdefault(parent,copy.deepcopy(DIR));parent=parent.rpartition('/')[0]
    facts=dict(elf={p.SONAME_TARGET:dict(class_=64)},configs={'etc/ld.so.conf':MAIN,'usr/lib/ld.so.conf.d/fakeroot.conf':'/usr/lib/libfakeroot\n'})
    facts['elf'][p.SONAME_TARGET]=dict(byte_order='little',machine=183,type=3,dynamic_present=True,soname='libvsscript.so',**{'class':64})
    payload=dict(schema_version=1,nodes=nodes,hardlinks=[],library_facts=facts,
        packages={name:row['version'] for name,row in p.SONAME_PACKAGES.items()},
        ownership={'vapoursynth':[p.SONAME_TARGET,'usr/lib/libvapoursynth-script.so','usr/lib/libvapoursynth-script.so.0'],'glibc':['usr/bin/ldconfig']})
    payload['soname_projection']=p.project_sonames(payload,paths.resolve)
    return payload


def observed(payload,derived=True):
    nodes=copy.deepcopy(payload['nodes'])
    if derived:nodes.update(copy.deepcopy(p.SONAME_OUTPUTS))
    for name,data in w.FIXTURES.items():nodes[name]=dict(file(data),mode=0o600)
    return dict(complete=True,unsupported_counts={},nodes=nodes,hardlink_groups={})


class SonameControls(unittest.TestCase):
    def test_complete_projection_finds_exact_literal_target_regardless_of_input_order(self):
        payload=fixture();self.assertEqual(payload['soname_projection']['outputs'],p.SONAME_OUTPUTS)
        payload['nodes']=dict(reversed(list(payload['nodes'].items())))
        self.assertEqual(p.project_sonames(payload,paths.resolve),payload['soname_projection'])
    def test_source_numeric_candidate_ordering(self):
        self.assertLess(p.soname_compare('libvapoursynth-script.so','libvapoursynth-script.so.0'),0)
        self.assertLess(p.soname_compare('liba.so.2','liba.so.10'),0)
        self.assertEqual(p.soname_compare('liba.so.01','liba.so.1'),0)
    def test_default_comparator_still_refuses_the_derived_node(self):
        payload=fixture()
        with self.assertRaisesRegex(ValueError,'unexpected installed output'):w.compare_payload(observed(payload),payload)
    def test_selected_complete_typed_node_passes(self):
        payload=fixture();self.assertTrue(w.compare_payload(observed(payload),payload,derived_output_binding=p.soname_binding(payload)))
    def test_each_wrong_type_mode_uid_gid_or_literal_target_fails(self):
        payload=fixture();binding=p.soname_binding(payload)
        for field,value in [('type','file'),('mode',0o755),('uid',1),('gid',5),('target','python3.14/site-packages/vapoursynth/libvsscript.so'),('target','libvapoursynth-script.so')]:
            view=observed(payload);view['nodes']['usr/lib/libvsscript.so'][field]=value
            with self.subTest(field=field,value=value),self.assertRaisesRegex(ValueError,'derived installed output differs'):
                w.compare_payload(view,payload,derived_output_binding=binding)
    def test_missing_derived_node_fails_selected_policy(self):
        payload=fixture()
        with self.assertRaisesRegex(ValueError,'derived installed output differs'):w.compare_payload(observed(payload,False),payload,derived_output_binding=p.soname_binding(payload))
    def test_no_extra_fields_or_other_unowned_paths_admitted(self):
        payload=fixture();binding=p.soname_binding(payload)
        view=observed(payload);view['nodes']['usr/lib/libvsscript.so']['extra']=True
        with self.assertRaisesRegex(ValueError,'derived installed output differs'):w.compare_payload(view,payload,derived_output_binding=binding)
        view=observed(payload);view['nodes']['usr/lib/another.so']=copy.deepcopy(p.SONAME_OUTPUTS['usr/lib/libvsscript.so'])
        with self.assertRaisesRegex(ValueError,'unexpected installed output'):w.compare_payload(view,payload,derived_output_binding=binding)
    def test_mutated_or_expanded_policy_fails(self):
        payload=fixture();binding=copy.deepcopy(p.soname_binding(payload));binding['outputs']['usr/lib/another.so']=binding['outputs']['usr/lib/libvsscript.so']
        with self.assertRaisesRegex(ValueError,'explicit held SONAME selection'):w.compare_payload(observed(payload),payload,derived_output_binding=binding)
    def test_exact_signed_archive_tuple_and_package_ownership_required(self):
        payload=fixture();manifest=dict(packages=[dict(name=name,**row) for name,row in p.SONAME_PACKAGES.items()])
        code=ROOT
        self.assertEqual(p.soname_selection(manifest,payload,code),p.soname_binding(payload))
        manifest['packages'][0]['sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'signed archive tuple'):p.soname_selection(manifest,payload,code)
        payload['ownership']['vapoursynth'].remove(p.SONAME_TARGET)
        with self.assertRaisesRegex(ValueError,'package ownership'):p.soname_binding(payload)
    def test_full_source_projection_catches_a_second_predictable_alias_before_selection(self):
        payload=fixture();name='usr/lib/libsecond-implementation.so.1';payload['nodes'][name]=file(b'fixture')
        payload['library_facts']['elf'][name]=dict(payload['library_facts']['elf'][p.SONAME_TARGET],soname='libsecond.so.9')
        payload['soname_projection']=p.project_sonames(payload,paths.resolve)
        self.assertIn('usr/lib/libsecond.so.9',payload['soname_projection']['outputs'])
        with self.assertRaisesRegex(ValueError,'unexpected finite SONAME output set'):p.soname_binding(payload)
    def test_equal_numeric_versions_cannot_guess_literal_target(self):
        payload=fixture()
        name='usr/lib/libvapoursynth-script.so.00'
        payload['nodes'][name]=copy.deepcopy(payload['nodes']['usr/lib/libvapoursynth-script.so.0'])
        with self.assertRaisesRegex(ValueError,'literal-target ambiguity'):p.project_sonames(payload,paths.resolve)
    def test_gnu_temporary_names_do_not_manufacture_another_alias(self):
        for suffix in ('.#prelink#','.#prelink#.ABCDEF','.dpkg-new','.dpkg-tmp',';rpm'):
            payload=fixture();name='usr/lib/libignored.so'+suffix;payload['nodes'][name]=file(b'fixture')
            payload['library_facts']['elf'][name]=dict(payload['library_facts']['elf'][p.SONAME_TARGET],soname='libignored-output.so')
            with self.subTest(suffix=suffix):self.assertEqual(p.project_sonames(payload,paths.resolve)['outputs'],p.SONAME_OUTPUTS)
    def test_unknown_scan_config_refused(self):
        payload=fixture();payload['library_facts']['configs']['usr/lib/ld.so.conf.d/fakeroot.conf']='/opt/unreviewed\n'
        node=payload['nodes']['usr/lib/ld.so.conf.d/fakeroot.conf'];node.update(file(b'/opt/unreviewed\n'))
        with self.assertRaisesRegex(ValueError,'undeclared scan directory'):p.project_sonames(payload,paths.resolve)
    def test_config_symlink_or_missing_facts_cannot_hide_a_scan_directory(self):
        payload=fixture();payload['nodes']['etc/ld.so.conf.d/extra.conf']=dict(type='symlink',uid=0,gid=0,mode=0o777,target='/etc/ld.so.conf')
        with self.assertRaisesRegex(ValueError,'configuration facts incomplete'):p.project_sonames(payload,paths.resolve)
    def test_source_elf_gaps_and_unsafe_sonames_refused(self):
        for value in ({'refused':'bad-header'},dict(fixture()['library_facts']['elf'][p.SONAME_TARGET],soname='../escape')):
            payload=fixture();payload['library_facts']['elf'][p.SONAME_TARGET]=value
            with self.assertRaises(ValueError):p.project_sonames(payload,paths.resolve)
    def test_payload_and_fixture_changes_still_fail(self):
        payload=fixture();binding=p.soname_binding(payload)
        for name in (p.SONAME_TARGET,next(iter(w.FIXTURES))):
            view=observed(payload);view['nodes'][name]['sha256']='0'*64
            with self.assertRaises(ValueError):w.compare_payload(view,payload,derived_output_binding=binding)
    def test_bounded_exact_path_diagnostic_retains_actual_node_without_file_content(self):
        payload=fixture();view=observed(payload);value=w.soname_observation(view)
        self.assertEqual(value,p.SONAME_OUTPUTS);self.assertLess(len(p.encoded(value)),8192)
        self.assertEqual(w.soname_observation(observed(payload,False)),{'usr/lib/libvsscript.so':{'type':'absent'}})
    def test_both_engine_and_independent_export_observer_select_the_same_policy(self):
        worker=(HERE/'installer.py').read_text();numeric=(HERE/'numeric_vm.py').read_text()
        self.assertIn("compare_payload(observed,payload,derived_output_binding=profile.get('derived_output_binding'))",worker)
        self.assertIn("worker.compare_payload(normalize(observation),payload,derived_output_binding=profile.get('derived_output_binding'))",numeric)
        self.assertIn("p.soname_selection(value,payload,SHARED/'code')",worker)


if __name__=='__main__':unittest.main()
