# SPDX-License-Identifier: MIT
"""FENCED certificate/namespace DATA only; no tool, reader, or actor calls."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent


def load(name):
    spec=importlib.util.spec_from_file_location('fenced_dynamic_'+name,HERE/(name+'.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m


C,O=load('contracts'),load('ownership')
OTHER=('util','rt','pthread','m','dl','c')


def certificate():
    expected=dict(bytes=1,sha256='a'*64)
    links={name:'/usr/lib/lib'+name+'.so' for name in OTHER};links['gcc_s']=C.GCC_S_PATH
    files={name:dict(bytes=1,sha256='b'*64,owner='FENCED',version='1',resolved=name if name.startswith('/usr/') else '/usr'+name) for name in set(C.REQUIRED_PATHS)|set(links.values())}
    files[C.GCC_S_PATH]=dict(C.GCC_S_PIN)
    g=dict(kind=C.GUEST_INPUT_KIND,issued_by='Root',status='ROOT_REVIEWED_READONLY_BASE111_INPUTS',base_raw=expected,expected111=expected,link_inputs=links,files=files)
    base=dict(files={'guest.raw':expected},base_packages=[dict(name='FENCED',version='1'),dict(name='libgcc',version=C.GCC_S_PIN['version'])])
    return g,base,expected


def namespace():
    nodes={'usr':dict(kind='dir',mode=0o755),'usr/lib':dict(kind='dir',mode=0o755)}
    nodes[C.GCC_S_PATH.lstrip('/')]=dict(kind='file',mode=0o755,**{key:C.GCC_S_PIN[key] for key in ('bytes','sha256')})
    for suffix in ('.so','.a'):nodes['usr/lib/libgcc_s'+suffix]=dict(kind='file',mode=0o644,bytes=1,sha256='d'*64)
    cert=dict(files={C.GCC_S_PATH:dict(C.GCC_S_PIN)},link_inputs={'gcc_s':C.GCC_S_PATH})
    owned={C.GCC_S_PATH.lstrip('/'):dict(owners=['libgcc'])}
    return nodes,cert,owned


class DynamicInputsControls(unittest.TestCase):
    def admitted(self,g,base,expected):
        with patch.object(C,'checked'),patch.object(C,'load',return_value=g),patch.object(C,'pin',return_value=expected):
            return C.guest_inputs(Path('/FENCED_CERTIFICATE.DATA'),dict(guest_inputs=expected),base)

    def test_exact_expected_future_dynamic_payload_and_new_certificate_kind(self):
        g,base,expected=certificate()
        self.assertIs(self.admitted(g,base,expected),g)
        self.assertEqual(C.GCC_S_PIN,dict(bytes=133352,sha256='ac598673a4bf67c0295b6609e46b1fafd0d4adf3f80a513d61ac49ecff772e48',owner='libgcc',version='16.1.1+r12+g301eb08fa2c5-1',resolved='/usr/lib/libgcc_s.so.1'))
        g['kind']='ARM16K_RUST_STAGE0_BASE111_INPUTS_V1'
        with self.assertRaisesRegex(ValueError,'dynamic-gcc'):self.admitted(g,base,expected)

    def test_wrong_script_static_missing_and_payload_pin_fields_refuse(self):
        for alteration in ('script','static','missing','bytes','sha256','owner','version','resolved'):
            g,base,expected=certificate()
            if alteration in ('script','static'):
                path='/usr/lib/libgcc_s'+('.so' if alteration=='script' else '.a');g['link_inputs']['gcc_s']=path
                g['files'][path]=dict(g['files']['/usr/lib/libc.so'])
            elif alteration=='missing':g['files'].pop(C.GCC_S_PATH)
            else:g['files'][C.GCC_S_PATH][alteration]={'bytes':133353,'sha256':'f'*64,'owner':'FENCED','version':'WRONG','resolved':'/usr/lib/other.so.1'}[alteration]
            with self.subTest(alteration=alteration),self.assertRaises(ValueError):self.admitted(g,base,expected)
        g,base,expected=certificate();base['base_packages'][1]['version']='WRONG'
        with self.assertRaisesRegex(ValueError,'file/owner'):self.admitted(g,base,expected)

    def test_template_remains_wholly_unissued(self):
        g=json.loads((HERE/'guest-inputs.TEMPLATE.json').read_text())
        self.assertEqual(g['kind'],C.GUEST_INPUT_KIND);self.assertEqual(g['status'],'UNQUALIFIED')
        for key in ('issued_by','base_raw','expected111'):self.assertIsNone(g[key])
        self.assertTrue(all(value is None for value in g['link_inputs'].values()))
        self.assertTrue(all(value is None for row in g['files'].values() for value in row.values()))
        _,base,expected=certificate()
        with self.assertRaises(ValueError):self.admitted(g,base,expected)

    def test_namespace_uses_dynamic_payload_despite_script_and_static_presence(self):
        nodes,cert,owned=namespace()
        self.assertEqual(O.qualify_nodes(cert,owned,nodes),cert['files'])
        for name in ('/usr/lib/libgcc_s.so','/usr/lib/libgcc_s.a'):
            bad=copy.deepcopy(cert);bad['link_inputs']['gcc_s']=name
            with self.assertRaisesRegex(ValueError,'search choice'):O.qualify_nodes(bad,owned,nodes)

    def test_namespace_missing_hash_owner_resolution_and_unqualified_payload_refuse(self):
        for alteration in ('missing','hash','owner','resolved','unqualified'):
            nodes,cert,owned=namespace();key=C.GCC_S_PATH.lstrip('/')
            if alteration=='missing':nodes.pop(key)
            elif alteration=='hash':nodes[key]['sha256']='e'*64
            elif alteration=='owner':owned[key]['owners']=['FENCED_OTHER']
            elif alteration=='resolved':cert['files'][C.GCC_S_PATH]['resolved']='/usr/lib/other.so.1'
            else:cert['files']={}
            with self.subTest(alteration=alteration),self.assertRaises(ValueError):O.qualify_nodes(cert,owned,nodes)

    def test_other_six_keep_so_before_static_and_static_fallback(self):
        nodes={};links={name:'/usr/lib/lib'+name+'.a' for name in OTHER}
        for path in links.values():nodes[path.lstrip('/')]=dict(kind='file',mode=0o644,bytes=1,sha256='d'*64)
        cert=dict(files={},link_inputs=links)
        self.assertEqual(O.qualify_nodes(cert,{},nodes),{})
        for name in OTHER:
            with self.subTest(name=name):
                so='/usr/lib/lib'+name+'.so';nodes[so.lstrip('/')]=dict(kind='file',mode=0o644,bytes=1,sha256='d'*64)
                with self.assertRaisesRegex(ValueError,'search choice'):O.qualify_nodes(cert,{},nodes)
                cert['link_inputs'][name]=so;self.assertEqual(O.qualify_nodes(cert,{},nodes),{})

    def test_filesystem_api_checks_bounded_actual_data_and_owner(self):
        with tempfile.TemporaryDirectory(prefix='fenced-dynamic-',dir=HERE) as tmp:
            root=Path(tmp);library=root/C.GCC_S_PATH.lstrip('/');library.parent.mkdir(parents=True)
            body=b'FENCED INERT DYNAMIC LIBRARY DATA';library.write_bytes(body)
            (library.parent/'libgcc_s.so').write_bytes(b'FENCED LINKER SCRIPT DATA')
            (library.parent/'libgcc_s.a').write_bytes(b'FENCED STATIC ARCHIVE DATA')
            row=dict(bytes=len(body),sha256=hashlib.sha256(body).hexdigest(),owner='libgcc',version=C.GCC_S_PIN['version'],resolved=C.GCC_S_PATH)
            cert=dict(files={C.GCC_S_PATH:row},link_inputs={'gcc_s':C.GCC_S_PATH});owned={C.GCC_S_PATH.lstrip('/'):dict(owners=['libgcc'])}
            self.assertEqual(O.qualify(root,cert,owned),cert['files'])
            with self.assertRaisesRegex(ValueError,'ownership'):O.qualify(root,cert,{})
            library.write_bytes(b'CHANGED DATA')
            with self.assertRaisesRegex(ValueError,'bytes/link'):O.qualify(root,cert,owned)


if __name__=='__main__':unittest.main()
