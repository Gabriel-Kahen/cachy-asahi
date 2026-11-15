# SPDX-License-Identifier: MIT
"""Fenced synthetic ownership controls; no artifact, image or actor imports."""
import hashlib
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest


def fence(event,args):
    if event.startswith(('subprocess.','socket.','ctypes.')) or event in ('os.system','os.exec','os.posix_spawn','os.fork','fcntl.flock'):
        raise RuntimeError('ownership DATA controls forbid operation: '+event)


sys.addaudithook(fence)
spec=importlib.util.spec_from_file_location('llvm_ownership_control',Path(__file__).with_name('ownership.py'))
O=importlib.util.module_from_spec(spec);spec.loader.exec_module(O)
NAMES=('usr/bin/[','usr/share/example/name,with,commas',r'usr/lib/systemd/system/dev-disk-by\x2duuid-example.device','usr/share/example/name with space')


def file_node(text):
    body=text.encode('utf-8')
    return dict(kind='file',mode=0o644,bytes=len(body),sha256=hashlib.sha256(body).hexdigest())


def model111():
    """Modeled versions/bytes, retaining only the reported filename classes."""
    db='var/lib/pacman/local';nodes={db:dict(kind='dir',mode=0o755)};records={}
    expected={name:'MODELED-1' for name in ['ca-certificates']+[f'model{i}' for i in range(110)]}
    for name in expected:
        directory=name+'-MODELED-1';base=db+'/'+directory
        desc='%NAME%\n'+name+'\n\n%VERSION%\nMODELED-1\n'
        files='' if name=='ca-certificates' else '%FILES%\n'+('\n'.join(NAMES)+'\n' if name=='model0' else '')
        records[directory]=dict(desc=desc,files=files)
        nodes[base]=dict(kind='dir',mode=0o755)
        nodes[base+'/desc']=file_node(desc);nodes[base+'/files']=file_node(files)
    nodes.update({name:file_node('MODELED CONTENT') for name in NAMES})
    return records,expected,nodes


def replace_files(records,nodes,directory,text):
    records[directory]['files']=text
    nodes['var/lib/pacman/local/'+directory+'/files']=file_node(text)


class OwnershipControls(unittest.TestCase):
    def test_reported_passive_classes_remain_literal(self):
        for name in NAMES:
            with self.subTest(name=name):self.assertEqual(O.passive_key(name),name)
        self.assertIn('\\x2d',O.passive_key(NAMES[2]))

    def test_passive_boundaries(self):
        self.assertEqual(O.passive_key('x'*255),'x'*255)
        for name in ('x'*256,'é'*128,'a/'*2048+'z',None,1,b'usr/bin/['):
            with self.subTest(name=repr(name)[:70]),self.assertRaises(ValueError):O.passive_key(name)

    def test_traversal_and_noncanonical_keys_refuse(self):
        for name in ('','/usr/bin/[','usr//bin/[','usr/./bin/[','usr/../bin/[','../usr/bin/[','usr/bin/[/', './x'):
            with self.subTest(name=name),self.assertRaises(ValueError):O.passive_key(name)

    def test_all_ASCII_controls_and_surrogates_refuse(self):
        for char in [chr(n) for n in range(32)]+['\x7f','\x85','\u2028','\ud800']:
            with self.subTest(char=repr(char)),self.assertRaises(ValueError):O.passive_key('usr/a'+char+'b')

    def test_active_safe_validator_remains_strict(self):
        self.assertEqual(O.safe('usr/bin/ordinary-tool'),'usr/bin/ordinary-tool')
        for name in NAMES:
            with self.subTest(name=name),self.assertRaises(ValueError):O.safe(name)

    def test_only_byteempty_or_declared_empty_record_accepted(self):
        self.assertEqual(O.files_text(''),[])
        self.assertEqual(O.files_text('%FILES%\n\n'),[])
        for text in ('\n',' ','\t','\r\n','ordinary/path\n','%BACKUP%\n','%%FILES%%\n','%FILES%\n%OTHER%\n'):
            with self.subTest(text=repr(text)),self.assertRaises(ValueError):O.files_text(text)

    def test_FILES_literal_classes_and_single_directory_suffix(self):
        self.assertEqual(O.files_text('%FILES%\n'+'\n'.join(NAMES)+'\nusr/share/example/\n'),list(NAMES)+['usr/share/example'])

    def test_malformed_nonempty_records_refuse(self):
        for text in ('%FILES%\nusr/a\n%FILES%\n','%FILES%\nusr/a\nusr/a/\n','%FILES%\nusr/a//\n','%FILES%\nusr/../a\n','%FILES%\nusr/a\tbad\n','%FILES%\nusr/a\r\n','%FILES%\nusr/a\x00\n','%FILES%\nusr/a\v\n','%FILES%\nusr/a\f\n','%FILES%\nusr/a\x85\n','%FILES%\n%BACKUP\n','%FILES%\n%BACKUP%\n%FILES%\n'):
            with self.subTest(text=repr(text)),self.assertRaises(ValueError):O.files_text(text)

    def test_backup_metadata_requires_unique_owned_literal_path_and_MD5(self):
        prefix='%FILES%\netc/example.conf\n\n%BACKUP%\n'
        good='etc/example.conf\t'+'a'*32+'\n'
        self.assertEqual(O.files_text(prefix+good),['etc/example.conf'])
        for bad in ('etc/other\t'+'a'*32,'etc/example.conf\twrong','etc/example.conf','etc/example.conf\t'+'a'*32+'\textra',good+good):
            with self.subTest(bad=bad),self.assertRaises(ValueError):O.files_text(prefix+bad)

    def test_complete111_with_byteempty_ca_certificates_and_literal_names(self):
        records,expected,nodes=model111()
        self.assertEqual(records['ca-certificates-MODELED-1']['files'],'')
        owned=O.all_owned_records(records,expected,nodes)
        self.assertEqual(set(owned),set(NAMES))
        self.assertTrue(all(row['owners']==['model0'] for row in owned.values()))

    def test_changed_record_bytes_refuse_before_ownership_join(self):
        records,expected,nodes=model111();records['ca-certificates-MODELED-1']['files']='%FILES%\n'
        with self.assertRaisesRegex(ValueError,'differs from namespace'):O.all_owned_records(records,expected,nodes)

    def test_rehashed_nonempty_malformed_record_and_missing_node_refuse(self):
        for text in ('\n','not-a-files-record','%FILES%\n../outside\n','%FILES%\nusr/missing\n'):
            records,expected,nodes=model111();replace_files(records,nodes,'ca-certificates-MODELED-1',text)
            with self.subTest(text=text),self.assertRaises(ValueError):O.all_owned_records(records,expected,nodes)

    def test_synthetic_namespace_uses_only_passive_validation(self):
        with tempfile.TemporaryDirectory(prefix='llvm-ownership-MODELED-') as tmp:
            root=Path(tmp)
            for name in NAMES:
                path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'MODELED')
            nodes=O.namespace(root)
            self.assertTrue(set(NAMES)<=set(nodes))
            self.assertTrue(all(nodes[name]['sha256']==hashlib.sha256(b'MODELED').hexdigest() for name in NAMES))

    def test_process_socket_ctypes_and_lock_audit_fence(self):
        for event in ('subprocess.Popen','socket.__new__','ctypes.dlopen','os.system','os.exec','os.posix_spawn','os.fork','fcntl.flock'):
            with self.subTest(event=event),self.assertRaises(RuntimeError):sys.audit(event)


if __name__=='__main__':unittest.main()
