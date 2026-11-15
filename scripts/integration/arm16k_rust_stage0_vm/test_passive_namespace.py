# SPDX-License-Identifier: MIT
"""Literal namespace/ALPM DATA with a mocked reader; no actual image or actor."""
import copy
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('fenced_passive_image_controls',HERE/'test_image.py')
T=importlib.util.module_from_spec(spec);spec.loader.exec_module(T)
O=T.O
LITERALS=('usr/bin/[','usr/share/i18n/charmaps/ISO_8859-1,GL.gz',
          r'usr/lib/systemd/system/system-systemd\x2dcryptsetup.slice',
          'usr/share/line\u2028separator','usr/share/paragraph\u2029separator',
          'usr/share/next\u0085line')


def corpus():
    rows={'.':dict(type='directory',mode=0o755,inode=2,size=4096)};bodies={};index=3
    def directory(name):
        nonlocal index
        if name in ('','.') or name in rows:return
        directory(Path(name).parent.as_posix())
        rows[name]=dict(type='directory',mode=0o755,inode=index,size=4096);index+=1
    def file(name,body):
        nonlocal index
        directory(Path(name).parent.as_posix())
        rows[name]=dict(type='file',mode=0o644,inode=index,size=len(body),sha256=hashlib.sha256(body).hexdigest())
        bodies[index]=body;index+=1
    packages=[('ca-certificates','20240618-1',[]),('dbus-units','37-3',[]),
              ('coreutils','9.11-2',[LITERALS[0]]),('glibc','2.43-2',[LITERALS[1]]),
              ('systemd','261.2-1',[LITERALS[2]]),('separator','1',list(LITERALS[3:]))]
    packages.extend(('fenced'+str(n),'1',['usr/share/fenced'+str(n)]) for n in range(105))
    for name,version,paths in packages:
        prefix='var/lib/pacman/local/'+name+'-'+version
        file(prefix+'/desc',('%NAME%\n'+name+'\n\n%VERSION%\n'+version+'\n').encode())
        file(prefix+'/files',('%FILES%\n'+'\n'.join(paths)+'\n').encode() if paths else b'')
        for path in paths:file(path,b'FENCED_LITERAL_DATA')
    return rows,bodies,{name:version for name,version,_ in packages}


def observation():
    rows,bodies,expected=corpus()
    with tempfile.TemporaryDirectory(prefix='fenced-passive-') as tmp:
        raw=Path(tmp)/'INERT_DATA';raw.write_bytes(b'x'*4096)
        result=T.ImageControls().scan(raw,rows,bodies)
    return result,expected


class PassiveNamespaceControls(unittest.TestCase):
    def test_literal_keys_are_preserved_without_unescaping_or_normalizing(self):
        for name in LITERALS:
            with self.subTest(name=name):
                self.assertEqual(O.passive(name),name)
                self.assertEqual(O.owned_paths('%FILES%\n'+name+'\n'),[name])
        self.assertNotEqual(LITERALS[2],LITERALS[2].replace(r'\x2d','-'))

    def test_passive_paths_reject_control_traversal_empty_and_overlong_utf8(self):
        values=(None,'','/absolute','a//b','a/./b','a/../b','a/', '.', '..',
                'x'*4097,'é'*2049,'surrogate\ud800')
        values+=tuple('usr/'+chr(n)+'name' for n in (0,9,10,13,31,127))
        for name in values:
            with self.subTest(name=repr(name)),self.assertRaises(ValueError):O.passive(name)
        self.assertEqual(O.passive('x'*4096),'x'*4096)
        self.assertEqual(O.passive('é'*2048),'é'*2048)

    def test_one_trailing_directory_slash_and_per_package_uniqueness(self):
        self.assertEqual(O.ownership_key('usr/'),'usr')
        self.assertEqual(O.owned_paths('%FILES%\nusr/\nusr/bin/[\n'),['usr','usr/bin/['])
        for value in ('/','usr//','usr///','usr//bin/','usr/../bin/'):
            with self.subTest(value=value),self.assertRaises(ValueError):O.ownership_key(value)
        for text in ('%FILES%\nusr\nusr/\n','%FILES%\nusr/bin/[\nusr/bin/[\n',
                     '%FILES%\nusr\n%FILES%\nusr/bin\n'):
            with self.subTest(text=text),self.assertRaises(ValueError):O.owned_paths(text)

    def test_only_exact_empty_files_record_selects_no_paths(self):
        self.assertEqual(O.owned_paths(''),[])
        for value in ('\n','%FILES%\n','%FILES%\n\n','%BACKUP%\nfile\n',' '):
            with self.subTest(value=value),self.assertRaises(ValueError):O.owned_paths(value)

    def test_lf_field_split_preserves_unicode_separators_and_refuses_other_controls(self):
        value='name\u2028line\u2029paragraph\u0085next'
        self.assertEqual(O.fields_text('%FILES%\n'+value+'\n')['FILES'],[value])
        self.assertEqual(O.fields_text('%DESC%\nname\tvalue\n')['DESC'],['name\tvalue'])
        for bad in ('\0','\r','\v','\f','\x1f','\x7f'):
            with self.subTest(bad=repr(bad)),self.assertRaises(ValueError):O.fields_text('%FILES%\nname'+bad+'other\n')
        with tempfile.TemporaryDirectory(prefix='fenced-fields-') as tmp:
            p=Path(tmp)/'DATA';p.write_bytes(b'%FILES%\r\nusr/bin/x\r\n')
            with self.assertRaises(ValueError):O.fields(p)

    def test_mock_image_scan_and_all111_literal_ownership_with_two_empty_records(self):
        result,expected=observation();nodes=result['nodes'];records=result['records']
        owned=O.all_owned_records(records,expected,nodes)
        self.assertEqual(len(records),111)
        for name in LITERALS:self.assertIn(name,nodes);self.assertIn(name,owned)
        self.assertEqual(records['ca-certificates-20240618-1']['files'],'')
        self.assertEqual(records['dbus-units-37-3']['files'],'')
        for package in ('ca-certificates','dbus-units'):
            self.assertTrue(all(package not in row['owners'] for row in owned.values()))
        self.assertNotIn(LITERALS[2].replace(r'\x2d','-'),owned)

    def test_full_mock_image_rejects_control_or_malformed_namespace_keys(self):
        for name in ('usr/share/control\0name','usr/share/control\nname',
                     'usr/share/control\x7fname','usr/share//name','../outside','/absolute'):
            rows,bodies,_=corpus()
            rows[name]=dict(type='file',mode=0o644,inode=999999,size=0,sha256=hashlib.sha256(b'').hexdigest())
            with self.subTest(name=repr(name)),tempfile.TemporaryDirectory(prefix='fenced-invalid-image-') as tmp:
                raw=Path(tmp)/'INERT_DATA';raw.write_bytes(b'x'*4096)
                with self.assertRaises(ValueError):T.ImageControls().scan(raw,rows,bodies)

    def test_local_passive_namespace_and_all_owned_match_record_join(self):
        result,expected=observation()
        with tempfile.TemporaryDirectory(prefix='fenced-passive-files-') as tmp:
            root=Path(tmp)
            for name in LITERALS:
                p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b'FENCED_LITERAL_DATA')
            for directory,record in result['records'].items():
                p=root/'var/lib/pacman/local'/directory;p.mkdir(parents=True)
                for kind,text in record.items():(p/kind).write_bytes(text.encode())
            # The local join requires every selected ordinary synthetic path.
            for name in result['nodes']:
                if name.startswith('usr/share/fenced'):
                    p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b'FENCED_LITERAL_DATA')
            nodes=O.namespace(root)
            self.assertEqual(O.all_owned(root,expected,nodes),O.all_owned_records(result['records'],expected,nodes))

    def test_hash_pairing_inventory_and_literal_key_presence_remain_strict(self):
        result,expected=observation();nodes=result['nodes'];records=result['records']
        for change in ('missing-package','missing-files','missing-desc','empty-desc','empty-FILES','duplicate-key','changed-bytes','wrong-version','missing-literal'):
            current=copy.deepcopy(records);current_nodes=copy.deepcopy(nodes)
            directory='coreutils-9.11-2'
            if change=='missing-package':current.pop(directory)
            elif change=='missing-files':current[directory].pop('files')
            elif change=='missing-desc':current[directory].pop('desc')
            elif change in ('empty-desc','empty-FILES','duplicate-key'):
                kind='desc' if change=='empty-desc' else 'files'
                text='' if change=='empty-desc' else '%FILES%\n' if change=='empty-FILES' else '%FILES%\nusr/bin/[\nusr/bin/[\n'
                current[directory][kind]=text;body=text.encode()
                current_nodes['var/lib/pacman/local/'+directory+'/'+kind].update(bytes=len(body),sha256=hashlib.sha256(body).hexdigest())
            elif change=='changed-bytes':current[directory]['files']+='usr/extra\n'
            elif change=='wrong-version':
                text=current[directory]['desc'].replace('9.11-2','WRONG')
                current[directory]['desc']=text;body=text.encode()
                current_nodes['var/lib/pacman/local/'+directory+'/desc'].update(bytes=len(body),sha256=hashlib.sha256(body).hexdigest())
            else:current_nodes.pop(LITERALS[0])
            with self.subTest(change=change),self.assertRaises(ValueError):O.all_owned_records(current,expected,current_nodes)

    def test_strict_active_command_validator_still_refuses_passive_punctuation(self):
        for name in LITERALS:
            with self.subTest(name=name),self.assertRaises(ValueError):O.safe(name)
        self.assertEqual(O.safe('fixture/main.rs'),'fixture/main.rs')
        writer=(HERE/'prepare_image.py').read_text()
        self.assertIn('O.safe(name)  # Active debugfs script operands',writer)


if __name__=='__main__':unittest.main()
