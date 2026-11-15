# SPDX-License-Identifier: MIT
"""FENCED synthetic tar/XZ DATA only; never read/extract real stage0 archives."""
import copy
import hashlib
import importlib.util
import io
import json
import lzma
import os
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('fenced_stage0_data',HERE/'stage0.py')
s = importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(s)


def encoded(value):return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
def checksum(body):return hashlib.sha256(body).hexdigest()


def synthetic_elf(ordinal):
    raw = bytearray(64);raw[:6] = b'\x7fELF\x02\x01'
    struct.pack_into('<HH',raw,16,3,183);struct.pack_into('<Q',raw,24,ordinal)
    struct.pack_into('<Q',raw,32,64);struct.pack_into('<HH',raw,54,56,1)
    return bytes(raw)+struct.pack('<IIQQQQQQ',1,5,0,0,0,120,120,16384)


def archive_bytes(entries,tail=b''):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw,mode='w',format=tarfile.GNU_FORMAT) as archive:
        for entry in entries:
            item = tarfile.TarInfo(entry['path']);item.mode = entry['mode']
            if entry['kind'] == 'dir':item.type = tarfile.DIRTYPE;archive.addfile(item)
            elif entry['kind'] == 'file':
                body = entry['body'];item.size = len(body);archive.addfile(item,io.BytesIO(body))
            elif entry['kind'] == 'link':
                item.type = tarfile.SYMTYPE;item.linkname = '/outside';archive.addfile(item)
            elif entry['kind'] == 'sparse':
                item.type = tarfile.GNUTYPE_SPARSE;archive.addfile(item)
    return lzma.compress(raw.getvalue()+tail,format=lzma.FORMAT_XZ,preset=0)


class Fixture:
    """Nonofficial tiny corpus with14 synthetic ELF headers and12 notice copies."""
    def __init__(self,root):
        self.root,self.materials,self.data = root,root/'materials',root/'data'
        self.materials.mkdir();self.data.mkdir();(self.data/'records').mkdir()
        self.spec = {'archives':{},'model':{},'notices':{}}
        self.entries = {};self.records = {};model = {};file_bytes = 0;ordinal = 0
        roles = [('cargo','cargo',5),('rustc','rustc',8),('std','rust-std-aarch64-unknown-linux-gnu',1)]
        for label,component,count in roles:
            archive = 'FENCED-'+label+'.tar.xz';prefix = 'FENCED-'+label
            entries = [{'path':prefix,'kind':'dir','mode':0o755},{'path':prefix+'/'+component,'kind':'dir','mode':0o755}]
            subdir = 'lib' if label == 'std' else 'bin'
            entries += [{'path':prefix+'/'+component+'/'+subdir,'kind':'dir','mode':0o755}]
            facts = {}
            for index in range(count):
                ordinal += 1;body = synthetic_elf(ordinal)
                # Exercise GNU long-name metadata using one>100-byte member.
                leaf = label+str(index)+('-'*110 if label == 'cargo' and index == 0 else '')
                member = prefix+'/'+component+'/'+subdir+'/'+leaf
                entries.append({'path':member,'kind':'file','mode':0o755,'body':body})
                facts[member] = dict(elf_class=64,endianness='little',machine=183,type=3,load_segments_16k_congruence_and_alignment=True,program_headers=[dict(type=1,flags=5,offset=0,vaddr=0,filesz=len(body),memsz=len(body),align=16384)])
            entries.append({'path':prefix+'/'+component+'/manifest.in','kind':'file','mode':0o644,'body':b'FENCED manifest only\n'})
            entries.append({'path':prefix+'/install.sh','kind':'file','mode':0o755,'body':b'FENCED INSTALLER MUST NEVER EXECUTE\n'})
            for index in range(4):
                body = (label+' FENCED notice '+str(index)+'\n').encode();member = prefix+'/NOTICE'+str(index)
                source = 'records/notices/'+prefix+'/NOTICE'+str(index)
                entries.append({'path':member,'kind':'file','mode':0o644,'body':body,'retained_data_path':source})
                target = self.data/source;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(body)
                self.spec['notices'][source] = dict(bytes=len(body),sha256=checksum(body),target='share/licenses/retained-stage0/'+prefix+'/NOTICE'+str(index))
            records = []
            for entry in entries:
                row = {k:v for k,v in entry.items() if k != 'body'};row['bytes'] = len(entry.get('body',b''))
                if row['kind'] == 'file':row['sha256'] = checksum(entry['body'])
                records.append(row)
                base = prefix+'/'+component+'/'
                if row['path'].startswith(base) and row['path'] != base+'manifest.in':
                    name = row['path'][len(base):];node = dict(kind=row['kind'],mode=row['mode'],content=row.get('sha256',''))
                    if name not in model and row['kind'] == 'file':file_bytes += row['bytes']
                    model[name] = node
            inventory = 'records/'+archive+'.inventory.json';elf = 'records/'+archive+'.elf.json'
            (self.data/inventory).write_bytes(encoded(records));(self.data/elf).write_bytes(encoded(facts))
            self.entries[archive] = entries;self.records[archive] = records
            self.spec['archives'][archive] = dict(bytes=0,sha256='',root=prefix,component=component,inventory=inventory)
            self.repack(archive)
        (self.data/'records/component-prefix-model.json').write_bytes(encoded(model))
        self.spec['model'] = dict(file='records/component-prefix-model.json',nodes=len(model),files=sum(n['kind']=='file' for n in model.values()),file_bytes=file_bytes,tree_sha256=s.tree_digest(model))
    def repack(self,archive,entries=None,tail=b'',compressed_tail=b''):
        body = archive_bytes(entries if entries is not None else self.entries[archive],tail)+compressed_tail
        (self.materials/archive).write_bytes(body)
        self.spec['archives'][archive].update(bytes=len(body),sha256=checksum(body))
    def write_records(self,archive):
        (self.data/self.spec['archives'][archive]['inventory']).write_bytes(encoded(self.records[archive]))


class FencedDataControls(unittest.TestCase):
    def test_complete_synthetic_join_and_assembly_modes(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Fixture(Path(tmp));plan = s.verify_specs(f.data,f.spec)
            self.assertEqual(plan['summary']['elf_files'],14)
            self.assertEqual(plan['summary']['compatibility'],'UNQUALIFIED')
            destination = f.root/'prefix'
            result = s.assemble(f.materials,destination,f.data,f.spec)
            self.assertEqual(result['component']['tree_sha256'],f.spec['model']['tree_sha256'])
            self.assertEqual(result['notice_files'],12)
            self.assertFalse(result['installer_execution'])
            self.assertEqual((destination/'bin/rustc0').stat().st_mode & 0o777,0o755)
            self.assertEqual(next((destination/'share/licenses/retained-stage0').rglob('NOTICE0')).stat().st_mode & 0o777,0o644)
            self.assertFalse((destination/'install.sh').exists())
            self.assertFalse((destination/'manifest.in').exists())
            self.assertEqual(destination.stat().st_mode & 0o777,0o755)
            with self.assertRaisesRegex(ValueError,'fresh absent'):
                s.assemble(f.materials,destination,f.data,f.spec)

    def test_source_guard_refuses_before_prefix_and_wraps_completed_assembly(self):
        with tempfile.TemporaryDirectory() as tmp:
            f=Fixture(Path(tmp));destination=f.root/'prefix'
            def refuse():raise ValueError('FENCED reserve exhausted')
            with self.assertRaisesRegex(ValueError,'reserve exhausted'):
                s.assemble(f.materials,destination,f.data,f.spec,guard=refuse)
            self.assertFalse(destination.exists())
            calls=[]
            s.assemble(f.materials,destination,f.data,f.spec,guard=lambda:calls.append(True))
            self.assertGreaterEqual(len(calls),2)

    def test_changed_material_refuses_before_destination_allocation(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Fixture(Path(tmp));archive = next(iter(f.entries))
            (f.materials/archive).write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError,'exact local archive identity'):
                s.assemble(f.materials,f.root/'prefix',f.data,f.spec)
            self.assertFalse((f.root/'prefix').exists())

    def test_skipped_installer_bytes_are_still_hashed(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Fixture(Path(tmp));archive = next(iter(f.entries));entries = copy.deepcopy(f.entries[archive])
            next(e for e in entries if e['path'].endswith('/install.sh'))['body'] = b'FENCED INSTALLER MUST NEVER EXECUTX\n'
            f.repack(archive,entries)
            with self.assertRaisesRegex(ValueError,'checksum differs'):
                s.assemble(f.materials,f.root/'prefix',f.data,f.spec)
            self.assertFalse((f.root/'prefix/install.sh').exists())

    def test_extra_missing_duplicate_link_sparse_and_escape_members(self):
        for change in ('extra','missing','duplicate','link','sparse','escape'):
            with self.subTest(change=change),tempfile.TemporaryDirectory() as tmp:
                f = Fixture(Path(tmp));archive = next(iter(f.entries));entries = copy.deepcopy(f.entries[archive])
                if change == 'extra':entries.append(dict(path='FENCED-cargo/extra',kind='file',mode=0o644,body=b'FENCED'))
                elif change == 'missing':entries.pop()
                elif change == 'duplicate':entries.append(copy.deepcopy(entries[0]))
                elif change == 'escape':entries.append(dict(path='FENCED-cargo/../outside',kind='file',mode=0o644,body=b'FENCED'))
                else:next(e for e in entries if e['kind'] == 'file')['kind'] = change
                f.repack(archive,entries)
                with self.assertRaises((ValueError,tarfile.TarError)):
                    s.assemble(f.materials,f.root/'prefix',f.data,f.spec)
                self.assertFalse((f.root/'outside').exists())

    def test_xz_concatenation_and_tar_tail_refuse(self):
        for style in ('xz','garbage','tar'):
            with self.subTest(style=style),tempfile.TemporaryDirectory() as tmp:
                f = Fixture(Path(tmp));archive = next(iter(f.entries))
                f.repack(archive,tail=b'FENCED EXTRA TAR' if style == 'tar' else b'',compressed_tail=lzma.compress(b'FENCED EXTRA XZ',preset=0) if style == 'xz' else b'GARBAGE' if style == 'garbage' else b'')
                with self.assertRaisesRegex(ValueError,'tail|trailer|concatenated'):
                    s.assemble(f.materials,f.root/'prefix',f.data,f.spec)

    def test_model_elf_and_notice_identity_refusals_before_allocation(self):
        for change in ('model','elf','notice','notice-target'):
            with self.subTest(change=change),tempfile.TemporaryDirectory() as tmp:
                f = Fixture(Path(tmp));archive = next(iter(f.entries))
                if change == 'model':f.spec['model']['tree_sha256'] = 'f'*64
                elif change == 'elf':
                    file = f.data/('records/'+archive+'.elf.json');facts = json.loads(file.read_bytes());next(iter(facts.values()))['machine'] = 62;file.write_bytes(encoded(facts))
                elif change == 'notice':(f.data/next(iter(f.spec['notices']))).write_text('changed')
                else:
                    rows = list(f.spec['notices'].values());rows[1]['target'] = rows[0]['target']+'/child'
                with self.assertRaises(ValueError):s.assemble(f.materials,f.root/'prefix',f.data,f.spec)
                self.assertFalse((f.root/'prefix').exists())

    def test_nonidentical_component_collision_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Fixture(Path(tmp));archive = 'FENCED-rustc.tar.xz';base = 'FENCED-rustc/rustc/'
            row = next(r for r in f.records[archive] if r['path'].startswith(base+'bin/') and r['kind'] == 'file')
            row['path'] = base+'bin/cargo0'+'-'*110
            f.write_records(archive)
            with self.assertRaisesRegex(ValueError,'nonidentical component collision'):
                s.verify_specs(f.data,f.spec)

    def test_truncated_tar_and_xz_refuse(self):
        for style in ('tar','xz'):
            with self.subTest(style=style),tempfile.TemporaryDirectory() as tmp:
                f = Fixture(Path(tmp));archive = next(iter(f.entries));p = f.materials/archive
                original = p.read_bytes()
                body = original[:-12] if style == 'xz' else lzma.compress(lzma.decompress(original)[:800],preset=0)
                p.write_bytes(body);f.spec['archives'][archive].update(bytes=len(body),sha256=checksum(body))
                with self.assertRaises((ValueError,tarfile.TarError,lzma.LZMAError,EOFError)):
                    s.assemble(f.materials,f.root/'prefix',f.data,f.spec)

    def test_symlink_fifo_and_ambiguous_namespace_refusals(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp);(root/'file').write_text('FENCED');(root/'link').symlink_to('file');os.mkfifo(root/'fifo')
            for p in (root/'link',root/'fifo'):
                with self.assertRaises(ValueError):s.pin(p)
        for candidate in ('../escape','root/../../escape','/absolute','root//file','root/./file','root\\file'):
            with self.assertRaises(ValueError):s.name(candidate)


if __name__ == '__main__':
    unittest.main()
