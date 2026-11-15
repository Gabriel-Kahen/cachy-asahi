# SPDX-License-Identifier: MIT
"""FENCED bootstrap DATA controls; no GPG, network, image, native or child role."""
import hashlib
from types import SimpleNamespace
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import time
import unittest

HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('bootstrap_DATA',HERE/'payload/hosted/bootstrap.py');B=importlib.util.module_from_spec(s);s.loader.exec_module(B)


class Controls(unittest.TestCase):
    def archive(self,base,rows):
        path=base/'FENCED.tar'
        with tarfile.open(path,'w') as out:
            for name,data,kind in rows:
                item=tarfile.TarInfo(name);item.mode=0o755 if kind=='dir' else 0o644
                if kind=='dir':item.type=tarfile.DIRTYPE;out.addfile(item)
                elif kind=='link':item.type=tarfile.SYMTYPE;item.linkname=data;out.addfile(item)
                else:item.size=len(data);out.addfile(item,io.BytesIO(data))
        return path
    def test_normal_install_preserves_signature_required_and_real_prefix(self):
        raw=B.normal_dockerfile('rust199-base:'+'a'*24,'B'*40).decode()
        for phrase in ('--network','--privileged','SigLevel = Never','--dbonly','--nodeps','ln -s'):
            self.assertNotIn(phrase,raw)
        for phrase in ('pacman --gpgdir','-U --noconfirm --noscriptlet','--import-ownertrust','test ! -L /opt/cachy-asahi/llvm23-source-reference','gpgconf','USER alarm'):
            self.assertIn(phrase,raw)
        for tag,fingerprint in (('other','B'*40),('rust199-base:'+'a'*24,'$(shell)')):
            with self.assertRaises(ValueError):B.normal_dockerfile(tag,fingerprint)
    def test_gpg_primary_key_and_validsig_match_only_one_TEST_key(self):
        row='pub:::::::::\nfpr:::::::::'+'A'*40+':\n';self.assertEqual(B.fingerprint(row.encode()),'A'*40)
        with self.assertRaises(ValueError):B.fingerprint((row+row).encode())
        good=('[GNUPG:] VALIDSIG '+'A'*40+' 2026 0 0 4 0 1 8 00 '+'A'*40+'\n').encode();B.signature_status(good,'A'*40)
        for bad in (good+b'[GNUPG:] BADSIG x\n',good+good,good.replace(b'A',b'B')):
            with self.assertRaises(ValueError):B.signature_status(bad,'A'*40)
    def test_rootfs_data_modes_links_hash_and_no_execution(self):
        with tempfile.TemporaryDirectory(prefix='FENCED-rootfs-DATA-')as temporary:
            base=Path(temporary);archive=self.archive(base,[('opt',b'','dir'),('opt/data',b'FENCED DATA','file'),('link','opt/data','link')]);root=base/'root'
            result=B.extract_rootfs(archive,root,time.monotonic()+2);self.assertEqual(result['files'],3);self.assertEqual((root/'opt/data').read_bytes(),b'FENCED DATA');self.assertEqual((root/'opt').stat().st_mode&0o777,0o755)
            before=B.tree_digest(root);(root/'opt/data').write_bytes(b'changed');self.assertNotEqual(before,B.tree_digest(root))
    def test_rootfs_escape_duplicate_and_special_nodes_refused(self):
        for rows in ([('../outside',b'bad','file')],[('/outside',b'bad','file')],[('same',b'a','file'),('same',b'b','file')]):
            with tempfile.TemporaryDirectory(prefix='FENCED-rootfs-refusal-')as temporary:
                base=Path(temporary);archive=self.archive(base,rows)
                with self.assertRaises(ValueError):B.extract_rootfs(archive,base/'root',time.monotonic()+2)
    def test_large_leaf_copy_and_tree_hash_observe_chunk_cancellation(self):
        with tempfile.TemporaryDirectory(prefix='FENCED-chunk-DATA-')as temporary:
            base=Path(temporary);archive=self.archive(base,[('large',b'x'*(3*1024**2),'file')]);calls=[]
            def cancel():
                calls.append(None)
                if (base/'root/large').exists() and (base/'root/large').stat().st_size>=1024**2:raise ValueError('FENCED cancellation')
            with self.assertRaisesRegex(ValueError,'FENCED cancellation'):B.extract_rootfs(archive,base/'root',time.monotonic()+2,cancel)
            self.assertLess((base/'root/large').stat().st_size,3*1024**2)
            (base/'hash').mkdir();(base/'hash/large').write_bytes(b'x'*(3*1024**2));calls.clear()
            def cancel_hash():
                calls.append(None)
                if len(calls)==4:raise ValueError('FENCED hash cancellation')
            with self.assertRaisesRegex(ValueError,'FENCED hash cancellation'):B.tree_digest(base/'hash',cancel_hash)
            self.assertEqual(len(calls),4)
    def test_raw_tar_metadata_headers_sparse_and_termination_are_bounded(self):
        with tempfile.TemporaryDirectory(prefix='FENCED-tar-raw-')as temporary:
            base=Path(temporary);normal=self.archive(base,[('data',b'FENCED','file')]).read_bytes()
            for index,raw in enumerate((normal+b'NONZERO_TRAILING',normal[:1024])):
                path=base/f'bad-{index}.tar';path.write_bytes(raw)
                with self.assertRaises((ValueError,tarfile.TarError)):B.extract_rootfs(path,base/f'root-{index}',time.monotonic()+2)
            for index,kind in enumerate((tarfile.XHDTYPE,tarfile.GNUTYPE_LONGNAME,tarfile.GNUTYPE_SPARSE)):
                info=tarfile.TarInfo('FENCED');info.type=kind;info.size=65537 if kind!=tarfile.GNUTYPE_SPARSE else 0
                path=base/f'meta-{index}.tar';path.write_bytes(info.tobuf()+bytes(512))
                with self.assertRaises((ValueError,tarfile.TarError)):B.extract_rootfs(path,base/f'meta-root-{index}',time.monotonic()+2)
            path=self.archive(base,[('a',b'a','file'),('b',b'b','file')]);info,state=B.bounded_info(1)
            with self.assertRaises(ValueError):
                with tarfile.open(path,'r|',tarinfo=info)as archive:list(archive)
    def test_provider_image_ownership_requires_actual_bootstrap_phase(self):
        provider=dict(schema=4,status='ACTUAL_PROVIDER_BINDING_ONLY',phase='bootstrap',run_attempt=1,manual_dispatch=True,source=dict(sha='a'*40,ref='refs/heads/codex/FENCED',run='1',job='2',map_sha256='b'*64,approval='c'*64))
        source=B.provider_source(provider);own=B.owner(source);self.assertTrue(own['tag'].startswith('rust199-qualified:'))
        with self.assertRaises(ValueError):B.provider_source(dict(provider,phase='build'))
        image='sha256:'+'d'*64;row=dict(Id=image,Os='linux',Architecture='arm64',Config=dict(Labels={B.LABEL:own['token'],B.LABEL+'.source':own['source']}));B.inspect_image(row,image,own)
        row['Config']['Volumes']={'/unexpected':{}}
        with self.assertRaises(ValueError):B.inspect_image(row,image,own)
    def test_retirement_recovers_only_exact_owned_image_tag_after_uncertain_build(self):
        provider=dict(schema=4,status='ACTUAL_PROVIDER_BINDING_ONLY',phase='bootstrap',run_attempt=1,manual_dispatch=True,source=dict(sha='a'*40,ref='refs/heads/codex/FENCED',run='1',job='2',map_sha256='b'*64,approval='c'*64))
        own=B.owner(B.provider_source(provider));image='sha256:'+'d'*64
        for foreign in (False,True):
            with tempfile.TemporaryDirectory(prefix='FENCED-retirement-DATA-') as temporary:
                work=Path(temporary);removed=[];present=[image]
                def command(argv,**kwargs):
                    args=argv[len(B.DOCKER):];stdout=b'';code=0;stderr=b''
                    if args[:2]==['container','ls']:pass
                    elif args[:2]==['image','ls']:
                        if 'reference='+own['base_tag'] in args or args[-1].startswith('label='):stdout=('\n'.join(present)).encode()
                    elif args[:2]==['image','inspect']:
                        if present:
                            labels={B.LABEL:own['token'],B.LABEL+'.source':own['source']}
                            if foreign:labels[B.LABEL]='FOREIGN'
                            stdout=json.dumps([dict(Id=image,Os='linux',Architecture='arm64',Config=dict(Labels=labels),RepoTags=[own['base_tag']])]).encode()
                        else:code=1;stderr=('Error response from daemon: No such image: '+image).encode()
                    elif args[:2]==['image','rm']:removed.append(args[-1]);present.clear()
                    else:raise AssertionError('unexpected DATA transition '+str(args))
                    return SimpleNamespace(returncode=code,stdout=stdout,stderr=stderr)
                if foreign:
                    with self.assertRaises(ValueError):B.retire(work,work,provider,dict(base_intent=True),command)
                    self.assertFalse(removed)
                else:
                    result=B.retire(work,work,provider,dict(base_intent=True),command);self.assertEqual(result['status'],'PASS_RETIRED');self.assertEqual(removed,[image])
    def test_final_retirement_recovers_exporter_after_native_deadline(self):
        provider=dict(schema=4,status='ACTUAL_PROVIDER_BINDING_ONLY',phase='bootstrap',run_attempt=1,manual_dispatch=True,source=dict(sha='a'*40,ref='refs/heads/codex/FENCED',run='1',job='2',map_sha256='b'*64,approval='c'*64))
        own=B.owner(B.provider_source(provider));image='sha256:'+'d'*64;name='rust199-rootfs-'+own['token'];cid='e'*64
        for foreign in (False,True):
            with tempfile.TemporaryDirectory(prefix='FENCED-exporter-retirement-')as temporary:
                alive=[name];removed=[]
                def command(argv,**kwargs):
                    args=argv[len(B.DOCKER):];out=b''
                    if args[:2]==['container','ls']:
                        if args[-1]=='name=^'+name+'$':out=('\n'.join(alive)).encode()
                    elif args[:2]==['container','inspect']:
                        labels={B.LABEL:'FOREIGN'if foreign else own['token'],B.LABEL+'.source':own['source']}
                        out=json.dumps([dict(Id=cid,Image=image,Config=dict(Labels=labels),Mounts=[],State=dict(Status='created'))]).encode()
                    elif args[:2]==['container','rm']:
                        self.assertEqual(args[-1],cid);alive.clear();removed.append(cid)
                    elif args[:2]==['image','inspect']:raise ValueError('FENCED omit image retirement')
                    elif args[:2]!=['image','ls']:raise AssertionError(args)
                    return SimpleNamespace(returncode=0,stdout=out,stderr=b'')
                with self.assertRaises(ValueError):B.retire(Path(temporary),Path(temporary),provider,dict(image=image,exporter_id=cid),command)
                self.assertEqual(removed,[]if foreign else[cid]);self.assertEqual(bool(alive),foreign)
    def test_missing_accepted_llvm_gate_cannot_start_bootstrap(self):
        text=(HERE/'payload/hosted/bootstrap.py').read_text()
        self.assertLess(text.index("gate.validate_llvm_material(plan['llvm']"),text.index("base,baseline=build_base("))
        self.assertIn("'--network=none','--pull=false'",text)
        self.assertIn("cap==16*1024**3",text)


if __name__=='__main__':unittest.main()
