# SPDX-License-Identifier: MIT
"""Synthetic package/ELF DATA controls; no archive payload is executed/extracted."""
import base64
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
import zlib

sys.dont_write_bytecode = True
HERE = Path(__file__).absolute().parent
sys.path.insert(0, str(HERE))
import assemble as A

# Exact immutable Git50d506 native/expected349.lock DATA, not a generated substitute.
LOCK_Z85 = 'c-oCw*^;9;)4i{!@O=dYo40wH2>}AD&DN6eQcwS#lLG9XnZN44=x8fbNU6+|YpK#{(?!)Z?Xo00B&YNkCsFpHs&1FX1%9U=s=h1ZRaDK^jn?h<=^x}~9Q;DeHlnG<A@Ud9>wj*4aiUJQs(S8<L!3qVhw4;ijrY%85{nf0=J%|6WzC>T+s7$swz_m?m><zqKf!8);OFH0&Q!L4=NCzlo++M>++?z-8m-3r4p}(Td&^b0bFPiw74gEF{Rn{@u#fq&?$uTA(m0h1Z|Y)p>0e2Fw$&blQaQcL@f`k$YJJn)F2&7QUUvI9k279U>Y=*eWmlYYj`!q4YHvD6tsg$^G5KuM{XRXNv`Q0o<Tu8R!!D0c(AMdr97pG)&XkTvWFmTLO?&Z!cCPXrG)9F%5Igz~GRDiMxhy+<w`!tJ^FaGDQ-&Q$e2NYq6-=$IH;t*3*DmPqke;ydAFQY!zf9LDNR{U4fAE(ly&qugNada41DB%90zfOcf>pv7=Qz!vlxi{~6q4@o3_!Go%xSzoL1wJ&bMj968OViB<nY;cJE$i-v{tvY=6*T5E}{HjfKznDa;D-^LNAq71U+4~-Q`Cd{zi!A!2sVc^7~q#u>ic*<=kq52e&}@S~qI${N^^f>~U8=PElhzy(lN4K;+y^rK4U=lO`CGJTByvOEpz^2CXTgnx+XK=0QjGeD!J~n&~sg51ln`vSZ8V6-Rly?wa+k^h~wuM|3lAf__q7<kAoR%78__q=8ZFIC|hZjq{^;Cnd(i3d+jg?&-YlX<DExp(vyeb-1XA)1Z{b0QLpW<t<I8AL3^PP{y!9^%*$mUl{?x=QdVr|D1G2vlrnjYf4iafoDobXx05nQN%&piWU#|w^g-+MPb%Yn`WPFo}{`=PL0aMHNjpS=9@irxq~Qa_(>J@aJm<zrym_4Xj@;S$vn!rp{PY60Bp7Q`r&sW7Ph9rbvs_hr?pr_gZB5)UKy5By!xDomdN5USf<Oe;;H$k%^>3`KV<q;=`<-bImmTN4uFN@{E#naJS#Kct4wgx_7iT-#Z}s2=G|SI4C0GvCe8}-)Jl{;hfQ8kg|{+(wZLKH$5BGks(`8OwOk=LPNIzjz_a-&ZuKdvQ*{6aTSS+O@j3vA{)^pKPb+3yJ2nl!ErP6YV-J<MX!Q?QAwj4u)x0(Y*!_!-SmQ%f3Cn9VBU*SJvQ4G19kLX>Fbx}WtaGmSBG62D=R}zB5f6DB<-RD}l=Iiu4sZ+^;(|lF(Z1(6e0LH~d%3G8JumFMLkI<KA^5yJCmW&xKcJeALJR7u+!C@2A;QEp35-xLN(4!_xbe<uK{x<}dm+$nS45&@6&bWG1O%m%bT^i==aMIk8dRix74qppT+LMT?syV6G=rIxbqG!cgD5EoGqZ=Q9v48E$t&a*CuSEIk+$W4eR4>sQRFc=7EH}78xa3X4UX9@TeJMH(zJX4v+(KTm!lOWe38c$eS{`T#PLXC4a028^|h?|Y49%80YQco+Q^}@Yd_YzJgDJn%RP}8yr!#qC!yyoQgm7kl4nLaSxBa2kzsCHT;;rwoEp9hE3(DSY7mSi3k9WwsebsZoaiXW^_xmD-5pQcDiX_|C7Y7cjdKmV+)S-4tzE2A3ubG9=KA$KIf=bRC`v%8m1evnND!ih;H}XDwzOFG=t=;b#ru`ebc)W-$QUTbO`Up1W@tvi*Lu9|CEld@a+ah^!P`E~{?1ofwGmq_Um<;MnTyM5d^{zurwneS+>kv9hGP5VrUwBJL70)!G)4@zY+&|54aSdF8~%_zWCyXpZ?brKK--Mg+aHbJcDJEk>?k6)$h|*(GqsVn7P^Km7R9tPUz+8oaEhr1qBUPFY6f^4w&&UUPUE_@!ocd+q}#~Pwj800Op+9-5AI2~Z?3LXJ8|H!?&<)#ZT&OYS=LS0HmdD7nStIPuIh(Q^7wvPPL%+1IT*<irG?k_Z$#DsYOStfpq1TV1FHM09Fc`1hQ`a8AtaH264*;Md)z!N(DGM?5Sp)K8w!|})JcNcmX19T1C-n}mcM=i$b{?>!ftk0y<@7RYF+9fAsAIvDALz>Mw*$l1Y<_d!-~j>Ngm7ny0%2VB#Gs*Q!sD3Dir-v-7A0jK~C##q3SwpYI90nn-VK~A?S();?@@hlGQ$3c-lT3XK41#wVb<T;lU~L8wtLyK0kjDiD|uO`Teptay?$$Abn53?AAzv<CPmyW{(%;qKqWfd?lbx#*X7ErZ-l=w)qNEWOy8kto*ZuI8~Xb_4A)GK9~QGJ%e#xnoz<#TZwlg(I6yNQd}vRUWK0-&Gy-fyc=4o5J$5RmG26sVI8(1{I1JsiJ9^V!8CPqUuqiwv%LC|rn@CK%f5%2Lt(wh_NXMQZu#ax42+Jo9COKWrAi<ymYzf?p{`+<nXjaq4<=dGHG270I_K@2y064JR{TCf^_*`T8uLJ%a1eiAD2Uvd_~m(}c!`1Q(!6W-f!Tq@y>iKtKpxj}t?StUXaAr^K}UaZr2APrXp;Ia3&qNk2Oh`)wUw;2UnzR1Mf>NMcHO0Kkao1ZaTU=^?YgDY$D=tNZvDHSmU1**Zmaa**1r6>#C8ru6f2WMA@x|AyvUP@E?P-Ju=)e(jj{b*aS$Q{l=Sc~PNe$!du}_;-)%s3Y)ALa4)oZn7BK&xTPkDi{M{J_sl5A!-=oSveRBO~%Yb^xsBbome91R_3-yk}cN?_ozL&w9Z<zOsz~+5Jck4qtn{6?(|Jwl?95%4I3A2r^M@vf(=7O(Tp>+;5Hh%95X{5z<z6!}cQZ&OEzhv@~AQ|*Uh+d3F+q{MyL$94;8;gqsnOFy>3X!Wvn`^wxaEee~zbFx6-m@GZbcBOQ(@!WYO|Lo}pM>M5#>ya0KJ`nDCqB{7OD{slXY3f%Fk))NodZLW1P%7-C>f%yi)HZz0;gkexN~6pjxVCSpq6;`FT4o5&G1XD(E!Vdxm8lgI6>7IZa`m$DcuMxAwur|S1~XtjJpQ7AOo&F$L+qT&qYdA1y<A>)_WatMzHkC?4@+f<&0h?j7yJp5Yo_&BJw^YWsGvF3x{I-U72lK6zZG_IXt7(1+9)Izas=f)JCm_y4gOr@bn*b35Fhg1-|DT2b%dnp(k@Nwl*}*G=?IX`b7e-CdVeFSh=n@t|DlU<j*b6>tqy1=F?wf$eD&NC9EU=yY89HL$gTvQM}0H398&9C&Ihxj$>j3ehKsT!g(uU%azm0*TD&7RdYZ^l)H<n$9w2QlbGR?7l3MY4Quo|v@n@?47QK6#gL9|e#cR(R4Y)*`2$mBds~3^=Um49?wCCR(_Eay&Gphv9^;Am++kwSjZ*4{p=g+KAn+ct*J^R~KS&n-*4@H*`VR*Fzb(_f!0?K>2@zobfdQ4gDc}iH6;xTu{(dWc(Ux|o9UT9G8hpb~eHM8qJ-Y-5|0S~x0#SocltmJ>*x`kE@S-i!uZ)}N>8voHbh21Rb{;(R{Z6J{loU!?C_xuO1W<7*FCD$0_>Sob5uee`{<HMCkByP+%txch31_UOP9Y?UyL8OiMhGpK3q{g9-AFN$ETM2CW7y!H{n~l&UyM)=EO+DqejD@N%LnXf9yp;Km93+7IvR$qkI}Z_Z!Hm0!B}$~Ch<@XA`|ftmEt<H%*YdkEKH9&rk7qMk2i9tdSt9FDh@;_XOfa+yZEshgA=qc3Lrgbkr)uqd_2VMFq088KfVxJ!p|=m*ZdXwwEW{s{umPC^%wdBxu5a&f2f6y#Q'
LOCK_RAW = zlib.decompress(base64.b85decode(LOCK_Z85))
assert len(LOCK_RAW) == A.LOCK['bytes'] and A.digest(LOCK_RAW) == A.LOCK['sha256']


def elf(*, needed=(), soname=None, static=False):
    """Inert ELF structure based on adjacent auditor's synthetic fixture layout."""
    raw = bytearray(2048)
    raw[:16] = b'\x7fELF\x02\x01\x01' + b'\0' * 9
    strings, tags = bytearray(b'\0'), []
    for tag, value in [(1, s) for s in needed] + [(14, soname)]:
        if value is not None:
            tags.append((tag, len(strings)))
            strings.extend(value.encode() + b'\0')
    tags.extend([(5, 1024), (10, len(strings)), (0, 0)])
    table = b''.join(struct.pack('<qQ', *r) for r in tags)
    headers = [(1, 5, 0, 0, 0, len(raw), len(raw), 16384)]
    if not static:
        headers.append((2, 4, 512, 512, 0, len(table), len(table), 8))
        raw[512:512+len(table)] = table
        raw[1024:1024+len(strings)] = strings
    struct.pack_into('<HHIQQQIHHHHHH', raw, 16, 2 if static else 3, 183, 1, 128,
                     64, 0, 0, 64, 56, len(headers), 0, 0, 0)
    for index, row in enumerate(headers):
        struct.pack_into('<IIQQQQQQ', raw, 64 + index*56, *row)
    return bytes(raw)


def tar_rows(rows, *, compressed=False, fmt=tarfile.USTAR_FORMAT):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w:xz' if compressed else 'w', format=fmt) as archive:
        for row in rows:
            path, raw = row['path'], row.get('raw', b'')
            member = tarfile.TarInfo(path)
            member.type, member.mode = row.get('type', tarfile.REGTYPE), row.get('mode', 0o644)
            member.size = len(raw)
            member.linkname = row.get('linkname', '')
            member.pax_headers = row.get('pax', {})
            member.uid, member.mtime = row.get('uid', 0), row.get('mtime', 0)
            archive.addfile(member, io.BytesIO(raw) if member.isfile() else None)
    return stream.getvalue()


def row(path, raw=b'data', mode=0o644, **other):
    return dict(path=path, raw=raw, mode=mode, **other)


class AssemblyControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='synthetic-rootfs-assembler-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.out = self.root / 'output'

    def package(self, rows):
        package = A.Package(tar_rows(rows, compressed=True))
        self.addCleanup(package.close)
        return package

    def fixture_plan(self):
        lock = dict(line.split() for line in LOCK_RAW.decode().splitlines())
        plan = dict(schema=1, actual=None, lock=copy.deepcopy(A.LOCK), packages=[], files=[])
        sources = {
            'bubblewrap': [row('usr/bin/bwrap', elf(static=True), 0o755)],
            'mkinitcpio-busybox': [row('usr/lib/initcpio/busybox', elf(static=True), 0o755)],
            'python': [row('usr/bin/python3.14', elf(static=True), 0o755),
                       row('usr/bin/python3', type=tarfile.SYMTYPE, linkname='python3.14', raw=b''),
                       row('usr/lib/python3.14/encodings/__init__.py', b'# synthetic DATA\n'),
                       row('usr/lib/python3.14/os.py', b'raise AssertionError("must never execute recipe DATA")\n'),
                       row('usr/lib/python3.14/lib-dynload/_demo.so', elf(needed=('libdemo.so.1',)))],
            'glibc': [row('usr/lib/libdemo.so.1', elf(soname='libdemo.so.1'))]}
        for name, payload in sources.items():
            recipe_hash = A.digest(('SYNTHETIC_NOT_NATIVE:' + name).encode())
            metadata = {
                '.PKGINFO': ('pkgname = '+name+'\npkgver = '+lock[name]+'\narch = aarch64\nlicense = MIT\nurl = https://example.invalid/synthetic-data\n').encode(),
                '.BUILDINFO': ('format = 2\npkgname = '+name+'\npkgver = '+lock[name]+'\npkgarch = aarch64\npkgbuild_sha256sum = '+recipe_hash+'\n').encode(),
                '.MTREE': b'# SYNTHETIC_NOT_NATIVE metadata\n'}
            payload += [row('usr/share/licenses/'+name+'/LICENSE', b'Synthetic MIT notice\n')]
            raw = tar_rows([row(n, raw) for n, raw in metadata.items()] + payload, compressed=True)
            archive_path = self.root / (name + '.pkg.tar.xz')
            signature_path = self.root / (name + '.sig')
            archive_path.write_bytes(raw)
            signature_path.write_bytes(b'SYNTHETIC_NOT_AUTHENTICATED:' + name.encode())
            def pin(path):
                body = path.read_bytes()
                return dict(path=path.name, bytes=len(body), sha256=A.digest(body))
            descriptor = dict(name=name, version=lock[name], arch='aarch64', archive=pin(archive_path),
                signature=pin(signature_path), license=['MIT'], upstream_sources=['https://example.invalid/synthetic-data'],
                metadata={n:dict(bytes=len(raw), sha256=A.digest(raw)) for n, raw in metadata.items()},
                pkgbuild_sha256=recipe_hash, retained_provenance={})
            descriptor['retained_provenance'] = dict(name=name, version=lock[name], license=['MIT'],
                archive=dict(descriptor['archive'], path=str(archive_path)),
                signature=dict(descriptor['signature'], path=str(signature_path)),
                metadata_members=copy.deepcopy(descriptor['metadata']),
                recipe_identity_from_BUILDINFO=dict(pkgbuild_sha256sum=recipe_hash),
                evidence='SYNTHETIC_NOT_NATIVE_NOT_AUTHENTICATED')
            plan['packages'].append(descriptor)
            for item in payload:
                if item.get('type', tarfile.REGTYPE) != tarfile.REGTYPE:
                    continue
                path = 'busybox' if item['path'] == 'usr/lib/initcpio/busybox' else item['path']
                plan['files'].append(dict(path=path, package=name, member=item['path'], bytes=len(item['raw']),
                    sha256=A.digest(item['raw']), mode=item['mode']))
        python = next(r for r in plan['files'] if r['path'] == 'usr/bin/python3.14')
        plan['files'].append(dict(python, path='usr/bin/python3', member='usr/bin/python3'))
        return plan

    def main(self, plan):
        plan_path, lock_path = self.root / 'plan.json', self.root / 'lock'
        raw = A.json_bytes(plan)
        plan_path.write_bytes(raw)
        lock_path.write_bytes(LOCK_RAW)
        argv = ['assemble.py', '--plan', str(plan_path), '--plan-sha256', A.digest(raw),
                '--input-root', str(self.root), '--lock', str(lock_path), '--output', str(self.out)]
        out = io.StringIO()
        with mock.patch.object(sys, 'argv', argv), contextlib.redirect_stdout(out):
            A.main()
        return json.loads(out.getvalue())

    def test_deterministic_regular_tar_manifest_and_exact_inverse(self):
        files = {'usr/share/z':dict(raw=b'last', mode=0o644), 'busybox':dict(raw=b'first', mode=0o755),
                 'usr/share/empty':dict(raw=b'', mode=0o644)}
        raw, manifest = A.archive_bytes(files), A.manifest(files)
        self.assertEqual(A.archive_bytes(dict(reversed(list(files.items())))), raw)
        self.assertEqual(A.verify_archive(raw, manifest), files)
        with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
            members = archive.getmembers()
            self.assertEqual([m.name for m in members], sorted(files))
            self.assertTrue(all(m.type == tarfile.REGTYPE and not m.pax_headers for m in members))
            self.assertTrue(all((m.uid,m.gid,m.mtime,m.uname,m.gname)==(0,0,0,'','') for m in members))

    def test_traversal_absolute_noncanonical_and_reserved_output_paths_refuse(self):
        for path in ('../escape','/usr/a','usr/../a','usr//a','usr/./a','usr\\a','usr/a b',
                     'init','probe/tool','proc/a','dev/null','tmp/a','home/a','var/lib/pacman/local/a'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                A.archive_bytes({path:dict(raw=b'data',mode=0o644)})

    def test_output_links_special_duplicate_and_privileged_modes_refuse(self):
        description = A.manifest({'usr/file':dict(raw=b'data',mode=0o644)})
        bad = [row('usr/file', raw=b'', type=t, linkname='usr/target' if t in (tarfile.LNKTYPE,tarfile.SYMTYPE) else '')
               for t in (tarfile.LNKTYPE,tarfile.SYMTYPE,tarfile.FIFOTYPE,tarfile.CHRTYPE,tarfile.DIRTYPE)]
        bad += [row('usr/file',mode=0o4755), row('usr/file',mode=0o2644), row('usr/file',mode=0o600)]
        for item in bad:
            with self.subTest(item=item), self.assertRaises(ValueError):
                A.verify_archive(tar_rows([item]), description)
        with self.assertRaises(ValueError):
            A.verify_archive(tar_rows([row('usr/file'),row('usr/file')]), description)

    def test_pax_noncanonical_metadata_order_and_trailing_tar_refuse(self):
        files = {'usr/a':dict(raw=b'a',mode=0o644),'usr/z':dict(raw=b'z',mode=0o644)}
        description, valid = A.manifest(files), A.archive_bytes(files)
        raw_cases = [tar_rows([row('usr/a', b'a', pax={'comment':'not canonical'}),row('usr/z',b'z')],fmt=tarfile.PAX_FORMAT),
                     tar_rows([row('usr/z',b'z'),row('usr/a',b'a')]),
                     tar_rows([row('usr/a',b'a',uid=1),row('usr/z',b'z')]),
                     tar_rows([row('usr/a',b'a',mtime=1),row('usr/z',b'z')]), valid+b'\0'*512,valid+b'garbage',valid[:-512]]
        for raw in raw_cases:
            with self.subTest(length=len(raw)), self.assertRaises(ValueError):
                A.verify_archive(raw,description)

    def test_manifest_tamper_refuses_and_output_setuid_encoding_refuses(self):
        files = {'usr/a':dict(raw=b'a',mode=0o644)}
        raw, description = A.archive_bytes(files), A.manifest(files)
        for field,value in (('bytes',2),('sha256','0'*64),('mode',0o755)):
            changed = copy.deepcopy(description)
            changed['files']['usr/a'][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):A.verify_archive(raw,changed)
        for change in ({'schema':True},{'status':'QUALIFIED'},{'extra':0},{'files':{}}):
            changed = dict(description,**change)
            with self.assertRaises(ValueError):A.verify_archive(raw,changed)
        with self.assertRaises(ValueError):A.archive_bytes({'usr/a':dict(raw=b'a',mode=0o4755)})

    def test_input_pins_refuse_same_length_mutation_and_wrong_size_digest_path(self):
        source = self.root/'input'
        source.write_bytes(b'abcd')
        pin = dict(path='input',bytes=4,sha256=A.digest(b'abcd'))
        self.assertEqual(A.pinned(self.root,pin),b'abcd')
        source.write_bytes(b'abce')
        with self.assertRaisesRegex(ValueError,'pin mismatch'):A.pinned(self.root,pin)
        source.write_bytes(b'abcd')
        for changed in (dict(pin,bytes=3),dict(pin,sha256='0'*64),dict(pin,path='../input'),dict(pin,bytes=True)):
            with self.assertRaises(ValueError):A.pinned(self.root,changed)

    def test_input_symlink_ancestor_hardlink_and_fifo_refuse(self):
        source = self.root/'input';source.write_bytes(b'data')
        alias = self.root/'alias';alias.symlink_to(source)
        with self.assertRaisesRegex(ValueError,'symlink'):A.read_regular(alias,100)
        folder = self.root/'real';folder.mkdir();(folder/'data').write_bytes(b'data')
        linked = self.root/'linked';linked.symlink_to(folder,target_is_directory=True)
        with self.assertRaisesRegex(ValueError,'symlink'):A.read_regular(linked/'data',100)
        alias.unlink();os.link(source,alias)
        with self.assertRaisesRegex(ValueError,'unaliased'):A.read_regular(source,100)
        fifo = self.root/'fifo';os.mkfifo(fifo)
        with self.assertRaisesRegex(ValueError,'regular'):A.read_regular(fifo,100)

    def test_package_aliases_flatten_relative_absolute_and_hardlink_without_extraction(self):
        package = self.package([row('usr/lib/real',b'payload',0o755),
            row('usr/lib/relative',raw=b'',type=tarfile.SYMTYPE,linkname='real'),
            row('absolute',raw=b'',type=tarfile.SYMTYPE,linkname='/usr/lib/relative'),
            row('hard',raw=b'',type=tarfile.LNKTYPE,linkname='usr/lib/real')])
        with mock.patch.object(tarfile.TarFile,'extract',side_effect=AssertionError('host extraction prohibited')), mock.patch.object(tarfile.TarFile,'extractall',side_effect=AssertionError('host extraction prohibited')):
            for name in ('usr/lib/relative','absolute','hard'):
                self.assertEqual(package.resolve(name),(b'payload',0o755,'usr/lib/real'))
        self.assertEqual(list(self.root.iterdir()),[])

    def test_package_cycles_escaping_missing_links_privileged_and_special_refuse(self):
        for rows,name in (([row('a',raw=b'',type=tarfile.SYMTYPE,linkname='b'),row('b',raw=b'',type=tarfile.SYMTYPE,linkname='a')],'a'),
                          ([row('a',raw=b'',type=tarfile.SYMTYPE,linkname='../escape')],'a'),
                          ([row('a',raw=b'',type=tarfile.SYMTYPE,linkname='missing')],'a'),
                          ([row('a',mode=0o4755)],'a')):
            with self.subTest(rows=rows),self.assertRaises(ValueError):self.package(rows).resolve(name)
        for rows in ([row('../escape')],[row('a'),row('a')],[row('a',raw=b'',type=tarfile.FIFOTYPE)]):
            with self.assertRaises(ValueError):self.package(rows)

    def test_package_hidden_pax_global_pax_and_gnu_extensions_refuse(self):
        cases = [tar_rows([row('ordinary', pax={'comment':'hidden metadata'})], compressed=True, fmt=tarfile.PAX_FORMAT),
                 tar_rows([row('usr/'+'x'*160)], compressed=True, fmt=tarfile.GNU_FORMAT),
                 tar_rows([row('alias',raw=b'',type=tarfile.SYMTYPE,linkname='usr/'+'x'*160)], compressed=True, fmt=tarfile.GNU_FORMAT)]
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream,mode='w:xz',format=tarfile.PAX_FORMAT,pax_headers={'comment':'global metadata'}) as archive:
            member=tarfile.TarInfo('ordinary');member.size=4;archive.addfile(member,io.BytesIO(b'data'))
        cases.append(stream.getvalue())
        for raw in cases:
            with self.subTest(length=len(raw)),self.assertRaisesRegex(ValueError,'extended package metadata'):
                A.Package(raw)

    def test_end_to_end_synthetic_plan_uses_real_closure_and_regular_aliases(self):
        plan = self.fixture_plan()
        with mock.patch.object(subprocess,'Popen',side_effect=AssertionError('process prohibited')), mock.patch.object(socket,'socket',side_effect=AssertionError('network prohibited')), mock.patch.object(tarfile.TarFile,'extractall',side_effect=AssertionError('host extraction prohibited')):
            result = self.main(plan)
        self.assertEqual(result['status'],'ASSEMBLED_STATIC_DATA_ONLY')
        self.assertIsNone(result['actual'])
        manifest = json.loads((self.out/'guest-rootfs.json').read_bytes())
        files = A.verify_archive((self.out/'guest-rootfs.tar').read_bytes(),manifest)
        self.assertEqual(files['usr/bin/python3'],files['usr/bin/python3.14'])
        report = json.loads((self.out/'assembly-report.json').read_bytes())
        self.assertEqual(report['elf_audit']['status'],'PASS_STATIC_AARCH64_ELF_DEPENDENCY_CLOSURE')
        self.assertEqual(report['runtime'],'NOT_RUN')
        self.assertEqual(report['signature_authentication'],'NOT_RUN')
        self.assertEqual(report['file_custody']['usr/bin/python3']['member'],'usr/bin/python3.14')

    def test_full_stdlib_or_license_omission_refuses_before_output(self):
        plan = self.fixture_plan()
        for name in ('usr/lib/python3.14/os.py','usr/lib/python3.14/lib-dynload/_demo.so','usr/share/licenses/glibc/LICENSE'):
            changed = copy.deepcopy(plan)
            changed['files'] = [r for r in changed['files'] if r['path'] != name]
            with self.subTest(path=name), self.assertRaisesRegex(ValueError,'missing full stdlib or package license'):
                self.main(changed)
            self.assertFalse(self.out.exists())

    def test_missing_extension_dependency_refuses_before_any_output(self):
        plan = self.fixture_plan()
        plan['files'] = [r for r in plan['files'] if r['path'] != 'usr/lib/libdemo.so.1']
        with self.assertRaisesRegex(ValueError,'libdemo.so.1'):self.main(plan)
        self.assertFalse(self.out.exists())

    def test_source_and_retained_provenance_tamper_refuse_before_output(self):
        original = self.fixture_plan()
        for kind in ('archive','signature'):
            changed=copy.deepcopy(original)
            changed['packages'][0]['retained_provenance'][kind]['sha256']='0'*64
            with self.subTest(kind=kind),self.assertRaisesRegex(ValueError,'retained provenance input mismatch'):
                self.main(changed)
            self.assertFalse(self.out.exists())
        changed=copy.deepcopy(original)
        changed['packages'][0]['upstream_sources']=['https://example.invalid/different-source']
        with self.assertRaisesRegex(ValueError,'PKGINFO identity/source mismatch'):self.main(changed)
        self.assertFalse(self.out.exists())

    def test_repinned_buildinfo_identity_mismatch_refuses_before_output(self):
        plan=self.fixture_plan();descriptor=plan['packages'][0]
        path=self.root/descriptor['archive']['path'];rows=[]
        with tarfile.open(fileobj=io.BytesIO(path.read_bytes()),mode='r:xz') as archive:
            for member in archive:
                with archive.extractfile(member) as stream:body=stream.read()
                if member.name=='.BUILDINFO':
                    body=body.replace(b'pkgname = bubblewrap\n',b'pkgname = wrong-package\n')
                    descriptor['metadata']['.BUILDINFO']=dict(bytes=len(body),sha256=A.digest(body))
                    descriptor['retained_provenance']['metadata_members']['.BUILDINFO']=copy.deepcopy(descriptor['metadata']['.BUILDINFO'])
                rows.append(row(member.name,body,member.mode))
        raw=tar_rows(rows,compressed=True);path.write_bytes(raw)
        descriptor['archive'].update(bytes=len(raw),sha256=A.digest(raw))
        descriptor['retained_provenance']['archive'].update(bytes=len(raw),sha256=A.digest(raw))
        with self.assertRaisesRegex(ValueError,'BUILDINFO recipe pin'):self.main(plan)
        self.assertFalse(self.out.exists())

    def test_aggregate_compressed_and_expanded_input_caps_refuse_before_output(self):
        plan=self.fixture_plan()
        compressed=sum(row['archive']['bytes'] for row in plan['packages'])
        expanded=[]
        for descriptor in plan['packages']:
            package=A.Package((self.root/descriptor['archive']['path']).read_bytes())
            try:expanded.append(package.expanded)
            finally:package.close()
        self.assertGreater(sum(expanded)-1,max(expanded))
        with mock.patch.object(A,'MAX_TOTAL',compressed-1),self.assertRaisesRegex(ValueError,'aggregate compressed input cap'):
            self.main(plan)
        self.assertFalse(self.out.exists())
        with mock.patch.object(A,'MAX_EXPANDED',sum(expanded)-1),self.assertRaisesRegex(ValueError,'aggregate expanded input cap'):
            self.main(plan)
        self.assertFalse(self.out.exists())

    def headless_fixture(self):
        gui='usr/lib/python3.14/lib-dynload/_tkinter.cpython-314-aarch64-linux-gnu.so'
        excluded_raw=elf(needed=('libtk8.6.so','libtcl8.6.so'))
        package=self.package([row(gui,excluded_raw),row('usr/lib/python3.14/os.py',b'# retained module DATA\n')])
        files={
            'busybox':dict(raw=elf(static=True),mode=0o755),
            'usr/lib/python3.14/os.py':dict(raw=b'# retained module DATA\n',mode=0o644),
            'usr/lib/python3.14/lib-dynload/_demo.so':dict(raw=elf(needed=('libdemo.so.1',)),mode=0o644),
            'usr/lib/libdemo.so.1':dict(raw=elf(soname='libdemo.so.1'),mode=0o644)}
        for path in ('encodings/__init__.py','encodings/utf_8.py','codecs.py','io.py','abc.py','site.py','_sitebuiltins.py'):
            files['usr/lib/python3.14/'+path]=dict(raw=b'# synthetic bootstrap DATA\n',mode=0o644)
        probe=self.root/'finite_probe.py'
        probe.write_bytes(b'import os, sys\nraise AssertionError("probe source must not execute")\n')
        profile=dict(name='finite-headless-namespace-v1',
            excluded=[dict(path=gui,package='python',member=gui,bytes=len(excluded_raw),sha256=A.digest(excluded_raw),mode=0o644,reason='Explicit synthetic finite GUI exclusion')],
            probe_sources=[dict(path=probe.name,bytes=probe.stat().st_size,sha256=A.digest(probe.read_bytes()))],
            required_modules=['os','sys'])
        return profile,{'python':package},files,probe

    def test_headless_exact_gui_exclusion_keeps_all_included_elf_dependencies_strict(self):
        profile,packages,files,_=self.headless_fixture();before=copy.deepcopy(files)
        excluded,report=A.headless_profile(profile,self.root,packages,files)
        self.assertEqual(set(excluded),{profile['excluded'][0]['path']})
        self.assertEqual(files,before)
        self.assertEqual(report['imports']['os']['kind'],'SELECTED_STDLIB_SOURCE')
        self.assertEqual(report['imports']['sys']['kind'],'CPYTHON_CORE_BUILTIN')
        self.assertEqual(A.audit_closure(files,roots=['busybox'])['status'],'PASS_STATIC_AARCH64_ELF_DEPENDENCY_CLOSURE')
        files.pop('usr/lib/libdemo.so.1')
        with self.assertRaisesRegex(ValueError,'libdemo.so.1'):A.audit_closure(files,roots=['busybox'])

    def test_headless_nongui_exclusion_or_wrong_exclusion_hash_refuses(self):
        profile,packages,files,_=self.headless_fixture()
        changed=copy.deepcopy(profile);changed['excluded'][0]['sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'exclusion pin mismatch'):
            A.headless_profile(changed,self.root,packages,files)
        changed=copy.deepcopy(profile);path='usr/lib/python3.14/os.py';body=files.pop(path)['raw']
        changed['excluded']=[dict(path=path,package='python',member=path,bytes=len(body),sha256=A.digest(body),mode=0o644,reason='Unapproved nonGUI exclusion')]
        with self.assertRaisesRegex(ValueError,'only declared unused Tk/GUI'):
            A.headless_profile(changed,self.root,packages,files)

    def test_headless_probe_import_of_removed_gui_or_unlisted_module_refuses(self):
        profile,packages,files,probe=self.headless_fixture()
        for source,required,message in ((b'import tkinter\n',['tkinter'],'probe/bootstrap module absent: tkinter'),
                                        (b'import os, json\n',['os'],'exact probe AST import inventory')):
            changed=copy.deepcopy(profile);probe.write_bytes(source)
            changed['probe_sources']=[dict(path=probe.name,bytes=len(source),sha256=A.digest(source))]
            changed['required_modules']=required
            with self.subTest(source=source),self.assertRaisesRegex(ValueError,message):
                A.headless_profile(changed,self.root,packages,files)

    def test_plan_identity_metadata_pin_and_file_binding_refuse_before_output(self):
        original = self.fixture_plan()
        variants = []
        changed=copy.deepcopy(original);changed['actual']={};variants.append(changed)
        changed=copy.deepcopy(original);changed['lock']['sha256']='0'*64;variants.append(changed)
        changed=copy.deepcopy(original);changed['packages'][0]['version']='0.13.0-2';variants.append(changed)
        changed=copy.deepcopy(original);changed['packages'][0]['metadata']['.MTREE']['sha256']='0'*64;variants.append(changed)
        changed=copy.deepcopy(original);changed['packages'][0]['pkgbuild_sha256']='0'*64;variants.append(changed)
        changed=copy.deepcopy(original);changed['files'][0]['sha256']='0'*64;variants.append(changed)
        changed=copy.deepcopy(original);changed['files'][0]['mode']=0o4755;variants.append(changed)
        for plan in variants:
            with self.assertRaises(ValueError):self.main(plan)
            self.assertFalse(self.out.exists())
        with self.assertRaisesRegex(ValueError,'frozen349 lock pin'):
            A.assemble_files(original,self.root,LOCK_RAW+b'\n')


if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(AssemblyControls))
    print(json.dumps(dict(status='PASS' if result.wasSuccessful() else 'FAIL',tests=result.testsRun,
        failures=len(result.failures),errors=len(result.errors),skipped=len(result.skipped),
        evidence='SYNTHETIC_PACKAGE_AND_ELF_DATA_NOT_NATIVE',payload_execution=0,host_extraction=0,
        download=0,signature_authentication='NOT_RUN',guest_native='NOT_RUN'),sort_keys=True))
    raise SystemExit(not result.wasSuccessful() or bool(result.skipped))
