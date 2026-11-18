# SPDX-License-Identifier: MIT
"""Exact signed rootfs import into the already owned offline legacy builder."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import tarfile


ROOTFS_BYTES = 829367415
ROOTFS_SHA256 = '42a4eeaa038994ffd31fa173256ef2f0ef511358eeb41b9ea1f8626391b9b319'
ROOTFS_DIFF_ID = 'sha256:44409090c83feba37bfaf8e897d84804331f1412f9f4665cacc95688c6e9b0fb'
ROOTFS_MEMBERS = 49104
ROOTFS_SCRATCH = b'FROM scratch\nADD rootfs.tar.gz /\n'


def rootfs_need(value, guard):
    if not value:
        raise ValueError(guard)


def rootfs_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid, info.st_gid,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def signed_rootfs_layout(path):
    """Read only the pinned archive and the executable headers used for bootstrap."""
    rootfs_need(path.is_absolute() and path == path.resolve(), 'ordinary signed rootfs context path')
    fd = os.open(path, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        rootfs_need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == os.getuid()
                    and not before.st_mode & 0o022 and before.st_size == ROOTFS_BYTES
                    and hashlib.file_digest(stream, 'sha256').hexdigest() == ROOTFS_SHA256, 'exact pinned signed rootfs context bytes')
        stream.seek(0)
        links = {'bin':'usr/bin', 'lib':'usr/lib', 'usr/bin/sh':'bash'}
        directories = {'usr','usr/bin','usr/lib'}
        elf = {'usr/bin/bash','usr/lib/ld-linux-aarch64.so.1'}
        required = set(links) | directories | elf
        seen = set()
        count = 0
        with tarfile.open(fileobj=stream, mode='r|gz') as archive:
            for count,info in enumerate(archive,1):
                rootfs_need(count <= ROOTFS_MEMBERS, 'finite signed rootfs member census')
                name = info.name.removeprefix('./')
                if name not in required:
                    continue
                rootfs_need(name not in seen and info.uid == info.gid == 0, 'unique root-owned bootstrap entry')
                seen.add(name)
                if name in links:
                    rootfs_need(info.issym() and info.linkname == links[name], 'literal signed rootfs shell or loader alias')
                elif name in directories:
                    rootfs_need(info.isdir() and info.mode == 0o755, 'literal signed rootfs directory')
                else:
                    rootfs_need(info.isfile() and info.mode == 0o755 and info.size >= 64, 'regular executable in signed rootfs')
                    with archive.extractfile(info) as member:
                        data = member.read(min(info.size,4096))
                    rootfs_need(len(data) >= 64 and data[:7] == b'\x7fELF\x02\x01\x01' and data[18:20] == b'\xb7\x00', 'AArch64 ELF in signed rootfs')
                    if name == 'usr/bin/bash':
                        phoff = struct.unpack_from('<Q',data,32)[0]
                        entsize, entries = struct.unpack_from('<HH',data,54)
                        rootfs_need(entsize == 56 and 0 < entries <= 32 and 64 <= phoff <= len(data)-entries*entsize,
                                    'bounded signed shell program headers')
                        targets = []
                        for offset in range(phoff,phoff+entries*entsize,entsize):
                            kind,_,start,_,_,length,_,_ = struct.unpack_from('<IIQQQQQQ',data,offset)
                            if kind == 3:
                                targets.append(data[start:start+length])
                        rootfs_need(targets == [b'/lib/ld-linux-aarch64.so.1\x00'], 'literal signed shell interpreter')
        rootfs_need(seen == required and count == ROOTFS_MEMBERS, 'complete finite signed rootfs entrypoints')
        identity = rootfs_identity(before)
        rootfs_need(rootfs_identity(os.fstat(stream.fileno())) == rootfs_identity(path.lstat()) == identity, 'same signed rootfs during read')
        return identity


class SignedRootfsBootstrap:
    """Install after the original audit and run cleanup after derived-image retirement."""
    def __init__(self,native,runner,out,nonce,operation='llhttp-reference',probe=None):
        rootfs_need(re.fullmatch('[0-9a-f]{32}',nonce) and re.fullmatch('[a-z][a-z0-9-]{3,28}',operation), 'fixed owned signed-rootfs scope')
        self.run_existing, self.runner, self.out, self.probe = native.run, runner, out, probe
        self.labels = {'org.cachy-asahi.'+operation+'.signed-rootfs':nonce}
        self.label = next(iter(self.labels))+'='+nonce
        self.tag = 'cachy-'+operation+'-rootfs:'+nonce
        self.submitted = False
        self.image = None
        native.run = self.call

    def _images(self,selector):
        raw = self.runner(['/usr/bin/docker','image','ls','--all','--quiet','--no-trunc','--filter',selector],15).stdout
        rows = raw.decode('ascii').splitlines()
        rootfs_need(len(rows) <= 1 and all(re.fullmatch(r'sha256:[0-9a-f]{64}',x) for x in rows), 'unambiguous signed-rootfs image census')
        return rows

    def _inspect(self,image,allow_untagged=False):
        rows = json.loads(self.runner(['/usr/bin/docker','image','inspect',image],15).stdout)
        rootfs_need(type(rows) is list and len(rows) == 1, 'one signed-rootfs image inspection')
        row = rows[0]
        tags = row.get('RepoTags') or []
        rootfs_need(row.get('Id') == image and row.get('Os') == 'linux' and row.get('Architecture') == 'arm64'
                    and (tags == [self.tag] or allow_untagged and not tags) and not row.get('RepoDigests')
                    and row['Config'].get('Labels') == self.labels
                    and row['RootFS'].get('Layers') == [ROOTFS_DIFF_ID], 'exact owned ARM signed-rootfs ID, tag, label and layer')

    def call(self,argv,log=None,timeout=1800):
        if argv[:2] != ['docker','build']:
            return self.run_existing(argv,log,timeout)
        context = self.out/'context'
        expected = ['docker','build','--network=none','--pull=false','--platform=linux/arm64',
                    '--iidfile',str(self.out/'image-id'),str(context)]
        rootfs_need(argv == expected and not self.submitted, 'one original owned offline bootstrap command')
        archive, dockerfile = context/'rootfs.tar.gz',context/'Dockerfile'
        rootfs_need(dockerfile == dockerfile.resolve() and dockerfile.is_file(), 'ordinary original Dockerfile')
        with dockerfile.open('rb') as stream:
            raw = stream.read(16*1024+1)
        rootfs_need(len(raw) <= 16*1024 and raw.startswith(ROOTFS_SCRATCH) and raw.count(ROOTFS_SCRATCH) == 1,
                    'single original scratch ADD projection seam')
        identity = signed_rootfs_layout(archive)
        rootfs_need(not self._images('label='+self.label) and not self._images('reference='+self.tag), 'fresh signed-rootfs label and tag')
        self.submitted = True
        imported = self.runner(['/usr/bin/docker','image','import','--platform=linux/arm64','--change','LABEL '+self.label,
                                str(archive),self.tag],180).stdout.decode('ascii').strip()
        rootfs_need(re.fullmatch(r'sha256:[0-9a-f]{64}',imported), 'complete immutable signed-rootfs import ID')
        self.image = imported
        self._inspect(imported)
        rootfs_need(rootfs_identity(archive.lstat()) == identity, 'same archive through signed-rootfs import')
        if self.probe is not None:
            self.probe(imported,dict(self.labels))
        # A bare full ID is resolvable locally by the legacy builder and is
        # invalid as a registry repository. Clear the inherited base label
        # before any derived image is made to keep the cleanup census exact.
        replacement = ('FROM '+imported.removeprefix('sha256:')+'\nLABEL '+next(iter(self.labels))+'=""\n').encode('ascii')
        projected = raw.replace(ROOTFS_SCRATCH,replacement,1)
        rootfs_need(projected.count(replacement) == 1 and projected.replace(replacement,ROOTFS_SCRATCH,1) == raw,
                    'whole Dockerfile inverse outside signed base image')
        temporary = context/'Dockerfile.rootfs-import'
        with temporary.open('xb') as stream:
            stream.write(projected)
        temporary.replace(dockerfile)
        archive.unlink()
        print(json.dumps(dict(kind='EXACT_SIGNED_ARM_ROOTFS_IMPORT_V1',image=imported,
                              layer=ROOTFS_DIFF_ID,accepting=False)),flush=True)
        return self.run_existing(argv,log,timeout)

    def cleanup(self):
        if not self.submitted:
            return dict(submitted=False)
        labelled = self._images('label='+self.label)
        tagged = self._images('reference='+self.tag)
        rootfs_need(not tagged or tagged == labelled, 'same owned signed-rootfs label and tag before retirement')
        if labelled:
            image = labelled[0]
            rootfs_need(self.image is None or self.image == image, 'same originally observed signed-rootfs image ID')
            self._inspect(image,allow_untagged=True)
            self.runner(['/usr/bin/docker','image','rm','--no-prune',image],30)
        rootfs_need(not self._images('label='+self.label) and not self._images('reference='+self.tag), 'owned signed-rootfs tag and image absent')
        return dict(submitted=True,image_id=self.image,owned_image_absence_verified=True)
