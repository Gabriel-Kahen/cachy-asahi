#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read-only ordinary DESTDIR layout checks. No payload is executed."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat


def need(value, message):
    if not value:
        raise ValueError(message)


def inspect(root, arch):
    root = Path(root)
    need(root.is_absolute() and root == root.resolve() and root != Path('/') and root.is_dir(), 'canonical staging root required')
    files = {}; links = {}; total = 0
    for path in sorted(root.rglob('*')):
        name = path.relative_to(root).as_posix(); info = path.lstat(); mode = stat.S_IMODE(info.st_mode)
        need(name == 'usr' or name.startswith('usr/'), 'payload escapes usr namespace')
        need(not name.startswith(('usr/local','usr/share/libalpm','usr/lib/systemd','usr/share/fish/vendor_conf.d')), 'operator/hook/service paths forbidden')
        need(stat.S_ISLNK(info.st_mode) or not mode & 0o7022, 'set-id/sticky/group-or-other-writable payload forbidden')
        if stat.S_ISDIR(info.st_mode):
            continue
        need(len(files) + len(links) < 12000 and total < 160 * 1024**2, 'finite Perl stage required')
        if stat.S_ISLNK(info.st_mode):
            target = os.readlink(path)
            need(not Path(target).is_absolute() and (path.parent / target).resolve().is_relative_to(root)
                 and (path.parent / target).exists(), 'dangling or escaping stage link')
            links[name] = target
        else:
            need(stat.S_ISREG(info.st_mode) and info.st_size <= 32 * 1024**2, 'ordinary bounded staged file required')
            body = path.read_bytes(); total += len(body)
            files[name] = dict(bytes=len(body), sha256=hashlib.sha256(body).hexdigest(), mode=mode)
    required = {'usr/bin/perl', 'usr/lib/perl5/5.42/core_perl/CORE/libperl.so',
                'usr/lib/perl5/5.42/core_perl/Config.pm', 'usr/share/perl5/core_perl/strict.pm',
                'usr/share/licenses/perl/Artistic', 'usr/share/licenses/perl/Copying', 'usr/share/licenses/perl/README'}
    need(required <= set(files), 'interpreter/shared library/core configuration/dual notices required')
    machine = {'aarch64': 183, 'x86_64': 62}[arch]
    for name in ('usr/bin/perl', 'usr/lib/perl5/5.42/core_perl/CORE/libperl.so'):
        raw = (root/name).read_bytes()
        need(raw[:6] == b'\x7fELF\x02\x01' and int.from_bytes(raw[18:20], 'little') == machine, 'actual staged ELF architecture required')
    need(not any(name.startswith('usr/local/') for name in files), 'local/site module contents are operator-owned')
    return dict(status='PASS_ORDINARY_PERL_DESTDIR_LAYOUT_ONLY', architecture=arch, files=len(files), links=len(links),
                payload_bytes=total, native='NOT_ESTABLISHED_BY_LAYOUT', installation='NOT_RUN', hardware='NOT_RUN')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--arch', choices=('aarch64','x86_64'), required=True)
    args = parser.parse_args()
    print(json.dumps(inspect(args.root,args.arch),sort_keys=True))
