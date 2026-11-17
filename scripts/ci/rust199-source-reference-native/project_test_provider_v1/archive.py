# SPDX-License-Identifier: MIT
"""Complete project-provider archive DATA, never signature or native authority.

The caller must verify its separately Root-selected TEST signature first. The
unchanged v18 audit proves metadata/BUILDINFO correspondence, not ALARM trust.
"""
from pathlib import PurePosixPath
import tarfile


def alias_closure(providers, D):
    """Every same-package alias must end at a declared regular library."""
    D.need(any(row['kind'] == 'file' for row in providers.values()), 'regular project provider required')
    for name in providers:
        current, seen = name, set()
        while providers[current]['kind'] == 'symlink':
            D.need(current not in seen and len(seen) < 32, 'acyclic project provider aliases')
            seen.add(current)
            target = providers[current]['target']
            D.need(D.literal(target) and '/' not in target and target not in ('', '.', '..')
                   and '\\' not in target and '\x00' not in target, 'internal project library alias')
            current = str(PurePosixPath(current).parent / target)
            D.need(current in providers, 'same-package declared alias target required')


def audit(path, row, D, tick=lambda: None):
    """Compose frozen metadata audit with complete provider and license closure."""
    base = D.audit_archive(path, row, tick)
    providers = row['providers']; alias_closure(providers, D)
    prefix = 'dependency-provenance/' + row['name'] + '/licenses/'
    installed = 'usr/share/licenses/' + row['name'] + '/'
    wanted = {}
    for name, descriptor in row['license_provenance']['license_files'].items():
        D.relative(name); D.need(name.startswith(prefix), 'package-scoped source license')
        suffix = name[len(prefix):]; D.relative(suffix)
        wanted[installed + suffix] = descriptor
    D.need(wanted, 'installed source-license correspondence required')
    observed, licenses, kinds, expanded, headers = {}, {}, {}, 0, 0
    with tarfile.open(path, 'r|xz') as package:
        for member in package:
            tick(); headers += 1
            name = member.name.removeprefix('./'); D.relative(name)
            D.need(not name.startswith('usr/lib/') or not name.endswith(('.a', '.la')),
                   'no undeclared static/libtool provider in shared-only project packages')
            D.need(headers <= 8192 and name not in kinds, 'bounded unique project package namespace')
            D.need(member.type != tarfile.GNUTYPE_SPARSE and not member.sparse
                   and not any(k.startswith('GNU.sparse') for k in member.pax_headers)
                   and (member.isdir() or member.isfile() or member.issym()), 'ordinary project package nodes')
            D.need(not member.mode & ~0o777 and 0 <= member.size <= 32 * D.MIB,
                   'ordinary project package modes and sizes')
            expanded += member.size; D.need(expanded <= D.EXPANDED_CAP, 'project package expanded bound')
            D.need(name != '.INSTALL' and not name.startswith(('usr/share/libalpm/hooks/', 'etc/pacman.d/hooks/')),
                   'no project package scripts or hooks')
            D.need('.so' not in PurePosixPath(name).name or not member.isdir(), 'library cannot be a directory')
            kinds[name] = 'dir' if member.isdir() else 'file' if member.isfile() else 'symlink'
            if member.issym():
                target = member.linkname
                D.need(type(target) is str and 0 < len(target) <= 255 and not target.startswith('/')
                       and '\\' not in target and '\x00' not in target, 'ordinary package alias target')
                resolved = list(PurePosixPath(name).parent.parts)
                for part in target.split('/'):
                    if part in ('', '.'): continue
                    if part == '..':
                        D.need(resolved, 'package alias may not escape archive'); resolved.pop()
                    else: resolved.append(part)
                D.need(not name.startswith('usr/share/licenses/'), 'installed source licenses must be regular')
                if name.startswith('usr/lib/') or '.so' in PurePosixPath(name).name:
                    D.need(name.startswith('usr/lib/') and name in providers, 'only declared project library aliases')
                    observed[name] = dict(kind='symlink', mode=member.mode, target=target)
            elif member.isfile():
                stream = package.extractfile(member)
                D.need(stream is not None, 'regular project package member')
                with stream:
                    head = stream.read(64)
                    library = '.so' in PurePosixPath(name).name
                    elf = head.startswith(b'\x7fELF')
                    if name in providers or elf or name.startswith('usr/lib/') and library:
                        D.need(name.startswith('usr/lib/') and name in providers and member.size <= 16 * D.MIB
                               and len(head) >= 64 and head[:6] == b'\x7fELF\x02\x01'
                               and head[16:20] == b'\x03\x00\xb7\x00', 'only declared ELF64 AArch64 shared library providers')
                        body = head + stream.read(member.size - len(head) + 1)
                        D.need(len(body) == member.size, 'complete regular project provider bytes')
                        observed[name] = dict(kind='file', mode=member.mode, **D.pin(body))
                    elif name.startswith('usr/share/licenses/'):
                        D.need(name in wanted and member.mode == 0o644 and member.size <= D.MIB,
                               'only retained regular package-scoped licenses')
                        body = head + stream.read(member.size - len(head) + 1)
                        D.need(len(body) == member.size, 'complete installed source license')
                        licenses[name] = D.pin(body)
            package.members.clear()
    for name in kinds:
        D.need(all(str(parent) not in kinds or kinds[str(parent)] == 'dir'
                   for parent in PurePosixPath(name).parents if str(parent) != '.'),
               'no file or alias ancestor in project package')
    D.need(observed == providers, 'complete exact project provider inventory')
    D.need(licenses == wanted, 'installed licenses equal retained source-license bytes')
    D.need(D.pin(D.read(path, D.INPUT_CAP, tick)) == row['archive'], 'project archive stayed whole after full audit')
    return dict(base, providers=observed, installed_licenses=licenses,
                complete_provider_inventory=True, native_acceptance=False, Root_acceptance=None)
