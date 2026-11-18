# SPDX-License-Identifier: MIT
"""Bind makepkg's generated llhttp provider to the inspected AArch64 package."""
import tarfile

from finish_pair import archive_members, elf, pin


def bind_llhttp_artifact(reviewed, report, recipe_hash, archive, bind_artifact):
    if sorted(reviewed.get('provides', [])) != ['libllhttp.so', 'llhttp=9.3.1'] or reviewed.get('provides_aarch64'):
        return ['unexpected reviewed llhttp providers']
    library = 'usr/lib/libllhttp.so.9.3.1'
    if set(report['elf']) != {library} or report['elf'][library]['errors']:
        return ['expected one structurally valid AArch64 llhttp library']
    try:
        raw, bodies = archive_members(archive, (library,))
        if (pin(raw)['sha256'] != report['sha256']
                or pin(bodies[library])['sha256'] != report['members'][library]['sha256']):
            return ['llhttp provider archive or ELF changed during inspection']
        soname = elf(bodies[library])['soname']
    except (ValueError, OSError, tarfile.TarError) as error:
        return [f'llhttp provider ELF validation failed: {error}']
    version = soname.removeprefix('libllhttp.so.')
    expected = dict(reviewed, provides=['llhttp=9.3.1', f'libllhttp.so={version}-64'])
    return bind_artifact(expected, report, recipe_hash)
