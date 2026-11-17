# SPDX-License-Identifier: MIT
"""Pure finite XZ gates over the held Fish contract, builder and comparator."""
import ast

PACKAGE = 'cachy-asahi-fish-config-0.1.0-2-any.pkg.tar.xz'
MAGIC = b'\xfd7zXZ\x00'
BUILD_BEFORE = "        paths = sorted(p for p in artifacts.glob('*.pkg.tar.*') if not p.name.endswith('.sig'))"
BUILD_AFTER = BUILD_BEFORE + f"""
        if len(paths) != 1 or paths[0].name != {PACKAGE!r}:
            raise ValueError('fixed Fish exact XZ archive required before package inspection')
        if not paths[0].is_file() or paths[0].is_symlink():
            raise ValueError('ordinary Fish XZ archive required before package inspection')
        with paths[0].open('rb') as archive:
            if archive.read(6) != {MAGIC!r}:
                raise ValueError('actual Fish XZ header required before package inspection')"""
COMPARE_BEFORE = "    for name, checksum in record['files'].items():"
COMPARE_AFTER = f"""    actual = {{p.name for p in (path / 'artifacts').glob('*.pkg.tar.*') if not p.name.endswith('.sig')}}
    if actual != {{{PACKAGE!r}}}:
        raise ValueError('fixed Fish exact XZ archive required before comparison inspection')
    archive_path = path / 'artifacts' / {PACKAGE!r}
    if not archive_path.is_file() or archive_path.is_symlink():
        raise ValueError('ordinary Fish XZ archive required before comparison digest or inspection')
    with archive_path.open('rb') as archive:
        if archive.read(6) != {MAGIC!r}:
            raise ValueError('actual Fish XZ header required before comparison inspection')
""" + COMPARE_BEFORE
FINISH_BEFORE = "name.startswith('cachy-asahi-fish-config-0.1.0-2-any.pkg.tar.')"
FINISH_AFTER = f'name=={PACKAGE!r}'
FINISH_ANCHOR = "    return dict(status='FISH02_NATIVE_PAIR_AND_CHECK_POSTCONDITIONS_PASSED'"
FINISH_GATE = f"""    for root in (first,second):
        archive_path=root/'artifacts'/name
        need(archive_path.is_file()and not archive_path.is_symlink(),'ordinary Fish XZ archive required after strict comparison')
        with archive_path.open('rb') as archive:
            need(archive.read(6)=={MAGIC!r},'actual Fish XZ header required after strict comparison')
"""


def replace_once(raw, before, after):
    text = raw.decode()
    if text.count(before) != 1 or after in text:
        raise ValueError('one exact finite XZ projection anchor required')
    result = text.replace(before, after)
    if result.replace(after, before).encode() != raw:
        raise ValueError('whole unchanged XZ projection inverse required')
    return result.encode()


def projected_compare(raw):
    return replace_once(raw, COMPARE_BEFORE, COMPARE_AFTER)


def projected_contract(raw):
    text = raw.decode()
    node, = [node for node in ast.parse(text).body if isinstance(node, ast.Assign)
             and any(isinstance(target, ast.Name) and target.id == 'BUILD_EDITS' for target in node.targets)]
    if len(ast.literal_eval(node.value)) != 3:
        raise ValueError('exact three inherited Fish builder edits required')
    original = ast.get_source_segment(text, node)
    if not original.endswith('\n)'):
        raise ValueError('exact finite Fish BUILD_EDITS layout required')
    amended = original[:-1] + ' ' + repr((BUILD_BEFORE, BUILD_AFTER)) + ',\n)'
    result = replace_once(raw, original, amended)
    result = replace_once(result, "here/'runtime/scripts/build/compare_v2.py'", "here/'runtime/scripts/build/compare_fish_xz.py'")
    extension = '\n\nCOMPARE_BEFORE=' + repr(COMPARE_BEFORE) + '\nCOMPARE_AFTER=' + repr(COMPARE_AFTER) + '''

def projected_compare(raw):
    text=raw.decode();need(text.count(COMPARE_BEFORE)==1 and COMPARE_AFTER not in text,'one finite Fish XZ comparator gate')
    text=text.replace(COMPARE_BEFORE,COMPARE_AFTER)
    need(text.replace(COMPARE_AFTER,COMPARE_BEFORE).encode()==raw,'whole unchanged comparator inverse')
    return text.encode()
'''
    if 'def projected_compare(' in result.decode():
        raise ValueError('Fish comparator projection must be absent in held contract')
    return result + extension.encode()


def projected_finisher(raw):
    result = replace_once(raw, FINISH_BEFORE, FINISH_AFTER)
    return replace_once(result, FINISH_ANCHOR, FINISH_GATE + FINISH_ANCHOR)
