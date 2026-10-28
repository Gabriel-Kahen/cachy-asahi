# SPDX-License-Identifier: MIT
"""Pure, fixed prepare()-only adaptation; original fixture remains a separate payload."""
import ast
import hashlib

ORIGINAL_SHA256='79a869d9adc6405a07ac647d01be905f99cc1e8dedd0821f38680fc504b919dd'
RECORDER='/fixtures/notify-recorder'


def adapt(raw):
    if hashlib.sha256(raw).hexdigest()!=ORIGINAL_SHA256:raise ValueError('original Done fixture hash differs')
    source=raw.decode();tree=ast.parse(source)
    prepare=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='prepare')
    lines=source.splitlines(keepends=True);old=''.join(lines[prepare.lineno-1:prepare.end_lineno])
    begin=old.index("    if missing != 'notify-send':");end=old.index('    return home',begin)
    new=old[:begin]+"    if missing != 'notify-send':\n        shim = home/'bin/notify-send'\n        shutil.copyfile("+repr(RECORDER)+", shim)\n        shim.chmod(0o700)\n"+old[end:]
    result=(''.join(lines[:prepare.lineno-1])+new+''.join(lines[prepare.end_lineno:])).encode()
    def unchanged(tree):
        return [ast.dump(node,include_attributes=False) for node in tree.body if not isinstance(node,ast.FunctionDef) or node.name!='prepare']
    if unchanged(tree)!=unchanged(ast.parse(result)):raise ValueError('adaptation escaped prepare()')
    return result
