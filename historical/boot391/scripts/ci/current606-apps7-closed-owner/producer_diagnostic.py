#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exact-source failure-only producer derivative; no actors on import/install."""
import ast, hashlib
from pathlib import Path
ORIGINAL = '98d61944888485870b31b5457bcad9edfd8e51cb367414833f8d54611d7b0eaf'
HELPER = 'def install_command_diagnostic(api, caller, raw, result):\n    """Derive only the held command\'s failure seam; original supervision stays intact."""\n    import base64\n    import stat\n    expected = \'b9840c79ffc6c45070ac12b80d469fb46c26059df63e121801d6ab223035e303\'\n    source = caller.read_bytes()\n    need(hashlib.sha256(source).hexdigest() == expected, \'diagnostic caller source differs\')\n    tree = ast.parse(source)\n    functions = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == \'command\']\n    need(len(functions) == 1, \'one held command required\')\n    function = functions[0]\n    text = \'\\n\'.join(source.decode().splitlines()[function.lineno-1:function.end_lineno]) + \'\\n\'\n    anchor = "        assert code == 0, \'command failed: \' + log.name\\n"\n    need(text.count(anchor) == 1, \'held command failure seam differs\')\n\n    def failed(argv, log, timeout, code):\n        if \'command_failure\' in result:\n            return\n        row = {\'schema_version\': 1, \'status\': \'FAILED_COMMAND_DATA_ONLY\',\n               \'exit_code\': code, \'time_limit\': timeout,\n               \'stream\': \'MERGED_STDOUT_STDERR_NOT_SEPARABLE\',\n               \'inner_cause\': \'UNKNOWN\', \'docker_build_returncode\': None,\n               \'caller_source_sha256\': expected,\n               \'acceptance\': \'NONE\'}\n        result[\'command_failure\'] = row\n        try:\n            path = Path(log)\n            relative = path.relative_to(raw)\n            need(not any(p.is_symlink() for p in (path, *path.parents)), \'ordinary failure log required\')\n            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)\n            with os.fdopen(fd, \'rb\') as stream:\n                before = os.fstat(stream.fileno())\n                need(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and before.st_nlink == 1,\n                     \'owned regular failure log required\')\n                size = before.st_size\n                full = stream.read(16 * 1024**2 + 1) if size <= 16 * 1024**2 else None\n                if full is not None:\n                    need(len(full) == size, \'failure log size changed\')\n                stream.seek(max(0, size - 8192))\n                tail = stream.read(8192)\n                after = os.fstat(stream.fileno())\n                need((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==\n                     (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),\n                     \'failure log changed during capture\')\n            row.update(log=str(relative), bytes=size,\n                       sha256=hashlib.sha256(full).hexdigest() if full is not None else None,\n                       full_hash_scope=\'COMPLETE\' if full is not None else \'UNKNOWN_OVER_16MIB\',\n                       tail_base64=base64.b64encode(tail).decode(), tail_bytes=len(tail),\n                       tail_sha256=hashlib.sha256(tail).hexdigest(), truncated=size > len(tail))\n            report = path.parent / \'report.json\'\n            if relative == Path(\'desktop574/build.log\') and report.is_file() and not report.is_symlink():\n                need(report.stat().st_size <= 65536, \'bounded574 report required\')\n                data = json.loads(report.read_bytes())\n                # Only a literal retained build result proves Docker was reached.\n                value = data.get(\'build_returncode\')\n                need(value is None or type(value) is int, \'typed Docker returncode required\')\n                row[\'docker_build_returncode\'] = value\n        except BaseException as error:\n            # Failure to diagnose must never replace the held command assertion.\n            row[\'diagnostic_error_type\'] = type(error).__name__\n\n    changed = text.replace(anchor, \'        if code != 0:\\n            _producer_failed_command(argv, log, timeout, code)\\n\' + anchor)\n    namespace = dict(api.__dict__, _producer_failed_command=failed)\n    exec(compile(changed, str(caller) + \':failure-data-only\', \'exec\'), namespace)\n    api.command = namespace[\'command\']\n\n\n'
ANCHOR = "    result = {'status': 'FAIL', 'phase': 'preparation-start', 'installer': 'NOT RUN', 'upgrade': 'NOT RUN'}\n"
CALL = '    install_command_diagnostic(api, caller, raw, result)\n'

def install(producer):
    """One explicit owner seam immediately after loading the held producer."""
    path=Path(producer.__file__)
    raw=path.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=ORIGINAL:
        raise ValueError('whole original producer hash mismatch')
    text=raw.decode()
    tree=ast.parse(text)
    functions=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='prepare']
    if len(functions)!=1 or text.count(ANCHOR)!=1:
        raise ValueError('one exact producer prepare seam')
    f=functions[0]
    before='\n'.join(text.splitlines()[f.lineno-1:f.end_lineno])+'\n'
    after=before.replace(ANCHOR,ANCHOR+CALL)
    if after.replace(CALL,'',1)!=before:
        raise ValueError('whole prepare byte inverse')
    namespace=producer.__dict__
    exec(compile(HELPER+after,str(path)+':command-failure-data-only','exec'),namespace)
    producer.prepare=namespace['prepare']
    return producer

OWNER_LINES = (
 "    producer=C.load('_expanded604_producer',args.code/'scripts/ci/full-composition-installer-vm/producer.py')\n",
 "    producer=C.load('_root604_producer',a.legacy_source/'scripts/ci/full-composition-installer-vm/producer.py')\n",
)
def route_owner(raw):
    """One source-owned generated-owner seam; caller supplies global PDIAG."""
    is_bytes=isinstance(raw,bytes);text=raw.decode() if is_bytes else raw
    matches=[line for line in OWNER_LINES if line in text]
    if len(matches)!=1 or text.count(matches[0])!=1:
        raise ValueError('one exact owner producer load seam')
    before=matches[0];after=before+'    PDIAG.install(producer)\n'
    out=text.replace(before,after)
    if out.replace(after,before,1)!=text:
        raise ValueError('whole generated owner inverse')
    ast.parse(out)
    return out.encode() if is_bytes else out
