# SPDX-License-Identifier: MIT
"""Fixed-role, observation-only filesystem diagnostics; never authorize access."""
import json
import os
from pathlib import Path
import stat
import sys

KIND='FISH02_FIXED_PATH_FILESYSTEM_DIAGNOSTIC_V7'
PREFIX='FILESYSTEM_DIAGNOSTIC: '
DECLARATION=dict(kind=KIND,fixed_labels=['tmp','var_tmp','source','quota_work'],
                 literal_paths=['/tmp','/var/tmp'],source_operand='source_root',
                 quota_work_operand='output_parent',max_record_bytes=2048,
                 permission_check='real-ID W_OK',mount_class='statvfs ST_RDONLY',
                 raw_paths=False,raw_environment=False,raw_exception_messages=False,
                 filesystem_enumeration=False,write_probe=False,
                 observation_only=True,acceptance_override=False)
ERRORS=frozenset(('OSError','PermissionError','FileNotFoundError','NotADirectoryError',
                  'ValueError','TypeError','OverflowError','MemoryError'))
FALLBACK=PREFIX+'{"kind":"'+KIND+'","status":"UNKNOWN"}'


def error_class(error):
    name=type(error).__name__
    return name if name in ERRORS else 'OTHER'


def probe(path):
    """Sample only the supplied fixed-role path, without opening or writing it."""
    row=dict(entry_class='UNKNOWN',mode_bits=None,write_access=None,mount_class='UNKNOWN',errors={})
    try:
        mode=Path(path).lstat().st_mode
        if type(mode)is not int or mode<0:raise ValueError('invalid mode')
        row['entry_class']=('DIRECTORY'if stat.S_ISDIR(mode)else 'FILE'if stat.S_ISREG(mode)
                            else 'SYMLINK'if stat.S_ISLNK(mode)else 'OTHER')
        row['mode_bits']=stat.S_IMODE(mode)
    except Exception as error:row['errors']['entry']=error_class(error)
    try:
        value=os.access(path,os.W_OK)
        if type(value)is not bool:raise ValueError('invalid access observation')
        row['write_access']=value
    except Exception as error:row['errors']['access']=error_class(error)
    try:
        flags=os.statvfs(path).f_flag
        if type(flags)is not int or flags<0:raise ValueError('invalid mount flags')
        row['mount_class']='READ_ONLY'if flags&os.ST_RDONLY else 'READ_WRITE'
    except Exception as error:row['errors']['mount']=error_class(error)
    return row


def record(source,work):
    targets=(('tmp',Path('/tmp')),('var_tmp',Path('/var/tmp')),
             ('source',Path(source)),('quota_work',Path(work)))
    rows=[dict(label=label,**probe(path))for label,path in targets]
    status='PARTIAL'if any(row['errors']for row in rows)else 'OBSERVED'
    text=PREFIX+json.dumps(dict(kind=KIND,status=status,paths=rows),sort_keys=True,separators=(',',':'))
    if len((text+'\n').encode('utf-8'))>DECLARATION['max_record_bytes']:
        raise ValueError('bounded filesystem diagnostic')
    return text


def emit(source,work):
    # Diagnostic failure must not prevent the original confinement guard running.
    try:text=record(source,work)
    except Exception:text=FALLBACK
    try:print(text,file=sys.stderr,flush=True)
    except Exception:pass
