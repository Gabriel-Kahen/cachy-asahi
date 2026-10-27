# SPDX-License-Identifier: MIT
"""Private fast path for canonical relative names; original refusal behavior remains."""
import re
_CANONICAL=re.compile(r'(?!(?:\.|\.\.)(?:/|$))[^/\x00]+(?:/(?!(?:\.|\.\.)(?:/|$))[^/\x00]+)*')
def bind(original):
    def relative(value):
        if type(value) is str and _CANONICAL.fullmatch(value) is not None:
            return value
        return original(value)
    relative.__wrapped__=original
    return relative

import hashlib,types
from pathlib import Path
ORIGINAL='scripts/install/local_transaction.py'
ORIGINAL_PIN=(93752,'14381d049506b52770059bf7af415f7a079f69872543e74417aca11ce24ac3c5')
def bind_installer(root,module,read):
    """One source-authenticated private facade; original fallback is retained."""
    path=root/ORIGINAL;raw=read(path)
    if (len(raw),hashlib.sha256(raw).hexdigest())!=ORIGINAL_PIN:
        raise ValueError('whole original installer relative source differs')
    codes={c.co_name:c for c in compile(raw,str(path),'exec').co_consts if type(c)is types.CodeType}
    space=vars(module)
    if Path(module.__file__)!=path or space.get('Path')is not Path or space.get('type',type)is not type or space.get('str',str)is not str:
        raise ValueError('original installer relative globals differ')
    for name in ('relative','need'):
        function=getattr(module,name,None)
        if type(function)is not types.FunctionType or function.__code__!=codes[name] or function.__globals__ is not space or function.__defaults__ is not None or function.__kwdefaults__ is not None or function.__closure__ is not None:
            raise ValueError('exact original installer predicate required')
    return types.SimpleNamespace(**dict(space,relative=bind(module.relative)))
