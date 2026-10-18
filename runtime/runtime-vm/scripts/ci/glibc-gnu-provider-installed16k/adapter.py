# SPDX-License-Identifier: MIT
"""Four counted edits; all native lifecycle transaction/check bodies are reused."""
import ast
from pathlib import Path
import contract as C

GUARD="""    C.need(os.geteuid()==os.getuid()==0 and platform.machine()=='aarch64' and Path('/.dockerenv').is_file() and os.environ.get('CACHY_GNU_PROVIDER_LIFECYCLE')=='1','explicit disposable native lifecycle container only')"""
GUEST_GUARD="""    C.need(os.geteuid()==os.getuid()==0 and platform.machine()=='aarch64' and os.sysconf('SC_PAGE_SIZE')==16384 and 'caa_gnu_installed16k=1' in Path('/proc/cmdline').read_text().split() and os.environ.get('CACHY_GNU_PROVIDER_LIFECYCLE')=='1','explicit disk-backed generic16K lifecycle guest only')"""

RULES=(
    ("sys.path.insert(0,str(Path(__file__).resolve().parent))","sys.path.insert(0,'/runner')"),
    ("results[0]['page_size']==4096","results[0]['page_size']==16384"),
    (GUARD,GUEST_GUARD),
    ("'actual generic4K runtime result'","'actual generic16K runtime result'"),
)

def derive(source):
    C.check_source(source);raw=C.read(Path(source)/C.NATIVE/'container.py');text=raw.decode()
    for before,after in RULES:
        C.need(text.count(before)==1,'counted native16K adapter anchor changed: '+before[:100]);text=text.replace(before,after)
    ast.parse(text)
    # Record exact unchanged function bodies, including transaction/config/payload,
    # all two-case operation sequencing, copy capability/hardlink checks and cleanup.
    a={n.name:ast.get_source_segment(raw.decode(),n) for n in ast.parse(raw).body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
    b={n.name:ast.get_source_segment(text,n) for n in ast.parse(text).body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
    unchanged=sorted(n for n in a if a[n]==b[n]);changed=sorted(n for n in a if a[n]!=b[n])
    C.need(changed==['guard','validate_runtime'] and len(unchanged)==20 and 'config_handoff' in unchanged,'finite unchanged lifecycle bodies required')
    return text,dict(status='DERIVED_SOURCE_ONLY',source_sha256=C.sha(raw),adapted_sha256=C.sha(text.encode()),counted_edits=len(RULES),unchanged_bodies=unchanged,changed_bodies=changed,native='NOT_RUN',hardware='NOT_RUN')
