"""Native pre-build relations, excluding only outputs built in this split recipe."""
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import contract as C
c,r,m=C.source(Path(sys.argv[1]),sys.argv[2])
outputs=set(m)-{'@base'}
# Preserve all original make/check relations, even if the name is a split output.
# Only runtime dependencies satisfied by siblings of this same build are omitted
# from the pre-build installed test. Full sibling relations remain in SRCINFO.
build=set(m['@base'].get('makedepends',[])+m['@base'].get('checkdepends',[]))
for block in m.values():
 for key in ('makedepends','checkdepends'):build.update(block.get(key,[]))
 for dep in block.get('depends',[]):
  if dep.split('=')[0]not in outputs:build.add(dep)
print('\n'.join(sorted(build)))
