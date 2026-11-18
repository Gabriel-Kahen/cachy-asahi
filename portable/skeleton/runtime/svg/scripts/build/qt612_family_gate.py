from pathlib import Path
import sys
_root=Path(__file__).resolve().parents[4]
sys.path.insert(0,str(_root/'scripts/ci/qt612-complete-family-native-source'))
from pipeline import require_actual_family as _require
def require_actual_family(component):
    return _require(component,source=str(_root),actor_argv=sys.argv[1:])
