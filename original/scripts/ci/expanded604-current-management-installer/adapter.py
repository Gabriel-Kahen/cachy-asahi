# SPDX-License-Identifier: MIT
"""Reuse the original closed604 AST transformer with current identity data only."""
import contract as C
OLD='expanded604-installer-vm';NEW='expanded604-current-management-installer'
A=C.scoped_load('_current604_original_installer_adapter',C.HERE.parent/OLD/'adapter.py',{'contract':C})
A.TARGET=C.TARGET_SHA
_original_rules=A.rules
IDENTITIES={
 OLD:NEW,
 'PASS_EXPANDED604_INSTALLER':'PASS_CURRENT604_INSTALLER',
 'generic4K-full604-installer-software-only':'generic4K-current604-installer-software-only',
 'cachy-asahi.expanded604-installer=':'cachy-asahi.current604-installer=',
 'cachy-asahi-expanded604-installer:':'cachy-asahi-current604-installer:',
 'cachy-expanded604-installer-':'cachy-current604-installer-',
 'cachy-asahi.expanded604-installer':'cachy-asahi.current604-installer'}
def rules(name):
 rows=_original_rules(name)
 return [(scope,before,IDENTITIES.get(after,after),count,keyword) for scope,before,after,count,keyword in rows]
A.rules=rules
# Same transform/materialize implementations, helper pins and complete AST guard.
for _name in ('NAMES','HELPERS','OLD','TARGET','accepted','nodes','transform','materialize'):globals()[_name]=getattr(A,_name)
