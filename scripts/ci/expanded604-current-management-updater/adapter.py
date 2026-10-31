# SPDX-License-Identifier: MIT
"""Current target/purpose over the exact original604 AST/copy adapter."""
from pathlib import Path
import contract as C
A=C.scoped('_current604_held_adapter',C.HERE.parent/'expanded604-root-upgrade/adapter.py',{'contract':C})
_original_rules=A.rules
IDENTITIES={
 'actual604-persistent-root-setup5-test':'actual-current604-persistent-root-setup5-test',
 'actual604-precommit-failure-disposal-test':'actual-current604-precommit-failure-disposal-test',
 'actual604-postcommit-failure-disposal-test':'actual-current604-postcommit-failure-disposal-test',
 'controlled-full604-precommit-failure-disposal':'controlled-full-current604-precommit-failure-disposal',
 'controlled-full604-postcommit-failure-disposal':'controlled-full-current604-postcommit-failure-disposal'}
def rules(name):
 return [(scope,before,IDENTITIES.get(after,after) if type(after) is str else after,count,role)
         for scope,before,after,count,role in _original_rules(name)]
A.rules=rules
# The held adapter loads its exact progress helper relative to __file__.
# Use the independently pinned current-basis helper, not the historical hashes.
A.__file__=str(C.HERE/'adapter.py')
HELPERS,MANAGEMENT,accepted,literals=A.HELPERS,A.MANAGEMENT,A.accepted,A.literals
PREFIX,nodes=A.PREFIX,A.nodes

def prepare(source,target,case,*,git=True,implementation=None):
 config,caller=A.prepare(source,target,case,git=git,implementation=implementation)
 value=C.read(config);value['purpose']=IDENTITIES[value['purpose']]
 value['release']['release_id']='current604-setup5-'+case+'-20261017'
 value['release']['namespace']='cachy-asahi-current604-'+case
 config.write_bytes(C.encoded(value));receipt=C.read(target/'adapter.json')
 receipt.update(status='PRIVATE_CURRENT604_SOURCE_SELECTION_ONLY',config_sha256=C.sha(config),
                GUI='FAIL_NOT_ACCEPTED',current_native_and_installer='UNBOUND_NO_TRANSFERRED_ACCEPTANCE')
 (target/'adapter.json').write_bytes(C.encoded(receipt));return config,caller
