import types as _updater_cost_types
_updater_cost_forward=_updater_cost_types.ModuleType('_private_updater_cost_forward')
exec(compile('# SPDX-License-Identifier: MIT\n"""Forward only bounded typed public scalar records through existing caller stderr."""\ndef forward(row):\n try:\n  import json,os\n  text=row[\'stderr\']\n  if type(text)is not str or len(text.encode())>1024**2:return\n  prefix=\'UPDATER489_COPY_COST \';lines=[line for line in text.splitlines()if line.startswith(prefix)]\n  if not 1<=len(lines)<=12:return\n  for index,line in enumerate(lines,1):\n   value=json.loads(line[len(prefix):])\n   if type(value)is not list or len(value)!=17 or any(type(v)is not int or not -2**63<v<2**63 for v in value):return\n   if value[:2]!=[2,index]or not 0<=value[2]<11 or not 0<=value[3]<4:return\n   if not(all(v==-1 for v in value[9:16])or all(v>=0 for v in value[9:16])):return\n  raw=(\'\\n\'.join(lines)+\'\\n\').encode(\'ascii\')\n  if len(raw)>3072:return\n  os.write(2,raw)\n except BaseException:pass\n','<private-updater-cost-forward>','exec'),_updater_cost_forward.__dict__)
#!/usr/bin/env python3
"""One future native upgrade in a complete copy of the retained persistent root."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

BEFORE = '72818a8a2ae488281b08486b92c435ec244ef3b5313f23b97473d1684ecb68b4'
AFTER = 'be35402204ba5c03d78279722afa83047c9575d2da70fb5c4064f46ed15954c5'
CODE = Path('/upgrade-code')
CONFIG = Path('/upgrade-config.json')
PAIR = Path('/upgrade-pair')
SIGNING = Path('/upgrade-signing')
VOLUME = Path('/measurement')
DRIVER = 'scripts/ci/full-root-upgrade/root_upgrade.py'

_NORMAL_REASON_LITERALS = ('341-package inventory differs', 'ALPM owned file count limit', 'ALPM package inventory limit', 'Docker overrides refused', 'GPG_HOME_SOCKET_PATH_TOO_LONG', 'Python compression.zstd is unavailable', 'Root must freeze the complete actual87 literal link selection before dispatch', 'absolute archive link refused', 'absolute canonical scope paths required', 'absolute contained copy paths required', 'absolute contained root required', 'absolute database root required', 'absolute payload link', 'absolute-comparator-source', 'actual base trust differs from pinned configuration', 'actual baseline differs from exact 604-package lock', 'actual before/after inventory differs', 'actual composition inventory required', 'actual composition lock differs', 'actual copied base differs from authenticated release', 'actual namespace identity/map refused', 'actual package-owned kernel modules required', 'actual post-update lock differs', 'actual protected platform packages absent', 'actual reduced capabilities differ', 'actual release requires explicit generic disposable update selection', 'actual root is not initial signed604/updater-v2 checkpoint', 'actual user-file baseline not exercised', 'actual user-file baseline required before commit', 'aggregate accounting exceeds limits', 'aggregate compressed byte limit exceeded', 'aggregate deadline exhausted', 'aggregate decoded archive bound', 'aggregate decoded archive byte bound', 'aggregate decoded byte limit exceeded', 'aggregate input bytes exceeded', 'aggregate member limit exceeded', 'aggregate owned file count limit', 'aggregate package inputs exceed tiny-root limit', 'aggregate package ownership bound', 'ambient capability clearing refused', 'ambiguous copy bind scope', 'apps-directory-inode-links-size-metadata', 'apps-directory-node-metadata', 'apps-directory-scan-row', 'apps604-selected-postcommit-only', 'archive deadline exhausted', 'archive exceeds tiny-root caller limit', 'archive input changed during inspection', 'archive node/sparse bound', 'archive payload overlap', 'archive special/hardlink member refused', 'authenticated result changed', 'authenticated snapshot drifted', 'aux-changed-before-commit', 'bare retained evidence directory required', 'base pacman configuration/trust required', 'base trust changed after commit', 'base trust changed before commit', 'boolean absolute path diagnostic required', 'bootstrap started without immutable image ID', 'bound evidence node identities required', 'bound worker/runtime/evidence identity required', 'bounded cleanup budgets required', 'bounded command failed', 'bounded declared release required', 'bounded decoder read required', 'bounded evidence file required', 'bounded existing local database required', 'bounded hardlink groups required', 'bounded inventory/depth/diagnostics required', 'bounded mount table required', 'bounded ordinary database record required', 'bounded ordinary source required', 'bounded original node metadata', 'bounded original observation reasons', 'bounded original stage maps', 'bounded owned package names required', 'bounded path collection required', 'bounded persistent stage diagnostic', 'bounded receipt file required', 'bounded regular reference required', 'bounded scan diagnostic', 'bounded scan maps', 'bounded scan path', 'bounded scan row', 'bounded shape samples required', 'bounded tracked source archive required', 'bounded unique copied package inventory', 'bundle has missing or undeclared members', 'cache-file', 'cache-parent', 'canonical owned paths required', 'canonical private path required', 'canonical relative root query required', 'canonical single-mount verification required', 'capability bounding reduction refused', 'capability reduction refused', 'capacity check missing', 'captured engine specification required', 'captured runtime bytes differ', 'captured worker launch required', 'changed archive required', 'changed copy source', 'checkout differs from product', 'clean standard command environment required', 'closed add row required', 'closed engine specification required', 'closed namespace identity required', 'closed transaction contract required', 'closure-changed', 'code source pin shape', 'comparator-binding', 'comparator-source-drift', 'comparator-source-pin', 'comparator-source-shape', 'complete CLI arguments required', 'complete byte-identical supplied-source copy required', 'complete declared protected versions required', 'complete driver commit truth required', 'complete explicit code closure required', 'complete generic fixture selection required', 'complete persistent stage differs', 'complete projected root required', 'complete single-mount copy scope required', 'complete-absolute-chain-set-differs', 'complete-link-observation', 'complete-observation', 'complete-projected-root', 'complete-selected-copy-scope', 'complete604 lock required', 'compressed archive size/type limit exceeded', 'config-metadata', 'consumed input byte bound', 'contained declared repository alias required', 'contained exclusions required', 'copied baseline bytes changed', 'copied package database differs from actual587 lock', 'copier-source-pin-or-drift', 'copier-source-shape', 'copy anchor drift', 'copy byte limit', 'copy depth limit', 'copy descriptor cleanup failed', 'copy destination alias drift', 'copy destination file mount drift', 'copy destination mount drift', 'copy destination nodes differ', 'copy directory drift', 'copy file byte limit', 'copy metadata differs', 'copy mount crossing', 'copy node limit', 'copy parent path drift', 'copy parent rebound', 'copy root path drift', 'copy source alias drift', 'copy source content drift', 'copy source group differs', 'copy source group drift', 'copy source nodes changed', 'copy source parent differs', 'copy source parent drift', 'copy source symlink drift', 'copy write made no progress', 'counts', 'cross-device node', 'cross-device node parent', 'current evidence directory metadata differs', 'current evidence namespace identity differs', 'cyclic payload link', 'database changed during observation', 'database mount crossing refused', 'database package directory changed', 'database record absent from root observation', 'database record changed', 'database record differs from root observation', 'database root alias refused', 'database section absent', 'declared full after map differs', 'declared parent is not a directory', 'declared release file differs', 'declared repository alias differs', 'decoded archive byte bound', 'decoder window budget below gzip minimum', 'descriptor mount identity APIs differ', 'descriptor statx mount identity unavailable', 'device identity refused', 'directory changed during inventory', 'directory content drift', 'directory depth limit', 'directory entry drift', 'directory-shape', 'disjoint-initialization-source', 'disk-backed persistent stage required', 'driver data/copy/source overlap refused', 'driver exit/status disagreement', 'duplicate ALPM package', 'duplicate JSON key', 'duplicate actual package', 'duplicate add or signer refused', 'duplicate database field', 'duplicate database section', 'duplicate hardlink membership', 'duplicate installed ownership', 'duplicate installed package', 'duplicate inventory entry', 'duplicate-key', 'duplicate/nonroot archive member', 'engine deadline refused', 'engine receipt execution identity differs', 'engine receipt refused', 'escaped mount names require explicit review', 'escaping existing filesystem link', 'escaping payload link', 'evidence byte bound', 'evidence descriptor cleanup incomplete', 'evidence descriptor lease replaced; foreign descriptor not closed', 'evidence descriptor lease unavailable; cleanup refused', 'evidence descriptor mount identity changed', 'evidence descriptor mount identity missing', 'evidence descriptor mount outside current namespace', 'evidence directory identity refused', 'evidence file changed', 'evidence file identity refused', 'evidence file pathname replaced', 'evidence pathname identity differs', 'evidence pathname replaced', 'evidence view changed during validation', 'exact caller configuration required', 'exact external helper closure required', 'exact file reference required', 'exact finite scale budgets required', 'exact initial signed604/updater-v2 inventory required', 'exact input digest required', 'exact inventory digest required', 'exact inventory drift', 'exact product commit required', 'exact release record required', 'exact repository selection required', 'exact setup/updater-v2 lock required', 'exact single prepared setup upgrade required', 'exact updater-v2/setup4 scale required', 'exact-apps5-to6-transition', 'exact-apps6-authenticated-archive', 'exact-apps604-after-lock-and-other603', 'exact-apps604-before-lock', 'exact-apps604-scale-locks', 'exact-eight-apps6-files', 'exclusive initial604 full-root route required', 'existing ancestor escapes root', 'existing bound/runtime update did not pass', 'existing copied package database required', 'existing external ephemeral TEST signer required', 'existing package-manager lock refused', 'existing suite case count differs', 'expected post-update lock differs', 'expected-length', 'expected-record', 'expected-string', 'explicit TEST release declarations required', 'explicit absolute driver paths required', 'explicit actual updater-v2→setup4 scale selection required', 'explicit archive limits required', 'explicit boolean release synthetic selection required', 'explicit bound-update nonce required', 'explicit comparator path required', 'explicit disposable namespace/container required', 'explicit disposable release configuration required', 'explicit finite future capacity budget required', 'explicit generic development policy required', 'explicit generic development runtime required', 'explicit generic development selection required', 'explicit initial604 upgrade selection required', 'explicit owned container marker required', 'explicit platform mode required', 'explicit release and platform configuration required', 'explicit scaled disposable configuration required', 'export database entry refused', 'export duplicate package', 'export local database absent', 'export ownership outside mapping', 'export package lock differs', 'export package metadata incomplete', 'export package ownership differs', 'export protected ownership differs', 'export protected payload differs', 'export root ownership refused', 'extended header byte limit exceeded', 'external input changed', 'externally pinned input differs', 'failed receipt bound', 'failed stage predicate only', 'fakeroot-config', 'fd-exec-unavailable', 'file content drift', 'file entry drift', 'file grew during observation', 'file-content', 'file-list bound', 'file-shape', 'filesystem byte bound', 'filesystem node bound', 'finite absolute monotonic deadline required', 'finite caller time budget required', 'finite copy bounds required', 'finite copy deadline required', 'finite deadline required', 'finite nonempty add set required', 'finite original stage clock', 'finite package map required', 'finite positive limit required', 'finite root path limits required', 'finite source bytes required', 'finite source capsule registry required', 'finite timeout required', 'finite total driver deadline required', 'finite worker bounds required', 'finite-source-link-selection', 'fixed evidence filename required', 'fresh disjoint stage required', 'fresh driver data directory required', 'fresh output required', 'fresh private copy required', 'full configuration digest required', 'full supported primary signer required', 'generic exact before/after locks differ', 'generic fixture Source data differs', 'generic fixture Source reference differs', 'generic fixture VM data differs', 'generic fixture duplicate proc field', 'generic fixture exact VM contract required', 'generic fixture fixed tool-profile data differs', 'generic fixture fixed worker location required', 'generic fixture input bytes changed', 'generic fixture input reference refused', 'generic fixture library profile differs', 'generic fixture ordinary guest required', 'generic fixture proc bound', 'generic fixture protected file required', 'generic fixture protected parent required', 'generic fixture real guest marker required', 'generic fixture tool alias differs', 'generic fixture tool closure differs', 'generic fixture worker/runtime pin differs', 'generic fixture zero-capability NNP parent required', 'generic kernel ownership changed', 'generic kernels must be protected', 'generic package-manager/runtime protection required', 'generic policy changed', 'generic policy phase refused', 'generic policy/configuration locks differ', 'generic protected package versions changed or absent', 'generic protected selection differs from authenticated release', 'growing copy source', 'guarded engine did not complete', 'guest device identity differs', 'hardlink alias limit', 'hardlink final drift', 'hardlink group limit', 'hardlink group not closed', 'hardlink groups changed', 'hardlink identity drift', 'hardlink member changed', 'hardlink member differs', 'hardlink member limit', 'hardlink named entry drift', 'hardlink observation required', 'hardlink or oversized file refused', 'hardlink parent changed', 'hardlink parent drift', 'hardlink parent missing or redirected', 'hardlink projection requires explicit mode', 'hardlink retained entry drift', 'hardlinked or oversized node', 'header', 'helper-alias', 'helper-hardlink', 'helper-pin', 'hwcaps-child', 'hwcaps-shape', 'include-content', 'include-directory', 'include-file', 'incomplete provisional receipt', 'incomplete tar zero padding', 'incomplete worker result', 'independent engine specification pin required', 'independently reviewed worker source pin required', 'initial inventory changed before quiescence', 'initial inventory changed before staging', 'initial keyring endpoints reappeared', 'initial signed587 source inventory differs', 'initial-string', 'initial604 keyring checkpoint required', 'initialization-cache-parent-or-temp', 'initialization-deadline', 'initialization-helper-mount', 'initialization-helper-pin', 'initialization-root-shape', 'initialization-source-changed', 'initialization-unrelated-root-change', 'initialization-worker-failed', 'initialized-cache-metadata', 'input bytes differ', 'input file type/mode/size refused', 'installed directory/architecture differs', 'installed package identity missing', 'installed package ownership differs', 'installed payload differs', 'insufficient disposable transaction capacity', 'insufficient future transaction bytes/inodes', 'insufficient or unknown filesystem free inode count', 'internal hardlinks require one device', 'invalid aggregate accounting', 'invalid aggregate counter', 'invalid copy hardlink mode', 'invalid hardlink content', 'invalid hardlink group record', 'invalid hardlink membership', 'invalid hardlink metadata', 'invalid hardlink observation mode', 'invalid installed identity', 'invalid owned package name', 'invalid package identity', 'invalid package path', 'invalid projected symlink', 'invalid release identity', 'invalid root path encoding', 'invalid root path text', 'isolated public transaction keyring failed', 'isolated source/workspace mounts required', 'layout', 'libalpm ABI changed', 'libalpm binary changed', 'libalpm list bound', 'link-target', 'listing-bound', 'listing-directory', 'listing-drift', 'listing-identity', 'listing-mount', 'live transaction observation required', 'loaded package identity differs', 'magic', 'main-cache-content-changed', 'main-config-pin', 'malformed database field', 'mapped disposable Linux root required', 'mapped x86 Linux namespace required', 'marked native owned container required', 'measured precommit capacity insufficient', 'member changed during inventory', 'member file byte limit exceeded', 'missing complete tar end marker', 'missing-fakeroot-config', 'missing-fakeroot-directory', 'mount crossing refused', 'mount identity byte limit', 'mount identity inventory refused', 'mount identity unavailable', 'mount propagation is not private', 'named copy source drift', 'named entry drift', 'named node drift', 'named retained evidence metadata differs', 'named-map', 'named-node-drift', 'namespace metadata byte bound', 'native fixture suite failed', 'native libalpm pin differs', 'native profile admits inert fixture identities only', 'native receiver profile differs', 'native receiver source grant absent', 'native root container required', 'native source/phase selection differs', 'native tiny checks failed', 'network-isolated disposable caller required', 'network-none clean container required', 'network-none container required', 'new fixed evidence output required', 'no original scan difference', 'node depth limit', 'node parent path drift', 'node-or-mount-drift', 'noncanonical payload path', 'nonfinite JSON', 'nonnegative finite capacity demand required', 'nonselected database changed', 'observed directory differs', 'observed file content changed', 'observed file differs', 'observed node changed', 'observed node drift', 'observed node missing', 'observed seed required', 'observed symlink differs', 'observed-node-missing', 'observed-seed', 'one committed disposed-copy upgrade required', 'one exact public primary certificate required', 'one existing changed package required', 'one selected604 root package limit', 'one selected607 package default', 'one-shot copied-root initialization did not pass', 'only bounded gzip/xz fixture archives supported', 'only failed evidence may be revoked', 'only gzip/xz/zstd archives supported', 'only pinned x86 synthetic engine supported', 'only retained setup3→4 permitted', 'ordinary absolute source required', 'ordinary explicit parent required', 'ordinary mount file changed', 'ordinary mount file grew', 'ordinary mount file hardlink refused', 'ordinary mount file required', 'ordinary native ARM coordinator required', 'ordinary package descriptor required', 'ordinary tracked source required', 'original bundle drifted', 'original input bytes drifted', 'original input identity drifted', 'outer inventory changed during staging', 'outer source inventory changed during copied upgrade', 'overlapping copy roots', 'overlapping installed file ownership', 'overlapping installed ownership', 'owned cleanup depth limit', 'owned cleanup node limit', 'owned cleanup output required', 'owned cleanup parent drift', 'owned cleanup path or mount drift', 'owned container name required', 'owned container remains', 'owned copied root required', 'owned copy descriptor cleanup failed', 'owned copy disposal not confirmed', 'owned evidence file mode required', 'owned image remains', 'owned immutable image ID required', 'owned initial keyring agent endpoints remain', 'owned non-writable-by-others copy parent required', 'owned persistent payload absent', 'owned private copy parent required', 'owned private staging parent required', 'owned private volume required', 'owned private workspace required', 'owned seeded cache required', 'owned separate measurement volume required', 'owned source capsules pending disposal', 'owned workspace identity unavailable; retained', 'package descriptor bound', 'package downgrade refused', 'package identity refused', 'package inventory changed during copy', 'package inventory limit', 'package ownership bound', 'package payload overlap', 'package writes protected platform/trust path', 'package writes protected service', 'package-manager handle release failed', 'package-manager transaction lock release failed', 'packages committed but checkpoint durability uncertain', 'path depth limit', 'payload exceeds declared file size', 'payload hardlink marker refused', 'payload-touches-auxiliary-closure', 'pending evidence identity changed', 'persistent baseline changed after staging', 'persistent copy skipped special nodes', 'persistent directory changed', 'persistent directory drift', 'persistent directory mount crossing', 'persistent file byte limit', 'persistent file mount crossing', 'persistent hardlink alias limit', 'persistent hardlink drift', 'persistent hardlink group limit', 'persistent hardlink group not closed', 'persistent initial keyring/database changed', 'persistent named entry drift', 'persistent outer source preservation refused', 'persistent root path drift', 'persistent scope byte limit', 'persistent scope depth limit', 'persistent scope node limit', 'persistent source changed during materialization', 'persistent source changed during verification', 'persistent source coverage refused', 'persistent special node refused', 'persistent verification stage differs', 'pinned exact composition lock required', 'positive finite scale limit required', 'postcommit actual database differs', 'precommit-checkpoint-required', 'private authentication command failed', 'private container environment required', 'private directory ownership required', 'private key directory type refused', 'private key material refused', 'private libalpm initialize failed', 'private writable mounts missing', 'projected byte limit', 'projected depth limit', 'projected file byte limit', 'projected file content observation missing', 'projected input limit', 'projected node limit', 'projected node/byte bound', 'projected parent missing or not directory', 'protected delta refused', 'protected package absent', 'protected package file changed', 'protected payload changed after commit', 'protected payload changed before commit', 'public certificate inspection failed', 'public certificate must not contain secret key packets', 'public log bound', 'public result bound', 'read-bound', 'read-only actual package query failed', 'read-size', 'real candidate/unadopted inputs are not authorized by this initial worker', 'real committed durable update required', 'receipt bound', 'receipt changed while reading', 'recursive read-only barrier refused', 'regular source capsule required', 'release changed during snapshot', 'release exceeds tiny-root package limit', 'release selects protected platform package', 'remove identity differs or overlaps add', 'remove package absent', 'remove version differs', 'required protected unit names must be preserved', 'retained evidence inode changed', 'retained evidence inode required', 'retained evidence required', 'retained inherited evidence FD required', 'reviewed copied-root initialization API required before updater baseline', 'reviewed mount encoding required', 'root byte limit', 'root changed before commit', 'root changed while constructing TEST repository', 'root file byte limit', 'root identity drift', 'root mount drift', 'root node limit', 'root observation deadline', 'root observation required', 'root path byte limit', 'root path depth limit', 'root path drift', 'root path escapes observed root', 'root path node limit', 'root path parent is not directory', 'root path symlink cycle', 'root path symlink expansion limit', 'root path trace limit', 'root path work limit', 'root-changed-before-commit', 'runtime directory required', 'runtime or mount-file alias refused', 'sanitized test log bound', 'scale configuration changed', 'scan-alias', 'scan-byte-bound', 'scan-directory', 'scan-entry-bound', 'secret key material refused', 'secret key record refused', 'seed ownership outside namespace mapping', 'selected external helper bytes changed', 'selected generic fixture required', 'selected hardlink path touched', 'selected installed version differs from release baseline', 'selected native fixture profile required', 'selected native profile absent', 'selected old path missing', 'selected old removal missing', 'selected package removes actual protected ownership', 'selected package writes actual protected ownership', 'selected payload removal unsupported', 'selected release digest differs', 'selected release synthetic label or identity differs', 'selected root required', 'selected scope API origin differs', 'selected-data-endpoint-drift', 'selected-data-link-drift', 'selected-data-parent-shape', 'selected-link-endpoint-drift', 'selected-literal-link-drift', 'selected-payload-removal-unsupported', 'selected-root', 'selected-var-lock-data-shape', 'self-referential release refused', 'semantic release selection differs', 'separate TEST signer mount required', 'service IPC seccomp guard refused', 'setup-parent-metadata', 'setup-payload-path', 'signature signer/status refused', 'single-mount staged copy required', 'size', 'snapshot member bound exceeded', 'snapshot root changed during inventory', 'snapshot total byte bound exceeded', 'source capsule cleanup incomplete; ownership retained', 'source capsule close did not close owned descriptor', 'source capsule descriptor identity changed', 'source capsule identity unavailable; ownership retained', 'source capsule write made no progress', 'source directory content drift', 'source directory drift', 'source file drift', 'source mount table changed', 'source root drift', 'source/output/cache must be separate', 'sparse archive member refused', 'special filesystem node refused', 'special node refused', 'special snapshot member refused', 'stage must be outside persistent source data', 'stage parent changed or aliased', 'staged ownership coverage differs', 'staged package records differ', 'stale-or-unobserved-aux-key', 'strict-auxiliary-only-observation', 'string file reference path required', 'string-coverage', 'string-offset', 'string-termination', 'target-budget', 'target-parent', 'target-pin', 'temporary-cache', 'trailing or concatenated compressed frame refused', 'trailing or concatenated tar data refused', 'trial-copied-root', 'trial-root-workspace', 'truncated compressed frame', 'truncated member payload', 'typed original node maps', 'unaccounted removal', 'unambiguous mount table required', 'unaudited auxiliary executable or alias refused', 'unaudited auxiliary executable refused', 'unaudited auxiliary ldconfig alias refused', 'unaudited auxiliary ldconfig refused', 'unexcluded cross-device source', 'unexpected control member', 'unexpected exposed device', 'unexpected local database node', 'unexpected owned container query', 'unexpected secret-listing record', 'unexpected writable inherited mount', 'unexpected-node', 'unique package descriptor identity required', 'unknown fixture selection', 'unknown hardlink member', 'unowned evidence name refused', 'unrecognized source mount refused', 'unrelated root content changed', 'unrelated-root-content-changed', 'unsafe package database directory', 'unsafe package path', 'unselected-absolute-link', 'unselected-root-shape', 'unsupported local database version', 'unsupported or incomplete root observation', 'unsupported projected shape', 'unsupported scale ceilings', 'unsupported seccomp architecture', 'unsupported update operation', 'unsupported update operations', 'unsupported-link-chain', 'update configuration changed', 'updater-v2 baseline required', 'user files changed', 'verification mount table changed', 'verified initial587 inventory differs', 'verified selection differs', 'verified staged database differs', 'whole original cost copier source', 'whole original inner relative validator source', 'whole original lifetime source', 'whole original relative validator source', 'whole persistent observation API source', 'workspace required', 'xz archive incomplete/concatenated or oversized')

def _normal_primary_record(error, where, path=None):
    """Source literal reasons and relative names only; no content/locals dump."""
    try:
        import base64,hashlib
        def part(value):
            raw=value.encode('utf-8','surrogatepass')
            return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),prefix_base64=base64.b64encode(raw[:256]).decode(),prefix_bytes=min(len(raw),256),truncated=len(raw)>256)
        message=str(error);allowed=type(error) is ValueError and message in _NORMAL_REASON_LITERALS
        if path is None:
            trace=error.__traceback__
            while trace is not None:
                frame=trace.tb_frame
                if frame.f_code.co_name=='walk' and frame.f_code.co_filename.endswith(('/full_root.py','/persistent_scope.py')):
                    candidate=frame.f_locals.get('name',frame.f_locals.get('prefix'))
                    if type(candidate) is str:path=candidate
                trace=trace.tb_next
        valid=type(path) is str and not path.startswith('/') and '\0' not in path and all(x not in('.','..') for x in path.split('/'))
        value=dict(schema_version=1,status='NORMAL_PRIMARY_EXCEPTION_DATA_NOT_ACCEPTANCE',where=where,error_type=type(error).__name__[:64],message=part(message) if allowed else None,message_disposition='SOURCE_LITERAL_EXACT_OR_PREFIX' if allowed else 'UNREVIEWED_TEXT_OMITTED',path=part(path) if valid else None,path_disposition='OBSERVED_RELATIVE_NAME' if valid else 'UNKNOWN_OR_ABSOLUTE_OMITTED',cleanup_authority=False,transaction_authority=False)
        if len(json.dumps(value,sort_keys=True,separators=(',',':')).encode())<=1800:return value
    except BaseException:pass
    return None

def _normal_primary_valid(value):
    try:
        import base64,hashlib
        keys={'schema_version','status','where','error_type','message','message_disposition','path','path_disposition','cleanup_authority','transaction_authority'}
        if type(value)is not dict or set(value)!=keys or type(value['schema_version'])is not int or value['schema_version']!=1 or value['status']!='NORMAL_PRIMARY_EXCEPTION_DATA_NOT_ACCEPTANCE' or value['cleanup_authority']is not False or value['transaction_authority']is not False:return False
        if value['where']not in ('NORMAL_ROOT_OBSERVATION','COPIED_ROOT_INITIALIZATION','DRIVER_CATCH','CALLER_SOURCE_WALK','CALLER_SOURCE_HARDLINKS','CALLER_CATCH','INITIALIZER_WORKER'):return False
        if type(value['error_type'])is not str or not 0<len(value['error_type'])<=64 or not value['error_type'].isascii() or not all(c.isalnum()or c=='_'for c in value['error_type']):return False
        for key in ('message','path'):
            row=value[key]
            if row is None:continue
            if type(row)is not dict or set(row)!={'bytes','sha256','prefix_base64','prefix_bytes','truncated'}:return False
            if type(row['bytes'])is not int or not 0<=row['bytes']<2**63 or type(row['prefix_bytes'])is not int or row['prefix_bytes']!=min(row['bytes'],256) or type(row['truncated'])is not bool or row['truncated']!=(row['bytes']>256):return False
            if type(row['sha256'])is not str or len(row['sha256'])!=64 or any(c not in '0123456789abcdef'for c in row['sha256'])or type(row['prefix_base64'])is not str:return False
            raw=base64.b64decode(row['prefix_base64'],validate=True)
            if len(raw)!=row['prefix_bytes'] or base64.b64encode(raw).decode()!=row['prefix_base64'] or (not row['truncated']and hashlib.sha256(raw).hexdigest()!=row['sha256']):return False
            if key=='message':
                expected=[]
                for literal in _NORMAL_REASON_LITERALS:
                    encoded=literal.encode('utf-8','surrogatepass')
                    expected.append(dict(bytes=len(encoded),sha256=hashlib.sha256(encoded).hexdigest(),prefix_base64=base64.b64encode(encoded[:256]).decode(),prefix_bytes=min(len(encoded),256),truncated=len(encoded)>256))
                if value['error_type']!='ValueError' or row not in expected:return False
            if key=='path'and (raw.startswith(b'/')or b'\0'in raw or any(x in(b'.',b'..')for x in raw.split(b'/'))):return False
        if value['message_disposition']!=('SOURCE_LITERAL_EXACT_OR_PREFIX'if value['message']is not None else'UNREVIEWED_TEXT_OMITTED')or value['path_disposition']!=('OBSERVED_RELATIVE_NAME'if value['path']is not None else'UNKNOWN_OR_ABSOLUTE_OMITTED'):return False
        return len(json.dumps(value,sort_keys=True,separators=(',',':')).encode())<=1800
    except BaseException:return False

def _normal_worker_summary(value):
    try:
        keys={'status','returncode','termination','direct_child_reaped','stderr','primary','unframed_stderr','authority'}
        if type(value)is not dict or set(value)!=keys or value['status']!='ORIGINAL_INITIALIZER_WORKER_FAILURE_DATA_NOT_ACCEPTANCE'or value['unframed_stderr']!='OMITTED_NO_TRACEBACK_OR_CONTENT_EXPORT'or value['authority']!='DIAGNOSTIC_ONLY':return None
        if value['returncode']is not None and (type(value['returncode'])is not int or not -255<=value['returncode']<=255):return None
        if value['termination']not in (None,'timeout','output-limit','interrupted')or type(value['direct_child_reaped'])is not bool:return None
        row=value['stderr']
        if type(row)is not dict or set(row)!={'bytes','sha256'}or type(row['bytes'])is not int or not 0<=row['bytes']<=65536 or type(row['sha256'])is not str or len(row['sha256'])!=64 or any(c not in '0123456789abcdef'for c in row['sha256']):return None
        if value['primary']is not None and not _normal_primary_valid(value['primary']):return None
        return {key:val for key,val in value.items()if key!='primary'}
    except BaseException:return None


def need(ok, reason):
    if not ok: raise ValueError(reason)


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def ordinary(path, limit=1024**2):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts and
         not any(p.is_symlink() for p in (path, *path.parents)), 'ordinary absolute source required')
    info = path.stat()
    need(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= limit, 'bounded ordinary source required')
    return path


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ordinary(path))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def configuration(path=CONFIG, code=CODE):
    value = json.loads(ordinary(path).read_bytes())
    need(type(value) is dict and set(value) == {
        'schema_version', 'purpose', 'code_pins', 'external_pins', 'scale',
        'stage_seconds', 'verify_seconds', 'copy_seconds', 'driver_seconds', 'release'}, 'exact caller configuration required')
    need(value['schema_version'] == 1 and value['purpose'] == 'actual-apps6-current604-persistent-root-test',
         "explicit initial604 upgrade selection required")
    for key, ceiling in (('stage_seconds', 1200), ('verify_seconds', 600), ('copy_seconds', 4260), ('driver_seconds', 10440)):
        need(type(value[key]) is int and 0 < value[key] <= ceiling, 'finite caller time budget required')
    pins = value['code_pins']
    need(type(pins) is dict and DRIVER in pins and
         'scripts/ci/full-root-upgrade/construct_repository.py' in pins and
         all('scripts/update/' + name + '.py' in pins for name in (
             'aux_copy', 'aux_initialize', 'linked_runtime', 'root_link_selection', 'supervision')),
         'complete explicit code closure required')
    for relative, expected in pins.items():
        need(type(relative) is str and not Path(relative).is_absolute() and '..' not in Path(relative).parts
             and re.fullmatch('[0-9a-f]{64}', expected), 'code source pin shape')
        need(digest(ordinary(code / relative)) == expected, 'selected code bytes changed: ' + relative)
    external = value['external_pins']
    need(type(external) is dict and set(external) == {'/setup4.py', '/footprint.py', '/persistent_scope.py'},
         'exact external helper closure required')
    for name, expected in external.items():
        need(re.fullmatch('[0-9a-f]{64}', expected) and digest(ordinary(name)) == expected,
             'selected external helper bytes changed')
    need(value['scale']['before_lock_sha256'] == BEFORE and value['scale']['after_lock_sha256'] == AFTER
         and value['scale']['platform_mode'] == 'generic-development', 'exact updater-v2/setup4 scale required')
    release = value['release']
    need(type(release) is dict and set(release) == {
        'release_id', 'repo_name', 'namespace', 'sequence', 'issued_utc', 'expires_utc', 'supported_models'}
         and release['supported_models'] == ['m2-air-13', 'm2-air-15'], 'explicit TEST release declarations required')
    return value


def selected_links(code):
    # The frozen literal list is source policy; runtime observations cannot grant it.
    links = load('root_link_selection', code / 'scripts/update/root_link_selection.py')
    need(len(links.CHAIN_PATHS) == 87 and len(links.LINK_NODES) >= 87,
         'Root must freeze the complete actual87 literal link selection before dispatch')


def quiesce(plan, expected, source, composition, roots):
    "Retain the existing keyring guards, with initial604 selection kept explicit."
    need(len(expected) == 607 and expected.get('cachy-asahi-apps') == '0.1.0-6'
         and expected.get('cachy-asahi-update') == '4.4.2-2', "initial604 keyring checkpoint required")
    helper = load("initial604_keyring_helper", Path('/setup4.py'))
    measurement = load("initial604_keyring_reads", Path('/footprint.py'))
    core, _provider = composition.lifecycle_helpers(plan['setup4'], source)
    limits = roots.Limits(deadline=time.monotonic() + 120, max_nodes=20000,
                          max_bytes=256 * 1024**2, max_file_bytes=32 * 1024**2)
    helper._keyring_guard(roots, limits)
    need(composition.inventory() == expected, 'initial inventory changed before quiescence')
    before = helper._persistent_state(roots, measurement, limits)
    fingerprints = helper._keyring_fingerprints(core, plan['signer_fingerprint'])
    present = helper._agent_sockets()
    if present:
        helper._bounded_keyring(core, ['/usr/bin/gpgconf', '--homedir', str(helper.KEYRING_HOME), '--kill', 'gpg-agent'])
    need(not helper._agent_sockets(), 'owned initial keyring agent endpoints remain')
    need(helper._keyring_fingerprints(core, plan['signer_fingerprint']) == fingerprints
         and helper._persistent_state(roots, measurement, limits) == before
         and composition.inventory() == expected, 'persistent initial keyring/database changed')
    helper._keyring_guard(roots, limits)
    need(not helper._agent_sockets(), 'initial keyring endpoints reappeared')
    return {'status': 'PASS-absence-verified', 'initial_endpoints': len(present),
            'persistent_keyring_config_preserved': True, 'package_database_inventory_preserved': True}


def driver_command(config, control, stage, signer, code=CODE, pair=PAIR, signing=SIGNING):
    package = pair / 'public/packages/cachy-asahi-apps-a/cachy-asahi-apps-0.1.0-16-any.pkg.tar.xz'
    options = dict(source_root=code, runtime=code / 'scripts/update/linked_runtime.py',
        runtime_sha256=config['code_pins']['scripts/update/linked_runtime.py'],
        initializer=code / 'scripts/update/aux_initialize.py',
        initializer_sha256=config['code_pins']['scripts/update/aux_initialize.py'],
        comparator=code / 'scripts/ci/full-development-composition/audio_aux.py',
        source=stage, workspace=control / 'copy', data=control / 'data',
        scale=control / 'scale.json', scale_sha256=digest(control / 'scale.json'),
        setup4_pair=pair, package=package, provenance=pair / 'public/runtime/cachy-asahi-apps-a/provenance.json',
        gpg_home=signing, signer=signer, copy_seconds=config['copy_seconds'],
        seconds=config['driver_seconds'], **{k: v for k, v in config['release'].items() if k != 'supported_models'})
    # The hook owns supervision. Direct worker avoids a second nested supervisor
    # and uses the driver's existing explicit aux/copy/initializer connection.
    argv = [sys.executable, '-I', '-B', str(code / DRIVER), '--worker', '--auxiliary-runtime']
    for key, value in options.items(): argv.extend(('--' + key.replace('_', '-'), str(value)))
    return argv + ['--supported-models', *config['release']['supported_models']]


def driver_result(row):
    unknown = dict(status='FAIL', phase='driver-worker', commit_started='UNKNOWN',
                   packages_committed='UNKNOWN', checkpoint_changed='UNKNOWN')
    if row.get('termination') is not None or row.get('direct_child_reaped') is not True or row.get('returncode') not in (0, 1):
        return unknown
    try:
        value = json.loads(row['stdout'])
        need(type(value) is dict and value.get('status') in ('PASS', 'FAIL') and
             all(k in value for k in ('commit_started', 'packages_committed', 'checkpoint_changed')),
             'complete driver commit truth required')
        need((row['returncode'] == 0) == (value['status'] == 'PASS'), 'driver exit/status disagreement')
        return value
    except (ValueError, TypeError, KeyError): return unknown


_lifecycle_ci=load('_private_lifecycle_ci',CODE/'scripts/ci/full-root-upgrade/lifecycle_ci.py')


def _normal_primary_emit(result):
    """Final compact stderr frame independent of nested driver stdout tail."""
    try:
        nonce=os.environ.get('CACHY_ASAHI_BOUND_UPDATE','')
        if len(nonce)!=32 or any(x not in '0123456789abcdef' for x in nonce):return
        driver=result.get('driver',{});init=driver.get('initialization',{})
        first=init.get('primary_failure') or driver.get('primary_failure');current=result.get('primary_failure')
        first=first if _normal_primary_valid(first) else None
        current=current if _normal_primary_valid(current) else None
        rows=[r for r in (first,current) if _normal_primary_valid(r)]
        if not rows:return
        value=dict(schema_version=1,status='NORMAL_PRIMARY_FAILURES_DATA_NOT_ACCEPTANCE',nonce=nonce,initialization=first,initializer_worker=_normal_worker_summary(init.get('initializer_worker_failure')),caller_verification_or_catch=current,authority='DIAGNOSTIC_ONLY_NO_TRANSACTION_OR_CLEANUP_AUTHORITY')
        raw=('UPDATER607_PRIMARY_FAILURE '+json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
        if len(raw)<=4096:os.write(2,raw)
    except BaseException:pass



_INITIALIZER_PHASES = ('WORKER_OBSERVE', 'WORKER_CHECKPOINT', 'WORKER_HELPER_PIN', 'WORKER_EXEC', 'PARENT_SOURCE_BEFORE', 'PARENT_ROOT_BEFORE', 'PARENT_ROOT_AFTER', 'PARENT_SOURCE_AFTER')
_INITIALIZER_PROFILE = 'I16K_STATX_V1'
_INITIALIZER_PREFIX = b'UPDATER607_INITIALIZER_TELEMETRY '
_INITIALIZER_MAX = 2**63-1

def _initializer_valid(value, nonce=None):
    if type(value) is not dict or set(value) != {'v','profile','nonce','lane','seq','phase','state','elapsed_ns','remaining_ns','ops','saturated'}:return False
    if type(value['v'])is not int or value['v']!=1 or value['profile']!=_INITIALIZER_PROFILE:return False
    n=value['nonce']
    if type(n)is not str or len(n)!=32 or any(c not in '0123456789abcdef'for c in n)or(nonce is not None and n!=nonce):return False
    lane=value['lane']
    if lane not in ('WORKER','PARENT')or type(value['seq'])is not int or not 0<=value['seq']<(6 if lane=='WORKER'else 8):return False
    if value['phase']not in _INITIALIZER_PHASES or not value['phase'].startswith(lane+'_')or value['state']not in ('STARTED','PROGRESS','RETURNED','REFUSED'):return False
    if type(value['elapsed_ns'])is not int or not 0<=value['elapsed_ns']<=_INITIALIZER_MAX:return False
    r=value['remaining_ns']
    if r is not None and(type(r)is not int or not -_INITIALIZER_MAX<=r<=_INITIALIZER_MAX):return False
    if type(value['ops'])is not list or len(value['ops'])!=8 or any(type(x)is not int or not 0<=x<=_INITIALIZER_MAX for x in value['ops'])or type(value['saturated'])is not bool:return False
    return len(_INITIALIZER_PREFIX)+len(json.dumps(value,sort_keys=True,separators=(',',':')).encode())+1<=768

def _initializer_capture(raw, nonce, complete=True):
    if type(raw)is not bytes or len(raw)>1024**2:return None,0
    lines=[line[len(_INITIALIZER_PREFIX):]for line in raw.splitlines()if line.startswith(_INITIALIZER_PREFIX)]
    if not 1<=len(lines)<=(6 if complete else 128):return None,0
    records=[]
    try:
        for i,line in enumerate(lines):
            if len(line)+len(_INITIALIZER_PREFIX)+1>768:return None,0
            def pairs(items):
                value={}
                for key,item in items:
                    if key in value:raise ValueError('duplicate initializer telemetry key')
                    value[key]=item
                return value
            value=json.loads(line,object_pairs_hook=pairs)
            if not _initializer_valid(value,nonce)or value['lane']!='WORKER'or(complete and value['seq']!=i):return None,0
            if complete and records and(value['elapsed_ns']<records[-1]['elapsed_ns']or any(a<b for a,b in zip(value['ops'],records[-1]['ops']))):return None,0
            records.append(value)
    except(ValueError,TypeError,KeyError,UnicodeError,RecursionError):return None,0
    return records[-1],len(records)

def _initializer_emit(value):
    if not _initializer_valid(value,os.environ.get('CACHY_ASAHI_BOUND_UPDATE','')):return
    raw=_INITIALIZER_PREFIX+json.dumps(value,sort_keys=True,separators=(',',':')).encode()+b'\n'
    try:os.write(2,raw)
    except OSError as error:
        # Ordinary diagnostic IO loss is not an acceptance predicate. The held
        # phase alarm raises TimeoutError without errno and must still propagate.
        if error.errno is None:raise

def _initializer_wrapper_valid(value,nonce):
    if type(value)is not dict or set(value)!={'v','profile','history','saturated','worker'}or type(value['v'])is not int or value['v']!=1 or value['profile']!=_INITIALIZER_PROFILE or type(value['saturated'])is not bool:return False
    history=value['history']
    if type(history)is not list or len(history)>8:return False
    for i,record in enumerate(history):
        if not _initializer_valid(record,nonce)or record['lane']!='PARENT'or record['seq']!=i:return False
        if i and(record['elapsed_ns']<history[i-1]['elapsed_ns']or any(a<b for a,b in zip(record['ops'],history[i-1]['ops']))):return False
    worker=value['worker']
    if worker is not None:
        if type(worker)is not dict or set(worker)!={'last','records','stderr','returncode','termination','direct_child_reaped','capture_scope'}or worker['capture_scope']!='ORIGINAL_SUPERVISOR_CAPTURE_MAY_BE_PARTIAL':return False
        if type(worker['records'])is not int or not 0<=worker['records']<=6 or type(worker['direct_child_reaped'])is not bool or worker['termination']not in(None,'timeout','output-limit','interrupted'):return False
        if worker['returncode']is not None and(type(worker['returncode'])is not int or not -255<=worker['returncode']<=255):return False
        last=worker['last']
        if worker['records']==0:
            if last is not None:return False
        elif not _initializer_valid(last,nonce)or last['lane']!='WORKER'or last['seq']!=worker['records']-1:return False
        pin=worker['stderr']
        if type(pin)is not dict or set(pin)!={'bytes','sha256'}or type(pin['bytes'])is not int or not 0<=pin['bytes']<=65536 or type(pin['sha256'])is not str or len(pin['sha256'])!=64 or any(c not in '0123456789abcdef'for c in pin['sha256']):return False
    return len(json.dumps(value,sort_keys=True,separators=(',',':')).encode())<=8192

def _initializer_final_emit(result, fallback):
    value=fallback
    driver=result.get('driver')
    if type(driver)is dict:
        initialization=driver.get('initialization')
        if type(initialization)is dict:
            telemetry=initialization.get('initializer_telemetry')
            if _initializer_wrapper_valid(telemetry,os.environ.get('CACHY_ASAHI_BOUND_UPDATE','')):
                worker=telemetry.get('worker')
                if type(worker)is dict and _initializer_valid(worker.get('last'),os.environ.get('CACHY_ASAHI_BOUND_UPDATE','')):value=worker['last']
    _initializer_emit(value)


def run(pacman, plan, expected, source, work, composition):
    result = dict(status='FAIL', phase='selection', committed_transactions=0,
                  commit_started=False, packages_committed=False, checkpoint_changed=False,
                  scope='complete-persistent-payload-in-disposable-container', whole_container_root=False,
                  hardware='NOT RUN', apple_acceptance='NOT ESTABLISHED', outer_cleanup='OWNER REQUIRED')
    _initializer_last=None
    try:
        composition.guard()
        need(plan.get('full_root_upgrade') is True and not plan.get('measurement_only')
             and not ({'audio', 'lifecycle', 'updater_v2'} & set(plan)), "exclusive initial604 full-root route required")
        need(len(expected) == 607 and hashlib.sha256(''.join(
            f'{name} {version}\n' for name, version in sorted(expected.items())).encode()).hexdigest() == BEFORE,
            "exact initial signed604/updater-v2 inventory required")
        config = _lifecycle_ci.release_window(configuration())
        sys.path.insert(0, str(CODE / 'scripts/update'))
        selected_links(CODE)
        roots = load('caller_stage_roots', CODE / 'scripts/update/full_root.py')
        supervision = load('caller_upgrade_supervision', CODE / 'scripts/update/supervision.py')
        scope = load('caller_persistent_scope', Path('/persistent_scope.py'))
        need(VOLUME.is_dir() and not VOLUME.is_symlink() and os.stat(VOLUME).st_uid == os.geteuid()
             and not os.stat(VOLUME).st_mode & 0o022, 'owned private volume required')
        control = VOLUME / 'upgrade-control'
        control.mkdir(mode=0o700)
        (control / 'data').mkdir(mode=0o700)
        (control / 'scale.json').write_text(json.dumps(config['scale'], sort_keys=True) + '\n')
        load('caller_scale_validation', CODE / 'scripts/update/scale_update.py').configuration(
            control / 'scale.json', digest(control / 'scale.json'))
        result['phase'] = 'initial-keyring-quiescence'
        result['keyring_quiescence'] = quiesce(plan, expected, source, composition, roots)
        need(composition.inventory() == expected, 'initial inventory changed before staging')
        limits = config['scale']['limits']
        stage_limits = roots.Limits(deadline=_lifecycle_ci.deadline(config['stage_seconds']),
            max_nodes=limits['root_nodes'], max_bytes=limits['root_bytes'],
            max_file_bytes=limits['file_bytes'], max_package_files=limits['package_files'])
        result['phase'] = 'complete-persistent-source'
        stage = control / 'persistent-source'
        result['persistent_source'] = scope.materialize(Path('/'), stage, CODE, stage_limits)
        need(result['persistent_source']['status'] == 'PASS', 'persistent source coverage refused')
        need(composition.inventory() == expected, 'outer inventory changed during staging')
        signer = plan['test_signer_fingerprint']
        need(re.fullmatch('[0-9A-F]{40}', signer) and SIGNING.is_dir() and not SIGNING.is_symlink(),
             'existing external ephemeral TEST signer required')
        env = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'LANG': 'C', 'HOME': str(control),
               'TMPDIR': str(control), 'PYTHONDONTWRITEBYTECODE': '1',
               'CACHY_ASAHI_BOUND_UPDATE': os.environ['CACHY_ASAHI_BOUND_UPDATE'],**{k:os.environ[k]for k in ('LIFECYCLE_GUEST_DEADLINE_NS','LIFECYCLE_LAUNCHER_EPOCH','LIFECYCLE_SOURCE_SHA')}}
        need(re.fullmatch('[0-9a-f]{32}', env['CACHY_ASAHI_BOUND_UPDATE']), 'explicit bound-update nonce required')
        result.update(phase='single-copied-root-upgrade', commit_started='UNKNOWN',
                      packages_committed='UNKNOWN', checkpoint_changed='UNKNOWN')
        row = supervision.run(driver_command(config, control, stage, signer), env=env, cwd=str(CODE),
                              timeout=_lifecycle_ci.guest_witness(config['driver_seconds'])['effective_seconds'], output_limit=1024**2)
        _initializer_last,_=_initializer_capture(row.get('stderr'),os.environ.get('CACHY_ASAHI_BOUND_UPDATE',''),complete=False)
        _initializer_emit(_initializer_last)
        result['worker_diagnostic'] = load('normal604_driver_progress', CODE / 'scripts/ci/full-root-upgrade/driver_progress.py').capture(row, control / 'data')
        _updater_cost_forward.forward(row)
        driver = driver_result(row)
        result['driver'] = driver
        result['worker'] = {k: row[k] for k in ('returncode', 'termination', 'direct_child_reaped', 'group_kill_sent')}
        for key in ('commit_started', 'packages_committed', 'checkpoint_changed'):
            result[key] = driver.get(key, 'UNKNOWN')
        result['committed_transactions'] = driver.get('committed_transactions', 'UNKNOWN')
        need(composition.inventory() == expected, 'outer source inventory changed during copied upgrade')
        result['outer_source_inventory_preserved'] = True
        # Re-observe complete persistent bytes/metadata and all ownership after the
        # driver; the stage must still match its original source, including caches.
        verify_limits = roots.Limits(deadline=_lifecycle_ci.deadline(config['verify_seconds']),
            max_nodes=limits['root_nodes'], max_bytes=limits['root_bytes'],
            max_file_bytes=limits['file_bytes'], max_package_files=limits['package_files'])
        result['persistent_source_after'] = scope.verify(Path('/'), stage, CODE, verify_limits)
        need(result['persistent_source_after']['source_manifest_sha256'] ==
             result['persistent_source']['source_manifest_sha256'], 'persistent baseline changed after staging')
        need(driver.get('status') == 'PASS' and driver.get('committed_transactions') == 1
             and driver.get('copy_cleanup') == 'PASS-owned-workspace-removed', 'one committed disposed-copy upgrade required')
        need(result['persistent_source_after']['status'] == 'PASS', 'persistent outer source preservation refused')
        result.update(status='PASS', phase='completed', committed_transactions=1,
                      persistent_source_preserved=True, transaction_acceptance='GENERIC SOFTWARE ONLY')
    except BaseException as error:
        result['primary_failure'] = getattr(error, '_normal_primary_failure', None) or _normal_primary_record(error, 'CALLER_CATCH')
        result.update(status='FAIL', error_type=type(error).__name__, error=str(error)[:512])
    finally:
        _normal_primary_emit(result)
        _initializer_final_emit(result,_initializer_last)
    return result
