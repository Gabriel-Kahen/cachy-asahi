#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Per-caller bounded ALPM inventory and descriptor-relative root observations."""
import ctypes as C
from dataclasses import dataclass
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import posixpath
import stat
import time

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location('_full_root_installer', ROOT / 'scripts/install/local_transaction.py')
installer = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(installer)

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
    if not ok:
        raise ValueError(reason)


@dataclass(frozen=True)
class Limits:
    deadline: float
    max_packages: int = 607
    max_nodes: int = 500000
    max_bytes: int = 8 * 1024**3
    max_file_bytes: int = 1024**3
    max_package_files: int = 100000
    max_depth: int = 128
    max_unsupported: int = 64
    allow_cross_device: bool = False
    max_hardlink_groups: int = 4096
    max_hardlink_aliases: int = 16384
    max_hardlink_members: int = 4096

    def __post_init__(self):
        need(type(self.deadline) in (int, float) and math.isfinite(self.deadline), 'finite deadline required')
        for name in ('max_packages', 'max_nodes', 'max_bytes', 'max_file_bytes',
                     'max_package_files', 'max_depth', 'max_unsupported',
                     'max_hardlink_groups', 'max_hardlink_aliases', 'max_hardlink_members'):
            value = getattr(self, name)
            need(type(value) is int and 0 < value <= 2**63 - 1, 'finite positive limit required')
        need(self.max_packages <= 4096 and self.max_depth <= 256
             and self.max_unsupported <= 1024 and type(self.allow_cross_device) is bool
             and self.max_hardlink_groups <= 4096 and self.max_hardlink_aliases <= 16384
             and self.max_hardlink_members <= 4096,
             'bounded inventory/depth/diagnostics required')

    def tick(self):
        need(time.monotonic() < self.deadline, 'root observation deadline')


def package_map(value, *, limits):
    limits.tick()
    need(type(value) is dict and len(value) <= limits.max_packages, 'package inventory limit')
    for name, version in value.items():
        need(type(name) is str and installer.NAME.fullmatch(name) and type(version) is str
             and 0 < len(version) <= 128 and not any(c.isspace() or c == '\0' for c in version),
             'invalid package identity')
    return dict(value)


def inventory_exact(actual, expected, *, limits):
    need(package_map(actual, limits=limits) == package_map(expected, limits=limits), 'exact inventory drift')
    return dict(actual)


def check_inventory(actual, expected, label='', *, limits):
    return inventory_exact(actual, expected, limits=limits)


class Alpm(installer.Alpm):
    """Retain the pinned ABI/signatures/handle; change only observation bounds."""
    def __init__(self, root, gpgdir, log, architecture='aarch64', *, limits):
        self.limits = limits
        limits.tick()
        super().__init__(root, gpgdir, log, architecture)

    def packages(self, entries):
        result = {}
        while entries:
            self.limits.tick()
            need(len(result) < self.limits.max_packages, 'ALPM package inventory limit')
            package = entries.contents.data
            name = self.alpm_pkg_get_name(package).decode()
            need(name not in result, 'duplicate ALPM package')
            result[name] = self.alpm_pkg_get_version(package).decode()
            entries = entries.contents.next
        return package_map(result, limits=self.limits)

    def owned_files(self, names):
        need(type(names) in (list, tuple, set) and len(names) <= self.limits.max_packages,
             'bounded owned package names required')
        paths = set()
        db = self.alpm_get_localdb(self.handle)
        for name in names:
            self.limits.tick()
            need(type(name) is str and installer.NAME.fullmatch(name), 'invalid owned package name')
            package = self.alpm_db_get_pkg(db, name.encode())
            need(package, 'protected package absent')
            files = self.alpm_pkg_get_files(package).contents
            need(files.count <= self.limits.max_package_files, 'ALPM owned file count limit')
            for index in range(files.count):
                self.limits.tick()
                paths.add(installer.relative(files.files[index].name.decode().rstrip('/')))
                need(len(paths) <= self.limits.max_nodes, 'aggregate owned file count limit')
        return paths


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _file_hash(descriptor, expected, limits):
    need(_identity(os.fstat(descriptor)) == _identity(expected), 'file entry drift')
    hashed, digest = 0, hashlib.sha256()
    while True:
        limits.tick()
        data = os.read(descriptor, min(1024**2, expected.st_size - hashed + 1))
        if not data:
            break
        hashed += len(data)
        need(hashed <= expected.st_size, 'file grew during observation')
        digest.update(data)
    need(hashed == expected.st_size and _identity(os.fstat(descriptor)) == _identity(expected),
         'file content drift')
    return digest.hexdigest()


def _open_root(root):
    root = Path(root)
    need(root.is_absolute() and '..' not in root.parts, 'absolute contained root required')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open('/', flags)
    try:
        for part in root.parts[1:]:
            child = os.open(part, flags, dir_fd=descriptor)
            previous, descriptor = descriptor, child
            os.close(previous)
        return descriptor
    except BaseException as error:
        try:
            os.close(descriptor)
        except OSError:
            error.add_note('root descriptor cleanup failed')
        raise


def node(root, relative, *, limits):
    """Observe one node through nofollow directory descriptors beneath known root."""
    limits.tick()
    installer.relative(relative)
    descriptor = _open_root(root)
    original = os.fstat(descriptor)
    try:
        parts = relative.split('/')
        need(len(parts) <= limits.max_depth + 1, 'node depth limit')
        for part in parts[:-1]:
            limits.tick()
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            need(limits.allow_cross_device or os.fstat(descriptor).st_dev == original.st_dev,
                 'cross-device node parent')
        name = parts[-1]
        before = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        need(limits.allow_cross_device or before.st_dev == original.st_dev, 'cross-device node')
        common = {'mode': stat.S_IMODE(before.st_mode), 'uid': before.st_uid, 'gid': before.st_gid}
        if stat.S_ISDIR(before.st_mode):
            common['type'] = 'directory'
        elif stat.S_ISREG(before.st_mode):
            need(before.st_nlink == 1 and before.st_size <= limits.max_file_bytes
                 and before.st_size <= limits.max_bytes, 'hardlinked or oversized node')
            file = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                           dir_fd=descriptor)
            try:
                common.update(type='file', bytes=before.st_size, sha256=_file_hash(file, before, limits))
            finally:
                os.close(file)
        elif stat.S_ISLNK(before.st_mode):
            common.update(type='symlink', target=os.readlink(name, dir_fd=descriptor))
            installer.resolve_nodes({relative: common}, relative)
        else:
            raise ValueError('special node refused')
        need(_identity(os.stat(name, dir_fd=descriptor, follow_symlinks=False)) == _identity(before),
             'named node drift')
        parent = _open_root(Path(root).joinpath(*parts[:-1]))
        try:
            need(_identity(os.fstat(parent)) == _identity(os.fstat(descriptor)), 'node parent path drift')
        finally:
            os.close(parent)
        rebound = _open_root(root)
        try:
            need(_identity(os.fstat(rebound)) == _identity(original), 'root path drift')
        finally:
            os.close(rebound)
        return common
    finally:
        os.close(descriptor)



def absolute_target_class(nodes, name, limits):
    """Trace only the observed node map for diagnostics; never authorize a path."""
    pending, parts, seen = name.split('/'), [], set()
    for _ in range(4096):
        limits.tick()
        if not pending: break
        part = pending.pop(0)
        if part in ('', '.'): continue
        if part == '..':
            if not parts: break
            parts.pop(); continue
        parts.append(part); current = '/'.join(parts)
        node = nodes.get(current, {})
        if node.get('type') != 'symlink': continue
        if current in seen or len(seen) >= 40: break
        seen.add(current); target = node['target']
        if target.startswith('/'):
            value = posixpath.normpath(target).strip('/')
            prefix = value.split('/', 1)[0]
            return {'usr': 'usr-path', 'etc': 'etc-path', 'var': 'var-path', 'opt': 'opt-path',
                    'run': 'runtime-run', 'proc': 'runtime-proc', 'sys': 'runtime-sys',
                    'dev': 'runtime-dev', 'tmp': 'runtime-tmp', 'root': 'root-home',
                    'home': 'user-home', '': 'filesystem-root'}.get(prefix, 'other-absolute')
        parts.pop(); pending = target.split('/') + pending
    return 'unclassified-chain'


def _mount_id(descriptor, limits):
    """Bounded Linux descriptor identity; same-device binds have different IDs."""
    limits.tick()
    with Path('/proc/self/fdinfo/' + str(descriptor)).open('rb') as stream:
        raw = stream.read(4097)
    need(len(raw) <= 4096, 'mount identity byte limit')
    fields = [row.split(b':', 1)[1].strip() for row in raw.splitlines()
              if row.startswith(b'mnt_id:')]
    need(len(fields) == 1 and fields[0].isdigit() and int(fields[0]) > 0,
         'mount identity unavailable')
    return int(fields[0])


ABSOLUTE_PATH_LIMIT = 4096
ABSOLUTE_PATH_BYTES = 256 * 1024


def observe(root, *, limits, shape_examples=0, hardlinks='refuse', absolute_paths=False):
    """Measure a root without following links; incomplete/unsupported is ineligible."""
    limits.tick()
    need(type(shape_examples) is int and 0 <= shape_examples <= 16, 'bounded shape samples required')
    need(type(absolute_paths) is bool, 'boolean absolute path diagnostic required')
    need(type(hardlinks) is str and hardlinks in ('refuse', 'generic-development-internal'),
         'invalid hardlink observation mode')
    internal = hardlinks == 'generic-development-internal'
    need(not internal or not limits.allow_cross_device, 'internal hardlinks require one device')
    groups, directories = {}, {}
    aliases = 0
    _normal_path = ''
    nodes, problems, counts = {}, [], {}
    categories, target_classes, auxiliary_paths = {}, {}, []
    absolute_entries, absolute_bytes, absolute_truncated = [], 2, False
    allocated_inodes, hardlinked_inodes = set(), set()
    footprint = {'nodes': 0, 'bytes': 0, 'largest_file_bytes': 0, 'hardlinks': 0,
                 'hardlink_entries': 0, 'hardlink_inodes': 0, 'hardlink_declared_links': 0,
                 'allocated_bytes': 0, 'allocated_bytes_by_entry': 0,
                 'symlinks': 0, 'database_bytes': 0, 'database_files': 0}
    report = {'nodes': nodes, 'footprint': footprint, 'unsupported': problems,
              'unsupported_counts': counts, 'complete': False, 'eligible': False}
    descriptor = _open_root(root)
    try:
        root_info = os.fstat(descriptor)
        space = os.fstatvfs(descriptor)
    except BaseException:
        os.close(descriptor)
        raise
    inode_counts_known = space.f_files > 0 and space.f_favail >= 0
    footprint.update(filesystem_free_bytes=space.f_bavail * space.f_frsize,
                     filesystem_free_inodes=space.f_favail if inode_counts_known else None,
                     filesystem_inode_counts_known=inode_counts_known,
                     filesystem_inode_source='statvfs' if inode_counts_known else 'unknown',
                     filesystem_free_bytes_source='statvfs-f_bavail')

    def problem(reason, name):
        nonlocal absolute_bytes, absolute_truncated
        counts[reason] = counts.get(reason, 0) + 1
        if len(problems) < limits.max_unsupported:
            problems.append({'reason': reason, 'path': name[:4096]})
        if shape_examples:
            category = reason if reason in ('hardlink', 'absolute-symlink', 'auxiliary-present',
                'special-node', 'cross-device', 'escaping-symlink', 'cyclic-symlink', 'unsupported-symlink') else 'observation-error'
            row = categories.setdefault(category, {'count': 0, 'examples': []})
            row['count'] += 1
            target_class = None
            if reason == 'absolute-symlink':
                target_class = absolute_target_class(nodes, name, limits)
                target_classes[target_class] = target_classes.get(target_class, 0) + 1
            if reason == 'auxiliary-present': auxiliary_paths.append(name)
            if len(row['examples']) < shape_examples:
                sample = {'path': name[:1024], 'path_truncated': len(name) > 1024}
                if target_class is not None: sample['target_class'] = target_class
                row['examples'].append(sample)
        if absolute_paths and reason == 'absolute-symlink':
            if not shape_examples: target_class = absolute_target_class(nodes, name, limits)
            entry = {'path': name, 'target_class': target_class}
            size = len(json.dumps(entry, sort_keys=True, separators=(',', ':')).encode('ascii'))
            added = size + bool(absolute_entries)
            if len(absolute_entries) < ABSOLUTE_PATH_LIMIT and absolute_bytes + added <= ABSOLUTE_PATH_BYTES:
                absolute_entries.append(entry); absolute_bytes += added
            else:
                absolute_truncated = True

    def walk(directory, prefix='', depth=0):
        nonlocal aliases, _normal_path
        _normal_path = prefix.rstrip('/')
        limits.tick()
        need(depth <= limits.max_depth, 'directory depth limit')
        before_directory = os.fstat(directory)
        if internal:
            need(_mount_id(directory, limits) == root_mount, 'mount crossing refused')
            directories[prefix.rstrip('/')] = _identity(before_directory)
        with os.scandir(directory) as entries:
            for entry in entries:
                _normal_path = prefix + entry.name
                limits.tick()
                need(footprint['nodes'] < limits.max_nodes, 'root node limit')
                name = prefix + entry.name
                installer.relative(name)
                before = os.stat(entry.name, dir_fd=directory, follow_symlinks=False)
                footprint['nodes'] += 1
                common = {'mode': stat.S_IMODE(before.st_mode), 'uid': before.st_uid, 'gid': before.st_gid}
                nodes[name] = common
                if before.st_dev != root_info.st_dev and not limits.allow_cross_device:
                    common['type'] = 'cross-device'
                    problem('cross-device', name)
                    continue
                if stat.S_ISDIR(before.st_mode):
                    common['type'] = 'directory'
                    child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                    dir_fd=directory)
                    try:
                        need(_identity(os.fstat(child)) == _identity(before), 'directory entry drift')
                        walk(child, name + '/', depth + 1)
                    finally:
                        os.close(child)
                elif stat.S_ISLNK(before.st_mode):
                    footprint['symlinks'] += 1
                    target = os.readlink(entry.name, dir_fd=directory)
                    common.update(type='symlink', target=target)
                    if target.startswith('/'):
                        problem('absolute-symlink', name)
                elif stat.S_ISREG(before.st_mode):
                    common.update(type='file', bytes=before.st_size)
                    footprint['bytes'] += before.st_size
                    inode = (before.st_dev, before.st_ino)
                    footprint['allocated_bytes_by_entry'] += before.st_blocks * 512
                    if inode not in allocated_inodes:
                        allocated_inodes.add(inode)
                        footprint['allocated_bytes'] += before.st_blocks * 512
                    footprint['largest_file_bytes'] = max(footprint['largest_file_bytes'], before.st_size)
                    if name.startswith('var/lib/pacman/'):
                        footprint['database_bytes'] += before.st_size
                        footprint['database_files'] += 1
                    need(footprint['bytes'] <= limits.max_bytes, 'root byte limit')
                    need(before.st_size <= limits.max_file_bytes, 'root file byte limit')
                    if before.st_nlink != 1:
                        footprint['hardlinks'] += 1
                        footprint['hardlink_entries'] += 1
                        if inode not in hardlinked_inodes:
                            hardlinked_inodes.add(inode)
                            footprint['hardlink_inodes'] += 1
                            footprint['hardlink_declared_links'] += before.st_nlink
                        if not internal:
                            problem('hardlink', name)
                            continue
                        aliases += 1
                        need(aliases <= limits.max_hardlink_aliases, 'hardlink alias limit')
                        need(2 <= before.st_nlink <= limits.max_hardlink_members, 'hardlink member limit')
                    file = os.open(entry.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                                   dir_fd=directory)
                    try:
                        if internal:
                            need(_mount_id(file, limits) == root_mount, 'mount crossing refused')
                        if internal and before.st_nlink > 1:
                            group = groups.get(inode)
                            if group is None:
                                need(len(groups) < limits.max_hardlink_groups, 'hardlink group limit')
                                digest = _file_hash(file, before, limits)
                                group = {'fd': file, 'identity': _identity(before),
                                         'members': [], 'sha256': digest}
                                groups[inode] = group
                                file = None  # Group owns this descriptor until final validation.
                            else:
                                need(_identity(os.fstat(file)) == group['identity'] == _identity(before),
                                     'hardlink identity drift')
                            group['members'].append(name)
                            need(len(group['members']) <= limits.max_hardlink_members, 'hardlink member limit')
                        else:
                            common['sha256'] = _file_hash(file, before, limits)
                    finally:
                        if file is not None:
                            os.close(file)
                else:
                    common['type'] = 'special'
                    problem('special-node', name)
                _normal_path = prefix + entry.name
                need(_identity(os.stat(entry.name, dir_fd=directory, follow_symlinks=False))
                     == _identity(before), 'named entry drift')
        _normal_path = prefix.rstrip('/')
        need(_identity(os.fstat(directory)) == _identity(before_directory), 'directory content drift')

    def validate_groups():
        nonlocal _normal_path
        _normal_path = ''
        result = {}
        for group in groups.values():
            _normal_path = ''
            limits.tick()
            identity, retained = group['identity'], group['fd']
            members = tuple(sorted(group['members']))
            need(len(members) == len(set(members)) == identity[5], 'hardlink group not closed')
            for name in members:
                _normal_path = name
                limits.tick()
                parent = os.dup(descriptor)
                prefix = ''
                try:
                    for part in name.split('/')[:-1]:
                        limits.tick()
                        child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                        dir_fd=parent)
                        os.close(parent)
                        parent = child
                        prefix = part if not prefix else prefix + '/' + part
                        need(_identity(os.fstat(parent)) == directories.get(prefix)
                             and _mount_id(parent, limits) == root_mount, 'hardlink parent drift')
                    file = os.open(name.split('/')[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                                   dir_fd=parent)
                    try:
                        need(_mount_id(file, limits) == root_mount
                             and _identity(os.fstat(file)) == identity == _identity(os.fstat(retained))
                             and _identity(os.stat(name.split('/')[-1], dir_fd=parent, follow_symlinks=False)) == identity,
                             'hardlink named entry drift')
                    finally:
                        os.close(file)
                finally:
                    os.close(parent)
            need(_identity(os.fstat(retained)) == identity and _mount_id(retained, limits) == root_mount,
                 'hardlink retained entry drift')
            common = nodes[members[0]]
            result[members[0]] = {key: common[key] for key in ('bytes', 'mode', 'uid', 'gid')}
            result[members[0]].update(members=members, nlink=len(members), sha256=group['sha256'])
        # Publish group tags only after all groups have passed.
        for key, group in result.items():
            for name in group['members']:
                nodes[name].update(sha256=group['sha256'], hardlink_group=key)
        report['hardlink_groups'] = result

    try:
        if internal:
            root_mount = _mount_id(descriptor, limits)
        walk(descriptor)
        if internal:
            validate_groups()
        for name, node in nodes.items():
            _normal_path = name
            limits.tick()
            if node['type'] == 'symlink':
                if node['target'].startswith('/'):
                    continue  # Already explicitly counted while walking.
                try:
                    installer.resolve_nodes(nodes, name)
                except ValueError as error:
                    reason = {'escaping payload link': 'escaping-symlink',
                              'cyclic payload link': 'cyclic-symlink',
                              'absolute payload link': 'absolute-symlink'}.get(str(error), 'unsupported-symlink')
                    problem(reason, name)
        _normal_path = ''
        for auxiliary in ('usr/bin/ldconfig','usr/sbin/ldconfig','sbin/ldconfig'):
            _normal_path = auxiliary
            limits.tick()
            try:
                resolved=installer.resolve_nodes(nodes,auxiliary)
                if auxiliary in nodes or resolved in nodes:
                    problem('auxiliary-present',auxiliary)
            except ValueError:
                pass  # Unsupported links are already recorded above.
        _normal_path = ''
        need(_identity(os.fstat(descriptor)) == _identity(root_info), 'root identity drift')
        rebound = _open_root(root)
        try:
            need(_identity(os.fstat(rebound)) == _identity(root_info), 'root path drift')
            if internal:
                need(_mount_id(descriptor, limits) == root_mount == _mount_id(rebound, limits),
                     'root mount drift')
                for group in groups.values():
                    limits.tick()
                    need(_identity(os.fstat(group['fd'])) == group['identity'], 'hardlink final drift')
        finally:
            os.close(rebound)
        report['complete'] = True
    except (ValueError, OSError) as error:
        report['primary_failure'] = _normal_primary_record(error, 'NORMAL_ROOT_OBSERVATION', _normal_path)
        # Existing refusal/counts unchanged; raw OS exception text omitted.
        reason = str(error) if type(error) is ValueError else 'filesystem-observation-failed'
        problem(reason, '')
    finally:
        for closing in [group['fd'] for group in groups.values()] + [descriptor]:
            try:
                os.close(closing)
            except OSError:
                # A failed close may already have released the FD. Never retry it.
                report['complete'] = False
                problem('filesystem-cleanup-failed', '')
    if shape_examples:
        for row in categories.values():
            row['examples_complete'] = report['complete'] and len(row['examples']) == row['count'] and not any(x['path_truncated'] for x in row['examples'])
        report['shape_diagnostics'] = {'sample_limit_per_category': shape_examples, 'sample_path_char_limit': 1024,
            'categories': categories, 'absolute_target_classes': target_classes,
            'auxiliary_paths': auxiliary_paths, 'auxiliary_paths_complete': report['complete'],
            'absolute_classes_complete': report['complete'] and sum(target_classes.values()) == counts.get('absolute-symlink', 0),
            'target_values': 'OMITTED',
            'scope': 'observed node-map diagnostics only; no policy permission'}
    if absolute_paths:
        report['absolute_chain_paths'] = {
            'entries': sorted(absolute_entries, key=lambda entry: entry['path']),
            'observed_count': counts.get('absolute-symlink', 0),
            'complete': report['complete'] and not absolute_truncated and len(absolute_entries) == counts.get('absolute-symlink', 0),
            'truncated': absolute_truncated, 'observation_complete': report['complete'],
            'entry_limit': ABSOLUTE_PATH_LIMIT, 'entry_json_byte_limit': ABSOLUTE_PATH_BYTES,
            'entry_json_bytes': absolute_bytes, 'target_values': 'OMITTED',
            'scope': 'observed node-map diagnostics only; no policy permission'}
    report['eligible'] = report['complete'] and not counts
    footprint['complete'] = report['complete'] and 'cross-device' not in counts
    return report


def require_eligible(observation):
    need(observation.get('eligible') is True and observation.get('complete') is True
         and not observation.get('unsupported_counts'), 'unsupported or incomplete root observation')
    return observation['nodes']


def _projected_paths(seed, added, *, limits, internal=False):
    """The existing path/ldconfig refusals with explicit per-caller size bounds."""
    limits.tick()
    need(type(seed) is dict and type(added) is dict
         and len(seed) <= limits.max_nodes and len(added) <= limits.max_nodes, 'projected input limit')
    if not internal:
        need(all(type(value) is dict and 'hardlink_group' not in value
                 for graph in (seed, added) for value in graph.values()),
             'hardlink projection requires explicit mode')
    combined = dict(seed)
    combined.update(added)
    need(len(combined) <= limits.max_nodes, 'projected node limit')
    total = 0
    for name, node in combined.items():
        limits.tick()
        installer.relative(name)
        need(type(node) is dict and (internal or 'hardlink_group' not in node), 'hardlink projection requires explicit mode')
        need(len(name.split('/')) <= limits.max_depth + 1, 'projected depth limit')
        need(node.get('type') in ('file', 'directory', 'symlink'), 'unsupported projected shape')
        if node['type'] == 'file':
            size = node.get('bytes')
            need(type(size) is int and 0 <= size <= limits.max_file_bytes, 'projected file byte limit')
            need(type(node.get('sha256')) is str and installer.HEX.fullmatch(node['sha256']),
                 'projected file content observation missing')
            total += size
        if node['type'] == 'symlink':
            need(type(node.get('target')) is str and 0 < len(node['target']) <= 4096,
                 'invalid projected symlink')
        installer.resolve_nodes(combined, name)
    need(total <= limits.max_bytes, 'projected byte limit')
    for name in ('usr/bin/ldconfig', 'usr/sbin/ldconfig', 'sbin/ldconfig'):
        resolved = installer.resolve_nodes(combined, name)
        need(name not in combined and resolved not in combined, 'unaudited auxiliary executable or alias refused')
    return combined


def projected_paths(seed, added, *, limits):
    return _projected_paths(seed, added, limits=limits)


def _path_set(value, limits):
    need(type(value) in (set, frozenset, tuple, list) and len(value) <= limits.max_nodes,
         'bounded path collection required')
    result = set()
    for name in value:
        limits.tick()
        installer.relative(name)
        need(len(name.split('/')) <= limits.max_depth + 1, 'path depth limit')
        result.add(name)
    return result


def _group_graph(observation, limits):
    """Validate ordinary in-memory observations, never a permission token."""
    limits.tick()
    need(type(observation) is dict, 'hardlink observation required')
    nodes = require_eligible(observation)
    groups = observation.get('hardlink_groups')
    need(type(groups) is dict and len(groups) <= limits.max_hardlink_groups,
         'bounded hardlink groups required')
    _projected_paths(nodes, {}, limits=limits, internal=True)
    members = set()
    for key, group in groups.items():
        limits.tick()
        installer.relative(key)
        need(type(group) is dict and set(group) ==
             {'members', 'nlink', 'bytes', 'mode', 'uid', 'gid', 'sha256'}, 'invalid hardlink group record')
        paths = group['members']
        need(type(paths) is tuple and 2 <= len(paths) <= limits.max_hardlink_members,
             'invalid hardlink membership')
        for name in paths:
            limits.tick()
            installer.relative(name)
        need(paths == tuple(sorted(set(paths))) and key == paths[0]
             and type(group['nlink']) is int and group['nlink'] == len(paths), 'invalid hardlink membership')
        need(type(group['bytes']) is int and 0 <= group['bytes'] <= limits.max_file_bytes
             and type(group['sha256']) is str and installer.HEX.fullmatch(group['sha256']),
             'invalid hardlink content')
        for field in ('mode', 'uid', 'gid'):
            need(type(group[field]) is int and 0 <= group[field] <= (0o7777 if field == 'mode' else 2**32 - 1),
                 'invalid hardlink metadata')
        for name in paths:
            limits.tick()
            need(name not in members, 'duplicate hardlink membership')
            members.add(name)
            need(len(members) <= limits.max_hardlink_aliases, 'hardlink alias limit')
            value = nodes.get(name)
            need(type(value) is dict and value.get('type') == 'file'
                 and value.get('hardlink_group') == key
                 and all(type(value.get(field)) is int for field in ('bytes', 'mode', 'uid', 'gid'))
                 and all(value.get(field) == group[field] for field in ('bytes', 'mode', 'uid', 'gid', 'sha256')),
                 'hardlink member differs')
            parts = name.split('/')
            for index in range(1, len(parts)):
                limits.tick()
                parent = nodes.get('/'.join(parts[:index]), {})
                need(parent.get('type') == 'directory'
                     and all(type(parent.get(field)) is int and 0 <= parent[field] <=
                             (0o7777 if field == 'mode' else 2**32 - 1) for field in ('mode', 'uid', 'gid')),
                     'hardlink parent missing or redirected')
    for name, value in nodes.items():
        limits.tick()
        need('hardlink_group' not in value or name in members, 'unknown hardlink member')
    return nodes, groups


def _same_groups(before, after, before_groups, after_groups, limits):
    need(before_groups == after_groups, 'hardlink groups changed')
    for group in before_groups.values():
        for name in group['members']:
            limits.tick()
            need(before[name] == after.get(name), 'hardlink member changed')
            parts = name.split('/')
            for index in range(1, len(parts)):
                limits.tick()
                parent = '/'.join(parts[:index])
                need(before[parent] == after.get(parent), 'hardlink parent changed')


def projected_internal_hardlinks(observation, added, *, selected_old_paths,
                                 removed_paths, protected_paths, limits):
    """Only unrelated updates: retain every existing group and its ancestors."""
    seed, groups = _group_graph(observation, limits)
    old = _path_set(selected_old_paths, limits)
    removed = _path_set(removed_paths, limits)
    _path_set(protected_paths, limits)  # Every group is preserved, including all protected aliases.
    need(type(added) is dict and len(added) <= limits.max_nodes, 'projected input limit')
    for name, value in added.items():
        limits.tick()
        installer.relative(name)
        need(type(value) is dict and 'hardlink_group' not in value, 'payload hardlink marker refused')
    need(removed <= old and removed <= seed.keys(), 'unaccounted removal')
    for name in old:
        limits.tick()
        need(name in seed, 'selected old path missing')
        need(name in added or name in removed or seed[name]['type'] == 'directory',
             'selected old removal missing')
    retained = {name: value for name, value in seed.items() if name not in removed}
    combined = _projected_paths(retained, added, limits=limits, internal=True)
    # A removed directory with retained children is an ambiguous extraction model.
    # Do not invent ALPM's rmdir decisions.
    for name in combined:
        limits.tick()
        parts = name.split('/')
        for index in range(1, len(parts)):
            limits.tick()
            parent = '/'.join(parts[:index])
            resolved = installer.resolve_nodes(combined, parent)
            need(combined.get(resolved, {}).get('type') == 'directory', 'projected parent missing or not directory')
    sensitive = set()
    for group in groups.values():
        for name in group['members']:
            parts = name.split('/')
            for index in range(1, len(parts) + 1):
                limits.tick()
                sensitive.add('/'.join(parts[:index]))
    for name in old | set(added) | removed:
        limits.tick()
        for graph in (seed, combined):
            resolved = installer.resolve_nodes(graph, name)
            if name in sensitive or resolved in sensitive:
                need(name not in removed and seed.get(name, {}).get('type') == 'directory'
                     and seed[name] == combined.get(name) and name == resolved
                     and (name not in added or seed[name] == added[name]), 'selected hardlink path touched')
    projected = dict(observation, nodes=combined)
    _, projected_groups = _group_graph(projected, limits)
    _same_groups(seed, combined, groups, projected_groups, limits)
    return combined


def check_hardlink_preservation(before_observation, after_observation, *, protected_paths, limits):
    """Pure all-group content/topology comparison; no write exclusion or rollback."""
    _path_set(protected_paths, limits)
    before, groups = _group_graph(before_observation, limits)
    after, after_groups = _group_graph(after_observation, limits)
    _same_groups(before, after, groups, after_groups, limits)
    return True
