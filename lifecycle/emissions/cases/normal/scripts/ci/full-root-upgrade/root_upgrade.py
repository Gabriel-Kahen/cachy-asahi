#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""One real setup3→setup4 update in a complete owned copy; never a target test."""
import argparse
from contextlib import contextmanager
from functools import partial
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import time
from types import SimpleNamespace

NAME = 'cachy-asahi-apps'
DB = 'var/lib/pacman/local'
BEFORE = '72818a8a2ae488281b08486b92c435ec244ef3b5313f23b97473d1684ecb68b4'
AFTER = 'be35402204ba5c03d78279722afa83047c9575d2da70fb5c4064f46ed15954c5'
PACKAGE = '319cc1db4738945ad3b146490ea0fabd80f8c8d89d8c41a11750dd0ba5d5b8af'
LABEL = re.compile(r'[a-z0-9][a-z0-9+_.-]{0,127}\Z')

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


def encoded(value): return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
def sha(data): return hashlib.sha256(data).hexdigest()
def inventory_sha(rows): return sha(''.join(k + ' ' + v + '\n' for k, v in sorted(rows.items())).encode())


def selection(source):
    directory = Path(source) / 'scripts/ci/full-development-composition'
    values = []
    for name, pin in [('expected-updater-v2.lock', BEFORE), ('expected-setup4-v2.lock', AFTER)]:
        raw = (directory / name).read_bytes(); need(sha(raw) == pin, 'exact setup/updater-v2 lock required')
        lines = [line.split() for line in raw.decode('ascii').splitlines()]
        need(len(lines) == 607 and all(len(line) == 2 for line in lines), "complete604 lock required")
        value = dict(lines); need(len(value) == 607, 'duplicate installed package')
        values.append(value)
    before, after = values
    need(before[NAME] == '0.1.0-6' and after == dict(before, **{NAME: '0.1.0-16'}), 'only retained setup3→4 permitted')
    need(before['cachy-asahi-update'] == after['cachy-asahi-update'] == '4.4.2-2', 'updater-v2 baseline required')
    return before, after


def relative(name):
    need(type(name) is str and bool(name) and '\0' not in name, 'invalid package path')
    path = PurePosixPath(name)
    need(not path.is_absolute() and path.as_posix() == name and not {'.', '..'} & set(path.parts), 'unsafe package path')
    return name


@contextmanager
def directory(root, name):
    """Read-only database traversal; no symlink or mount substitution is accepted."""
    root = Path(root)
    need(root.is_absolute() and '..' not in root.parts, 'absolute database root required')
    need(root.resolve(strict=True) == root and not any(p.is_symlink() for p in (root, *root.parents)), 'database root alias refused')
    fds = [os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)]
    device = os.fstat(fds[0]).st_dev
    try:
        for component in relative(name).split('/'):
            fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fds[-1])
            fds.append(fd); need(os.fstat(fd).st_dev == device, 'database mount crossing refused')
        yield fds[-1]
    finally:
        for fd in reversed(fds): os.close(fd)


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid, info.st_gid,
            info.st_size, info.st_ctime_ns, info.st_mtime_ns)


def read_record(parent, name, maximum=4 * 1024**2, expected=None):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= maximum, 'bounded ordinary database record required')
        raw = stream.read(before.st_size + 1)
        need(len(raw) == before.st_size and identity(before) == identity(os.fstat(stream.fileno()))
             == identity(os.stat(name, dir_fd=parent, follow_symlinks=False)), 'database record changed')
        if expected is not None:
            actual = dict(type='file', mode=stat.S_IMODE(before.st_mode), uid=before.st_uid,
                          gid=before.st_gid, bytes=len(raw), sha256=sha(raw))
            need(actual == expected, 'database record differs from root observation')
        return raw


def fields(raw):
    result, current = {}, None
    for line in raw.decode('utf-8').splitlines():
        if not line: current = None; continue
        if re.fullmatch(r'%[A-Z0-9_]+%', line):
            current = line[1:-1]; need(current not in result, 'duplicate database field')
            result[current] = []
        else:
            need(current is not None, 'malformed database field')
            result[current].append(line)
    return result


def database(root, *, max_packages=607, max_files=1000000, max_nodes=4000000, observed=None):
    """Observe real installed desc/files records; never manufacture an inventory."""
    rows, spent = [], 0
    with directory(root, 'var/lib/pacman') as parent:
        try: os.stat('db.lck', dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError: pass
        else: raise ValueError('existing package-manager lock refused')
    with directory(root, DB) as local:
        before = identity(os.fstat(local)); names = sorted(os.listdir(local))
        def expected(path):
            if observed is None: return None
            need(DB + '/' + path in observed, 'database record absent from root observation')
            return observed[DB + '/' + path]
        need(len(names) <= max_packages + 1 and 'ALPM_DB_VERSION' in names, 'bounded existing local database required')
        need(read_record(local, 'ALPM_DB_VERSION', expected=expected('ALPM_DB_VERSION')) == b'9\n', 'unsupported local database version')
        for name in names:
            if name == 'ALPM_DB_VERSION': continue
            need('/' not in name and name not in ('.', '..'), 'unsafe package database directory')
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=local)
            try:
                initial = identity(os.fstat(fd))
                desc = fields(read_record(fd, 'desc', expected=expected(name + '/desc')))
                ownership_raw = read_record(fd, 'files', expected=expected(name + '/files'))
                owned = fields(ownership_raw)
                need(all(len(desc.get(key, [])) == 1 for key in ('NAME', 'VERSION', 'ARCH')), 'installed package identity missing')
                package, version, arch = (desc[key][0] for key in ('NAME', 'VERSION', 'ARCH'))
                need(LABEL.fullmatch(package) and 0 < len(version) <= 128 and not any(c.isspace() or c == '\0' for c in version), 'invalid installed identity')
                need(name == package + '-' + version and arch in ('aarch64', 'any'), 'installed directory/architecture differs')
                # ALPM writes a present, zero-byte files record for metapackages.
                paths = owned.get('FILES', [] if ownership_raw == b'' else None)
                need(type(paths) is list, 'installed ownership missing: ' + package)
                need(len(paths) <= max_files, 'package ownership bound')
                need(len(paths) == len(set(paths)), 'duplicate installed ownership')
                for path in paths: relative(path[:-1] if path.endswith('/') else path)
                files = [path for path in paths if not path.endswith('/')]
                spent += len(files); need(spent <= max_nodes, 'aggregate package ownership bound')
                rows.append(dict(name=package, version=version, arch=arch, depend=desc.get('DEPENDS', []),
                                 provides=desc.get('PROVIDES', []), conflict=desc.get('CONFLICTS', []), files=files))
                need(initial == identity(os.fstat(fd)) == identity(os.stat(name, dir_fd=local, follow_symlinks=False)), 'database package directory changed')
            finally: os.close(fd)
        need(before == identity(os.fstat(local)) and names == sorted(os.listdir(local)), 'database changed during observation')
    need(len({row['name'] for row in rows}) == len(rows), 'duplicate installed package')
    return sorted(rows, key=lambda row: row['name'])


def ownership(packages, nodes, runtime):
    owners, protected, kernels = {}, set(), []
    for package in packages:
        module_paths = []
        for name in package['files']:
            need(name not in owners, 'overlapping installed file ownership')
            owners[name] = package['name']
            parent, _, leaf = name.rpartition('/')
            resolved = runtime.resolve_nodes(nodes, parent)
            actual = resolved + '/' + leaf if resolved else leaf
            need(actual in nodes and nodes[actual]['type'] != 'directory', 'package-owned payload absent from supplied root: ' + name)
            if package['name'] != NAME: protected.add(actual)
            if name.startswith('usr/lib/modules/') and name.endswith(('.ko', '.ko.xz', '.ko.zst', '.ko.gz')): module_paths.append('/' + name)
        if module_paths: kernels.append(package['name'])
    need(kernels, 'actual package-owned kernel modules required')
    return protected, sorted(kernels)


def preserved(before, after, protected):
    old, new = DB + '/' + NAME + '-0.1.0-6', DB + '/' + NAME + '-0.1.0-16'
    def prefix(name, base): return name == base or name.startswith(base + '/')
    def held_db(nodes): return {n: v for n, v in nodes.items() if prefix(n, DB) and not any(prefix(n, x) for x in (old, new))}
    def users(nodes): return {n: v for n, v in nodes.items() if any(prefix(n, x) for x in ('home', 'root'))}
    need(any(v.get('type') == 'file' for v in users(before).values()), 'actual user-file baseline not exercised')
    need(held_db(before) == held_db(after), 'nonselected database changed')
    need(users(before) == users(after), 'user files changed')
    need({n: before[n] for n in protected} == {n: after.get(n) for n in protected}, 'protected package file changed')
    return {'nonselected_database': 'PRESERVED', 'user_files': 'PRESERVED', 'protected_payload': 'PRESERVED',
            'protected_nodes': len(protected), 'user_nodes': len(users(before))}


def committed(result, before, after):
    need(result.get('status') == 'PASS', 'existing bound/runtime update did not pass')
    need(all(result.get(key) is True for key in ('commit_started', 'packages_committed', 'checkpoint_changed', 'checkpoint_directory_synced')), 'real committed durable update required')
    need(result.get('before') == before and result.get('after') == after, 'actual before/after inventory differs')
    need(result.get('prepared_add') == {NAME: '0.1.0-16'} and result.get('prepared_remove') == {}, 'exact single prepared setup upgrade required')


def write(path, value):
    with Path(path).open('xb') as stream: stream.write(encoded(value))


def run(args, *, runtime_module, copy_module, constructor, prepare_copy=None):
    """One owned copy lifetime; Root supplies reviewed/frozen implementation paths."""
    scale, bound = runtime_module.scale, runtime_module.scale.bound
    result = dict(status='FAIL', phase='selection', commit_started=False, packages_committed=False,
                  checkpoint_changed=False, scope='actual-copied-root-generic-setup-upgrade', hardware='NOT RUN',
                  apple_acceptance='NOT ESTABLISHED', copy_cleanup='NOT RUN')
    copy_report, delegated = {}, False
    _lifecycle_state = None
    _trace = None
    try:
        before, after = selection(args.source_root)
        config = scale.configuration(args.scale, args.scale_sha256)
        need(config['platform_mode'] == 'generic-development' and config['before_lock_sha256'] == BEFORE
             and config['after_lock_sha256'] == AFTER, 'explicit actual updater-v2→setup4 scale selection required')
        data = bound.install.private(Path(args.data), os.geteuid())
        need(not any(data.iterdir()), 'fresh driver data directory required')
        _lifecycle_state = _lifecycle.begin(args, config)
        _progress = load('normal604_driver_progress', Path(__file__).with_name('driver_progress.py'))
        _trace = _progress.start(data, result)
        _progress.note(_trace, result)
        workspace, source = Path(args.workspace), Path(args.source)
        need(not data.is_relative_to(workspace) and not workspace.is_relative_to(data)
             and not data.is_relative_to(source) and not source.is_relative_to(data), 'driver data/copy/source overlap refused')
        need(type(args.copy_seconds) is int and 0 < args.copy_seconds <= 4260, 'finite copy deadline required')
        limits = config['limits']
        copy_limits = scale.roots.Limits(deadline=_lifecycle.ci.deadline(args.copy_seconds, 300),
            max_nodes=limits['root_nodes'], max_bytes=limits['root_bytes'], max_file_bytes=limits['file_bytes'],
            max_package_files=limits['package_files'])
        result['phase'] = 'copy'
        _progress.note(_trace, result)
        with copy_module.copied_root(source, workspace, limits=copy_limits) as (root, copy_report):
            need(copy_report['copy']['copy_complete'] is True and copy_report['copy']['excluded'] == []
                 and copy_report['copy'].get('copy_byte_identical_before_initialization') is True,
                 'complete byte-identical supplied-source copy required')
            result['copy'] = dict(copy_report['copy'])
            result['initial_copy_byte_identical'] = copy_report['copy']['copy_byte_identical_before_initialization']
            args.root = str(root); bound.guard(root, workspace)
            need(prepare_copy is not None, 'reviewed copied-root initialization API required before updater baseline')
            # Root supplies Tools' separately reviewed one-time initialization.
            # It runs after byte-preserving copy and before ANY update baseline.
            result['phase'] = 'copied-root-initialization'
            _progress.note(_trace, result)
            result['initialization'] = prepare_copy(args, config)
            need(type(result['initialization']) is dict and result['initialization'].get('status') == 'PASS'
                 and result['initialization'].get('root_initialized') is True
                 and result['initialization'].get('source_preserved') is True,
                 'one-shot copied-root initialization did not pass')
            runtime = runtime_module.Runtime(args, config)
            result['phase'] = 'baseline'
            _progress.note(_trace, result)
            nodes = runtime.tree(root)  # The selected Runtime's eligibility stays enforced.
            result['prepared_root_baseline'] = 'ESTABLISHED-after-one-shot-initialization'
            need(any((name.startswith('home/') or name.startswith('root/')) and node['type'] == 'file'
                     for name, node in nodes.items()), 'actual user-file baseline required before commit')
            packages = database(root, max_files=limits['package_files'], max_nodes=limits['root_nodes'], observed=nodes)
            actual = {p['name']: p['version'] for p in packages}
            need(actual == before, "actual root is not initial signed604/updater-v2 checkpoint")
            protected, kernels = ownership(packages, nodes, runtime)
            _lifecycle.prepare(_lifecycle_state,args,runtime_module,copy_module,SimpleNamespace(**globals()),nodes,protected,before)
            base = data / 'base.json'
            write(base, dict(schema_version=1, snapshot_id='inventory-sha256:' + BEFORE,
                             target_arch='aarch64', kind='complete-target-transaction', packages=packages))
            result['phase'] = 'construct-test-repository'
            _progress.note(_trace, result)
            release = constructor.construct(args, base=base, protected=sorted(set(before) - {NAME}), output=data / 'release-inputs')
            need(release.get('status') not in ('REFUSED_API_CONTRACT', 'FAIL'),
                 'TEST repository construction refused: ' + str(release.get('stage_blockers', release.get('error', 'unknown'))))
            for field in ('bundle', 'metadata', 'signature', 'public_keyring'): setattr(args, field, str(release[field]))
            generic = runtime.policy_module
            policy = dict(schema_version=1, purpose='cachy-asahi-generic-development-update-policy',
                release_id=release['release_id'], protected_packages=sorted(set(before) - {NAME}),
                protected_versions={k: v for k, v in before.items() if k != NAME}, platform_roles={'kernel': kernels},
                protected_units={k: sorted(v) for k, v in generic.asahi.REQUIRED_UNITS.items()},
                before_lock_sha256=BEFORE, after_lock_sha256=AFTER)
            args.policy = str(data / 'policy.json'); write(args.policy, policy); args.policy_sha256 = sha(Path(args.policy).read_bytes())
            generic.read_policy(args.policy, args.policy_sha256)
            args.state_dir = str(data / 'state'); Path(args.state_dir).mkdir(mode=0o700)
            settings = dict(schema_version=1, purpose='disposable-generic-bound-update', namespace=args.namespace,
                release_synthetic=False,
                signer=release['signer'], minimum_sequence=args.sequence, release_id=release['release_id'],
                repo_name=release['repo_name'], metadata_sha256=sha(Path(args.metadata).read_bytes()),
                release_sha256=sha((Path(args.bundle) / 'release.json').read_bytes()),
                public_keyring_sha256=sha(Path(args.public_keyring).read_bytes()), base_trust_sha256=bound.trust_digest(nodes),
                model='generic-development-only', running_kernel_release='NOT-HARDWARE-OBSERVED', operations=['repository-update'])
            args.settings = str(data / 'settings.json'); write(args.settings, settings); args.settings_sha256 = sha(Path(args.settings).read_bytes())
            args.operation = 'repository-update'; args.measure_only = False
            need(runtime.tree(root) == nodes, 'root changed while constructing TEST repository')
            result['prepared_root_preserved_during_repository_construction'] = True
            result.update(phase='update', commit_started='UNKNOWN', packages_committed='UNKNOWN', checkpoint_changed='UNKNOWN')
            _progress.note(_trace, result)
            delegated = True
            update = runtime_module.apply(args)  # Checked scale/schema/guard/bound entry.
            result['update'] = update
            for key in ('commit_started', 'packages_committed', 'checkpoint_changed'): result[key] = update.get(key, 'UNKNOWN')
            committed(update, before, after)
            result['phase'] = 'preservation'
            _progress.note(_trace, result)
            observer = runtime_module.Runtime(args, config)
            final = observer.tree(root)
            need({p['name']: p['version'] for p in database(root, max_files=limits['package_files'],
                 max_nodes=limits['root_nodes'], observed=final)} == after, 'postcommit actual database differs')
            result['preservation'] = preserved(nodes, final, protected)
            result['normal_report_scope'] = 'INITIAL_SIGNED_UPDATE_ONLY'
            result['lifecycle'] = _lifecycle.complete(_lifecycle_state,args,runtime_module,SimpleNamespace(**globals()),constructor,update,release,protected)
            result['restoration'] = 'DISPOSAL-selected; no downgrade or live-root restoration attempted'
            result['phase'] = 'copy-cleanup'
            _progress.note(_trace, result)
        result['copy_cleanup'] = copy_report.get('cleanup', 'UNKNOWN')
        need(result['copy_cleanup'] == 'PASS-owned-workspace-removed', 'owned copy disposal not confirmed')
        result.update(status='PASS', phase='completed', committed_transactions=1,
                      before_sha256=BEFORE, after_sha256=AFTER, selected_archive_sha256=PACKAGE)
    except BaseException as error:
        result['primary_failure'] = _normal_primary_record(error, 'DRIVER_CATCH')
        result.update(status='FAIL', error_type=type(error).__name__, error=str(error)[:512],
                      copy_cleanup=copy_report.get('cleanup', 'UNKNOWN' if result['phase'] != 'selection' else 'NOT RUN'))
        if delegated: result['recovery'] = 'dispose outer owned container on any cleanup/worker uncertainty'
    finally:
        try:_lifecycle.finish(_lifecycle_state,result,copy_report)
        except BaseException as e:result.update(status='FAIL',lifecycle_error_type=type(e).__name__,lifecycle_error=str(e)[:512])
        if _trace is not None:
            _progress.note(_trace, result)
            _trace.close()
    return result


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); sys.modules[name] = module; spec.loader.exec_module(module)
    return module


def connect(runtime, initializer, comparator_path, *, auxiliary_runtime=False):
    """Bind the exact supplied Tools APIs; strict Runtime remains an explicit route."""
    comparator = Path(comparator_path)
    need(comparator.is_absolute() and '..' not in comparator.parts, 'explicit comparator path required')
    kwargs = {'comparator_path': comparator} if auxiliary_runtime else {}
    api = SimpleNamespace(scale=runtime.scale, Runtime=partial(runtime.Runtime, **kwargs),
                          apply=partial(runtime.apply, **kwargs))
    def prepare_copy(args, config):
        return initializer.initialize(args, Path(args.source), comparator_path=comparator)
    return api, prepare_copy


def worker_result(row):
    if row['termination'] is None and row['returncode'] in (0, 1):
        try:
            value = json.loads(row['stdout'])
            need(type(value) is dict and value.get('status') in ('PASS', 'FAIL')
                 and all(key in value for key in ('commit_started', 'packages_committed', 'checkpoint_changed')),
                 'incomplete worker result')
            return value
        except (ValueError, TypeError): pass
    return dict(status='FAIL', phase='driver-worker', termination=row['termination'],
        commit_started='UNKNOWN', packages_committed='UNKNOWN', checkpoint_changed='UNKNOWN',
        recovery='dispose outer owned container; no rollback or lock-file removal attempted')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source-root', 'runtime', 'runtime-sha256', 'initializer', 'initializer-sha256', 'comparator',
                 'source', 'workspace', 'data', 'scale', 'scale-sha256',
                 'setup4-pair', 'package', 'provenance', 'gpg-home', 'signer', 'release-id', 'repo-name', 'namespace',
                 'issued-utc', 'expires-utc'):
        parser.add_argument('--' + name, required=True)
    for name in ('copy-seconds', 'seconds', 'sequence'): parser.add_argument('--' + name, type=int, required=True)
    parser.add_argument('--supported-models', nargs='*', default=[])
    parser.add_argument('--auxiliary-runtime', action='store_true', help='Use selected aux_runtime Runtime/apply with the pinned comparator')
    parser.add_argument('--worker', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    for name in ('source_root', 'runtime', 'initializer', 'comparator', 'source', 'workspace', 'data', 'scale',
                 'setup4_pair', 'package', 'provenance', 'gpg_home'):
        path = Path(getattr(args, name))
        need(path.is_absolute() and '..' not in path.parts, 'explicit absolute driver paths required')
    root = Path(args.source_root).resolve(strict=True)
    sys.path.insert(0, str(root / 'scripts/update'))
    modules = []
    for label in ('runtime', 'initializer'):
        path = Path(getattr(args, label))
        need(path.is_file() and not path.is_symlink() and path.stat().st_size <= 512 * 1024
             and sha(path.read_bytes()) == getattr(args, label + '_sha256'), 'exact selected ' + label + ' source required')
        modules.append(load('root_upgrade_' + label, path))
    runtime, initialize = connect(*modules, args.comparator, auxiliary_runtime=args.auxiliary_runtime)
    if args.worker:
        copy = load('root_upgrade_copy', root / 'scripts/update/aux_copy.py')
        constructor = load('root_upgrade_constructor', Path(__file__).with_name('construct_repository.py'))
        value = run(args, runtime_module=runtime, copy_module=copy, constructor=constructor, prepare_copy=initialize)
    else:
        need((0 < args.seconds <= 7200 or (type(args.seconds) is int and args.seconds == 10440)), 'finite total driver deadline required')
        row = runtime.scale.supervision.run([sys.executable, '-B', str(Path(__file__).resolve()), *sys.argv[1:], '--worker'],
            env=dict(os.environ), cwd=str(root), timeout=_lifecycle.ci.guest_witness(args.seconds)['effective_seconds'], output_limit=2 * 1024**2)
        value = worker_result(row)
    print(json.dumps(value, sort_keys=True))
    return int(value['status'] != 'PASS')


_lifecycle=load('_private_lifecycle_extension',Path(__file__).with_name('lifecycle_extension.py'))

if __name__ == '__main__': raise SystemExit(main())
