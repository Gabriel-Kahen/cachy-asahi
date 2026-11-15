#!/usr/bin/env python3
"""Bounded retained package DATA audit; no rootfs read, installation or payload execution."""
import argparse
import base64
from collections import Counter
import gc
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import posixpath
import resource
import signal
import stat
import subprocess
import sys
import tarfile
import time
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
BAD = {'EXPSIG', 'EXPKEYSIG', 'REVKEYSIG', 'BADSIG', 'ERRSIG', 'NO_PUBKEY', 'FAILURE', 'ERROR', 'NODATA', 'BADARMOR'}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def checked_bytes(ref, ceiling=16*1024**2):
    p = Path(ref['path'])
    if p.is_symlink() or any(x.is_symlink() for x in p.parents):
        raise ValueError('linked input path refused')
    fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size != ref['bytes'] or not 0 < info.st_size <= ceiling:
            raise ValueError('input size/type cap or byte pin mismatch')
        data = source.read(info.st_size + 1)
        if len(data) != info.st_size or sha(data) != ref['sha256']:
            raise ValueError('input content pin mismatch')
    return data


def modules(config):
    result = {}
    paths = {'stream': 'scripts/update/archive_stream.py', 'elf': 'scripts/platform/elf_audit.py',
             'geometry': 'scripts/checks/package_checks.py', 'catalog': 'scripts/port/arm-rust-toolchain-inputs/catalog.py',
             'versions': 'scripts/port/arm-rust-toolchain-inputs/qtbase-successor/elf_versions.py',
             'resolver': 'scripts/port/platform-residual-closure/resolve.py'}
    for name, relative in paths.items():
        checked_bytes({'path': str(ROOT / relative), **config['reader_sources'][relative]})
        spec = importlib.util.spec_from_file_location('retained_ui_' + name, ROOT / relative)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        result[name] = module
    return result


def candidate_paths(item, config, intake):
    paths = []
    for observation in item['observations']:
        if 'archive' in observation:
            paths.append((observation['archive']['path'], observation['signature']['path']))
        elif 'path' in observation:
            paths.append((observation['path'], observation['path'] + '.sig'))
    if not paths and item['archive']['filename'] in {r['archive']['filename'] for r in intake['pairs']}:
        archive = str(Path(config['six_pair_archive_root']) / item['archive']['filename'])
        paths.append((archive, archive + '.sig'))
    return list(dict.fromkeys(paths))


def signature_status(code, status, expected):
    rows = [line.split()[1:] for line in status.splitlines() if line.startswith('[GNUPG:] ')]
    valid = [r for r in rows if r and r[0] == 'VALIDSIG']
    if code or any(r and r[0] in BAD for r in rows) or len(valid) != 1 or len(valid[0]) != 11 or valid[0][1] != expected or valid[0][-1] != expected:
        raise ValueError('gpgv strict direct-primary signature refusal')
    return {'status': 'PASS_SIGNATURE_MATHEMATICS', 'primary': expected, 'signature_date': valid[0][2],
            'status_lines': status.splitlines(), 'freshness_external_trust_native_build': 'HOLD'}


def snapshot(path, expected, target, limits, budget):
    if expected['bytes'] > limits['archive_object_bytes']:
        raise ValueError('archive object byte cap')
    if budget['compressed_allowance'] + 3 * expected['bytes'] > limits['compressed_archive_read_allowance']:
        raise ValueError('aggregate hash/signature/decode compressed allowance')
    # Reserve all three reads before consuming bytes, including on later refusal.
    budget['compressed_allowance'] += 3 * expected['bytes']
    if path.is_symlink() or any(p.is_symlink() for p in path.parents):
        raise ValueError('linked archive input refused')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as source, target.open('xb') as output:
        before = os.fstat(source.fileno())
        identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if not stat.S_ISREG(before.st_mode) or before.st_size != expected['bytes']:
            raise ValueError('archive full-size/type mismatch')
        digest, count = hashlib.sha256(), 0
        while count < expected['bytes']:
            block = source.read(min(65536, expected['bytes'] - count))
            if not block: break
            if time.monotonic() > budget['deadline']:
                raise TimeoutError('whole audit deadline')
            count += len(block)
            budget['compressed_observed_snapshot_bytes'] += len(block)
            if count > expected['bytes']:
                raise ValueError('archive changed/grown')
            digest.update(block); output.write(block)
        if count != expected['bytes'] or digest.hexdigest() != expected['sha256'] or identity(os.fstat(source.fileno())) != identity(before):
            raise ValueError('archive full SHA256/identity mismatch')
    return {'status': 'PASS_FULL_SIZE_SHA256', 'bytes': count, 'sha256': digest.hexdigest(), 'path': str(path)}


def inspect(path, item, m, limits, budget, payload_paths=()):
    A, C = m['stream'], m['catalog']
    deadline = budget['deadline']
    spec = A.Limits(limits['archive_object_bytes'], limits['compressed_archive_read_allowance'],
                    limits['logical_bytes'], limits['members'], limits['elf_object_bytes'],
                    limits['decoder_memory_bytes'], deadline)
    headers, ended, seen, entries, metadata, objects = 0, False, set(), {}, {}, []

    class TarInfo(tarfile.TarInfo):
        @classmethod
        def _fromtarfile(cls, archive, *, dircheck=True):
            nonlocal headers, ended
            A.tick(spec)
            raw = archive.fileobj.read(512)
            if raw == bytes(512): ended = True
            else:
                headers += 1
                A.need(budget['headers'] + headers <= limits['members'], 'aggregate raw tar header cap')
            member = cls._frombuf(raw, archive.encoding, archive.errors, dircheck=dircheck)
            member.offset = archive.fileobj.tell() - 512
            return member._proc_member(archive)

        def _proc_pax(self, archive):
            A.need(self.size <= 65536, 'PAX metadata cap')
            return super()._proc_pax(archive)

        def _proc_gnulong(self, archive):
            A.need(self.size <= 65536, 'GNU long metadata cap')
            return super()._proc_gnulong(archive)

        def _proc_sparse(self, *_args):
            raise ValueError('sparse tar refused')
        _proc_gnusparse_00 = _proc_gnusparse_01 = _proc_gnusparse_10 = _proc_sparse

    class Decoded(A.Decoded):
        def read(self, size):
            remaining = limits['logical_bytes'] - self.before - self.total
            A.need(remaining > 0, 'aggregate logical byte cap')
            return super().read(min(size, remaining))

    with path.open('rb') as raw:
        decoded = Decoded(raw, spec, budget['logical_bytes'])
        try:
            with tarfile.open(fileobj=decoded, mode='r|', bufsize=65536, tarinfo=TarInfo, stream=True) as archive:
                for member in archive:
                    A.tick(spec)
                    if member.name in ('.', './') and member.isdir(): continue
                    name = C.canonical(member.name.removeprefix('./'))
                    A.need(name not in seen and member.size >= 0 and not member.sparse, 'duplicate/negative/sparse member')
                    seen.add(name)
                    entry = {'type': 'directory'}
                    payload = {'type': member.type.decode('ascii'), 'mode': member.mode,
                               'uid': member.uid, 'gid': member.gid, 'bytes': member.size,
                               'sha256': None, 'link': member.linkname} if name in payload_paths else None
                    if member.isfile():
                        stream = archive.extractfile(member)
                        prefix = stream.read(min(4, member.size))
                        is_policy = name == '/usr/share/polkit-1/actions/org.freedesktop.NetworkManager.policy'
                        is_control = name in ('/.PKGINFO', '/.BUILDINFO') or is_policy
                        is_elf = prefix == b'\x7fELF'
                        cap = limits['metadata_object_bytes'] if is_control else limits['elf_object_bytes']
                        A.need(not is_control or member.size <= cap, 'metadata object cap before allocation')
                        keep = is_control or is_elf and member.size <= cap
                        body = bytearray(prefix) if keep else None
                        digest, count = hashlib.sha256(prefix), len(prefix)
                        while block := stream.read(65536):
                            A.tick(spec); count += len(block); digest.update(block)
                            if body is not None: body.extend(block)
                        A.need(count == member.size, 'truncated member body')
                        entry.update(type='file', bytes=count, sha256=digest.hexdigest())
                        if payload is not None: payload['sha256'] = digest.hexdigest()
                        if is_policy:
                            policy=ET.fromstring(body)
                            actions=[a for a in policy.findall('action') if a.get('id')=='org.freedesktop.NetworkManager.settings.modify.own']
                            A.need(len(actions)==1,'actual NM policy action absent/ambiguous')
                            metadata['NM_policy']={'path':name,'bytes':count,'sha256':digest.hexdigest(),
                                'action':actions[0].get('id'),'defaults':{child.tag:child.text for child in actions[0].find('defaults')}}
                            metadata['NM_policy']['exact_bytes_base64']=base64.b64encode(body).decode()
                        elif is_control:
                            A.need(count <= cap, 'metadata object cap')
                            metadata[name] = {'fields': C.fields(body), 'bytes': count, 'sha256': digest.hexdigest()}
                        elif is_elf:
                            obj = {'path': name, 'bytes': count, 'sha256': digest.hexdigest(), 'status': 'HOLD_OBJECT_CAP'}
                            if body is not None:
                                try:
                                    parsed = m['elf'].parse_elf(body)
                                    geometry = m['geometry'].elf_check(body)
                                    obj.update(elf=parsed, geometry=geometry, status='PASS_STATIC_ELF' if not geometry['errors'] else 'FAIL_GEOMETRY_OR_ARCH')
                                    if payload is not None:
                                        A.need(not geometry['errors'], 'required payload ELF geometry')
                                        payload['ELF'] = ({'machine': 'aarch64', 'type': 'relocatable',
                                            'LOAD_geometry': 'not applicable; compiler/link consumption NOT RUN', 'runtime': 'NOT RUN'}
                                            if parsed['type'] == 1 else {'machine': 'aarch64', 'LOAD': [
                                                {'offset': load['offset'], 'vaddr': load['virtual_address'],
                                                 'align': load['alignment'], 'flags': load['flags']} for load in parsed['PT_LOAD']], 'runtime': 'NOT RUN'})
                                    if parsed['class'] == 64 and parsed['byte_order'] == 'little' and parsed['machine'] == 183:
                                        obj['gnu_versions'] = m['versions'].parse(body)
                                except (ValueError, IndexError, UnicodeError) as error:
                                    obj.update(status='HOLD_ELF_PARSER_REFUSAL', reason=str(error))
                            objects.append(obj)
                        if name.endswith('.hook') or name == '/.INSTALL': entry['package_hook_or_script_data'] = True
                        del body
                    elif member.issym() or member.islnk():
                        entry.update(type='hardlink' if member.islnk() else 'symlink',
                                     resolved=C.link_target(name, member.linkname, member.islnk()))
                    else:
                        A.need(member.isdir(), 'special package node refused')
                    entries[name] = entry
                    if payload is not None: entry['payload'] = payload
                A.need(ended, 'tar end marker absent')
                tail = 0
                while block := archive.fileobj.read(65536):
                    A.need(not any(block), 'trailing nonzero tar data'); tail += len(block)
                A.need(decoded.done and tail >= 512 and decoded.total % 512 == 0, 'incomplete compressed/tar end')
        finally:
            budget['logical_bytes'] += decoded.total
            budget['headers'] += headers
    for name in entries:
        parent = posixpath.dirname(name)
        while parent != '/':
            A.need(parent not in entries or entries[parent]['type'] == 'directory', 'non-directory path ancestor')
            parent = posixpath.dirname(parent)
    info = metadata.get('/.PKGINFO', {}).get('fields', {})
    expected = {'pkgname': [item['name']], 'pkgver': [item['version']], 'arch': [item['arch']],
                'depend': item['depends'], 'license': item['licenses_declared']}
    mismatches = [key for key, wanted in expected.items() if sorted(info.get(key, [])) != sorted(wanted)]
    build = metadata.get('/.BUILDINFO', {}).get('fields', {})
    build_issues = [key for key, wanted in [('pkgname', item['name']), ('pkgver', item['version']), ('pkgarch', item['arch'])]
                    if build.get(key) != [wanted]] if build else ['ABSENT']
    if build and (len(info.get('pkgbase', [])) != 1 or build.get('pkgbase') != info.get('pkgbase')):
        build_issues.append('pkgbase')
    return {'metadata': metadata, 'PKGINFO_status': 'PASS_EXACT_PLAN' if not mismatches else 'FAIL',
            'PKGINFO_mismatched_fields': mismatches, 'BUILDINFO_status': 'PASS_IDENTITY' if not build_issues else 'HOLD',
            'BUILDINFO_issues': build_issues, 'ELF_objects': objects, 'members': len(entries),
            'raw_headers': headers, 'logical_bytes': decoded.total}, entries


def worker(config, output):
    limits = config['limits']
    resource.setrlimit(resource.RLIMIT_AS, (limits['worker_AS'], limits['worker_AS']))
    signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(TimeoutError('900second audit wall')))
    signal.alarm(895)
    started = time.monotonic()
    m = modules(config)
    plan = json.loads(checked_bytes(config['inputs']['plan']))
    intake = json.loads(checked_bytes(config['inputs']['intake_contract']))
    baseline = json.loads(checked_bytes(config['inputs']['baseline111']))
    checked_bytes(config['inputs']['intake_receipt'])
    carried={}
    if 'carry_report' in config:
        old=json.loads(checked_bytes(config['carry_report']))
        carried=old['budget'];del old;gc.collect()
    if 'seat_proposal' in config:
        proposal=json.loads(checked_bytes(config['seat_proposal']))
        if proposal['additions']!=44 or proposal['preserved_baseline']!=111 or proposal['total']!=155:raise ValueError('exact44/111/155 seat boundary')
        identities={r['name']:{'name':r['name'],'version':r['version'],'repo':r['repo']} for r in proposal['materials']}
        identities.update({r['name']:{'name':r['name'],'version':r['version'],'repo':'signed-rootfs111'} for r in baseline['packages']})
        plan={'materials':proposal['materials'],'edges':[{'consumer':identities[e['package']],'requirement':e['relation'],
              'selected':identities.get(e['provider'])} for e in proposal['metadata_prepare']['dependencies']],
              'required_real_policy':proposal['required_real_policy']}
    for tool in config['host_tools'].values(): checked_bytes(tool)
    official = checked_bytes(config['official_binary_keyring'])
    cert = checked_bytes(config['project_public_certificate'])
    encoded = b''.join(line for line in cert.splitlines() if line and not line.startswith((b'-----', b'=')))
    test = base64.b64decode(encoded, validate=True)
    if sha(test) != config['project_binary_keyring_sha256']: raise ValueError('TEST public key conversion pin')
    keydir = output / 'public-keys'; keydir.mkdir()
    (keydir/'official.gpg').write_bytes(official); (keydir/'TEST.gpg').write_bytes(test)
    home = output/'empty-gpg-home'; home.mkdir(mode=0o700)
    budget = {'deadline': started + 890-config.get('carried_elapsed_seconds',0), 'compressed_allowance': 0, 'compressed_observed_snapshot_bytes': 0, 'logical_bytes': 0, 'headers': 0}
    for key in carried:
        if key in budget and key!='deadline':budget[key]=carried[key]
    results, namespace = [], {}
    report = {'scope': config['scope'], 'status': 'HOLD_INCOMPLETE', 'packages': results,
              'baseline111_payload_read': False, 'network_install_payload_native_actors': False}
    def save():
        report.update(budget={k:v for k,v in budget.items() if k!='deadline'}, seconds=round(time.monotonic()-started, 3),
                      peak_RSS_bytes=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024)
        text = json.dumps(report, indent=2, sort_keys=True)+'\n'
        if len(text.encode()) > limits['retained_report_bytes']: raise ValueError('retained report cap')
        (output/'report.json').write_text(text)
    for item in plan['materials']:
        row = {'name': item['name'], 'version': item['version'], 'arch': item['arch'], 'repo': item['repo'],
               'archive': item['archive'], 'status': 'HOLD', 'prior_availability': item['availability'], 'candidates': []}
        results.append(row); save()
        if time.monotonic() >= budget['deadline']: row['reason']='AUDIT_WALL_CAP'; break
        selected = None
        for a,s in candidate_paths(item, config, intake):
            observed={'archive': a, 'signature': s, 'archive_exists':Path(a).is_file(), 'signature_exists':Path(s).is_file()}
            row['candidates'].append(observed)
            if selected is None and observed['archive_exists'] and observed['signature_exists']: selected=(Path(a),Path(s))
        if selected is None: row['reason']='MISSING_DECLARED_ARCHIVE_OR_SIGNATURE'; save(); continue
        ap,sp=selected
        snap=output/'opaque-current-archive'; sig=output/'opaque-current-signature'
        try:
            sigdata=checked_bytes({'path':str(sp),'bytes':item['archive']['signature_bytes'],'sha256':item['archive']['signature_sha256']},65536)
            sig.write_bytes(sigdata)
            row['bytes_authentication']=snapshot(ap,item['archive'],snap,limits,budget)
            project=item['repo']=='project'
            if project and item['name'] not in {'cachy-asahi-first-login','cachy-asahi-first-login-ui','cachy-asahi-setup'}: raise ValueError('unexpected project signer route')
            signer=config['project_primary'] if project else config['official_primary']
            ring=keydir/('TEST.gpg' if project else 'official.gpg')
            command=['/usr/bin/prlimit','--as='+str(32*1024**2)+':'+str(32*1024**2),'--',
                     '/usr/bin/gpgv','--homedir',str(home),'--keyring',str(ring),'--status-fd','1',str(sig),str(snap)]
            # Separate bounded signature phase: 64MiB supervisor +160MiB worker
            # +32MiB host gpgv. Payload scanning restores the192MiB worker cap.
            resource.setrlimit(resource.RLIMIT_AS,(160*1024**2,limits['worker_AS']))
            try:
                result=subprocess.run(command,capture_output=True,text=True,timeout=10,env={'PATH':'/usr/bin','LC_ALL':'C','HOME':str(home)})
            finally:
                resource.setrlimit(resource.RLIMIT_AS,(limits['worker_AS'],limits['worker_AS']))
            if len(result.stdout.encode())+len(result.stderr.encode())>65536:raise ValueError('gpgv output cap')
            row['gpgv_call']={'argv':command,'exit':result.returncode,'stdout_sha256':sha(result.stdout.encode()),'stderr_sha256':sha(result.stderr.encode()),'natural_retirement':True}
            row['signature']=signature_status(result.returncode,result.stdout,signer)
            row['signer_role']='PROJECT_TEST_NOT_BUILD_PROOF' if project else 'OFFICIAL_PINNED_PRIMARY_MATHEMATICS'
            scanned,entries=inspect(snap,item,m,limits,budget)
            row.update(scanned,status='PASS_BYTE_SIGNATURE_METADATA_SCAN' if scanned['PKGINFO_status']=='PASS_EXACT_PLAN' else 'HOLD_METADATA')
            for path, entry in entries.items():
                if path.startswith('/.'): continue
                if path in namespace and any(namespace[path].get(k)!=entry.get(k) for k in ('type','sha256','resolved')) and entry['type']!='directory':
                    report.setdefault('namespace_collisions',[]).append({'path':path,'first':namespace[path]['package'],'second':item['name']})
                namespace[path]={**entry,'package':item['name']}
            del entries
        except (ValueError,OSError,tarfile.TarError,MemoryError,EOFError,ET.ParseError,subprocess.TimeoutExpired) as error:
            row.update(status='HOLD',reason=type(error).__name__+': '+str(error)[:400])
        finally:
            snap.unlink(missing_ok=True); sig.unlink(missing_ok=True)
            gc.collect(); save()
    finish_joins(report,plan,baseline,namespace,m)
    report['summary']={'planned':len(plan['materials']),'processed':len(results),'byte_signature_metadata_pass':sum(r['status']=='PASS_BYTE_SIGNATURE_METADATA_SCAN' for r in results),
                       'missing':sum(r.get('reason')=='MISSING_DECLARED_ARCHIVE_OR_SIGNATURE' for r in results),'elf_objects':sum(len(r.get('ELF_objects',[])) for r in results)}
    if 'required_real_policy' in plan:
        expected=plan['required_real_policy'];policies=[r for r in results if r['name']=='networkmanager' and r['status']=='PASS_BYTE_SIGNATURE_METADATA_SCAN']
        actual=policies[0].get('metadata',{}).get('NM_policy') if len(policies)==1 else None
        report['NM_policy']={'expected_x86_sha256':expected['x86_source_hash_comparison'],'actual':actual,
            'status':'PASS_ACTUAL_ARM_POLICY_BYTES_MATCH_X86' if actual and actual['sha256']==expected['x86_source_hash_comparison'] else 'HOLD_MISSING_OR_DIFFERENT_ACTUAL_ARM_POLICY'}
        if actual:
            body=base64.b64decode(actual.pop('exact_bytes_base64'),validate=True)
            (output/'networkmanager-original-policy.data').write_bytes(body)
            actual['private_data_path']=str(output/'networkmanager-original-policy.data')
    report['final_holds']=([] if 'seat_proposal' in config else ['Xvfb exact input and any failed/missing packages are not substituted'])+['baseline111 payload symbols not read',
                           'GNU version names are not full-symbol ABI','Source/native build/GTK seat/runtime/M2/install/legal/release NOT ESTABLISHED']
    save()


def finish_joins(report, plan, baseline, namespace, m):
    rows = {r['name']:r for r in report['packages']}
    providers={}
    for name,row in rows.items():
        info=row.get('metadata',{}).get('/.PKGINFO',{}).get('fields',{})
        if row.get('signature',{}).get('status')=='PASS_SIGNATURE_MATHEMATICS' and row.get('PKGINFO_status')=='PASS_EXACT_PLAN' and info:
            providers[name]={'name':name,'version':row['version'],'repo':row['repo'],'provides':info.get('provides',[])}
    for row in baseline['packages']:
        providers[row['name']]={'name':row['name'],'version':row['version'],'repo':'signed-rootfs111','provides':row['desc'].get('PROVIDES',[])}
    joins=[]
    for edge in plan['edges']:
        name=edge['consumer']['name']
        if name not in rows: continue
        selected=edge.get('selected'); provider=providers.get(selected['name']) if selected else None
        status='HOLD_MISSING_ACTUAL_PROVIDER'
        if provider and m['resolver'].witnesses(provider,edge['requirement']): status='PASS_METADATA_ONLY'
        joins.append({'consumer':name,'requirement':edge['requirement'],'selected':selected,'status':status})
    report['actual_dependency_joins']=joins
    authenticated={r['name'] for r in report['packages'] if r.get('status')=='PASS_BYTE_SIGNATURE_METADATA_SCAN'}
    namespace={p:node for p,node in namespace.items() if node['package'] in authenticated}
    elfs={o['path']:{**o.get('elf',{}),'gnu_versions':o.get('gnu_versions',{}),'package':r['name'],'static_status':o['status']} for r in report['packages'] if r['name'] in authenticated for o in r.get('ELF_objects',[]) if o.get('elf')}
    needed=[]; versions=[]
    for path, obj in elfs.items():
        search=obj.get('runpath') if obj.get('runpath') is not None else obj.get('rpath')
        directories=[] if not search else search.split(':')
        unsupported=any(not d or not d.startswith(('/','$ORIGIN','${ORIGIN}')) for d in directories)
        directories=[d.replace('${ORIGIN}',posixpath.dirname(path)).replace('$ORIGIN',posixpath.dirname(path)) for d in directories]+['/usr/lib','/lib']
        for library in obj.get('needed',[])+([obj['interpreter']] if obj.get('interpreter') else []):
            paths=[library] if library.startswith('/') else [posixpath.normpath(posixpath.join(d,library)) for d in directories if d.startswith('/') and '$'not in d]
            found=None
            for candidate in paths:
                try:
                    resolved=m['catalog'].resolve(candidate,namespace)
                    if resolved in elfs: found=resolved;break
                except ValueError: pass
            status='HOLD_BASELINE_OR_MISSING_PAYLOAD_PROVIDER' if found is None else 'PASS_ADDITION_NAMESPACE_VERSION_NAMES_ONLY'
            provider_usable=found and elfs[found]['static_status']=='PASS_STATIC_ELF' and elfs[found]['classification']=='aarch64-loadable-elf'
            if found and not provider_usable:status='HOLD_PROVIDER_GEOMETRY_ARCH_OR_TYPE'
            if unsupported:status='HOLD_UNSUPPORTED_SEARCH_PATH'
            needed.append({'consumer':path,'needed':library,'provider':found,'status':status})
            definitions=set(elfs[found]['gnu_versions'].get('defines',[])) if found else set()
            for version in obj.get('gnu_versions',{}).get('needs',{}).get(library,[]):
                versions.append({'consumer':path,'library':library,'version':version,'provider':found,
                                 'status':'HOLD_UNSUPPORTED_SEARCH_PATH' if unsupported else 'PASS_VERSION_NAME' if provider_usable and version in definitions else 'FAIL_VERSION_NAME' if provider_usable else 'HOLD_BASELINE_OR_PROVIDER_GEOMETRY_SYMBOLS'})
    report['static_NEEDED_joins']=needed;report['GNU_version_name_joins']=versions


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--worker',action='store_true');parser.add_argument('--input-contract',type=Path,default=HERE/'inputs.json');args=parser.parse_args()
    if args.input_contract.resolve() not in {HERE/'inputs.json',HERE/'seat-inputs.json'}:parser.error('only fixed audit contracts are accepted')
    config=json.loads(args.input_contract.read_text());output=args.output.resolve()
    if not output.is_relative_to(Path('/tmp')):parser.error('new private output required below/tmp')
    if args.worker: worker(config,output);return
    resource.setrlimit(resource.RLIMIT_AS,(config['limits']['supervisor_AS'],config['limits']['worker_AS']))
    output.mkdir(mode=0o700,exist_ok=False)
    started=time.monotonic()
    try:
        result=subprocess.run([sys.executable,'-I','-B',str(Path(__file__).resolve()),'--worker','--input-contract',str(args.input_contract.resolve()),'--output',str(output)],capture_output=True,timeout=899-config.get('carried_elapsed_seconds',0),
                              env={'PATH':'/usr/bin:/bin','LC_ALL':'C','TZ':'UTC'})
        receipt={'exit':result.returncode,'natural_retirement':True,'stderr':result.stderr.decode(errors='replace')[:4000]}
    except subprocess.TimeoutExpired: receipt={'exit':None,'natural_retirement':False,'status':'HOLD_900SECOND_WATCHDOG'}
    receipt.update(seconds=round(time.monotonic()-started,3),limits=config['limits'],network=False,rootfs_read=False)
    (output/'execution.json').write_text(json.dumps(receipt,indent=2,sort_keys=True)+'\n');print(json.dumps(receipt,sort_keys=True))


if __name__=='__main__':main()
