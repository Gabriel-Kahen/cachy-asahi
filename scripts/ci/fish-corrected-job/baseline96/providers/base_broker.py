#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 cachy-asahi contributors
"""Extend a caller-pinned accepted broker for one nonce-owned legacy base build."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
from types import SimpleNamespace
import uuid

LABEL = 'org.cachy-asahi.fdk-native-job.nonce'
CONTEXT = 'org.cachy-asahi.fdk-native-job.context-sha256'
DOCKERFILE = 'org.cachy-asahi.fdk-native-job.dockerfile-sha256'
IMAGE = re.compile(r'sha256:[0-9a-f]{64}')


def broker_class(adapter_dir):
    """Load immutable caller-reviewed sources without replacing global modules."""
    directory = Path(adapter_dir).resolve()
    previous = sys.modules.get('runtime')
    def load(name, path):
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    runtime = load('base_job_runtime_' + uuid.uuid4().hex, directory / 'runtime.py')
    try:
        sys.modules['runtime'] = runtime
        accepted = load('base_job_broker_' + uuid.uuid4().hex, directory / 'broker.py')
    finally:
        if previous is None:
            sys.modules.pop('runtime', None)
        else:
            sys.modules['runtime'] = previous
    need = accepted.need

    class BaseBroker(accepted.Broker):
        def __init__(self, runner, cleanup_runner, binary, binary_sha, endpoint, uid, gid,
                     journal_path, nonce, *, jobroot, context, iidfile, container_journals=(),
                     expected_mounts=None):
            self.jobroot = Path(jobroot)
            need(self.jobroot.is_absolute() and self.jobroot == self.jobroot.resolve() and
                 self.jobroot.is_dir() and self.jobroot.stat().st_uid == os.getuid() and
                 self.jobroot.stat().st_mode & 0o077 == 0, 'base-job-root')
            self.context, self.iidfile = Path(context), Path(iidfile)
            self.image_journal_path = Path(journal_path)
            for path in (self.context, self.iidfile, self.image_journal_path):
                need(path.is_absolute() and path == path.resolve() and path.is_relative_to(self.jobroot),
                     'base-job-path')
            self.container_journals = tuple(map(Path, container_journals))
            container_path = self.image_journal_path.with_name(self.image_journal_path.stem + '-containers.json')
            super().__init__(runner, cleanup_runner, binary, binary_sha, endpoint, 'sha256:' + '0'*64,
                             uid, gid, container_path, nonce, expected_mounts=expected_mounts)
            self.final_deadline = None

        def _local(self, runner):
            need(runner.env.get('DOCKER_BUILDKIT') in (None, '0'), 'base-legacy-builder-env')
            return super()._local(SimpleNamespace(env={key: value for key, value in runner.env.items()
                                                       if key != 'DOCKER_BUILDKIT'}))

        def _operation(self, args, *, cleanup=False, timeout=30):
            if tuple(args[:2]) == ('image','rm'):
                need(cleanup and len(args) == 4 and tuple(args[:3]) == ('image','rm','--no-prune') and
                     type(args[3]) is str and IMAGE.fullmatch(args[3]), 'base-owned-image-remove')
            runner = self.cleanup_runner if cleanup else self.runner
            if cleanup and self.final_deadline is not None:
                runner.deadline = min(runner.deadline, self.final_deadline)
                need(self.final_deadline > time.monotonic(), 'base-cleanup-deadline')
            return super()._operation(args, cleanup=cleanup, timeout=timeout)

        def _image_identity(self):
            identity = super()._identity()
            identity.pop('image')
            return {**identity, 'jobroot': str(self.jobroot), 'context': str(self.context),
                    'iidfile': str(self.iidfile)}

        def _image_record(self):
            data, _ = accepted.regular(self.image_journal_path, 2 * 1024 * 1024)
            record = accepted.decode(data)
            need(type(record) is dict and set(record) == {'schema_version','identity','reservation'} and
                 record['schema_version'] == 1 and record['identity'] == self._image_identity(),
                 'base-image-journal-binding')
            row = record['reservation']
            if row is not None:
                need(type(row) is dict and set(row) == {'phase','attempted','context_files','context_sha256',
                     'dockerfile_sha256','actual_argv','image_ids'} and type(row['attempted']) is bool and
                     type(row['context_files']) is dict and len(row['context_files']) <= 4096 and
                     type(row['image_ids']) is list and len(row['image_ids']) <= 16 and
                     len(set(row['image_ids'])) == len(row['image_ids']) and
                     all(type(item) is str and IMAGE.fullmatch(item) for item in row['image_ids']) and
                     re.fullmatch('[0-9a-f]{64}', row['context_sha256']) and
                     re.fullmatch('[0-9a-f]{64}', row['dockerfile_sha256']), 'base-image-reservation')
                need(row['phase'] in ('reserved','create-attempted','created','recovered','removed') and
                     hashlib.sha256(json.dumps(row['context_files'],sort_keys=True,separators=(',',':')).encode()).hexdigest()
                     == row['context_sha256'] and row['context_files'].get('Dockerfile',{}).get('sha256')
                     == row['dockerfile_sha256'],'base-image-context-binding')
            return record

        def _save_image(self, record, first=False):
            data = (json.dumps(record, sort_keys=True, indent=2) + '\n').encode()
            need(len(data) <= 2 * 1024 * 1024, 'base-image-journal-size')
            path = self.image_journal_path if first else self.image_journal_path.with_name('.base-' + uuid.uuid4().hex)
            try:
                with path.open('xb') as stream:
                    path.chmod(0o600)
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
                if not first:
                    os.replace(path, self.image_journal_path)
                fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
            finally:
                if not first:
                    path.unlink(missing_ok=True)

        def initialize(self, expected_daemon=None):
            self.pins = self._local(self.runner)
            self._local(self.cleanup_runner)
            self.daemon = self._info(self.runner)
            if expected_daemon is not None:
                need(self.daemon == expected_daemon, 'base-expected-daemon')
            if self.image_journal_path.exists() or self.image_journal_path.is_symlink():
                record = self._image_record()
                if record['reservation'] and record['reservation']['image_ids'] and record['reservation']['phase'] != 'removed':
                    self._set_image(record['reservation']['image_ids'][0], record['reservation'])
            else:
                self._save_image({'schema_version':1,'identity':self._image_identity(),'reservation':None}, first=True)
            return dict(self.daemon)

        def _context_files(self):
            need(self.context.is_dir() and self.context == self.context.resolve(), 'base-context-directory')
            files, total = {}, 0
            for path in sorted(self.context.rglob('*')):
                need(not path.is_symlink(), 'base-context-symlink')
                if path.is_dir():
                    continue
                relative = str(path.relative_to(self.context))
                need('\\' not in relative and all(part not in ('','.','..') for part in relative.split('/')) and
                     all(ord(char) >= 32 for char in relative),'base-context-path')
                need(len(files) < 4096 and len(relative) <= 512, 'base-context-count')
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                try:
                    before = os.fstat(fd)
                    need(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= 2*1024**3,
                         'base-context-file')
                    digest, count = hashlib.sha256(), 0
                    while True:
                        need(time.monotonic() < self.runner.deadline, 'base-context-deadline')
                        data = os.read(fd, 1024*1024)
                        if not data:
                            break
                        count += len(data)
                        need(count <= before.st_size, 'base-context-drift')
                        digest.update(data)
                    after = os.fstat(fd)
                    need(count == before.st_size and (before.st_size,before.st_mtime_ns,before.st_mode) ==
                         (after.st_size,after.st_mtime_ns,after.st_mode), 'base-context-drift')
                finally:
                    os.close(fd)
                total += count
                need(total <= 8*1024**3, 'base-context-size')
                files[relative] = {'sha256':digest.hexdigest(),'bytes':count,'mode':before.st_mode & 0o7777}
            need('Dockerfile' in files and 'rootfs.tar.gz' in files, 'base-context-required')
            return files

        def bootstrap(self, command, timeout):
            original = ['docker','build','--network=none','--pull=false','--platform=linux/arm64',
                        '--iidfile',str(self.iidfile),str(self.context)]
            need(command == original and type(timeout) in (int,float) and 0 < timeout <= 7200,
                 'base-build-command')
            need(self.runner.env.get('DOCKER_BUILDKIT') == '0', 'base-legacy-builder-env')
            need(not self.iidfile.exists() and not self.iidfile.is_symlink() and
                 self.iidfile.parent.is_dir() and self.iidfile == self.iidfile.resolve(), 'base-new-iidfile')
            record = self._image_record()
            need(record['reservation'] is None, 'base-build-already-reserved')
            files = self._context_files()
            context_sha = hashlib.sha256(json.dumps(files,sort_keys=True,separators=(',',':')).encode()).hexdigest()
            dockerfile_sha = files['Dockerfile']['sha256']
            additions = ['--force-rm=true','--memory=4g','--memory-swap=4g',
                         '--cpu-period=100000','--cpu-quota=400000','--label',LABEL+'='+self.nonce,
                         '--label',CONTEXT+'='+context_sha,'--label',DOCKERFILE+'='+dockerfile_sha]
            actual = ['build',*additions,*command[2:]]
            row = {'phase':'reserved','attempted':False,'context_files':files,'context_sha256':context_sha,
                   'dockerfile_sha256':dockerfile_sha,'actual_argv':[str(self.binary),'--host',self.endpoint,*actual],
                   'image_ids':[]}
            record['reservation'] = row
            self._save_image(record)
            row.update(phase='create-attempted',attempted=True)
            self._save_image(record)
            result = self._operation(actual, timeout=timeout)
            need(self._context_files() == files, 'base-context-drift')
            if result.returncode:
                return result
            data, _ = accepted.regular(self.iidfile, 1024)
            identifier = data.decode().strip()
            need(IMAGE.fullmatch(identifier), 'base-build-unknown-image')
            self._verify_image(identifier,row)
            row.update(phase='created',image_ids=[identifier])
            self._save_image(record)
            self._set_image(identifier,row)
            return result

        def _verify_image(self, identifier, row, cleanup=False):
            result = self._operation(['image','inspect',identifier], cleanup=cleanup)
            need(result.returncode == 0, 'base-owned-image-inspect')
            values = accepted.decode(result.stdout)
            need(type(values) is list and len(values) == 1, 'base-owned-image-inspect')
            value = values[0]
            config = value['Config']
            labels = config.get('Labels') or {}
            need(value['Id'] == identifier and value['Architecture'] == 'arm64' and value['Os'] == 'linux' and
                 config.get('User') == 'alarm' and not config.get('Volumes') and
                 labels.get(LABEL) == self.nonce and labels.get(CONTEXT) == row['context_sha256'] and
                 labels.get(DOCKERFILE) == row['dockerfile_sha256'], 'base-owned-image-binding')
            return config

        def _set_image(self, identifier, row):
            self.image_config = self._verify_image(identifier,row)
            self.image = identifier
            if self.journal_path.exists():
                self._journal()
            else:
                self._write({'schema_version':1,'identity':self._identity(),'containers':[]}, first=True)

        def capture(self, args):
            if args == ['docker','context','inspect']:
                self._info(self.runner)
                return json.dumps([{'Endpoints':{'docker':{'Host':self.endpoint}}}])
            if args == ['docker','version']:
                result = self._operation(['version'])
                need(result.returncode == 0, 'base-docker-version')
                return result.stdout.decode().strip()
            return super().capture(args)

        def command(self, command, timeout):
            if command[:2] == ['docker','build']:
                return self.bootstrap(command,timeout)
            expected = ['docker','run','--rm','--pull=never','--network=none','--cap-drop=ALL',
                        '--security-opt=no-new-privileges','--read-only','--entrypoint=/bin/cat',
                        self.image,'/builder-packages.lock']
            need(command == expected and self.image != 'sha256:'+'0'*64, 'base-lock-probe-command')
            result = self._launch('cachy-asahi-probe-'+self.nonce,{}, {},
                                  ['-euc','cat /builder-packages.lock'],timeout)
            need(result.returncode == 0 and result.stdout and result.stdout.endswith(b'\n') and
                 result.stdout.splitlines(keepends=True) == sorted(result.stdout.splitlines(keepends=True)) and
                 all(re.fullmatch(rb'[A-Za-z0-9@+_.-]+ [^\s]+\n',line) for line in result.stdout.splitlines(keepends=True)),
                 'base-lock-probe-inventory')
            return result

        def _owned_ids(self):
            result = self._operation(['image','ls','--no-trunc','--quiet','--filter','label='+LABEL+'='+self.nonce],
                                     cleanup=True)
            need(result.returncode == 0, 'base-owned-image-list')
            values = result.stdout.decode().splitlines()
            need(len(values) <= 16 and all(IMAGE.fullmatch(item) for item in values), 'base-owned-image-list')
            return set(values)

        def cleanup(self, remove_image=False, container_journals=None):
            if not remove_image:
                return super().cleanup()
            self.final_deadline = time.monotonic()+180
            self.cleanup_runner = runtime.Runner(180,{key:value for key,value in self.cleanup_runner.env.items()
                                                      if key != 'DOCKER_BUILDKIT'},self.cleanup_runner.log_dir)
            errors, cancelled = [], False
            def recover(action):
                nonlocal cancelled
                for attempt in range(2):
                    try:
                        return action()
                    except runtime.Cancelled:
                        cancelled = True
                        if attempt:
                            raise ValueError('base-cleanup-cancellation-uncertain')

            def remove_owned(identifier, row):
                if identifier in self._owned_ids():
                    self._verify_image(identifier,row,cleanup=True)
                    result = self._operation(['image','rm','--no-prune',identifier],cleanup=True)
                    need(result.returncode == 0, 'base-owned-image-remove')
                result = self._operation(['image','ls','--all','--no-trunc','--quiet'],cleanup=True)
                need(result.returncode == 0 and identifier not in result.stdout.decode().splitlines(),
                     'base-owned-image-absence')

            with runtime.defer_signals() as events:
                try:
                    record = self._image_record()
                    row = record['reservation']
                    if row is not None:
                        discovered = recover(self._owned_ids)
                        need(discovered or row['image_ids'] or not row['attempted'], 'base-image-absence-uncertain')
                        for identifier in sorted(discovered):
                            recover(lambda: self._verify_image(identifier,row,cleanup=True))
                        row['image_ids'] = sorted(set(row['image_ids'])|discovered)
                        row['phase'] = 'recovered' if discovered else row['phase']
                        self._save_image(record)
                        paths = set(self.container_journals if container_journals is None else map(Path,container_journals))
                        if self.journal_path.exists():
                            paths.add(self.journal_path)
                        need(len(paths) <= 16, 'base-container-journal-count')
                        for path in sorted(paths):
                            need(path.is_relative_to(self.jobroot) and path == path.resolve(), 'base-container-journal-path')
                            data,_ = accepted.regular(path,65536)
                            journal = accepted.decode(data)
                            identity = journal['identity']
                            need(identity['image'] in row['image_ids'] and all(identity[key] == self._identity()[key]
                                 for key in ('uid','gid','endpoint','binary_sha256','daemon','local_pins')),
                                 'base-container-journal-binding')
                            owner = BudgetBroker(self.cleanup_runner,self.cleanup_runner,self.binary,self.binary_sha,
                                self.endpoint,identity['image'],self.uid,self.gid,path,identity['nonce'])
                            owner.final_deadline = self.final_deadline
                            owner.pins,owner.daemon = self.pins,self.daemon
                            images = recover(lambda: self._operation(['image','ls','--all','--no-trunc','--quiet'],cleanup=True))
                            need(images.returncode == 0,'base-owned-image-list')
                            if identity['image'] in images.stdout.decode().splitlines():
                                owner.image_config = recover(lambda: self._verify_image(identity['image'],row,cleanup=True))
                            owner._journal()
                            result = owner.cleanup()
                            cancelled = cancelled or bool(result.get('cancelled'))
                            need(result['absence_verified'] is True and (result['status'] == 'PASS' or
                                 (result.get('cancelled') is True and not result.get('errors'))),
                                 'base-container-cleanup')
                        for identifier in row['image_ids']:
                            recover(lambda: remove_owned(identifier,row))
                        need(not recover(self._owned_ids), 'base-owned-image-absence')
                        row['phase'] = 'removed'
                        self._save_image(record)
                except runtime.Cancelled:
                    cancelled = True
                    errors.append('base-cleanup-cancelled')
                except (OSError,ValueError,KeyError,TypeError) as error:
                    errors.append(str(error))
            cancelled = cancelled or bool(events)
            return {'status':'FAIL' if errors or cancelled else 'PASS','absence_verified':not errors,
                    'owned_image_absence':not errors, 'legacy_cache_cleanup':'NOT CLAIMED',
                    'cancelled':cancelled,'errors':errors}

    class BudgetBroker(accepted.Broker):
        def _inspect(self,*args,**kwargs):
            need(self.image_config is not None,'base-container-image-missing')
            return super()._inspect(*args,**kwargs)
        def _operation(self,args,*,cleanup=False,timeout=30):
            runner = self.cleanup_runner if cleanup else self.runner
            runner.deadline = min(runner.deadline,self.final_deadline)
            need(time.monotonic() < self.final_deadline,'base-cleanup-deadline')
            return super()._operation(args,cleanup=cleanup,timeout=timeout)
        def _info(self,runner):
            runner.deadline = min(runner.deadline,self.final_deadline)
            return super()._info(runner)

    BaseBroker.accepted = accepted
    BaseBroker.runtime = runtime
    return BaseBroker
